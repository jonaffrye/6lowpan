-module(lowpan_layer).

-behaviour(gen_statem).

-include("lowpan.hrl").

-export([init/1, start_link/1, start/1, stop_link/0, stop/0]).
-export([idle_state/3, callback_mode/0]).
-export([send_packet/1, send_unc_datagram/3, tx/3]).
-export([frame_reception/0]).
-export([input_callback/4]).

%---------- API Functions --------------------------------------------------------------
init(Params) ->
    CurrNodeMacAdd = maps:get(node_mac_addr, Params),
    setup_ets(),
    set_nodeData_value(currNodeMacAdd, CurrNodeMacAdd),

    Data = #{node_mac_addr => CurrNodeMacAdd, datagram_map => #{}, fragment_tags=>#{}},

    {ok, idle_state, Data}.

-spec start_link(Params :: #{}) -> {ok, pid()} | {error, any()}.
start_link(Params) ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, Params, []).

% Starts statem
start(Params) ->
    gen_statem:start({local, ?MODULE}, ?MODULE, Params, []),
    io:format("~p: Stack successfully launched~n", [node()]),

    RoutingTable  = maps:get(routing_table, Params),

    case erpc:call(node(), routing_table, start, [RoutingTable]) of
        {ok, _} ->
            io:format("~p: Routing table server successfully launched~n", [node()]);
        {error, Reason} ->
            io:format("~p: Failed to start routing table server: ~p~n", [node(), Reason]),
            exit({error, Reason})
    end, 
    CurrNodeMacAdd = maps:get(node_mac_addr, Params),
    io:format("Current node mac address: ~p~n", [CurrNodeMacAdd]),
    io:format("----------------------------------------------------------------------------------------~n").

stop_link() ->
    gen_statem:stop(?MODULE).

% Stops statem
stop() ->
    io:format("lowpan layer stopped"),
    erpc:call(node(), routing_table, stop, []),
    gen_statem:stop(?MODULE).

%-------------------------------------------------------------------------------
% Send Ipv6 packet using 6lowpan mechanisms
%-------------------------------------------------------------------------------
send_packet(Ipv6Pckt) ->
    io:format("New packet transmission ~n"),
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),
    SrcAddress = PcktInfo#ipv6PckInfo.sourceAddress,
   
    case <<SrcAddress:128>> of  % Check if the source address is multicast
        <<16#FF:16, _:112>> ->
            io:format("Error, Source address cannot be a multicast address~n"),
            {error_multicast_src};
        _ ->
            gen_statem:call(?MODULE, {pckt_tx, Ipv6Pckt, PcktInfo})
    end.

%-------------------------------------------------------------------------------
% Send uncompressed Ipv6 packet directly to ieee802154
%-------------------------------------------------------------------------------
send_unc_datagram(Ipv6Pckt, FrameControl, MacHeader) ->
    gen_statem:call(?MODULE, {dtg_tx, Ipv6Pckt, FrameControl, MacHeader}).

%-------------------------------------------------------------------------------
% Send datagram packet directly to ieee802154
%-------------------------------------------------------------------------------
tx(Frame, FrameControl, MacHeader) ->
    gen_statem:call(?MODULE, {simple_tx, Frame, FrameControl, MacHeader}).

%-------------------------------------------------------------------------------
% Get any datagram from ieee802154
%-------------------------------------------------------------------------------
frame_reception() ->
    gen_statem:cast(?MODULE, {frame_rx, self()}),
    receive
        {reassembled_packet, ReassembledPacket} ->
            ReassembledPacket; 
        {dtg_discarded} -> 
            io:format("Datagram successfully discarded ~n"),
            dtg_discarded
    after 10000 ->
        %gen_statem:call(?MODULE, {reassembly_timeout, Datagram})
        timeout
    end.
    

%-------------------------------------------------------------------------------
% Callback function used to retrieve datagram
%-------------------------------------------------------------------------------
input_callback(Frame, _, _, _) ->
    {FC, MH, Datagram} = Frame,
    io:format("New frame received~n"),
    case Datagram of
        ?ACK_FRAME -> 
            %io:format("From              : ~p~n",[ MH#mac_header.src_addr]),
            ok;   
        Dtg ->
            io:format("~p~n", [Dtg])
    end,

    % check packet type, if meshType,retrieve final destination addr 
    {IsMeshedPckt, FinalDstMacAdd, MeshPckInfo} = case lowpan:contains_mesh_header(Datagram) of
            {true, MeshInfo} ->
                {true, MeshInfo#meshInfo.final_destination_address, MeshInfo};
            false ->
                {false, MH#mac_header.dest_addr, #{}}
    end,
    
    CurrNodeMacAdd = get_nodeData_value(currNodeMacAdd),
    handle_Datagram(IsMeshedPckt, MeshPckInfo, FinalDstMacAdd, CurrNodeMacAdd, FC, MH, Datagram).

%-------------------------------------------------------------------------------
% Checks if received datagram reached destination or not
%-------------------------------------------------------------------------------
handle_Datagram(IsMeshedPckt, MeshPckInfo, FinalDstMacAdd, CurrNodeMacAdd, FC, MH, Datagram) ->
    DestAdd = lowpan:convert_addr_to_bin(FinalDstMacAdd),
    io:format("Final destination address: ~p~n", [DestAdd]),
    io:format("Current node address     : ~p~n", [CurrNodeMacAdd]),

    case DestAdd of
        CurrNodeMacAdd ->
            io:format("Destination node reached, Forwarding to lowpan layer~n"),
            Rest = lowpan:remove_mesh_header(Datagram),
            gen_statem:cast(?MODULE, {new_frame, Rest});
        ?BroadcastAdd ->
            io:format("Ack received"),
            io:format("------------------------------------------------------~n");
        _ ->
            io:format("The datagram needs to be meshed"),
            gen_statem:cast(?MODULE, {forward, Datagram, IsMeshedPckt, MeshPckInfo, FinalDstMacAdd, CurrNodeMacAdd, FC, MH})
    end.


%---------- States --------------------------------------------------------------------

%-------------------------------------------------------------------------------
% state: forward, in this state, the node forwards the datagram to the next hop
%-------------------------------------------------------------------------------
idle_state(cast, {forward, Datagram, IsMeshedPckt, MeshPckInfo, DstMacAdd, CurrNodeMacAdd, FC, MH}, Data) ->
    NewDatagram =
        case IsMeshedPckt of
            true ->
                update_datagram(MeshPckInfo, Datagram, Data);
            false ->
                SenderMacAdd = MH#mac_header.src_addr,
                lowpan:create_new_mesh_datagram(Datagram, SenderMacAdd, DstMacAdd)
        end,
    case NewDatagram of
        {discard, _} ->
            {next_state, idle_state, Data};
        _ ->
            DestMacAddress = lowpan:convert_addr_to_bin(DstMacAdd),
            io:format("Searching next hop in the routing table..."),
            NextHopAddr = routing_table:get_route(DestMacAddress),

            case NextHopAddr of
                DestMacAddress ->
                    io:format("Direct link found~nForwarding to node: ~p", [NextHopAddr]);
                _ ->
                    io:format("Next hop found~nForwarding to node: ~p", [NextHopAddr])
            end,
            NewMH = MH#mac_header{src_addr = CurrNodeMacAdd, dest_addr = NextHopAddr},
            io:format("------------------------------------------------------~n"),
            forward_datagram(NewDatagram, FC, NewMH, Data)
    end;
    

%-------------------------------------------------------------------------------
% state: simple_tx, in this state, the node transmit datagram to ieee802154
%-------------------------------------------------------------------------------
idle_state({call, From}, {simple_tx, Frame, FrameControl, MacHeader}, Data) ->
    Transmit = ieee802154:transmission({FrameControl, MacHeader, Frame}),
    case Transmit of
        {ok, _} ->
            io:format("Packet sent successfully~n"),
            {next_state, idle_state, Data, [{reply, From, ok}]};
        {error, Error} ->
            io:format("Transmission error: ~p~n", [Error]),
            {next_state, idle_state, Data, [{reply, From, Error}]}
    end;

%-------------------------------------------------------------------------------
% state: dtg_tx, in this state, the node transmit uncomp packet to ieee802154
%-------------------------------------------------------------------------------
idle_state({call, From}, {dtg_tx, Ipv6Pckt, FrameControl, MacHeader}, Data) ->
    Frame = <<?IPV6_DHTYPE:8, Ipv6Pckt/bitstring>>,
    Transmit = ieee802154:transmission({FrameControl, MacHeader, Frame}),
    case Transmit of
        {ok, _} ->
            {next_state, idle_state, Data, [{reply, From, ok}]};
        {error, Error} ->
            {next_state, idle_state, Data, [{reply, From, Error}]}
    end;


%-------------------------------------------------------------------------------
% state: pckt_tx, in this state, the node transmit Ipv6 packet to ieee802154
%-------------------------------------------------------------------------------
idle_state({call, From}, {pckt_tx, Ipv6Pckt, PcktInfo}, Data = #{node_mac_addr := CurrNodeMacAdd, fragment_tags := TagsMap}) ->
    % 1st - retrieve useful info from Ip packet
    DestAddress = PcktInfo#ipv6PckInfo.destAddress,
    SrcAddress = PcktInfo#ipv6PckInfo.sourceAddress,
    Payload = PcktInfo#ipv6PckInfo.payload,
   
    % retrieve macAddress from Ipv6 address
    DestMacAddress = lowpan:get_EUI64_mac_addr(DestAddress),
    SenderMacAdd = lowpan:get_EUI64_mac_addr(SrcAddress),

    io:format("Final destination: ~p~n",[DestMacAddress]),

    % 2nd - compress the header
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt),
    CompressedPacket = <<CompressedHeader/binary, Payload/bitstring>>,
    CompressedPacketLen = byte_size(CompressedPacket),

    io:format("Compressed packet size: ~p bytes~n", [CompressedPacketLen]),

    % get unique tag
    Tag = rand:uniform(?MAX_TAG_VALUE),
    {ValidTag, UpdatedTagsMap} = lowpan:check_tag_unicity(TagsMap, Tag),
    
    % 3rd - check if fragmentation is needed, if so return fragments list
    {FragReq, Fragments} = lowpan:trigger_fragmentation(CompressedPacket, ValidTag),

    % 4th - get next hop
    io:format("Routing check...~n"),
    {RouteExist, MeshedHdrBin, MH} =
        lowpan:get_next_hop(CurrNodeMacAdd, SenderMacAdd, DestMacAddress),
    
    % 5th - send to next hop
    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    case FragReq of
        true ->
            Response = send_fragments(RouteExist, Fragments, 1, MeshedHdrBin, MH, FC),
            {next_state, idle_state, Data#{fragments => Fragments, fragment_tags => UpdatedTagsMap}, [{reply, From, Response}]};
        false ->
            Response = send_fragment(RouteExist, Fragments, MeshedHdrBin, MH, FC),
            {next_state, idle_state, Data#{fragments => Fragments, fragment_tags => UpdatedTagsMap}, [{reply, From, Response}]}; 
        size_err -> 
            io:format("The datagram size exceed the authorized length~n"),
            {next_state, idle_state, Data, [{reply, From, error_frag_size}]}
    end;


%-------------------------------------------------------------------------------
% state: frame_rx, in this state, the node activates the rx_on in ieee802154
%-------------------------------------------------------------------------------
idle_state(cast, {frame_rx, From}, Data) ->
    % ieee802154:rx_on(),  
    io:format("~p waiting to receive data... ~n", [node()]),
    NewData = Data#{caller => From},
    {next_state, idle_state, NewData};

   
    % case Rx_on of % TODO 
    %     ok ->
    %         io:format("Rx_on activated on node: ~p~n", [node()]),
    %         NewData = Data#{caller => From},
    %         {next_state, idle_state, NewData};
    %     {error, E} ->
    %         {next_state, idle_state, Data, [{reply, From, {error, E}}]}
    % end;

%-------------------------------------------------------------------------------
% state: new_frame, in this state, the node process the received frame
%-------------------------------------------------------------------------------
idle_state(cast, {new_frame, Datagram}, Data = #{datagram_map := DatagramMap, caller := From}) ->
    <<Type:3, _/bitstring>> = Datagram,
    case Type of
        ?IPHC_DHTYPE -> % compressed datagram
            io:format("Datagram reassembled ~n"),
            From ! {reassembled_packet, Datagram},
            {next_state, idle_state, Data};
        _ -> % fragmented datagram
            io:format("Storing fragment~n"),
            UpdatedMap = put_and_reassemble(Datagram, DatagramMap, Data),
            {keep_state, Data#{datagram_map => UpdatedMap}}
    end;

%-------------------------------------------------------------------------------
% state: collected, in this state, the node sends the reassemble packet
%-------------------------------------------------------------------------------
idle_state(cast, {collected, Tag, UpdatedMap}, StateData = #{caller := From}) ->
    ReassembledPacket = lowpan:reassemble(Tag, UpdatedMap),
    io:format("Complete for pckt ~p~n", [Tag]),
    From ! {reassembled_packet, ReassembledPacket},
    {next_state, idle_state, StateData};

% idle_state(cast, {discard_datagram, _}, Data = #{caller := From}) ->
%     io:format("Hop left value: 0, discarding the datagram~n"),
%     From ! {dtg_discarded},
%     {next_state, idle_state, Data};

%-------------------------------------------------------------------------------
% state: reassembly_timeout, in this state, the node discards the datagram
%-------------------------------------------------------------------------------
idle_state({call, From}, {reassembly_timeout}, Data) ->
    % io:format("Timeout for datagram ~p~n", []),
    {next_state, idle_state, Data, [{reply, From, timeout}]}.


%---------- utils functions -----------------------------------------------------------

%-------------------------------------------------------------------------------
% Transmits each fragment in the FragmentList to ieee802154
%-------------------------------------------------------------------------------
% No frag needed => send CompressedPacket  
send_fragment(RouteExist, CompressedPacket, MeshedHdrBin, MH, FC) ->
    Pckt = case RouteExist of
                true ->
                    <<MeshedHdrBin/binary, CompressedPacket/bitstring>>;

                false ->
                    CompressedPacket
            end,
    io:format("Sending ~p bytes~n", [byte_size(Pckt)]),
    case ieee802154:transmission({FC, MH, Pckt}) of
        {ok, _} ->
            ok;
        {error, Error} ->
            Error
    end.

%frag needed => add mesh header
send_fragments(RouteExist, [{FragHeader, FragPayload} | Rest], Counter, MeshedHdrBin, MH, FC) ->
    Pckt = case RouteExist of
                true ->
                    <<MeshedHdrBin/binary, FragHeader/binary, FragPayload/bitstring>>;
                    
                false ->
                    <<FragHeader/binary, FragPayload/bitstring>>
            end, 
    %timer:sleep(10),
    case ieee802154:transmission({FC, MH, Pckt}) of
        {ok, _} ->
            io:format("~pth fragment: ~p bytes sent~n", [Counter, byte_size(Pckt)]),
            send_fragments(RouteExist, Rest, Counter + 1, MeshedHdrBin, MH, FC);
        {error, Error} ->
            io:format("Error during transmission of fragment ~p: ~p~n", [Counter, Error]),
            Error
    end;          
send_fragments(_RouteExist, [], _Counter, _MeshedHdrBin, _MH, _FC) ->
    ok.


%---------------------------------------------------------------------------------
% Add new datagram in the datgram map and check if all of them have been received
%---------------------------------------------------------------------------------
put_and_reassemble(Datagram, Map, _) ->
    DtgInfo = lowpan:datagram_info(Datagram),

    Size = DtgInfo#datagramInfo.datagramSize,
    Tag = DtgInfo#datagramInfo.datagramTag,
    Offset = DtgInfo#datagramInfo.datagramOffset,
    Payload = DtgInfo#datagramInfo.payload,

    io:format("Received ~pth payload: ~p bytes~n", [Offset + 1, byte_size(Payload)]),

    {UpdatedMap, DatagramComplete} =
        case maps:is_key(Tag, Map) of
            true -> % datagram in map
                {NewMap, AllReceived} =
                    lowpan:check_duplicate_frag(Map, Tag, Offset, Size, Payload),
                {NewMap, AllReceived};

            false -> % datagram not in map
                CurrSize = byte_size(Payload),
                NewDatagram =
                    #datagram{tag = Tag,
                              size = Size,
                              cmpt = CurrSize,
                              fragments = #{Offset => Payload}},
                NewMap = maps:put(Tag, NewDatagram, Map),
                AllReceived = CurrSize == Size,
                {NewMap, AllReceived}
        end,
    io:format("Map: ~p~n", [UpdatedMap]),

    case DatagramComplete of
        true ->
            gen_statem:cast(?MODULE, {collected, Tag, UpdatedMap});
        false ->
            io:format("Uncomplete datagram ~n"),
            io:format("------------------------------------------------------")
    end,
    UpdatedMap.

%-------------------------------------------------------------------------------
% Decrements hop left field, build new mesh header and returns new datagram
%-------------------------------------------------------------------------------
update_datagram(MeshInfo, Datagram, Data) ->
    HopsLft = MeshInfo#meshInfo.hops_left - 1,
    case HopsLft of
        0 ->
            % discard datagram => don't transmit it
            {discard, discard_datagram(Datagram, Data)};
        _ ->
            Payload = MeshInfo#meshInfo.payload,
            OrigAdd = lowpan:convert_addr_to_bin(MeshInfo#meshInfo.originator_address),
            DestAdd = lowpan:convert_addr_to_bin(MeshInfo#meshInfo.final_destination_address),
            MeshHeader =
                #mesh_header{v_bit = MeshInfo#meshInfo.v_bit,
                             f_bit = MeshInfo#meshInfo.f_bit,
                             hops_left = HopsLft,
                             originator_address = OrigAdd,
                             final_destination_address = DestAdd},

            BinMeshHeader = lowpan:build_mesh_header(MeshHeader),
            <<BinMeshHeader/binary, Payload/bitstring>>
    end.

discard_datagram(_, Data = #{caller := From})->
    io:format("~nHop left value: 0, discarding the datagram~n"),
    From ! {dtg_discarded},
    {next_state, idle_state, Data}.


%-------------------------------------------------------------------------------
% Forward datagram to next hop
%-------------------------------------------------------------------------------
forward_datagram(Frame, FrameControl, MacHeader, Data) ->
    Transmit = ieee802154:transmission({FrameControl, MacHeader, Frame}),
    case Transmit of
        {ok, _} ->
            io:format("Packet sent successfully~n"),
            {next_state, idle_state, Data};
        {error, Error} ->
            io:format("Transmission error: ~p~n", [Error]),
            {next_state, idle_state, Data}
    end. 

%---------- Helper --------------------------------------------------------------------

%-------------------------------------------------------------------------------
% Used to store current node mac address
%-------------------------------------------------------------------------------
setup_ets() ->
    ets:new(nodeData, [named_table, public, {keypos, 1}]).

set_nodeData_value(Key, Value) ->
    ets:insert(nodeData, {Key, Value}).

get_nodeData_value(Key) ->
    case ets:lookup(nodeData, Key) of
        [] ->
            undefined;
        [{_, Value}] ->
            Value
    end.

callback_mode() ->
    [state_functions].