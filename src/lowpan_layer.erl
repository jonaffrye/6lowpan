-module(lowpan_layer).

-behaviour(gen_statem).

-include("lowpan.hrl").

-export([init/1, start_link/1, start/1, stop_link/0, stop/0]).
-export([idle_state/3, callback_mode/0]).
-export([send_packet/1, send_unc_datagram/3, tx/3, extended_hopsleft_tx/1]).
-export([frame_reception/0, frame_info_rx/0]).
-export([input_callback/4]).

%---------- API Functions --------------------------------------------------------------
init(Params) ->
    
    MacAdd = maps:get(node_mac_addr, Params),
    CurrNodeMacAdd = lowpan:generate_EUI64_mac_addr(MacAdd), % Convert mac address to valid 64-bit address
    io:format("Current node address: ~p~n",[CurrNodeMacAdd]),
    setup_node_info_ets(),
    set_nodeData_value(currNodeMacAdd, CurrNodeMacAdd),

    RoutingTable  = maps:get(routing_table, Params),

    case routing_table:start(RoutingTable) of
        {ok, _Pid} ->
            io:format("~p: Routing table server successfully launched~n", [node()]);
        {error, Reason} ->
            io:format("~p: Failed to start routing table server: ~p~n", [node(), Reason]),
            exit({error, Reason})
    end, 

    ieee802154_setup(CurrNodeMacAdd),

    DatagramMap = ets:new(datagram_map, [named_table, public]),

    Data = #{node_mac_addr => CurrNodeMacAdd, datagram_map => DatagramMap, 
            fragment_tag => ?DEFAULT_TAG_VALUE, seqNum => ?BC_SEQNUM},

    io:format("~p: 6lowpan layer successfully launched~n", [node()]),

    io:format("----------------------------------------------------------------------------------------~n"),
    {ok, idle_state, Data}.

-spec start_link(Params :: #{}) -> {ok, pid()} | {error, any()}.
start_link(Params) ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, Params, []).

% Starts statem
start(Params) ->
    gen_statem:start({local, ?MODULE}, ?MODULE, Params, []).

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
            Extended_hopsleft = false,
            gen_statem:call(?MODULE, {pckt_tx, Ipv6Pckt, PcktInfo, Extended_hopsleft})
    end.

extended_hopsleft_tx(Ipv6Pckt) ->
    io:format("New packet transmission ~n"),
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),
    SrcAddress = PcktInfo#ipv6PckInfo.sourceAddress,
   
    case <<SrcAddress:128>> of  % Check if the source address is multicast
        <<16#FF:16, _:112>> ->
            io:format("Error, Source address cannot be a multicast address~n"),
            {error_multicast_src};
        _ ->
            Extended_hopsleft = true,
            gen_statem:call(?MODULE, {pckt_tx, Ipv6Pckt, PcktInfo, Extended_hopsleft})
    end.

%-------------------------------------------------------------------------------
% Send uncompressed Ipv6 packet directly to ieee802154
%-------------------------------------------------------------------------------
send_unc_datagram(Ipv6Pckt, FrameControl, MacHeader) ->
    gen_statem:call(?MODULE, {tx_datagram, Ipv6Pckt, FrameControl, MacHeader}).

%-------------------------------------------------------------------------------
% Send datagram packet directly to ieee802154
%-------------------------------------------------------------------------------
tx(Frame, FrameControl, MacHeader) ->
    case Frame of 
        <<?NALP_DHTYPE,_/bitstring>> -> 
            io:format("The received frame is not a lowpan frame~n"),
            error_nalp;
        _-> gen_statem:call(?MODULE, {tx_frame, Frame, FrameControl, MacHeader})
    end.

%-------------------------------------------------------------------------------
% Get any datagram from ieee802154
%-------------------------------------------------------------------------------
frame_reception() ->
    gen_statem:cast(?MODULE, {frame_rx, self()}),
    receive
        {reassembled_packet, ReassembledPacket} ->
            io:format("Datagram reassembled ~n"),
            ReassembledPacket; 
        {dtg_discarded} -> 
            io:format("Datagram successfully discarded ~n"),
            dtg_discarded; 
        {reassembly_timeout, DatagramMap, EntryKey} -> 
            io:format("Reassembly timeout for entry ~p~n", [EntryKey]),
            ets:delete(DatagramMap, EntryKey),
            io:format("Entry deleted~n"),
            reassembly_timeout; 
        {error_nalp}->
            error_nalp
    after 15000 ->
        error_timeout
    end.

%-------------------------------------------------------------------------------
% Get any datagram from ieee802154 and return additional info (frag_header, ...)
% mainly use for testing purpose
%-------------------------------------------------------------------------------
frame_info_rx() ->
    gen_statem:cast(?MODULE, {frame_info_rx, self()}),
    receive
        {additional_info, Info, _} ->
            Info
    after ?REASSEMBLY_TIMEOUT ->
        gen_statem:call(?MODULE, {reassembly_timeout})
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

    OriginatorAddr = case MeshPckInfo of
                        #{}-> MH#mac_header.src_addr;
                        _ -> MeshPckInfo#meshInfo.originator_address
                    end,
    
    CurrNodeMacAdd = get_nodeData_value(currNodeMacAdd),

    handle_Datagram(IsMeshedPckt, MeshPckInfo, OriginatorAddr, FinalDstMacAdd, CurrNodeMacAdd, FC, MH, Datagram).

%-------------------------------------------------------------------------------
% Checks if received datagram reached destination or not
%-------------------------------------------------------------------------------
handle_Datagram(IsMeshedPckt, MeshPckInfo,OriginatorAddr, FinalDstMacAdd, CurrNodeMacAdd, FC, MH, Datagram) ->
    DestAdd = lowpan:convert_addr_to_bin(FinalDstMacAdd),
    io:format("Final destination address: ~p~n", [DestAdd]),
    io:format("Current node address     : ~p~n", [CurrNodeMacAdd]),

    case DestAdd of
        CurrNodeMacAdd ->
            io:format("Final destination node reached, Forwarding to lowpan layer~n"),
            case IsMeshedPckt of
                true -> 
                    HopsLeft = MeshPckInfo#meshInfo.hops_left,
                    Rest = lowpan:remove_mesh_header(Datagram,HopsLeft),
                    gen_statem:cast(?MODULE, {new_frame, OriginatorAddr, Rest});
                false-> 
                    HopsLeft = 1,
                    Rest = lowpan:remove_mesh_header(Datagram,HopsLeft),
                    gen_statem:cast(?MODULE, {new_frame, OriginatorAddr, Rest})

            end;
        ?BroadcastAdd ->
            io:format("Ack received"),
            io:format("------------------------------------------------------~n");
        _ ->
            io:format("The datagram needs to be meshed~n"),
            gen_statem:cast(?MODULE, {forward_datagram, Datagram, IsMeshedPckt, MeshPckInfo, FinalDstMacAdd, CurrNodeMacAdd, FC, MH})
    end.


%---------- States --------------------------------------------------------------------

%-------------------------------------------------------------------------------

%-------------------------------------------------------------------------------

%% @doc State: tx_frame, in this state, the node transmits datagram to ieee802154
%% @spec idle_state({call, any()}, {tx_frame, binary(), map(), map()}, map()) -> {next_state, atom(), map(), [{reply, any(), any()}]}.
idle_state({call, From}, {tx_frame, Frame, FrameControl, MacHeader}, Data) ->
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
idle_state({call, From}, {tx_datagram, Ipv6Pckt, FrameControl, MacHeader}, Data) ->
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
idle_state({call, From}, {pckt_tx, Ipv6Pckt, PcktInfo, Extended_hopsleft}, Data = #{node_mac_addr := CurrNodeMacAdd,
     fragment_tag := Tag, seqNum := SeqNum}) ->
    % 1st - retrieve useful info from Ip packet
    DestAddress = PcktInfo#ipv6PckInfo.destAddress,

    % process if DestAddress if broadcast or multicast 

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
    
    % 3rd - check if fragmentation is needed, if so return fragments list
    {FragReq, Fragments} = lowpan:trigger_fragmentation(CompressedPacket, Tag),

    % 4th - get next hop
    io:format("Routing check...~n"),

    {RouteExist, MeshedHdrBin, MH} =
        lowpan:get_next_hop(CurrNodeMacAdd, SenderMacAdd, DestMacAddress, DestAddress, SeqNum+1, Extended_hopsleft),

    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},

    % 5th - send to next hop
    case FragReq of
        true ->
            Response = send_fragments(RouteExist, Fragments, 1, MeshedHdrBin, MH, FC, Tag),
            NewTag = Tag+1 rem ?MAX_TAG_VALUE,
            {next_state, idle_state, Data#{fragments => Fragments, fragment_tag => NewTag}, [{reply, From, Response}]};
        false ->
            Response = send_fragment(RouteExist, Fragments, MeshedHdrBin, MH, FC, Tag),
            NewTag = Tag+1 rem ?MAX_TAG_VALUE,
            {next_state, idle_state, Data#{fragments => Fragments, fragment_tag => NewTag}, [{reply, From, Response}]}; 
        size_err -> 
            io:format("The datagram size exceed the authorized length~n"),
            {next_state, idle_state, Data, [{reply, From, error_frag_size}]}
    end;


%-------------------------------------------------------------------------------
% state: frame_rx, in this state, the node activates the rx_on in ieee802154
%-------------------------------------------------------------------------------
idle_state(cast, {frame_rx, From}, Data) ->
    io:format("~p waiting to receive data... ~n", [node()]),
    NewData = Data#{caller => From,  info=>?INFO_OFF},
    {next_state, idle_state, NewData}; 

idle_state(cast, {frame_info_rx, From}, Data) ->
    io:format("~p waiting to receive data... ~n", [node()]),
    NewData = Data#{caller => From, info=>?INFO_ON},
    {next_state, idle_state, NewData};

%-------------------------------------------------------------------------------
% state: new_frame, in this state, the node processes the received frame
%-------------------------------------------------------------------------------
idle_state(cast, {new_frame, OriginatorAddr, Datagram}, Data = #{caller := From}) ->
    case Datagram of
        <<?IPHC_DHTYPE:3, _Rest/bitstring>> -> % compressed datagram
            io:format("Received a compressed datagram~n"),
            From ! {reassembled_packet, Datagram},
            {next_state, idle_state, Data};

        <<?IPV6_DHTYPE:8, Payload/bitstring>> -> % uncompressed IPv6 datagram
            io:format("Received a uncompressed IPv6 datagram~n"),
            % Process uncompressed IPv6 datagram
            From ! {reassembled_packet, Payload},
            {next_state, idle_state, Data};

        <<?NALP_DHTYPE,_/bitstring>> -> 
            io:format("The received frame is not a lowpan frame~n"),
            From ! {error_nalp},
            {next_state, idle_state, Data};

        <<Type:5, _Rest/bitstring>> when Type =:= ?FRAG1_DHTYPE; Type =:= ?FRAGN_DHTYPE -> % fragmented datagram
            FragInfo = lowpan:datagram_info(Datagram),
            % Info = #additional_info{
            %                 datagram_tag = FragInfo#frag_info.datagram_tag, 
            %                 datagram_size = FragInfo#frag_info.datagram_size
            %         },
            Info = FragInfo#datagramInfo.datagramTag,
            NewData = Data#{additional_info => Info},
            io:format("Storing fragment~n"),
            gen_statem:cast(?MODULE, {add_fragment, OriginatorAddr, Datagram}),
            {keep_state, NewData} 
    end;

%-------------------------------------------------------------------------------
% state: add_fragment, in this state, the node adds new fragment to the map 
%-------------------------------------------------------------------------------
idle_state(cast, {add_fragment, OriginatorAddr, Datagram}, Data = #{datagram_map := DatagramMap, caller := From}) ->
    DtgInfo = lowpan:datagram_info(Datagram),

    Size = DtgInfo#datagramInfo.datagramSize,
    Tag = DtgInfo#datagramInfo.datagramTag,
    Offset = DtgInfo#datagramInfo.datagramOffset,
    Payload = DtgInfo#datagramInfo.payload,

    Key = {OriginatorAddr, Tag}, 
    CurrTime = os:system_time(second),
    case lowpan:store_fragment(DatagramMap, Key, Offset, Payload, CurrTime, Size, Tag, From) of
        {complete_first_frag, ReassembledPacket} ->
            io:format("Complete for pckt ~p~n", [Key]),
            io:format("----------------------------------------------------------------------------------------~n"),
            From ! {reassembled_packet, ReassembledPacket},
            {next_state, idle_state, Data};

        {complete, UpdatedDatagram} ->
            gen_statem:cast(?MODULE, {collected, Key, UpdatedDatagram}),
            NewData = Data#{key => Key},
            {keep_state, NewData};

        {duplicate, _} ->
            io:format("Duplicate frame detected~n"),
            io:format("----------------------------------------------------------------------------------------~n"),
            NewData = Data#{key => Key},
            {keep_state, NewData};

         {incomplete_first, EntryKey} ->
            io:format("Uncomplete first datagram, waiting for other fragments ~n"),
            erlang:send_after(?REASSEMBLY_TIMEOUT, From, {reassembly_timeout, DatagramMap, EntryKey}),
            io:format("----------------------------------------------------------------------------------------~n"),
            NewData = Data#{key => Key},
            {keep_state, NewData};

        {incomplete, _} ->
            io:format("Uncomplete datagram, waiting for other fragments ~n"),
            io:format("----------------------------------------------------------------------------------------~n"),
            NewData = Data#{key => Key},
            {keep_state, NewData}
    end;


%-------------------------------------------------------------------------------
% state: collected, in this state, the node sends the reassembled packet
%-------------------------------------------------------------------------------
idle_state(cast, {collected, Key, UpdatedDatagram}, Data = #{datagram_map := DatagramMap, caller := From, additional_info:=Info, info:=InfoReq}) ->
    ReassembledPacket = lowpan:reassemble(UpdatedDatagram),
    io:format("Complete for pckt ~p~n", [Key]),
    ets:delete(DatagramMap, Key),
    case InfoReq of
        ?INFO_ON -> 
            From ! {additional_info, Info, ReassembledPacket};
        _ -> 
            From ! {reassembled_packet, ReassembledPacket}
    end,
    {next_state, idle_state, Data}.

%---------- utils functions -----------------------------------------------------------

%-------------------------------------------------------------------------------
% Transmits each fragment in the FragmentList to ieee802154
%-------------------------------------------------------------------------------
% No frag needed => send CompressedPacket  
send_fragment(RouteExist, CompressedPacket, MeshedHdrBin, MH, FC, Tag) ->
    Pckt = case RouteExist of
                true ->
                    <<MeshedHdrBin/binary, CompressedPacket/bitstring>>;

                false ->
                    CompressedPacket
            end,
    io:format("Sending ~p bytes~n", [byte_size(Pckt)]),
    MacHeader = MH#mac_header{seqnum = Tag},
    io:format("MH ~p~n",[MH]),
    case ieee802154:transmission({FC, MacHeader, Pckt}) of
        {ok, _} ->
            ok;
        {error, Error} ->
            Error
    end.

%frag needed => add mesh header
send_fragments(RouteExist, [{FragHeader, FragPayload} | Rest], Counter, MeshedHdrBin, MH, FC, Tag) ->
    Pckt = case RouteExist of
                true ->
                    <<MeshedHdrBin/binary, FragHeader/binary, FragPayload/bitstring>>;
                    
                false ->
                    <<FragHeader/binary, FragPayload/bitstring>>
            end, 
    %timer:sleep(10),
    MacHeader = MH#mac_header{seqnum = Tag+Counter},
    case ieee802154:transmission({FC, MacHeader, Pckt}) of
        {ok, _} ->
            io:format("~pth fragment: ~p bytes sent~n", [Counter, byte_size(Pckt)]),
            send_fragments(RouteExist, Rest, Counter + 1, MeshedHdrBin, MacHeader, FC, Tag);
        {error, Error} ->
            io:format("Error during transmission of fragment ~p: ~p~n", [Counter, Error]),
            Error
    end;          
send_fragments(_RouteExist, [], _Counter, _MeshedHdrBin, _MH, _FC, _Tag) ->
    ok.


%-------------------------------------------------------------------------------
% Decrements hop left field, build new mesh header and returns new datagram
%-------------------------------------------------------------------------------
update_datagram(MeshInfo, Datagram, Data) ->
    HopsLeft = MeshInfo#meshInfo.hops_left, 
    
    {Is_Extended_hopsleft, HopLft} = 
        case HopsLeft of 
                ?DeepHopsLeft -> 
                    HopsLft = MeshInfo#meshInfo.deep_hops_left-1,
                    {true, HopsLft}; 
                 _ -> HopsLft = HopsLeft-1,
                    {false, HopsLft}
        end,

    case {Is_Extended_hopsleft, HopLft}  of
        {_, 0} ->
            % discard datagram => don't transmit it
            {discard, discard_datagram(Datagram, Data)};

        {false, _} ->
            Payload = MeshInfo#meshInfo.payload,
            % update mesh header
            MeshHeader =
                #mesh_header{v_bit = MeshInfo#meshInfo.v_bit,
                             f_bit = MeshInfo#meshInfo.f_bit,
                             hops_left = HopsLft,
                             originator_address = MeshInfo#meshInfo.originator_address,
                             final_destination_address =  MeshInfo#meshInfo.final_destination_address},

            BinMeshHeader = lowpan:build_mesh_header(MeshHeader),
            % build new datagram
            <<BinMeshHeader/binary, Payload/bitstring>>; 
            
        {true, _} ->
            Payload = MeshInfo#meshInfo.payload,

            % update mesh header
            VBit = MeshInfo#meshInfo.v_bit,
            FBit = MeshInfo#meshInfo.f_bit,
            OriginatorAddress = MeshInfo#meshInfo.originator_address,
            FinalDestinationAddress =  MeshInfo#meshInfo.final_destination_address,

            BinMeshHeader = <<?MESH_DHTYPE:2, VBit:1, FBit:1, ?DeepHopsLeft:4, 
                            OriginatorAddress/binary, FinalDestinationAddress/binary, HopLft:8>>,
            
            % build new datagram
            <<BinMeshHeader/binary, Payload/bitstring>>
    end.

discard_datagram(_, Data = #{caller := From})->
    io:format("~nHop left value: 0, discarding the datagram~n"),
    From ! {dtg_discarded},
    {next_state, idle_state, Data}.


%-------------------------------------------------------------------------------
% Forward datagram to next hop
%-------------------------------------------------------------------------------
forward_datagram(Frame, FrameControl, MacHeader, Data = #{caller := From}) ->
    case Frame of 
        <<?NALP_DHTYPE,_/bitstring>> ->
            io:format("The received frame is not a lowpan frame~n"), 
            From ! {error_nalp};
        _->
            Transmit = ieee802154:transmission({FrameControl, MacHeader, Frame}),
            case Transmit of
                {ok, _} ->
                    io:format("Packet sent successfully~n");    
                {error, Error} ->
                    io:format("Transmission error: ~p~n", [Error])
            end
    end, 
    {next_state, idle_state, Data}.



%---------- Helper --------------------------------------------------------------------

%-------------------------------------------------------------------------------
% Used to store current node mac address
%-------------------------------------------------------------------------------
setup_node_info_ets() ->
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


%-------------------------------------------------------------------------------
% Setup ieee802154 layer
%-------------------------------------------------------------------------------
ieee802154_setup(MacAddr)->
    ieee802154:start(#ieee_parameters{
        %phy_layer = mock_phy_network, % uncomment when testing
        duty_cycle = duty_cycle_non_beacon,
        input_callback = fun lowpan_layer:input_callback/4
    }),

    case application:get_env(robot, pan_id) of
        {ok, PanId} ->
            ieee802154:set_pib_attribute(mac_pan_id, PanId);
        _ ->
            ok
    end,

    case byte_size(MacAddr) of 
        ?EXTENDED_ADDR_LEN -> ieee802154:set_pib_attribute(mac_extended_address, MacAddr); 
        ?SHORT_ADDR_LEN -> ieee802154:set_pib_attribute(mac_short_address, MacAddr)
    end, 

    ieee802154:rx_on(), 
    io:format("~p IEEE 802.15.4 layer successfully launched ~n",[node()]).

callback_mode() ->
    [state_functions].