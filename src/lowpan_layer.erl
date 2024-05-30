-module(lowpan_layer).

-behaviour(gen_statem).

-include("lowpan.hrl").

% API
-export([start_link/1, start/1, stop_link/0, stop/0, input_callback/4]).
% gen_statem callbacks
-export([init/1, callback_mode/0, idle_state/3]).
-export([send_packet/1, send_unc_datagram/3, frame_reception/0, tx/3]).

%%---Helper -----------------------------------------------------------------------------

setup_ets() ->
    ets:new(nodeData, [named_table, public, {keypos, 1}]).

set_nodeData_value(Key, Value) ->
    ets:insert(nodeData, {Key, Value}).

% Get a value from the ETS table
get_nodeData_value(Key) ->
    case ets:lookup(nodeData, Key) of
        [] ->
            undefined;
        [{_, Value}] ->
            Value
    end.

%--- API --------------------------------------------------------------------------------

%% @doc Starts the 6lowpan statck and creates a link
%% @end
init(Params) ->
    CurrNodeMacAdd = maps:get(node_mac_addr, Params),
    %Routing_table = maps:get(default_routing_table, Params),
    io:format("CurrNodeMacAdd: ~p~n", [CurrNodeMacAdd]),

    setup_ets(),
    set_nodeData_value(currNodeMacAdd, CurrNodeMacAdd),

    Data =
        #{node_mac_addr => CurrNodeMacAdd,
          %default_routing_table => Routing_table,
          datagram_map => #{}},

    {ok, idle_state, Data}.

-spec start_link(Params :: #{}) -> {ok, pid()} | {error, any()}.
start_link(Params) ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, Params, []).

% Starts statem
start(Params) ->
    gen_statem:start({local, ?MODULE}, ?MODULE, Params, []),
    io:format("lowpan layer launched on node ~p~n", [node()]),

    case erpc:call(node(), routing_table, start, [?Routing_table]) of
        {ok, _} ->
            io:format("~p: Routing table server successfully launched~n", [node()]);
        {error, Reason} ->
            io:format("~p: Failed to start routing table server: ~p~n", [node(), Reason]),
            exit({error, Reason})
    end.

stop_link() ->
    gen_statem:stop(?MODULE).

% Stops statem
stop() ->
    io:format("lowpan layer stopped"),
    erpc:call(node(), routing_table, stop, []),
    gen_statem:stop(?MODULE).

% Send an IPv6 packet
-spec send_packet(Ipv6Pckt :: bitstring()) -> ok.
send_packet(Ipv6Pckt) ->
    gen_statem:call(?MODULE, {pckt_tx, Ipv6Pckt}).  % gen_statem:call(StateName, Event)

% Send an uncompressed IPv6 packet
send_unc_datagram(Ipv6Pckt, FrameControl, MacHeader) ->
    gen_statem:call(?MODULE, {dtg_tx, Ipv6Pckt, FrameControl, MacHeader}).

% Send datagram
tx(Frame, FrameControl, MacHeader) ->
    gen_statem:call(?MODULE, {simple_tx, Frame, FrameControl, MacHeader}).

% Receive a processed packet
frame_reception() ->
    gen_statem:cast(?MODULE, {frame_rx, self()}),
    receive
        {reassembled_packet, ReassembledPacket} ->
            ReassembledPacket
    after ?REASSEMBLY_TIMEOUT ->
        timeout
    end.

input_callback(Frame, _, _, _) ->
    {FC, MH, Datagram} = Frame,
    io:format("New frame received~n~p~n", [Datagram]),

    CurrNodeMacAdd = get_nodeData_value(currNodeMacAdd),
    DstMacAdd = MH#mac_header.dest_addr,
    SenderMacAdd = MH#mac_header.src_addr,

    case DstMacAdd of
        CurrNodeMacAdd ->
            io:format("Dest reached, Forwarding to lowpan layer~n"),
            gen_statem:cast(?MODULE, {new_frame, Datagram});
        ?BroadcastAdd ->
            io:format("Ack received~n");
        _ -> % forward using mesh under
            NewDatagram =
                case lowpan:contains_mesh_header(Datagram) of
                    true ->
                        io:format("Retrieving mesh header info~n"),
                        % retrive mesh header data
                        MeshInfo = lowpan:get_mesh_info(Datagram),
                        VBit = MeshInfo#meshInfo.v_bit,
                        FBit = MeshInfo#meshInfo.f_bit,
                        OrAddr = MeshInfo#meshInfo.originator_address,
                        DstAddr = MeshInfo#meshInfo.final_destination_address,
                        HopsLft = MeshInfo#meshInfo.hops_left,
                        Payload = MeshInfo#meshInfo.payload,

                        case HopsLft of
                            0 ->
                                gen_statem:cast(?MODULE,
                                                {frame_discarded, Datagram}) %discard packet
                        end,

                        % decrement hopsleft and build new mesh header
                        MeshHeader =
                            #mesh_header{v_bit = VBit,
                                         f_bit = FBit,
                                         hops_left = HopsLft - 1,
                                         originator_address = OrAddr,
                                         final_destination_address = DstAddr},

                        BinMeshHeader = lowpan:build_mesh_header(MeshHeader),
                        <<BinMeshHeader/binary, Payload/bitstring>>;
                    false -> % create new mesh header
                        io:format("Building new mesh header~n"),
                        % build mesh header
                        VBit =
                            case byte_size(SenderMacAdd) of
                                8 ->
                                    0;
                                _ ->
                                    1
                            end,
                        FBit =
                            case byte_size(DstMacAdd) of
                                8 ->
                                    0;
                                _ ->
                                    1
                            end,

                        % build mesh header
                        MeshHeader =
                            #mesh_header{v_bit = VBit,
                                         f_bit = FBit,
                                         hops_left = ?Max_Hops - 1,
                                         originator_address = SenderMacAdd,
                                         final_destination_address = DstMacAdd},

                        BinMeshHeader = lowpan:build_mesh_header(MeshHeader),
                        <<BinMeshHeader/binary, Datagram/bitstring>>
                end,

            NextHopAddr = routing_table:get_route(DstMacAdd), % retrieve next hop address

            % send packet
            NewMH = MH#mac_header{src_addr = CurrNodeMacAdd, dest_addr = NextHopAddr},
            NewFrame = {FC, NewMH, NewDatagram},
            io:format("Not the dest, Keep forwarding~n"),
            gen_statem:cast(?MODULE, {forward, NewFrame})
    end.

% --- state -----------

%--------------------------------------------------------
% In the Idle state, when a pckt_tx event is received
% compress the header, fragment the pckt and transmit it
% to the mac layer via ieee802154
% state_name(EventType, EventContent, Data)
% EventType specify the type of event
% EventContent is the previous state
% Data, the current data of the syst
%--------------------------------------------------------

idle_state({call, From}, {dtg_tx, Ipv6Pckt, FrameControl, MacHeader}, Data) ->
    Frame = <<?IPV6_DHTYPE:8, Ipv6Pckt/bitstring>>,
    Transmit = ieee802154:transmission({FrameControl, MacHeader, Frame}),
    case Transmit of
        {ok, _} ->
            {next_state, idle_state, Data, [{reply, From, ok}]};
        {error, Error} ->
            {next_state, idle_state, Data, [{reply, From, Error}]}
    end;
idle_state({call, From}, {simple_tx, Frame, FrameControl, MacHeader}, Data) ->
    Transmit = ieee802154:transmission({FrameControl, MacHeader, Frame}),
    case Transmit of
        {ok, _} ->
            {next_state, idle_state, Data, [{reply, From, ok}]};
        {error, Error} ->
            {next_state, idle_state, Data, [{reply, From, Error}]}
    end;
idle_state({call, From},
           {pckt_tx, Ipv6Pckt},
           Data = #{node_mac_addr := CurrNodeMacAdd}) ->
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),
    DestAddress = PcktInfo#ipv6PckInfo.destAddress,
    Payload = PcktInfo#ipv6PckInfo.payload,
    PacketLen = byte_size(Ipv6Pckt),
    DestMacAddress =
        lowpan:encode_integer(DestAddress), % because return DestAddress is in integer form (TODO)
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt), % 1st - compress the header
    CompressedPacket = <<CompressedHeader/binary, Payload/bitstring>>,
    io:format("Compressed pckt size: ~p bytes~n", [byte_size(CompressedPacket)]),
    NeedFragmentation =
        lowpan:trigger_fragmentation(CompressedPacket,
                                     PacketLen),  % 2nd - check if fragmentation is needed, if so return graments list
    case NeedFragmentation of
        {true, Fragments} ->
            Response = send_fragments(Fragments, CurrNodeMacAdd, DestMacAddress),
            {next_state, idle_state, Data#{fragments => Fragments}, [{reply, From, Response}]};
        false ->
            UnFragPckt =
                lowpan:create_iphc_pckt(CompressedHeader,
                                        Payload),% lowpan:build_firstFrag_pckt(?FRAG1_DHTYPE, PacketLen, Datagram_tag, CompressedHeader, Payload),
            io:format("UnFragPckt ~p~n", [UnFragPckt]),
            io:format("Pckt to be transmit len: ~p bytes~n", [byte_size(UnFragPckt)]),
            FC = #frame_control{frame_type = ?FTYPE_DATA,
                                src_addr_mode = ?EXTENDED,
                                dest_addr_mode = ?EXTENDED},
            MH = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = DestMacAddress},
            Transmit = ieee802154:transmission({FC, MH, UnFragPckt}),
            case Transmit of
                {ok, _} ->
                    {next_state, idle_state, Data, [{reply, From, ok}]};
                {error, Error} ->
                    {next_state, idle_state, Data, [{reply, From, Error}]}
            end
    end;
% Idle call for frame reception
idle_state(cast, {frame_rx, From}, Data) ->
    Rx_on = ieee802154:rx_on(), % ensures continuous reception
    case Rx_on of
        ok ->
            io:format("Rx_on activated on node: ~p~n", [node()]),
            NewData = Data#{caller => From},
            {next_state, idle_state, NewData};
        {error, E} ->
            {next_state, idle_state, Data, [{reply, From, {error, E}}]}
    end;
idle_state(cast, {new_frame, Payload}, Data = #{datagram_map := DatagramMap}) ->
    UpdatedMap = put_and_reassemble(Payload, DatagramMap, Data),
    {keep_state, Data#{datagram_map => UpdatedMap}};
idle_state({call, From}, {frame_discarded, _}, Data) ->
    {next_state, idle_state, Data, [{reply, From, frame_discarded}]};
idle_state(cast, {forward, ReceivedFrame}, Data) ->
    ieee802154:transmission(ReceivedFrame),
    {next_state, idle_state, Data};
idle_state(cast, {collected, Tag, UpdatedMap}, StateData = #{caller := From}) ->
    ReassembledPacket = lowpan:reassemble(Tag, UpdatedMap),
    io:format("Complete for pckt ~p~n", [Tag]),
    From ! {reassembled_packet, ReassembledPacket},
    {next_state, idle_state, StateData};
idle_state({call, From}, _, Data) ->
    {next_state, idle_state, Data, [{reply, From, ok}]}.

% --- Utils functions -----------

put_and_reassemble(Frame, Map, Data) ->
    DtgInfo = lowpan:datagram_info(Frame),

    Size = DtgInfo#datagramInfo.datagramSize,
    Tag = DtgInfo#datagramInfo.datagramTag,
    Offset = DtgInfo#datagramInfo.datagramOffset,
    Payload = DtgInfo#datagramInfo.payload,

    io:format("Received ~pth payload: ~p bytes~n", [Offset + 1, byte_size(Payload)]),

    {UpdatedMap, DatagramComplete} =
        case maps:is_key(Tag, Map) of
            true ->
                {NewMap, AllReceived} = check_duplicate_frag(Map, Tag, Offset, Size, Payload),
                {NewMap, AllReceived};
            false ->
                CurrSize = byte_size(Payload),
                Datagram =
                    #datagram{tag = Tag,
                              size = Size,
                              cmpt = CurrSize,
                              fragments = #{Offset => Payload}},
                NewMap = maps:put(Tag, Datagram, Map),
                AllReceived = CurrSize == Size,
                {NewMap, AllReceived} % return Map and "fullness" of frame
        end,
    io:format("Map: ~p~n", [UpdatedMap]),

    case DatagramComplete of
        true ->
            gen_statem:cast(?MODULE, {collected, Tag, UpdatedMap});
        false ->
            io:format("Uncomplete datagram: ~n"),
            {keep_state, Data#{datagram_map => UpdatedMap}}
    end,
    UpdatedMap.

check_duplicate_frag(Map, Tag, Offset, Size, Payload) ->
    Datagram = maps:get(Tag, Map),
    FragmentsMap = Datagram#datagram.fragments,
    KnownFragment = maps:is_key(Offset, FragmentsMap),

    case KnownFragment of
        true ->
            io:format("Duplicate frame detected~n"),
            {Map, false};
        false ->
            io:format("Not a Duplicated frame~n"),
            update_datagram_map(Size, Tag, Offset, Payload, Map)
    end.

update_datagram_map(Size, Tag, Offset, Payload, Map) ->
    OldDatagram = maps:get(Tag, Map),
    CurrSize = byte_size(Payload),
    UpdatedCmpt = OldDatagram#datagram.cmpt + CurrSize,
    FragmentsMap = OldDatagram#datagram.fragments,
    NewFragments = FragmentsMap#{Offset => Payload},
    UpdatedDatagram = OldDatagram#datagram{cmpt = UpdatedCmpt, fragments = NewFragments},
    NewMap = maps:put(Tag, UpdatedDatagram, Map),
    AllReceived = UpdatedCmpt == Size,
    io:format("Pckt Size: ~p bytes ~n", [Size]),
    io:format("Current pckt len: ~p bytes~n", [UpdatedCmpt]),
    {NewMap, AllReceived}.

send_fragments(Fragments, CurrNodeMacAdd, DestMacAddress) ->
    send_fragments(Fragments, CurrNodeMacAdd, DestMacAddress, 1).

send_fragments([], _CurrNodeMacAdd, _DestMacAddress, _Counter) ->
    ok;
send_fragments([{Header, FragPayload} | Rest], CurrNodeMacAdd, DestMacAddress, Counter) ->
    Pckt = <<Header/binary, FragPayload/bitstring>>,
    io:format("~pth packet length: ~p bytes~n", [Counter, byte_size(Pckt)]),
    FC = #frame_control{frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    MH = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = DestMacAddress},
    case ieee802154:transmission({FC, MH, Pckt}) of
        {ok, _} ->
            send_fragments(Rest, CurrNodeMacAdd, DestMacAddress, Counter + 1);
        {error, Error} ->
            io:format("Error during transmission of fragment ~p: ~p~n", [Counter, Error])
    end.

callback_mode() ->
    [state_functions].
