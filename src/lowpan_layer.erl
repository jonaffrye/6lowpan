-module(lowpan_layer).

-behaviour(gen_statem).

-include("lowpan.hrl").

-export([init/1, start_link/1, start/1, stop_link/0, stop/0]).
-export([idle_state/3, callback_mode/0]).
-export([send_packet/1, send_with_perf_report/1, send_unc_datagram/3, tx/3, extended_hopsleft_tx/1]).
-export([frame_reception/0, frame_info_rx/0]).
-export([input_callback/4]).

%---------- API Functions --------------------------------------------------------------

%% @doc Initializes the 6LoWPAN layer with given parameters
%% @spec init(map()) -> {ok, atom(), map()}.
init(Params) ->
    io:format("-----------------------------------------------------~n"),
    io:format("Initialization~n"), 
    io:format("-----------------------------------------------------~n"),
    MacAdd = maps:get(node_mac_addr, Params),
    CurrNodeMacAdd = lowpan:generate_EUI64_mac_addr(MacAdd), % Convert mac address to valid 64-bit address
    io:format("Current node address: ~p~n",[CurrNodeMacAdd]),
    setup_node_info_ets(),

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
            fragment_tag => ?DEFAULT_TAG_VALUE, seqNum => ?BC_SEQNUM, 
            metrics => #metrics{}, ack_req => false},

    set_nodeData_value(state_data, Data),

    io:format("~p: 6lowpan layer successfully launched~n", [node()]),

    %io:format("----------------------------------------------------------------------------------------~n"),
    {ok, idle, Data}.

%% @doc Starts the 6LoWPAN layer and links the process
%% @spec start_link(map()) -> {ok, pid()} | {error, any()}.
start_link(Params) ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, Params, []).

%% @doc Starts the 6LoWPAN layer
%% @spec start(map()) -> {ok, pid()} | {error, any()}.
start(Params) ->
    gen_statem:start({local, ?MODULE}, ?MODULE, Params, []).

%% @doc Stops the linked 6LoWPAN process
%% @spec stop_link() -> ok.
stop_link() ->
    gen_statem:stop(?MODULE).

%% @doc Stops the 6LoWPAN layer
%% @spec stop() -> ok.
stop() ->
    io:format("lowpan layer stopped"),
    erpc:call(node(), routing_table, stop, []),
    gen_statem:stop(?MODULE).

%-------------------------------------------------------------------------------

%% @doc Sends an IPv6 packet using 6LoWPAN mechanisms
%% @spec send_packet(binary()) -> {ok, any()} | {error, any()}.
send_packet(Ipv6Pckt) ->
    io:format("-----------------------------------------------------~n"),
    io:format("Transmission mode~n"), 
    io:format("-----------------------------------------------------~n"),
    io:format("Transmission request~n"),
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),
    SrcAddress = PcktInfo#ipv6PckInfo.sourceAddress,
    DstAddress = PcktInfo#ipv6PckInfo.destAddress,
   
    case {<<SrcAddress:128>>, <<DstAddress:128>>} of  % Check if the source address is multicast
       {<<16#FF:16, _:112>>, _} ->
            io:format("Error, Source address cannot be a multicast address~n"),
            {error_multicast_src};
        {_, <<0:128>>} -> % Check if the dest address is the Unspecified address
            io:format("Error, destination address cannot be the Unspecified address~n"),
            {error_unspecified_addr};
        _ ->
            Extended_hopsleft = false,
            gen_statem:call(?MODULE, {pckt_tx, Ipv6Pckt, PcktInfo, Extended_hopsleft})
    end.

%-------------------------------------------------------------------------------

%% @doc Sends an IPv6 packet and gets a performance report
%% @spec send_with_perf_report(binary()) -> {ok, {float(), float(), float()}} | {error, any()}.
send_with_perf_report(Ipv6Pckt) ->
    io:format("-----------------------------------------------------~n"),
    io:format("Transmission mode~n"), 
    io:format("-----------------------------------------------------~n"),
    io:format("New packet transmission ~n"),
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),
    SrcAddress = PcktInfo#ipv6PckInfo.sourceAddress,
    DstAddress = PcktInfo#ipv6PckInfo.destAddress,
   
    case {<<SrcAddress:128>>, <<DstAddress:128>>} of  % Check if the source address is multicast
       {<<16#FF:16, _:112>>, _} ->
            io:format("Error, Source address cannot be a multicast address~n"),
            {error_multicast_src};
        {_, <<0:128>>} -> % Check if le dest address is the Unspecified address
            io:format("Error, destination address cannot be the Unspecified address~n"),
            {error_unspecified_addr};
        _ ->
            Extended_hopsleft = false,
            {ok, NewMetrics} = gen_statem:call(?MODULE, {pckt_tx_with_perf, Ipv6Pckt, PcktInfo, Extended_hopsleft}), 
            {ok, RTT, SuccessRate, CompressionRatio} = handle_ack(NewMetrics), 
            MetricsResult = {RTT, SuccessRate, CompressionRatio}, 
            io:format("RTT: ~p ms~nSuccessRate: ~p~nCompressionRatio: ~p~n", [RTT, SuccessRate, CompressionRatio]),
            MetricsResult
    end.

%% @doc Sends a packet with extended hops left
%% @spec extended_hopsleft_tx(binary()) -> {ok, any()} | {error, any()}.
extended_hopsleft_tx(Ipv6Pckt) ->
    io:format("New packet transmission ~n"),
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),
    SrcAddress = PcktInfo#ipv6PckInfo.sourceAddress,
    DstAddress = PcktInfo#ipv6PckInfo.destAddress,

    case {<<SrcAddress:128>>, <<DstAddress:128>>} of  % Check if the source address is multicast
        {<<?MULTICAST_PREFIX:16, _Rest:112>>, _} ->
            io:format("Error, Source address cannot be a multicast address~n"),
            {error_multicast_src};
        {_, <<0:128>>} -> % Check if the dest address is the Unspecified address
            io:format("Error, destination address cannot be the Unspecified address~n"),
            {error_unspecified_addr};
        _ ->
            Extended_hopsleft = true,
            gen_statem:call(?MODULE, {pckt_tx, Ipv6Pckt, PcktInfo, Extended_hopsleft})
    end.

%-------------------------------------------------------------------------------

%% @doc Sends an uncompressed IPv6 packet directly to ieee802154
%% @spec send_unc_datagram(binary(), map(), map()) -> {ok, any()} | {error, any()}.
send_unc_datagram(Ipv6Pckt, FrameControl, MacHeader) ->
    gen_statem:call(?MODULE, {tx_datagram, Ipv6Pckt, FrameControl, MacHeader}).

%-------------------------------------------------------------------------------

%% @doc Transmits a datagram packet directly to ieee802154
%% @spec tx(binary(), map(), map()) -> {ok, any()} | {error, any()}.
tx(Frame, FrameControl, MacHeader) ->
    case Frame of 
        <<?NALP_DHTYPE,_/bitstring>> -> 
            io:format("The received frame is not a lowpan frame~n"),
            error_nalp;
        _-> gen_statem:call(?MODULE, {tx_frame, Frame, FrameControl, MacHeader})
    end.

%-------------------------------------------------------------------------------

%% @doc Receives a datagram from ieee802154
%% @spec frame_reception() -> {ok, any()} | {error, any()}.
frame_reception() ->
    io:format("-----------------------------------------------------~n"),
    io:format("Reception mode~n"), 
    io:format("-----------------------------------------------------~n"),
    gen_statem:cast(?MODULE, {frame_rx, self()}),
    receive
        {reassembled_packet, IsMeshedPckt, OriginatorMacAddr, CurrNodeMacAdd, ReassembledPacket} ->
            io:format("Datagram reassembled, start packet decoding ~n"),
            _DecodedPacket = lowpan:decode_ipv6_pckt(IsMeshedPckt, OriginatorMacAddr, CurrNodeMacAdd, ReassembledPacket),
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

%% @doc Receives a datagram from ieee802154 and returns additional information for testing purposes
%% @spec frame_info_rx() -> {ok, any()} | {error, any()}.
frame_info_rx() ->
    gen_statem:cast(?MODULE, {frame_info_rx, self()}),
    receive
        {additional_info, Info, _} ->
            Info
    after ?REASSEMBLY_TIMEOUT ->
        gen_statem:call(?MODULE, {reassembly_timeout})
    end.
    
%-------------------------------------------------------------------------------

%% @doc Callback function used to retrieve a datagram
%% @spec input_callback(Frame :: tuple(), any(), any(), any()) -> {ok, any()} | {error, any()}.
input_callback(Frame, _, _, _) ->
    {FC, MH, Datagram} = Frame,
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
    
    StateData = get_nodeData_value(state_data), % returns a map containing node data
    
    handle_Datagram(IsMeshedPckt, MeshPckInfo, OriginatorAddr, FinalDstMacAdd, FC, MH, Datagram, StateData).

%-------------------------------------------------------------------------------

%% @doc Handles the received datagram
%% @spec handle_Datagram(boolean(), map(), binary(), binary(), map(), map(), binary(), map()) -> {ok, any()} | {error, any()}.
handle_Datagram(IsMeshedPckt, MeshPckInfo, OriginatorAddr, FinalDstMacAdd, FC, MH, Datagram, StateData) ->
    DestAdd = lowpan:convert_addr_to_bin(FinalDstMacAdd),
    CurrNodeMacAdd = maps:get(node_mac_addr, StateData),

    
    case DestAdd of
        CurrNodeMacAdd ->
            io:format("New frame received~n"),
            io:format("Originator               : ~p~n",[OriginatorAddr]),
            io:format("Final destination address: ~p~n", [DestAdd]),
            io:format("Current node address     : ~p~n", [CurrNodeMacAdd]),

            io:format("Final destination node reached, Forwarding to lowpan layer~n"),
            case IsMeshedPckt of
                true -> 
                    HopsLeft = MeshPckInfo#meshInfo.hops_left,
                    Rest = lowpan:remove_mesh_header(Datagram,HopsLeft),
                    gen_statem:cast(?MODULE, {new_frame_rcv, IsMeshedPckt, OriginatorAddr, Rest});
                false-> 
                    HopsLeft = 1,
                    Rest = lowpan:remove_mesh_header(Datagram,HopsLeft),
                    gen_statem:cast(?MODULE, {new_frame_rcv, IsMeshedPckt, OriginatorAddr, Rest})

            end;
        ?BroadcastAdd ->
            {keep_state, idle_state};
        _ ->
            io:format("New frame received~n"),
            io:format("Originator               : ~p~n",[OriginatorAddr]),
            io:format("Final destination address: ~p~n", [DestAdd]),
            io:format("Current node address     : ~p~n", [CurrNodeMacAdd]),
            io:format("The datagram needs to be meshed~n"),
            gen_statem:cast(?MODULE, {forward_datagram, Datagram, IsMeshedPckt, MeshPckInfo, FinalDstMacAdd, CurrNodeMacAdd, FC, MH})
    end.

%---------- States --------------------------------------------------------------------

%idle({call, From}, {pckt_tx, Ipv6Pckt, PcktInfo, Extended_hopsleft}, Data)->
%    {next_state, 

%-------------------------------------------------------------------------------
idle_state(cast, {forward_datagram, Datagram, IsMeshedPckt, MeshPckInfo, DstMacAdd, CurrNodeMacAdd, FC, MH}, Data) ->
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
            io:format("Searching next hop in the routing table...~n"),
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

%% @doc State: dtg_tx, in this state, the node transmits uncompressed packet to ieee802154
%% @spec idle_state({call, any()}, {tx_datagram, binary(), map(), map()}, map()) -> {next_state, atom(), map(), [{reply, any(), any()}]}.
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

%% @doc State: pckt_tx, in this state, the node transmits IPv6 packet to ieee802154
%% @spec idle_state({call, any()}, {pckt_tx, binary(), map(), boolean()}, map()) -> {next_state, atom(), map(), [{reply, any(), any()}]}.
idle_state({call, From}, {pckt_tx, Ipv6Pckt, PcktInfo, Extended_hopsleft}, Data = #{node_mac_addr := CurrNodeMacAdd,
    fragment_tag := Tag, seqNum := SeqNum}) ->
    DestAddress = PcktInfo#ipv6PckInfo.destAddress,
    SrcAddress = PcktInfo#ipv6PckInfo.sourceAddress,
    Payload = PcktInfo#ipv6PckInfo.payload,
    DestMacAddress = lowpan:get_EUI64_mac_addr(DestAddress),
    SenderMacAdd = lowpan:get_EUI64_mac_addr(SrcAddress),
    io:format("Final destination: ~p~n", [DestMacAddress]),
    io:format("Searching next hop...~n"),
    {RouteExist, MeshedHdrBin, MH} = lowpan:get_next_hop(CurrNodeMacAdd, SenderMacAdd, DestMacAddress, DestAddress, SeqNum+1, Extended_hopsleft),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt, RouteExist),
    CompressedPacket = <<CompressedHeader/binary, Payload/bitstring>>,
    _CompressedPacketLen = byte_size(CompressedPacket),
    {FragReq, Fragments} = lowpan:trigger_fragmentation(CompressedPacket, Tag),
    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},

    case FragReq of
        true ->
            {Response, _NoAckCnt} = send_fragments(RouteExist, Fragments, 1, MeshedHdrBin, MH, FC, Tag, 0),
            NewTag = Tag+1 rem ?MAX_TAG_VALUE,
            {next_state, idle_state, Data#{fragments => Fragments, fragment_tag => NewTag}, [{reply, From, Response}]};
        false ->
            {Response, _NoAckCnt} = send_fragment(RouteExist, Fragments, MeshedHdrBin, MH, FC, Tag),
            NewTag = Tag+1 rem ?MAX_TAG_VALUE,
            {next_state, idle_state, Data#{fragments => Fragments, fragment_tag => NewTag}, [{reply, From, Response}]}; 
        size_err -> 
            io:format("The datagram size exceed the authorized length~n"),
            {next_state, idle_state, Data, [{reply, From, error_frag_size}]}
    end;

%-------------------------------------------------------------------------------

%% @doc State: pckt_tx_with_perf, in this state, the node transmits IPv6 packet to ieee802154 and computes metrics
%% @spec idle_state({call, any()}, {pckt_tx_with_perf, binary(), map(), boolean()}, map()) -> {next_state, atom(), map(), [{reply, any(), any()}]}.
idle_state({call, From}, {pckt_tx_with_perf, Ipv6Pckt, PcktInfo, Extended_hopsleft}, Data = #{node_mac_addr := CurrNodeMacAdd, fragment_tag := Tag, seqNum := SeqNum, metrics := Metrics}) ->
    DestAddress = PcktInfo#ipv6PckInfo.destAddress,
    SrcAddress = PcktInfo#ipv6PckInfo.sourceAddress,
    Payload = PcktInfo#ipv6PckInfo.payload,
    DestMacAddress = lowpan:get_EUI64_mac_addr(DestAddress),
    SenderMacAdd = lowpan:get_EUI64_mac_addr(SrcAddress),
    PcktHeader = ipv6:get_header(Ipv6Pckt),
    io:format("Final destination: ~p~n", [DestMacAddress]),
    io:format("Searching next hop...~n"),
    {RouteExist, MeshedHdrBin, MH} = lowpan:get_next_hop(CurrNodeMacAdd, SenderMacAdd, DestMacAddress, DestAddress, SeqNum+1, Extended_hopsleft),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt, RouteExist),
    CompressedPacket = <<CompressedHeader/binary, Payload/bitstring>>,
    _CompressedPacketLen = byte_size(CompressedPacket),
    %io:format("Compressed packet size: ~p bytes~n", [CompressedPacketLen]),
    {FragReq, Fragments} = lowpan:trigger_fragmentation(CompressedPacket, Tag),
    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    case FragReq of
        true ->
            NewTag = Tag+1 rem ?MAX_TAG_VALUE,
            StartTime = os:system_time(millisecond),
            
            NewData = Data#{caller => From, fragment_tag => NewTag, ack_req => true}, 
            set_nodeData_value(state_data, NewData),
            {ok, NoAckCnt} = send_fragments(RouteExist, Fragments, 1, MeshedHdrBin, MH, FC, Tag, 0),
            FragmentsNbr = length(Fragments),
            AckCounter = FragmentsNbr - NoAckCnt, 
            NewMetrics = Metrics#metrics{fragments_nbr = FragmentsNbr, ack_counter = AckCounter, start_time = StartTime, 
                                        pckt_len = byte_size(PcktHeader), compressed_pckt_len = byte_size(CompressedHeader)},
            MetricsResult = {ok, NewMetrics},         
            ResetMetrics = Metrics#metrics{fragments_nbr = 0, ack_counter = 0, start_time = 0, 
                                        pckt_len = 0, compressed_pckt_len = 0}, 
            ResetData = Data#{caller => From, ack_req => false, metrics => ResetMetrics},                   
            {next_state, idle_state, ResetData, [{reply, From, MetricsResult}]};

        false ->
            NewTag = Tag+1 rem ?MAX_TAG_VALUE,
            StartTime = os:system_time(millisecond),
            NewData = Data#{caller => From, fragment_tag => NewTag, ack_req => true}, 
            set_nodeData_value(state_data, NewData),
            {_R, NoAckCnt}= send_fragment(RouteExist, Fragments, MeshedHdrBin, MH, FC, Tag),
            FragmentsNbr = 1,
            AckCounter = FragmentsNbr - NoAckCnt, 
            NewMetrics = Metrics#metrics{fragments_nbr = FragmentsNbr, ack_counter = AckCounter, start_time = StartTime, 
                                        pckt_len = byte_size(PcktHeader), compressed_pckt_len = byte_size(CompressedHeader)},
            MetricsResult = {ok, NewMetrics},         
            ResetMetrics = Metrics#metrics{fragments_nbr = 0, ack_counter = 0, start_time = 0, 
                                        pckt_len = 0, compressed_pckt_len = 0}, 
            ResetData = Data#{caller => From, ack_req => false, metrics => ResetMetrics},                   
            {next_state, idle_state, ResetData, [{reply, From, MetricsResult}]};
        size_err -> 
            io:format("The datagram size exceed the authorized length~n"),
            {next_state, idle_state, Data, [{reply, From, error_frag_size}]}
    end;

%-------------------------------------------------------------------------------

%% @doc State: frame_rx, in this state, the node activates the rx_on in ieee802154
%% @spec idle_state({cast, {frame_rx, pid()}}, map()) -> {next_state, atom(), map()}.
idle_state(cast, {frame_rx, From}, Data) ->
    io:format("~p waiting to receive data... ~n", [node()]),
    NewData = Data#{caller => From,  info=>?INFO_OFF},
    {next_state, idle_state, NewData}; 

%% @doc State: frame_info_rx, in this state, the node activates the rx_on in ieee802154 for additional info
%% @spec idle_state({cast, {frame_info_rx, pid()}}, map()) -> {next_state, atom(), map()}.
idle_state(cast, {frame_info_rx, From}, Data) ->
    io:format("~p waiting to receive data... ~n", [node()]),
    NewData = Data#{caller => From, info=>?INFO_ON},
    {next_state, idle_state, NewData};

%-------------------------------------------------------------------------------

%% @doc State: new_frame, in this state, the node processes the received frame
%% @spec idle_state({cast, {new_frame_rcv, boolean(), binary(), binary()}}, map()) -> {next_state, atom(), map()}.
idle_state(cast, {new_frame_rcv, IsMeshedPckt, OriginatorAddr, Datagram}, Data = #{caller := From, node_mac_addr := CurrNodeMacAdd}) ->
    case Datagram of
        <<?IPHC_DHTYPE:3, _Rest/bitstring>> -> % compressed datagram
            io:format("Received a compressed datagram, starting reassembly~n"),
            
            From ! {reassembled_packet, IsMeshedPckt, OriginatorAddr, CurrNodeMacAdd, Datagram},
            {next_state, idle_state, Data};

        <<?IPV6_DHTYPE:8, Payload/bitstring>> -> % uncompressed IPv6 datagram
            io:format("Received a uncompressed IPv6 datagram, starting reassembly~n"),
            % Process uncompressed IPv6 datagram
            From ! {reassembled_packet, IsMeshedPckt, OriginatorAddr, CurrNodeMacAdd, Payload},
            {next_state, idle_state, Data};

        % <<?NALP_DHTYPE,_/bitstring>> -> 
        %     io:format("The received frame is not a lowpan frame, starting reassembly~n"),
        %     From ! {error_nalp},
        %     {next_state, idle_state, Data};

        <<Type:5, _Rest/bitstring>> when Type =:= ?FRAG1_DHTYPE; Type =:= ?FRAGN_DHTYPE -> % fragmented datagram
            FragInfo = lowpan:datagram_info(Datagram),
            Info = FragInfo#datagramInfo.datagramTag,
            NewData = Data#{additional_info => Info},
            io:format("Storing fragment~n"),
            gen_statem:cast(?MODULE, {add_fragment, IsMeshedPckt, OriginatorAddr, Datagram}),
            {keep_state, NewData} 
    end;

%-------------------------------------------------------------------------------

%% @doc State: add_fragment, in this state, the node adds new fragment to the map 
%% @spec idle_state({cast, {add_fragment, boolean(), binary(), binary()}}, map()) -> {keep_state, map()} | {next_state, atom(), map()}.
idle_state(cast, {add_fragment, IsMeshedPckt, OriginatorAddr, Datagram}, Data = #{datagram_map := DatagramMap, caller := From, node_mac_addr := CurrNodeMacAdd}) ->
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
            io:format("------------------------------------------------------~n"),
            From ! {reassembled_packet, IsMeshedPckt, OriginatorAddr, CurrNodeMacAdd, ReassembledPacket},
            {next_state, idle_state, Data};

        {complete, UpdatedDatagram} ->
            gen_statem:cast(?MODULE, {collected, IsMeshedPckt, OriginatorAddr, Key, UpdatedDatagram}),
            NewData = Data#{key => Key},
            {keep_state, NewData};

        {duplicate, _} ->
            io:format("Duplicate frame detected~n"),
            io:format("------------------------------------------------------~n"),
            NewData = Data#{key => Key},
            {keep_state, NewData};

         {incomplete_first, EntryKey} ->
            io:format("Uncomplete first datagram, waiting for other fragments ~n"),
            erlang:send_after(?REASSEMBLY_TIMEOUT, From, {reassembly_timeout, DatagramMap, EntryKey}),
            io:format("------------------------------------------------------~n"),
            NewData = Data#{key => Key},
            {keep_state, NewData};

        {incomplete, _} ->
            io:format("Uncomplete datagram, waiting for other fragments ~n"),
            io:format("------------------------------------------------------~n"),
            NewData = Data#{key => Key},
            {keep_state, NewData}
    end;

%-------------------------------------------------------------------------------

%% @doc State: collected, in this state, the node sends the reassembled packet
%% @spec idle_state({cast, {collected, boolean(), binary(), any(), binary()}}, map()) -> {next_state, atom(), map()}.
idle_state(cast, {collected, IsMeshedPckt, OriginatorAddr, Key, UpdatedDatagram}, Data = #{datagram_map := DatagramMap, 
        caller := From, additional_info:=Info, info:=InfoReq, node_mac_addr := CurrNodeMacAdd}) ->
    ReassembledPacket = lowpan:reassemble(UpdatedDatagram),
    io:format("Complete for pckt ~p~n", [Key]),
    ets:delete(DatagramMap, Key),
    case InfoReq of
        ?INFO_ON -> 
            From ! {additional_info, Info, ReassembledPacket};
        _ -> 
            From ! {reassembled_packet, IsMeshedPckt, OriginatorAddr, CurrNodeMacAdd, ReassembledPacket}
    end,
    {next_state, idle_state, Data}.


%---------- Utils Functions -----------------------------------------------------------

%-------------------------------------------------------------------------------

%% @doc Transmits each fragment in the FragmentList to ieee802154
%% @spec send_fragment(boolean(), binary(), binary(), map(), map(), any()) -> {ok, integer()} | {error, any()}.
send_fragment(RouteExist, CompressedPacket, MeshedHdrBin, MH, FC, Tag) ->
    Pckt = case RouteExist of
                true ->
                    <<MeshedHdrBin/binary, CompressedPacket/bitstring>>;

                false ->
                    CompressedPacket
            end,
    MacHeader = MH#mac_header{seqnum = Tag},
    case ieee802154:transmission({FC, MacHeader, Pckt}) of
        {ok, _} ->
            io:format("Packet successfully sent~n"),
            {ok, 0};
        {error, Error} ->
            io:format("Transmission error: ~p~n", [Error]),
            NoAck = 1, 
            {Error, NoAck}
    end.

%% @doc Transmits all fragments in the FragmentList to ieee802154
%% @spec send_fragments(boolean(), list(), integer(), binary(), map(), map(), any(), integer()) -> {ok, integer()}.
send_fragments(RouteExist, [{FragHeader, FragPayload} | Rest], PcktCounter, MeshedHdrBin, MH, FC, Tag, NoAckCnt) ->
    Pckt = case RouteExist of
                true ->
                    <<MeshedHdrBin/binary, FragHeader/binary, FragPayload/bitstring>>;

                false ->
                    <<FragHeader/binary, FragPayload/bitstring>>
            end, 
    MacHeader = MH#mac_header{seqnum = Tag+PcktCounter},
    case ieee802154:transmission({FC, MacHeader, Pckt}) of
        {ok, _} ->
            io:format("~pth fragment: ~p bytes sent~n", [PcktCounter, byte_size(Pckt)]),
            send_fragments(RouteExist, Rest, PcktCounter + 1, MeshedHdrBin, MacHeader, FC, Tag, NoAckCnt);
        {error, Error} ->
            io:format("Error during transmission of fragment ~p: ~p~n", [PcktCounter, Error]),
            send_fragments(RouteExist, Rest, PcktCounter+1, MeshedHdrBin, MacHeader, FC, Tag, NoAckCnt + 1)
    end;          
send_fragments(_RouteExist, [], _PcktCounter, _MeshedHdrBin, _MH, _FC, _Tag, NoAckCnt) ->
    case NoAckCnt of
        0 -> 
            io:format("Packet successfully sent~n"); 
        _-> 
            io:format("Issue during transmission~n")
    end,
    {ok, NoAckCnt}.

%-------------------------------------------------------------------------------

%% @doc Decrements hop left field, builds new mesh header and returns new datagram
%% @spec update_datagram(map(), binary(), map()) -> {binary(), binary()} | {discard, {next_state, atom(), map()}}.
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

%% @doc Discards the datagram when hop left value reaches 0
%% @spec discard_datagram(binary(), map()) -> {next_state, atom(), map()}.
discard_datagram(_, Data = #{caller := From})->
    io:format("~nHop left value: 0, discarding the datagram~n"),
    From ! {dtg_discarded},
    {next_state, idle_state, Data}.

%-------------------------------------------------------------------------------

%% @doc Forwards datagram to the next hop
%% @spec forward_datagram(binary(), map(), map(), map()) -> {next_state, atom(), map()}.
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
                    %{next_state, idle_state, Data, [{reply, From, Error}]}
            end
    end, 
    io:format("------------------------------------------------------~n"),
    {next_state, idle_state, Data}.

%% @doc Handles acknowledgements and computes metrics
%% @spec handle_ack(map()) -> {ok, float(), float(), float()}.
handle_ack(Metrics) ->
    TotalFragments = Metrics#metrics.fragments_nbr,
    AckCounter = Metrics#metrics.ack_counter,
    EndTime = os:system_time(millisecond),

    RTT = EndTime - Metrics#metrics.start_time,
    SuccessRate = AckCounter / TotalFragments,
    _LossRate = 1 - SuccessRate,

    OrigPcktLen = Metrics#metrics.pckt_len, 
    CompPcktLen = Metrics#metrics.compressed_pckt_len, 
    CompressionRatio = (CompPcktLen/OrigPcktLen),
    {ok, RTT, SuccessRate, CompressionRatio}.


%---------- Helper --------------------------------------------------------------------

%-------------------------------------------------------------------------------

%% @doc Sets up ETS table for storing current node MAC address
%% @spec setup_node_info_ets() -> any().
setup_node_info_ets() ->
    ets:new(nodeData, [named_table, public, {keypos, 1}]).

%% @doc Sets a value in the nodeData ETS table
%% @spec set_nodeData_value(atom(), any()) -> ok.
set_nodeData_value(Key, Value) ->
    ets:insert(nodeData, {Key, Value}).

%% @doc Gets a value from the nodeData ETS table
%% @spec get_nodeData_value(atom()) -> any() | undefined.
get_nodeData_value(Key) ->
    case ets:lookup(nodeData, Key) of
        [] ->
            undefined;
        [{_, Value}] ->
            Value
    end.

%-------------------------------------------------------------------------------

%% @doc Sets up the ieee802154 layer
%% @spec ieee802154_setup(binary()) -> ok.
ieee802154_setup(MacAddr)->
    ieee802154:start(#ieee_parameters{
        phy_layer = mock_phy_network, % uncomment when testing
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
    io:format("~p IEEE 802.15.4: layer successfully launched ~n",[node()]).

%% @doc Returns the callback mode for the gen_statem behaviour
%% @spec callback_mode() -> list().
callback_mode() ->
    [state_functions].
