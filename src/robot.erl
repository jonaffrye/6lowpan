-module(robot).

-behaviour(application).

-include("utils.hrl").

-export([
    tx/0,
    tx3/0,
    tx4/0,
    tx5/0,
    tx_unc_ipv6/0,
    tx_iphc_pckt/0,
    tx_frag_iphc_pckt/0,
    tx_big_payload/1,
    tx_with_udp/0,
    tx_msh_iphc_pckt/0,
    tx_msh_frag_iphc_pckt/0,
    msh_pckt_tx/0,
    msh_big_pckt_tx/0,
    rx/0, 
    tx_broadcast_pckt/0, 
    extendedHopsleftTx/0, 
    tx_unc_ipv6_udp/0, 
    tx_comp_ipv6_udp/0, 
    tx_mesh_prefix/0, 
    %tx_with_metrics/1, 
    ieeetx2/0, 
    ieeetx3/0, 
    tx_big_payload3/1, 
    tx_big_payload4/1, 
    tx_big_payload5/1
]).

-export([start/2]).
-export([stop/1]).
 

%--- Macros --------------------------------------------------------------------

-define(TX_ANTD, 16450).
-define(RX_ANTD, 16450).

%-------------------------------------------------------------------------------
% Uncompressed ipv6 packet format verification
%-------------------------------------------------------------------------------
tx_unc_ipv6() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header, ?Payload),
    io:format("Frame ~p~n", [Ipv6Pckt]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Ipv6Pckt)]),

    lowpan_api:sendUncDatagram(Ipv6Pckt, ?FrameControl, ?MacHeader).


%-------------------------------------------------------------------------------
% compressed header packet format verificationCo
%-------------------------------------------------------------------------------
tx_iphc_pckt() ->
    InlineData = <<12:8, ?Node1MacAddress/binary, ?Node2MacAddress/binary>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, 3:2, 12:1, 3:2, 0:1, 0:1, 1:2, 0:1, 0:1, 1:2, InlineData/binary>>,

    % Create the IPHC packet
    IPHC = lowpan_core:createIphcPckt(ExpectedHeader, ?Payload),
    io:format("IphcHeader ~p~n", [IPHC]),
    io:format("Fragment size: ~p bytes~n", [byte_size(IPHC)]),

    lowpan_api:tx(IPHC, ?FrameControl, ?MacHeader).

%-------------------------------------------------------------------------------
% Meshed and compressed header packet format verification
%-------------------------------------------------------------------------------
tx_msh_iphc_pckt() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan_core:compressIpv6Header(Ipv6Pckt, true),

    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?Node1MacAddress,
            final_destination_address = ?Node2MacAddress
        },

    BinMeshHeader = lowpan_core:buildMeshHeader(MeshHeader),
    Datagram = <<BinMeshHeader/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Datagram ~p~n", [Datagram]),

    lowpan_api:tx(Datagram, ?FrameControl, ?MacHeader).

%-------------------------------------------------------------------------------
% Fragmented and compressed packet format verification
%-------------------------------------------------------------------------------
tx_frag_iphc_pckt() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan_core:compressIpv6Header(Ipv6Pckt, false),
    PcktLen = byte_size(Ipv6Pckt),

    FragHeader =
        #frag_header{
            frag_type = ?FRAG1_DHTYPE,
            datagram_size = PcktLen,
            datagram_tag = 124
        },

    FragHeaderBin = lowpan_core:buildFirstFragHeader(FragHeader),

    Datagram = <<FragHeaderBin/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Frame ~p~n", [Datagram]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Datagram)]),

    lowpan_api:tx(Datagram, ?FrameControl, ?MacHeader).

%-------------------------------------------------------------------------------
% Meshed, fragmented and compressed packet format verification
%-------------------------------------------------------------------------------
tx_msh_frag_iphc_pckt() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan_core:compressIpv6Header(Ipv6Pckt, true),
    PcktLen = byte_size(Ipv6Pckt),

    FragHeader =
        #frag_header{
            frag_type = ?FRAG1_DHTYPE,
            datagram_size = PcktLen,
            datagram_tag = 124
        },

    FragHeaderBin = lowpan_core:buildFirstFragHeader(FragHeader),

    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?Node1MacAddress,
            final_destination_address = ?Node2MacAddress
        },

    BinMeshHeader = lowpan_core:buildMeshHeader(MeshHeader),
    Datagram =
        <<BinMeshHeader/binary, FragHeaderBin/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Datagram ~p~n", [Datagram]),

    lowpan_api:tx(Datagram, ?FrameControl, ?MacHeader).

%-------------------------------------------------------------------------------
% Broadcast packet format verification
%-------------------------------------------------------------------------------
tx_broadcast_pckt() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan_core:compressIpv6Header(Ipv6Pckt, false),
    PcktLen = byte_size(Ipv6Pckt),

    FragHeader =
        #frag_header{
            frag_type = ?FRAG1_DHTYPE,
            datagram_size = PcktLen,
            datagram_tag = 124
        },

    FragHeaderBin = lowpan_core:buildFirstFragHeader(FragHeader),

    DestMacAddr = lowpan_core:generateEUI64MacAddr(<<16#1234:16>>),

    DestAddr = <<16#FF02:16, 0:64, 1:16, 16#FF00:16, 16#1234:16>>,
    DestAddress = binary:decode_unsigned(DestAddr),
    {_, BroadcastHeader, _} = lowpan_core:getNextHop(?Node1MacAddress, ?Node1MacAddress, DestMacAddr, DestAddress, 3, false),

    Datagram =
        <<BroadcastHeader/binary, FragHeaderBin/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Datagram ~p~n", [Datagram]),

    MacHeader = #mac_header{src_addr = ?Node1MacAddress, dest_addr = DestMacAddr},
    lowpan_api:tx(Datagram, ?FrameControl, MacHeader).


%-------------------------------------------------------------------------------
% Simple transmission 
%-------------------------------------------------------------------------------
tx() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header, ?Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).

tx3() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header3, ?Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).

tx4() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header4, ?Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).

tx5() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header5, ?Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).



%-------------------------------------------------------------------------------
% Big payload transmission
%-------------------------------------------------------------------------------
tx_big_payload(N) ->
    Payload = lowpan_core:generateChunks(N),

    Node1Address = lowpan_core:generateLLAddr(?Node1MacAddress),
    Node2Address = lowpan_core:generateLLAddr(?Node2MacAddress),
    PayloadLength = byte_size(Payload),

    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = PayloadLength,
            next_header = 12,
            hop_limit = 64,
            source_address = Node1Address,
            destination_address = Node2Address
        },
    Ipv6Pckt = ipv6:buildIpv6Packet(IPv6Header, Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).

tx_big_payload3(N) ->
    Payload = lowpan_core:generateChunks(N),

    Node1Address = lowpan_core:generateLLAddr(?Node1MacAddress),
    Node2Address = lowpan_core:generateLLAddr(?Node3MacAddress),
    PayloadLength = byte_size(Payload),

    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = PayloadLength,
            next_header = 12,
            hop_limit = 64,
            source_address = Node1Address,
            destination_address = Node2Address
        },
    Ipv6Pckt = ipv6:buildIpv6Packet(IPv6Header, Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).

tx_big_payload4(N) ->
    Payload = lowpan_core:generateChunks(N),

    Node1Address = lowpan_core:generateLLAddr(?Node1MacAddress),
    Node2Address = lowpan_core:generateLLAddr(?Node4MacAddress),
    PayloadLength = byte_size(Payload),

    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = PayloadLength,
            next_header = 12,
            hop_limit = 64,
            source_address = Node1Address,
            destination_address = Node2Address
        },
    Ipv6Pckt = ipv6:buildIpv6Packet(IPv6Header, Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).

tx_big_payload5(N) ->
    Payload = lowpan_core:generateChunks(N),

    Node1Address = lowpan_core:generateLLAddr(?Node1MacAddress),
    Node2Address = lowpan_core:generateLLAddr(?Node5MacAddress),
    PayloadLength = byte_size(Payload),

    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = PayloadLength,
            next_header = 12,
            hop_limit = 64,
            source_address = Node1Address,
            destination_address = Node2Address
        },
    Ipv6Pckt = ipv6:buildIpv6Packet(IPv6Header, Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).


%-------------------------------------------------------------------------------
% Transmission of uncompressed ipv6 packet with udp next header
%-------------------------------------------------------------------------------
tx_unc_ipv6_udp() ->
    Payload = <<"Hello world">>,
    PayloadLength = byte_size(Payload),
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            % 4 bytes for the UDP header
            payload_length = PayloadLength,
            next_header = 17,
            hop_limit = 255,
            source_address = ?Node1Address,
            destination_address = ?Node2Address
        },
    UdpHeader =
        #udp_header{
            source_port = 1025,
            destination_port = 61617,
            length = PayloadLength,
            checksum = 16#f88c
        },

    Ipv6Pckt = ipv6:buildIpv6UdpPacket(IPv6Header, UdpHeader, Payload),
    io:format("Frame ~p~n", [Ipv6Pckt]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Ipv6Pckt)]),

    lowpan_api:sendUncDatagram(Ipv6Pckt, ?FrameControl, ?MacHeader).


%-------------------------------------------------------------------------------
% Transmission of compressed ipv6 packet with udp next header
%-------------------------------------------------------------------------------
tx_comp_ipv6_udp() ->
    Payload = <<"Hello world">>,
    PayloadLength = byte_size(Payload),
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            % 4 bytes for the UDP header
            payload_length = PayloadLength,
            next_header = 17,
            hop_limit = 64,
            source_address = ?Node1Address,
            destination_address = ?Node2Address
        },
    UdpHeader =
        #udp_header{
            source_port = 1025,
            destination_port = 61617,
            length = PayloadLength,
            checksum = 16#f88c
        },

    Ipv6Pckt = ipv6:buildIpv6UdpPacket(IPv6Header, UdpHeader, Payload),
    lowpan_api:sendPacket(Ipv6Pckt).

%-------------------------------------------------------------------------------
% Ipv6 with nextHeader packet format verification
%-------------------------------------------------------------------------------
tx_with_udp() ->
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            % 4 bytes for the UDP header
            payload_length = ?PayloadLength,
            next_header = 17,
            hop_limit = 64,
            source_address = ?Node1Address,
            destination_address = ?Node2Address
        },
    UdpHeader =
        #udp_header{
            source_port = 1025,
            destination_port = 61617,
            length = ?PayloadLength,
            checksum = 16#f88c
        },

    Ipv6Pckt = ipv6:buildIpv6UdpPacket(IPv6Header, UdpHeader, ?Payload),
    lowpan_api:sendPacket(Ipv6Pckt).

%-------------------------------------------------------------------------------
% Transmission of packet that needs routing
%-------------------------------------------------------------------------------
msh_pckt_tx() ->
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = ?PayloadLength,
            next_header = 10,
            hop_limit = 64,
            source_address = ?Node1Address,
            destination_address = ?Node3Address
        },

    Ipv6Pckt = ipv6:buildIpv6Packet(IPv6Header, ?Payload),
    lowpan_api:sendPacket(Ipv6Pckt).

%-------------------------------------------------------------------------------
% Transmission of big packet that needs routing
%-------------------------------------------------------------------------------
msh_big_pckt_tx() ->
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = ?PayloadLength,
            next_header = 10,
            hop_limit = 64,
            source_address = ?Node1Address,
            destination_address = ?Node3Address
        },

    Ipv6Pckt = ipv6:buildIpv6Packet(IPv6Header, ?BigPayload),
    lowpan_api:sendPacket(Ipv6Pckt).

%-------------------------------------------------------------------------------
% Extended hopsLeft packet transmission 
%-------------------------------------------------------------------------------
extendedHopsleftTx() ->
    Ipv6Pckt = ipv6:buildIpv6Packet(?IPv6Header, ?Payload),
    lowpan_api:extendedHopsleftTx(Ipv6Pckt).

%-------------------------------------------------------------------------------
% Transmission of mesh level packet (mesh-local prefix used)
%-------------------------------------------------------------------------------
tx_mesh_prefix() ->
    MacAddress = lowpan_core:generateEUI64MacAddr(?Node2MacAddress),
    IPv6Header = #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = byte_size(?Payload),
            next_header = 12,
            hop_limit = 64,
            source_address = ?Node1Address,
            destination_address =  <<?MESH_LOCAL_PREFIX:16, 16#0DB8:16, 0:32, 2:8,0:48, MacAddress/binary>>
        },
    Packet = ipv6:buildIpv6Packet(IPv6Header, ?Payload), 
    lowpan_api:sendPacket(Packet).

%-------------------------------------------------------------------------------
% Data reception
%-------------------------------------------------------------------------------
rx() ->
    grisp_led:color(2, red),
    lowpan_api:frameReception(), 
    grisp_led:color(2, green),
    rx().

%-------------------------------------------------------------------------------
% Transmission of N packets with report of performance and stats
%-------------------------------------------------------------------------------
% tx_with_metrics(N)->
%     Payload = lowpan_core:generateChunks(N),
%     io:format("Payload ~p~n",[Payload]),
%     PayloadLength = byte_size(Payload),

%     IPv6Header =
%         #ipv6_header{
%             version = 6,
%             traffic_class = 0,
%             flow_label = 0,
%             payload_length = PayloadLength,
%             next_header = 58,
%             hop_limit = 64,
%             source_address = lowpan_core:generateLLAddr(?Node1MacAddress),
%             destination_address = lowpan_core:generateLLAddr(?Node3MacAddress)
%         },
%     Ipv6Pckt = ipv6:buildIpv6Packet(IPv6Header, Payload),
%     lowpan_api:sendWithPerfReport(Ipv6Pckt).


ieeetx2()->
    FrameControl = #frame_control{
    frame_type = ?FTYPE_DATA,
    src_addr_mode = ?EXTENDED,
    dest_addr_mode = ?EXTENDED}, 

    MacHeader = #mac_header{src_addr = ?Node1MacAddress, 
                dest_addr = ?Node2MacAddress},

    lowpan_api:tx(<<"Hello">>, FrameControl, MacHeader).


ieeetx3()->
    FrameControl = #frame_control{
    frame_type = ?FTYPE_DATA,
    src_addr_mode = ?EXTENDED,
    dest_addr_mode = ?EXTENDED}, 

    MacHeader = #mac_header{src_addr = ?Node1MacAddress, 
                dest_addr = ?Node3MacAddress},

    lowpan_api:tx(<<"Hello">>, FrameControl, MacHeader).


%-------------------------------------------------------------------------------
% IEEE 802.15.4 setup only for manual configuration
%-------------------------------------------------------------------------------
% ieee802154_setup(MacAddr)->
%     ieee802154:start(#ieee_parameters{
%         duty_cycle = duty_cycle_non_beacon,
%         input_callback = fun lowpan_api:input_callback/4
%     }),

%     case application:get_env(robot, pan_id) of
%         {ok, PanId} ->
%             ieee802154:set_pib_attribute(mac_pan_id, PanId);
%         _ ->
%             ok
%     end,

%     case byte_size(MacAddr) of 
%         ?EXTENDED_ADDR_LEN -> ieee802154:set_pib_attribute(mac_extended_address, MacAddr); 
%         ?SHORT_ADDR_LEN -> ieee802154:set_pib_attribute(mac_short_address, MacAddr)
%     end, 

%     ieee802154:rx_on().
    
start(_Type, _Args) ->
    {ok, Supervisor} = robot_sup:start_link(),
    grisp:add_device(spi2, pmod_uwb),
    pmod_uwb:write(tx_antd, #{tx_antd => ?TX_ANTD}),
    pmod_uwb:write(lde_if, #{lde_rxantd => ?RX_ANTD}),

    NodeMacAddr = case application:get_env(robot, mac_addr) of
        {ok, MacAddr} ->
            MacAddr;
        _ ->
            ?Node1MacAddress
    end,

    %ieee802154_setup(NodeMacAddr),

    lowpan_api:start(#{node_mac_addr => NodeMacAddr, routing_table => ?Node1_routing_table}),
    
    %rx(),
    {ok, Supervisor}.

% @private
stop(_State) ->
    ok.
