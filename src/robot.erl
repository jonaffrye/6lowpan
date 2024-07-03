-module(robot).

-behaviour(application).

-include("utils.hrl").

-export([
    tx/0,
    tx_unc_ipv6/0,
    tx_iphc_pckt/0,
    tx_frag_iphc_pckt/0,
    tx_big_payload/0,
    tx_with_udp/0,
    tx_msh_iphc_pckt/0,
    tx_msh_frag_iphc_pckt/0,
    msh_pckt_tx/0,
    msh_big_pckt_tx/0,
    rx/0, 
    tx_broadcast_pckt/0, 
    extended_hopsleft_tx/0, 
    tx_unc_ipv6_udp/0, 
    tx_comp_ipv6_udp/0
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
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    io:format("Frame ~p~n", [Ipv6Pckt]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Ipv6Pckt)]),

    lowpan_layer:send_unc_datagram(Ipv6Pckt, ?FrameControl, ?MacHeader).


%-------------------------------------------------------------------------------
% compressed header packet format verification
%-------------------------------------------------------------------------------
tx_iphc_pckt() ->
    InlineData = <<12:8, ?Node1MacAddress/binary, ?Node2MacAddress/binary>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, 3:2, 12:1, 3:2, 0:1, 0:1, 1:2, 0:1, 0:1, 1:2, InlineData/binary>>,

    % Create the IPHC packet
    IPHC = lowpan:create_iphc_pckt(ExpectedHeader, ?Payload),
    io:format("IphcHeader ~p~n", [IPHC]),
    io:format("Fragment size: ~p bytes~n", [byte_size(IPHC)]),

    lowpan_layer:tx(IPHC, ?FrameControl, ?MacHeader).

%-------------------------------------------------------------------------------
% Meshed and compressed header packet format verification
%-------------------------------------------------------------------------------
tx_msh_iphc_pckt() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt),

    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?Node1MacAddress,
            final_destination_address = ?Node2MacAddress
        },

    BinMeshHeader = lowpan:build_mesh_header(MeshHeader),
    Datagram = <<BinMeshHeader/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Datagram ~p~n", [Datagram]),

    lowpan_layer:tx(Datagram, ?FrameControl, ?MacHeader).

%-------------------------------------------------------------------------------
% Fragmented and compressed packet format verification
%-------------------------------------------------------------------------------
tx_frag_iphc_pckt() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt),
    PcktLen = byte_size(Ipv6Pckt),

    FragHeader =
        #frag_header{
            frag_type = ?FRAG1_DHTYPE,
            datagram_size = PcktLen,
            datagram_tag = 124
        },

    FragHeaderBin = lowpan:build_first_frag_header(FragHeader),

    Datagram = <<FragHeaderBin/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Frame ~p~n", [Datagram]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Datagram)]),

    lowpan_layer:tx(Datagram, ?FrameControl, ?MacHeader).

%-------------------------------------------------------------------------------
% Meshed, fragmented and compressed packet format verification
%-------------------------------------------------------------------------------
tx_msh_frag_iphc_pckt() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt),
    PcktLen = byte_size(Ipv6Pckt),

    FragHeader =
        #frag_header{
            frag_type = ?FRAG1_DHTYPE,
            datagram_size = PcktLen,
            datagram_tag = 124
        },

    FragHeaderBin = lowpan:build_first_frag_header(FragHeader),

    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?Node1MacAddress,
            final_destination_address = ?Node2MacAddress
        },

    BinMeshHeader = lowpan:build_mesh_header(MeshHeader),
    Datagram =
        <<BinMeshHeader/binary, FragHeaderBin/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Datagram ~p~n", [Datagram]),

    lowpan_layer:tx(Datagram, ?FrameControl, ?MacHeader).

%-------------------------------------------------------------------------------
% Broadcast packet format verification
%-------------------------------------------------------------------------------
tx_broadcast_pckt() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt),
    PcktLen = byte_size(Ipv6Pckt),

    FragHeader =
        #frag_header{
            frag_type = ?FRAG1_DHTYPE,
            datagram_size = PcktLen,
            datagram_tag = 124
        },

    FragHeaderBin = lowpan:build_first_frag_header(FragHeader),

    DestMacAddr = lowpan:generate_EUI64_mac_addr(<<16#1234:16>>),

    DestAddr = <<16#FF02:16, 0:64, 1:16, 16#FF00:16, 16#1234:16>>,
    DestAddress = binary:decode_unsigned(DestAddr),
    {_, BroadcastHeader, _} = lowpan:get_next_hop(?Node1MacAddress, ?Node1MacAddress, DestMacAddr, DestAddress, 3, false),

    Datagram =
        <<BroadcastHeader/binary, FragHeaderBin/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Datagram ~p~n", [Datagram]),

    MacHeader = #mac_header{src_addr = ?Node1MacAddress, dest_addr = DestMacAddr},
    lowpan_layer:tx(Datagram, ?FrameControl, MacHeader).


%-------------------------------------------------------------------------------
% Simple transmission 
%-------------------------------------------------------------------------------
tx() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    lowpan_layer:send_packet(Ipv6Pckt).

%-------------------------------------------------------------------------------
% Big payload transmission
%-------------------------------------------------------------------------------
tx_big_payload() ->
    Payload = lowpan:generate_chunks(),

    Node1Address = lowpan:generate_LL_addr(?Node1MacAddress),
    Node2Address = lowpan:generate_LL_addr(?Node2MacAddress),
    PayloadLength = byte_size(Payload),

    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = PayloadLength,
            next_header = 58,
            hop_limit = 64,
            source_address = Node1Address,
            destination_address = Node2Address
        },
    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),
    lowpan_layer:send_packet(Ipv6Pckt).


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

    Ipv6Pckt = ipv6:build_ipv6_udp_packet(IPv6Header, UdpHeader, Payload),
    io:format("Frame ~p~n", [Ipv6Pckt]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Ipv6Pckt)]),

    lowpan_layer:send_unc_datagram(Ipv6Pckt, ?FrameControl, ?MacHeader).


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

    Ipv6Pckt = ipv6:build_ipv6_udp_packet(IPv6Header, UdpHeader, Payload),
    lowpan_layer:send_packet(Ipv6Pckt).

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

    Ipv6Pckt = ipv6:build_ipv6_udp_packet(IPv6Header, UdpHeader, ?Payload),
    lowpan_layer:send_packet(Ipv6Pckt).

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

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, ?Payload),
    lowpan_layer:send_packet(Ipv6Pckt).

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

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, ?BigPayload),
    lowpan_layer:send_packet(Ipv6Pckt).

%-------------------------------------------------------------------------------
% Extended hopsLeft packet transmission 
%-------------------------------------------------------------------------------
extended_hopsleft_tx() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    lowpan_layer:extended_hopsleft_tx(Ipv6Pckt).

%-------------------------------------------------------------------------------
% Data reception
%-------------------------------------------------------------------------------
rx() ->
    lowpan_layer:frame_reception(), 
    rx().

%-------------------------------------------------------------------------------
% IEEE 802.15.4 setup only for manual configuration
%-------------------------------------------------------------------------------
% ieee802154_setup(MacAddr)->
%     ieee802154:start(#ieee_parameters{
%         duty_cycle = duty_cycle_non_beacon,
%         input_callback = fun lowpan_layer:input_callback/4
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

    lowpan_layer:start(#{node_mac_addr => NodeMacAddr, routing_table => ?Default_routing_table}),
    {ok, Supervisor}.

% @private
stop(_State) ->
    ok.
