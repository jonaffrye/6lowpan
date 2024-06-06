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
    rx/0
]).
-export([rx_off/0]).
% Benchmarking
-export([tx_benchmark/0]).
-export([rx_benchmark/0]).
% Callbacks
-export([start/2]).
-export([stop/1]).

-compile([{nowarn_unused_function, [rx_callback/4]}]).

%--- Macros --------------------------------------------------------------------
-define(JAMMING_DATA, <<"JAMMING">>).
-define(DATALENGTH, byte_size(?JAMMING_DATA)).
-define(BENCHMARK_DATA, <<16#F:(111 * 8)>>).
-define(BENCHMARK_DATA_LENGTH, bit_size(?BENCHMARK_DATA)).
-define(PANID, <<16#CAFE:16>>).
-define(SENDER_ADDR, <<16#0001:16>>).
-define(RECEIVER_ADDR, <<16#0002:16>>).
-define(CCA_DURATION, 283).
-define(TX_ANTD, 16450).
-define(RX_ANTD, 16450).

%--- API -----------------------------------------------------------------------
% Sends/receive only 1 frame

tx_unc_ipv6() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    io:format("Frame ~p~n", [Ipv6Pckt]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Ipv6Pckt)]),

    lowpan_layer:send_unc_datagram(Ipv6Pckt, ?FrameControl, ?MacHeader).

tx_iphc_pckt() ->
    InlineData = <<12:8, 14627373598910709761:64, 14627373598910709762:64>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, 3:2, 12:1, 3:2, 0:1, 0:1, 1:2, 0:1, 0:1, 1:2, InlineData/binary>>,

    % Create the IPHC packet
    IPHC = lowpan:create_iphc_pckt(ExpectedHeader, ?Payload),
    io:format("IphcHeader ~p~n", [IPHC]),
    io:format("Fragment size: ~p bytes~n", [byte_size(IPHC)]),

    lowpan_layer:tx(IPHC, ?FrameControl, ?MacHeader).

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

tx_frag_iphc_pckt() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt),

    PcktLen = byte_size(Ipv6Pckt),

    Frag =
        lowpan:build_firstFrag_pckt(?FRAG1_DHTYPE, PcktLen, 124, CompressedHeader, ?Payload),
    io:format("Frame ~p~n", [Frag]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Frag)]),

    lowpan_layer:tx(Frag, ?FrameControl, ?MacHeader).

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

    Frag = lowpan:build_first_frag_header(FragHeader),

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
        <<BinMeshHeader/binary, Frag/binary, CompressedHeader/binary, ?Payload/bitstring>>,
    io:format("Datagram ~p~n", [Datagram]),

    lowpan_layer:tx(Datagram, ?FrameControl, ?MacHeader).

tx() ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    lowpan_layer:send_packet(Ipv6Pckt).

tx_big_payload() ->
    Payload = lowpan:generate_chunks(),

    Node1Address = lowpan:get_default_LL_add(?Node1MacAddress),
    Node2Address = lowpan:get_default_LL_add(?Node2MacAddress),
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

tx_with_udp() ->
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            % 4 bytes for the UDP header
            payload_length = ?PayloadLength + 4,
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

msh_pckt_tx() ->
    Node1MacAddress = <<16#CAFEDECA00000001:64>>,
    Node3MacAddress = <<16#CAFEDECA00000003:64>>,
    Node1Address = lowpan:get_default_LL_add(Node1MacAddress),
    Node3Address = lowpan:get_default_LL_add(Node3MacAddress),

    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = ?PayloadLength,
            next_header = 17,
            hop_limit = 64,
            source_address = Node1Address,
            destination_address = Node3Address
        },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, ?Payload),
    lowpan_layer:send_packet(Ipv6Pckt).

rx() ->
    lowpan_layer:frame_reception(), 
    rx().

-spec rx_callback(Frame, LinkQuality, Security, Ranging) -> ok when
    Frame :: frame(),
    LinkQuality :: integer(),
    Security :: ieee802154:security(),
    Ranging :: ieee802154:ranging_informations().
rx_callback({_FrameControl, _MacHeader, _Payload}, LQI, Security, Ranging) ->
    io:format("------ Frame report ------~n"),
    io:format("Link quality: ~p ~n", [LQI]),
    io:format("Security: ~w~n", [Security]),
    io:format("Ranging: ~w~n", [Ranging]),
    io:format("-------------------------~n").

% io:format("Received frame with seqnum: ~w - Payload: ~w ~n",
%           [_MacHeader#mac_header.seqnum, _Payload]).

rx_off() ->
    ieee802154:rx_off().

tx(0, Total, Success, Error) ->
    {Success, Error, Total};
tx(N, Total, Success, Error) ->
    Seqnum = Total rem 512,
    case
        ieee802154:transmission({
            #frame_control{pan_id_compr = ?ENABLED, ack_req = ?ENABLED},
            #mac_header{
                seqnum = Seqnum,
                dest_pan = ?PANID,
                dest_addr = ?RECEIVER_ADDR,
                src_addr = ?SENDER_ADDR
            },
            ?BENCHMARK_DATA
        })
    of
        {ok, _} ->
            tx(N - 1, Total + 1, Success + 1, Error);
        _ ->
            tx(N - 1, Total + 1, Success, Error + 1)
    end.

tx_benchmark() ->
    ieee802154:set_pib_attribute(mac_pan_id, ?PANID),
    ieee802154:set_pib_attribute(mac_short_address, ?SENDER_ADDR),
    pmod_uwb:set_preamble_timeout(?CCA_DURATION),
    NbrFrames = 100,
    % NbrFrames = 1000,
    Start = os:timestamp(),
    {Success, Error, Total} = tx(NbrFrames, 0, 0, 0),
    End = os:timestamp(),
    Time = timer:now_diff(End, Start) / 1000000,
    io:format("------------------- Report -------------------~n"),
    io:format(
        "Sent ~w frames - Success rate ~.3f (~w/~w) - Error rate ~.3f (~w/~w)~n",
        [Total, Success / Total, Success, Total, Error / Total, Error, Total]
    ),
    io:format(
        "Data rate ~.1f b/s - ~w b in ~w s ~n",
        [
            ?BENCHMARK_DATA_LENGTH * NbrFrames / Time,
            ?BENCHMARK_DATA_LENGTH * NbrFrames,
            Time
        ]
    ),
    io:format("----------------------------------------------~n").

rx_benchmark() ->
    ieee802154:set_pib_attribute(mac_pan_id, ?PANID),
    ieee802154:set_pib_attribute(mac_short_address, ?RECEIVER_ADDR),
    % rx().
    ieee802154:rx_on().

start(_Type, _Args) ->
    {ok, Supervisor} = robot_sup:start_link(),
    grisp:add_device(spi2, pmod_uwb),
    pmod_uwb:write(tx_antd, #{tx_antd => ?TX_ANTD}),
    pmod_uwb:write(lde_if, #{lde_rxantd => ?RX_ANTD}),

    ieee802154:start(#ieee_parameters{
        duty_cycle = duty_cycle_non_beacon,
        input_callback = fun lowpan_layer:input_callback/4
    }),

    case application:get_env(robot, pan_id) of
        {ok, PanId} ->
            ieee802154:set_pib_attribute(mac_pan_id, PanId);
        _ ->
            ok
    end,
    case application:get_env(robot, mac_addr) of
        {ok, MacAddr} ->
            ieee802154:set_pib_attribute(mac_short_address, MacAddr);
        _ ->
            ok
    end,

    NodeMacAddress = <<16#CAFEDECA00000001:64>>,
    lowpan_layer:start(#{node_mac_addr => NodeMacAddress, routing_table => ?Node1_routing_table}),
    %tx(),
    ieee802154:rx_on(?ENABLED),
    {ok, Supervisor}.

% @private
stop(_State) ->
    ok.
