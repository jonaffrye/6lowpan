-module(lowpan_sender_receiver_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("../src/utils.hrl").

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2,

    simple_pckt_sender/1,
    simple_pckt_receiver/1,
    big_payload_sender/1,
    big_payload_receiver/1,
    multicast_sender/1,
    multicast_receiver/1,
    routing_req_sender/1,
    routing_req_receiver/1,
    big_pyld_routing_sender/1,
    big_pyld_routing_receiver/1
]).

all() ->
    [{group, test_scenarios}].

%---------- Tests groups --------------------------------------------------------------

groups() ->
    [
        {test_scenarios, [], [
            {group, simple_tx_rx},
            {group, big_payload_tx_rx},
            {group, multicast_src_tx},
            {group, routing_req_tx_rx},
            {group, big_pyld_routing_tx_rx}
        ]},
        {simple_tx_rx, [parallel, {repeat, 1}], [simple_pckt_sender, simple_pckt_receiver]},
        {big_payload_tx_rx, [parallel, {repeat, 1}], [big_payload_sender, big_payload_receiver]},
        {multicast_src_tx, [parallel, {repeat, 1}], [multicast_sender, multicast_receiver]},
        {routing_req_tx_rx, [parallel, {repeat, 1}], [routing_req_sender, routing_req_receiver]},
        {big_pyld_routing_tx_rx, [parallel, {repeat, 1}], [big_pyld_routing_sender, big_pyld_routing_receiver]}
    ].

init_per_group(simple_tx_rx, Config) ->
    init_per_group_setup("simple_tx_rx", Config);
init_per_group(big_payload_tx_rx, Config) ->
    init_per_group_setup("big_payload_tx_rx", Config);
init_per_group(multicast_src_tx, Config) ->
    init_per_group_setup("multicast_src_tx", Config);
init_per_group(routing_req_tx_rx, Config) ->
    init_per_group_setup("routing_req_tx_rx", Config);
init_per_group(big_pyld_routing_tx_rx, Config) ->
    init_per_group_setup("big_pyld_routing_tx_rx", Config);
init_per_group(_, Config) ->
    Config.

init_per_group_setup(GroupName, Config) ->
    {NetPid, Network} = lowpan_node:boot_network_node(#{loss => false}),
    io:format("Initializing group: ~p~n", [GroupName]),
    Payload = <<"Hello world this is an ipv6 packet for testing purpose">>,
    BigPayload = lowpan:generate_chunks(),
    NewConfig = packets_setup(Payload, BigPayload, GroupName, Config),
    [
        {net_pid, NetPid},
        {network, Network},
        {node1_mac_address, ?Node1MacAddress},
        {node2_mac_address, ?Node2MacAddress},
        {node3_mac_address, ?Node3MacAddress}
        | NewConfig
    ].

packets_setup(Payload, BigPayload, Group, Config) ->
    case Group of
        "simple_tx_rx" ->
            Packet = setup_packet(?Node1Address, ?Node2Address, Payload), 
            [{ipv6_packet, Packet} | Config];
        "big_payload_tx_rx" ->
            Packet = setup_packet(?Node1Address, ?Node3Address, BigPayload), 
            [{ipv6_packet, Packet} | Config];
        "multicast_src_tx" ->
            Packet = setup_packet(<<16#FF:16, 0:112>>, ?Node2Address, Payload), 
            [{ipv6_packet, Packet} | Config];
        "routing_req_tx_rx" ->
            Packet = setup_packet(?Node1Address, ?Node2Address, Payload), 
            [{ipv6_packet, Packet} | Config];
        "big_pyld_routing_tx_rx" ->
            Packet = setup_packet(?Node1Address, ?Node3Address, BigPayload),
            [{ipv6_packet, Packet} | Config];
        _ -> Config
    end.

setup_packet(Src, Dst, Payload) ->
    IPv6Header = #ipv6_header{
        version = 6,
        traffic_class = 0,
        flow_label = 0,
        payload_length = byte_size(Payload),
        next_header = 12,
        hop_limit = 64,
        source_address = Src,
        destination_address = Dst
    },
    ipv6:build_ipv6_packet(IPv6Header, Payload).

end_per_group(_Group, Config) ->
    Network = ?config(network, Config),
    NetPid = ?config(net_pid, Config),
    lowpan_node:stop_network_node(Network, NetPid).


%---------- Tests cases initialization ------------------------------------------------
init_per_testcase(TestCase, Config) ->
    Network = ?config(network, Config),
    case TestCase of
        simple_pckt_sender ->
            Node1MacAddress = ?config(node1_mac_address, Config),
            Node = lowpan_node:boot_lowpan_node(node1, Network, Node1MacAddress, ?Default_routing_table),
            [{node1, Node} | Config];

        simple_pckt_receiver ->
            Node2MacAddress = ?config(node2_mac_address, Config),
            Callback = fun lowpan_layer:input_callback/4,
            Node = lowpan_node:boot_lowpan_node(node2, Network, Node2MacAddress, Callback, ?Default_routing_table),
            [{node2, Node} | Config];

        big_payload_sender ->
            Node1MacAddress = ?config(node1_mac_address, Config),
            Node = lowpan_node:boot_lowpan_node(node1, Network, Node1MacAddress, ?Default_routing_table),
            [{node1, Node} | Config];

        big_payload_receiver ->
            Node3MacAddress = ?config(node3_mac_address, Config),
            Callback = fun lowpan_layer:input_callback/4,
            Node = lowpan_node:boot_lowpan_node(node3, Network, Node3MacAddress, Callback, ?Default_routing_table),
            [{node3, Node} | Config];

        multicast_sender ->
            Node1MacAddress = ?config(node1_mac_address, Config),
            Node = lowpan_node:boot_lowpan_node(node1, Network, Node1MacAddress, ?Default_routing_table),
            [{node1, Node} | Config];

        multicast_receiver ->
            Node2MacAddress = ?config(node2_mac_address, Config),
            Callback = fun lowpan_layer:input_callback/4,
            Node = lowpan_node:boot_lowpan_node(node2, Network, Node2MacAddress, Callback, ?Default_routing_table),
            [{node2, Node} | Config];

        routing_req_sender ->
            Node1MacAddress = ?config(node1_mac_address, Config),
            Node = lowpan_node:boot_lowpan_node(node1, Network, Node1MacAddress, ?Node1_routing_table),
            [{node1, Node} | Config];

        routing_req_receiver ->
            Callback = fun lowpan_layer:input_callback/4,

            Node2MacAddress = ?config(node2_mac_address, Config),
            Node2 = lowpan_node:boot_lowpan_node(node2, Network, Node2MacAddress, Callback, ?Node2_routing_table),
            
            Node3MacAddress = ?config(node3_mac_address, Config),
            Node3 = lowpan_node:boot_lowpan_node("node3", Network, Node3MacAddress, Callback, ?Node3_routing_table),

            [{node2, Node2}, {node3, Node3} | Config];

        big_pyld_routing_sender ->
            Node1MacAddress = ?config(node1_mac_address, Config),
            Node = lowpan_node:boot_lowpan_node(node1, Network, Node1MacAddress, ?Node1_routing_table),
            [{node1, Node} | Config];

        big_pyld_routing_receiver ->
            Callback = fun lowpan_layer:input_callback/4,

            Node2MacAddress = ?config(node2_mac_address, Config),
            Node2 = lowpan_node:boot_lowpan_node(node2, Network, Node2MacAddress, Callback, ?Node2_routing_table),
            
            Node3MacAddress = ?config(node3_mac_address, Config),
            Node3 = lowpan_node:boot_lowpan_node(node3, Network, Node3MacAddress, Callback, ?Node3_routing_table),

            [{node2, Node2}, {node3, Node3} | Config];

        _ ->
            Config
    end.

end_per_testcase(_, _) ->
    ok.

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%-------------------------------------------------------------------------------
% Send a single payload from node 1 to node 2
%-------------------------------------------------------------------------------
simple_pckt_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ct:pal("Payload sent successfully from node1 to node2"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Payload from node 1 received by node 2
%-------------------------------------------------------------------------------
simple_pckt_receiver(Config) ->
    {Pid2, Node2} = ?config(node2, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    {CompressedHeader, _} = lowpan:compress_ipv6_header(IPv6Pckt),
    PcktInfo = lowpan:get_ipv6_pckt_info(IPv6Pckt),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node2, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Payload received successfully at node2"),
    lowpan_node:stop_lowpan_node(Node2, Pid2).

%-------------------------------------------------------------------------------
% Send a large payload from node 1 to node 3
%-------------------------------------------------------------------------------
big_payload_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt2 = ?config(ipv6_packet, Config),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt2]),
    ct:pal("Big payload sent successfully from node1 to node3"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Large payload from node 1 received by node 3
%-------------------------------------------------------------------------------
big_payload_receiver(Config) ->
    {Pid3, Node3}  = ?config(node3, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    {CompressedHeader, _} = lowpan:compress_ipv6_header(IPv6Pckt),
    PcktInfo = lowpan:get_ipv6_pckt_info(IPv6Pckt),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node3, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Big payload received successfully at node3"),
    lowpan_node:stop_lowpan_node(Node3, Pid3).

%-------------------------------------------------------------------------------
% Send packet with a multicast source address
%-------------------------------------------------------------------------------
multicast_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt3 = ?config(ipv6_packet, Config),
    {error_multicast_src} = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt3]),
    ct:pal("Multicast Source address done"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of a multicast packet from node 1 by node 2
%-------------------------------------------------------------------------------
multicast_receiver(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    %IPv6Pckt3 = ?config(ipv6_packet, Config),
    ReceivedData = erpc:call(Node2, lowpan_layer, frame_reception, []),
    io:format(ReceivedData),
    ct:pal("Multicast packet received successfully at node2"),
    lowpan_node:stop_lowpan_node(Node2, Pid2).

%-------------------------------------------------------------------------------
% Send a packet that needs routing from node 1 to node 2
%-------------------------------------------------------------------------------
routing_req_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ct:pal("Routed packet sent successfully from node1 to node2"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of a routed packet
%-------------------------------------------------------------------------------
routing_req_receiver(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    {Pid3, Node3} = ?config(node3, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    {CompressedHeader, _} = lowpan:compress_ipv6_header(IPv6Pckt),
    PcktInfo = lowpan:get_ipv6_pckt_info(IPv6Pckt),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node2, lowpan_layer, frame_reception, []),
    _ = erpc:call(Node3, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Routed packet received successfully at node2"),
    lowpan_node:stop_lowpan_node(Pid2, Node2),
    lowpan_node:stop_lowpan_node(Pid3, Node3).

%-------------------------------------------------------------------------------
% Send a big packet that needs routing from node 1 to node 3
%-------------------------------------------------------------------------------
big_pyld_routing_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ct:pal("Big payload with routing sent successfully from node1 to node3"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of a big payload with routing by node 3
%-------------------------------------------------------------------------------
big_pyld_routing_receiver(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    {Pid3, Node3}  = ?config(node3, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    {CompressedHeader, _} = lowpan:compress_ipv6_header(IPv6Pckt),
    PcktInfo = lowpan:get_ipv6_pckt_info(IPv6Pckt),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node2, lowpan_layer, frame_reception, []),
    _ = erpc:call(Node3, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Big routed packet received successfully at node2"),
    lowpan_node:stop_lowpan_node(Pid2, Node2),
    lowpan_node:stop_lowpan_node(Pid3, Node3).
