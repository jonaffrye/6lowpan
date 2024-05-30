-module(lowpan_sender_receiver_SUITE).

-include_lib("common_test/include/ct.hrl").

-include("../src/utils.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2,
         end_per_group/2, init_per_testcase/2, end_per_testcase/2]).
-export([sender/1]).
-export([receiver/1]).
-export([receiver2/1]).

all() ->
    [{group, unr_simple_tx_rx}].

groups() ->
    [{unr_simple_tx_rx, [sequential], [{group, simple_tx_rx}]},
     {simple_tx_rx, [parallel, {repeat, 2}], [sender, receiver, receiver2]}].

%------Default Initialization-----------------------------------------
%init_per_group(unr_simple_tx_rx, Config) ->
%    ok;

init_per_group(unr_simple_tx_rx, Config) ->
    {NetPid, Network} = lowpan_node:boot_network_node(#{loss => true}),

    % use default address (LL) for both the sender and the receiver
    Node1Address = lowpan:get_default_LL_add(?Node1MacAddress),
    Node2Address = lowpan:get_default_LL_add(?Node2MacAddress),
    Node3Address = lowpan:get_default_LL_add(?Node3MacAddress),

    io:format("----------------------------------------------------------------"),
    io:format("                          Initialization"),
    io:format("----------------------------------------------------------------~n"),
    io:format("Node1 LL add: ~p~n", [Node1Address]),
    io:format("Node2 LL add: ~p~n", [Node2Address]),
    io:format("Node3 LL add: ~p~n", [Node3Address]),
    io:format("----------------------------------------------------------------~n"),

    Payload2 = lowpan:generate_chunks(),
    Payload = <<"Hello world">>,

    IPv6Header =
        #ipv6_header{version = 6,
                     traffic_class = 4,
                     flow_label = 2,
                     payload_length = byte_size(Payload),
                     next_header = 12,
                     hop_limit = 64,
                     source_address = Node1Address,
                     destination_address = Node2Address},
    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),

    IPv6Header2 =
        #ipv6_header{version = 6,
                     traffic_class = 24,
                     flow_label = 2,
                     payload_length = byte_size(Payload2),
                     next_header = 12,
                     hop_limit = 64,
                     source_address = Node1Address,
                     destination_address = Node3Address},
    Ipv6Pckt2 = ipv6:build_ipv6_packet(IPv6Header2, Payload2),

    [{net_pid, NetPid},
     {network, Network},
     {ipv6_packet, Ipv6Pckt},
     {ipv6_packet2, Ipv6Pckt2},
     {node1_address, Node1Address},
     {node2_address, Node2Address},
     {node3_address, Node3Address},
     {node1_mac_address, ?Node1MacAddress},
     {node2_mac_address, ?Node2MacAddress},
     {node3_mac_address, ?Node3MacAddress}
     | Config];
init_per_group(_, Config) ->
    Config.

end_per_group(unr_simple_tx_rx, Config) ->
    Network = ?config(network, Config),
    NetPid = ?config(net_pid, Config),
    lowpan_node:stop_network_node(Network, NetPid);
end_per_group(_, _) ->
    ok.

init_per_testcase(sender, Config) ->
    Network = ?config(network, Config),

    Node1MacAddress = ?config(node1_mac_address, Config),
    %Node2MacAddress = ?config(node2_mac_src_address, Config),
    Node1 = lowpan_node:boot_lowpan_node(node1, Network, Node1MacAddress),
    [{node1, Node1} | Config];
init_per_testcase(receiver, Config) ->
    Network = ?config(network, Config),

    %Node1MacAddress = ?config(node1_mac_src_address, Config),
    Node2MacAddress = ?config(node2_mac_address, Config),
    %Node3MacAddress = ?config(node3_mac_src_address, Config),
    %Callback = fun frame_handler:rx_frame/4,
    Callback = fun lowpan_layer:input_callback/4,
    Node2 =
        lowpan_node:boot_lowpan_node(node2,
                                     Network,
                                     Node2MacAddress,
                                     Callback), % create receiver node
    [{node2, Node2} | Config];
init_per_testcase(receiver2, Config) ->
    Network = ?config(network, Config),
    %Node1MacAddress = ?config(node1_mac_src_address, Config),
    Node3MacAddress = ?config(node3_mac_address, Config),

    Callback = fun lowpan_layer:input_callback/4,
    Node3 =
        lowpan_node:boot_lowpan_node(node3,
                                     Network,
                                     Node3MacAddress,
                                     Callback), % create receiver node
    [{node3, Node3} | Config];
init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _) ->
    ok.

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%------End Default Initialization-----------------------------------------

%--- Test cases -----------------------------------------------------------------------------

% sender(Config) ->
%     ct:sleep(100),
%     ct:pal("Launching node1..."),
%     {Pid1, Node1} = ?config(node1, Config),
%     IPv6Packet = ?config(ipv6_packet, Config),
%     IPv6Packet2 = ?config(ipv6_packet2, Config),

%     ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Packet]),
%     ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Packet2]),

%     % io:format("Adding route to routing table on ~p~n", [Node1]),
%     % DestAddr = <<16#0003:16>>,
%     % NextHopAddr = <<16#0002:16>>,
%     % case erpc:call(Node1, routing_table, add_route, [DestAddr, NextHopAddr]) of
%     %     ok -> io:format("Route added successfully.~n");
%     %     {error, Reason} -> io:format("Failed to add route: ~p~n", [Reason])
%     % end,
%     % io:format("Verifying route in routing table on ~p~n", [Node1]),
%     % case erpc:call(Node1, routing_table, get_route, [DestAddr]) of
%     %     NextHopAddr -> io:format("Route ~p verified successfully.~n",[NextHopAddr]);
%     %     _ -> io:format("Failed to verify route.~n")
%     % end,
%     lowpan_node:stop_lowpan_node(Node1, Pid1),
%     ct:pal("Node1 done").

sender(Config) ->
    ct:sleep(100),
    ct:pal("Launching node1..."),
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Packet = ?config(ipv6_packet, Config),
    IPv6Packet2 = ?config(ipv6_packet2, Config),

    case erpc:call(Node1, lowpan_layer, send_packet, [IPv6Packet]) of
        ok ->
            io:format("First packet sent successfully~n");
        Error ->
            io:format("Error sending first packet: ~p~n", [Error]),
            ct:fail(Error)
    end,

    io:format("----------------------------------------~n"),

    case erpc:call(Node1, lowpan_layer, send_packet, [IPv6Packet2]) of
        ok ->
            io:format("Second packet sent successfully~n");
        Err ->
            io:format("Error sending second packet: ~p~n", [Err]),
            ct:fail(Err)
    end,

    lowpan_node:stop_lowpan_node(Node1, Pid1),
    ct:pal("Node1 done").

% reception of node2 from node1
receiver(Config) ->
    %ct:sleep(100),
    ct:pal("Launching node2..."),
    {Pid2, Node2} = ?config(node2, Config),
    ExpectedIpv6 = ?config(ipv6_packet, Config),
    %Node2MacAddress = ?config(node2_mac_src_address, Config),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(ExpectedIpv6),
    PcktInfo = lowpan:get_ipv6_pckt_info(ExpectedIpv6),
    Payload = PcktInfo#ipv6PckInfo.payload,
    ExpectedIpv6CompIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node2, lowpan_layer, frame_reception, []),

    io:format("Original comp: ~p~n~nReceived comp: ~p~n",
              [ExpectedIpv6CompIpv6Packet, ReceivedData]),
    ReceivedData = ExpectedIpv6CompIpv6Packet,

    ct:pal("Node2 done"),

    lowpan_node:stop_lowpan_node(Node2, Pid2).

% reception of node3 from node1
receiver2(Config) ->
    ct:sleep(100),
    ct:pal("Launching node3..."),
    {Pid3, Node3} = ?config(node3, Config),
    ExpectedIpv6 = ?config(ipv6_packet2, Config),

    {CompressedHeader, _} = lowpan:compress_ipv6_header(ExpectedIpv6),
    PcktInfo = lowpan:get_ipv6_pckt_info(ExpectedIpv6),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node3, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Node3 done"),
    lowpan_node:stop_lowpan_node(Node3, Pid3).
