-module(lowpan_sender_receiver_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("../src/utils.hrl").

-export([
    all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2,
    end_per_group/2, init_per_testcase/2, end_per_testcase/2,
    simple_pckt_sender/1, simple_pckt_receiver/1, big_payload_sender/1,
    big_payload_receiver/1, multicast_sender/1, multicast_receiver/1,
    routing_req_sender/1, routing_req_receiver2/1, routing_req_receiver3/1,
    big_pyld_routing_sender/1, big_pyld_routing_receiver2/1, big_pyld_routing_receiver3/1, 
    discarded_sender/1, discarded_receiver/1, unexpected_dtg_size_sender/1
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
            {group, big_pyld_routing_tx_rx}, 
            {group, discard_datagram_tx_rx}, 
            {group, unexpected_dtg_size_tx}
        ]},
        {simple_tx_rx, [parallel, {repeat, 1}], [simple_pckt_sender, simple_pckt_receiver]},
        {big_payload_tx_rx, [parallel, {repeat, 1}], [big_payload_sender, big_payload_receiver]},
        {multicast_src_tx, [parallel, {repeat, 1}], [multicast_sender, multicast_receiver]},
        {routing_req_tx_rx, [parallel, {repeat, 1}], [routing_req_sender, routing_req_receiver3, routing_req_receiver2]},
        {big_pyld_routing_tx_rx, [parallel, {repeat, 1}], [big_pyld_routing_sender, big_pyld_routing_receiver2, big_pyld_routing_receiver3]}, 
        {discard_datagram_tx_rx, [parallel, {repeat, 1}], [discarded_sender, discarded_receiver]}, 
        {unexpected_dtg_size_tx, [sequential], [unexpected_dtg_size_sender]}
    ].

%--------------------------
init_per_group(simple_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?Payload, Config); 
%--------------------------
init_per_group(big_payload_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node3Address, ?BigPayload, Config); 
%--------------------------
init_per_group(multicast_src_tx, Config) ->
    init_per_group_setup(<<16#FF:16, 0:112>>, ?Node2Address, ?Payload, Config);
%--------------------------
init_per_group(routing_req_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?Payload, Config); 
%--------------------------
init_per_group(big_pyld_routing_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node3Address, ?BigPayload, Config); 
%--------------------------
init_per_group(discard_datagram_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?Payload, Config);
%--------------------------
init_per_group(unexpected_dtg_size_tx, Config) ->
    Paylaod = lowpan:generate_chunks(120),
    init_per_group_setup(?Node1Address, ?Node2Address, Paylaod, Config);
%--------------------------
init_per_group(_, Config) ->
    Config.

init_per_group_setup(Src, Dst, Payload, Config) ->
    {NetPid, Network} = lowpan_node:boot_network_node(#{loss => true}),
    io:format("Initializing group ~n"),

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
    Packet = ipv6:build_ipv6_packet(IPv6Header, Payload), 
    [
        {net_pid, NetPid},
        {network, Network},
        {node1_mac_address, ?Node1MacAddress},
        {node2_mac_address, ?Node2MacAddress},
        {node3_mac_address, ?Node3MacAddress}, 
        {ipv6_packet, Packet}
        | Config
    ].

end_per_group(_Group, Config) ->
    Network = proplists:get_value(network, Config),
    NetPid = proplists:get_value(net_pid, Config),
    
    if
        Network =:= undefined ->
            io:format("Error: Network not found in Config~n"),
            {error, network_not_found};
        NetPid =:= undefined ->
            io:format("Error: NetPid not found in Config~n"),
            {error, net_pid_not_found};
        true ->
            lowpan_node:stop_network_node(Network, NetPid),
            ok
    end.



%---------- Tests cases initialization ------------------------------------------------

defaut_sender_init_per_testcase(Config, RoutingTable)->
    Network = ?config(network, Config),
    Node1MacAddress = ?config(node1_mac_address, Config),
    Node = lowpan_node:boot_lowpan_node(node1, Network, Node1MacAddress, RoutingTable),
    [{node1, Node} | Config].

defaut_receiver2_init_per_testcase(Config, RoutingTable)->
    Network = ?config(network, Config),
    Node2MacAddress = ?config(node2_mac_address, Config),
    Callback = fun lowpan_layer:input_callback/4,
    Node = lowpan_node:boot_lowpan_node(node2, Network, Node2MacAddress, Callback, RoutingTable),
    [{node2, Node} | Config].

defaut_receiver3_init_per_testcase(Config, RoutingTable)->
    Network = ?config(network, Config),
    Node3MacAddress = ?config(node3_mac_address, Config),
    Callback = fun lowpan_layer:input_callback/4,
    Node = lowpan_node:boot_lowpan_node(node3, Network, Node3MacAddress, Callback, RoutingTable),
    [{node3, Node} | Config].

%--------------------------
init_per_testcase(simple_pckt_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Default_routing_table); 

init_per_testcase(simple_pckt_receiver, Config)->
    defaut_receiver2_init_per_testcase(Config, ?Default_routing_table); 

%--------------------------
init_per_testcase(big_payload_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Default_routing_table); 

init_per_testcase(big_payload_receiver, Config)->
    defaut_receiver3_init_per_testcase(Config, ?Default_routing_table); 

%--------------------------
init_per_testcase(multicast_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Default_routing_table); 

init_per_testcase(multicast_receiver, Config)->
    defaut_receiver2_init_per_testcase(Config, ?Default_routing_table); 

%--------------------------
init_per_testcase(routing_req_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Node1_routing_table); 

init_per_testcase(routing_req_receiver2, Config)->
    defaut_receiver2_init_per_testcase(Config, ?Node2_routing_table); 

init_per_testcase(routing_req_receiver3, Config)->
    defaut_receiver3_init_per_testcase(Config, ?Node3_routing_table); 

%--------------------------
init_per_testcase(big_pyld_routing_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Node1_routing_table); 

init_per_testcase(big_pyld_routing_receiver2, Config)->
    defaut_receiver2_init_per_testcase(Config, ?Node2_routing_table); 

init_per_testcase(big_pyld_routing_receiver3, Config)->
    defaut_receiver3_init_per_testcase(Config, ?Node3_routing_table); 

%--------------------------
init_per_testcase(discarded_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Node1_routing_table); 

init_per_testcase(discarded_receiver, Config)->
    defaut_receiver2_init_per_testcase(Config, ?Node2_routing_table); 
    
%--------------------------
init_per_testcase(unexpected_dtg_size_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Node1_routing_table); 

%--------------------------
init_per_testcase(_, Config) ->
            Config.
  

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
routing_req_receiver2(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    {CompressedHeader, _} = lowpan:compress_ipv6_header(IPv6Pckt),
    PcktInfo = lowpan:get_ipv6_pckt_info(IPv6Pckt),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node2, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Routed packet received successfully at node2"),
    lowpan_node:stop_lowpan_node(Node2, Pid2).

routing_req_receiver3(Config) ->
    {Pid3, Node3} = ?config(node3, Config),
    erpc:call(Node3, lowpan_layer, frame_reception, []),
    lowpan_node:stop_lowpan_node(Node3, Pid3).

%-------------------------------------------------------------------------------
% Send a big packet that needs routing from node 1 to node 3
%-------------------------------------------------------------------------------
big_pyld_routing_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ct:pal("Big routed packet sent successfully from node1 to node3"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of a big payload with routing by node 3
%-------------------------------------------------------------------------------

big_pyld_routing_receiver2(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    erpc:call(Node2, lowpan_layer, frame_reception, []),
    lowpan_node:stop_lowpan_node(Node2, Pid2).

big_pyld_routing_receiver3(Config) ->
    {Pid3, Node3} = ?config(node3, Config),
    
    IPv6Pckt = ?config(ipv6_packet, Config),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(IPv6Pckt),
    PcktInfo = lowpan:get_ipv6_pckt_info(IPv6Pckt),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node3, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Routed packet received successfully at node2"),

    lowpan_node:stop_lowpan_node(Node3, Pid3).


%-------------------------------------------------------------------------------
% Send a datagram with 1 as value for hop left to node 2
%-------------------------------------------------------------------------------
discarded_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    Node1MacAddress = ?config(node1_mac_address, Config),
    Node2MacAddress = ?config(node2_mac_address, Config),
    Node3MacAddress = ?config(node3_mac_address, Config),

    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 1,
            originator_address = Node1MacAddress,
            final_destination_address = Node3MacAddress
        },

    BinMeshHeader = lowpan:build_mesh_header(MeshHeader),

    Datagram = <<BinMeshHeader/binary, ?Payload/bitstring>>, % meshHeader + Data

    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    MacHdr = #mac_header{src_addr = Node1MacAddress, dest_addr = Node2MacAddress},

    ok = erpc:call(Node1, lowpan_layer, tx, [Datagram, FC, MacHdr]),
    ct:pal("Big routed packet sent successfully from node1 to node3"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Discard datagram received from node 1
%-------------------------------------------------------------------------------
discarded_receiver(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    dtg_discarded = erpc:call(Node2, lowpan_layer, frame_reception, []),
    lowpan_node:stop_lowpan_node(Node2, Pid2).

%-------------------------------------------------------------------------------
% Check if error is return when datagram size is unexpected 
%-------------------------------------------------------------------------------
unexpected_dtg_size_sender(Config) ->
    {Pid1, Node1}  = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),
    error_frag_size = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    lowpan_node:stop_lowpan_node(Node1, Pid1).