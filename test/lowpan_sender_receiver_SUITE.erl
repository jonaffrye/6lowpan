-module(lowpan_sender_receiver_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("../src/utils.hrl").

-export([
    all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2,
    end_per_group/2, init_per_testcase/2, end_per_testcase/2,
    simple_pckt_sender/1, simple_pckt_receiver/1, big_payload_sender/1,
    big_payload_receiver/1, multicast_sender/1,routing_req_sender/1, routing_req_receiver2/1, 
    routing_req_receiver3/1, big_pyld_routing_sender/1, big_pyld_routing_receiver2/1, 
    big_pyld_routing_receiver3/1, discarded_sender/1, discarded_receiver/1, 
    no_hoplft_dst_reached_sender/1, no_hoplft_dst_reached_receiver/1, 
    unexpected_dtg_size_sender/1, tag_verification_receiver/1,
    same_tag_different_senders_sender/1, same_tag_different_senders_receiver/1,
    timeout_sender/1, timeout_receiver/1, tag_verification_sender/1, duplicate_sender/1,
    duplicate_receiver/1, multiple_hop_sender/1, multiple_hop_receiver2/1, multiple_hop_receiver3/1, multiple_hop_receiver4/1,
    nalp_sender/1, broadcast_sender/1, broadcast_receiver/1
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
            {group, no_hoplft_dst_reached_tx_rx},
            {group, unexpected_dtg_size_tx},
            {group, same_tag_different_senders},
            {group, timeout_scenario},
            {group, tag_verification_tx_rx},
            {group, duplicate_tx_rx},
            {group, multiple_hop_tx_rx},
            {group, nalp_tx_rx}, 
            {group, broadcast_tx_rx}
        ]},
        {simple_tx_rx, [parallel, {repeat, 1}], [simple_pckt_sender, simple_pckt_receiver]},
        {big_payload_tx_rx, [parallel, {repeat, 1}], [big_payload_sender, big_payload_receiver]},
        {multicast_src_tx, [sequential], [multicast_sender]},
        {routing_req_tx_rx, [parallel, {repeat, 1}], [routing_req_sender, routing_req_receiver3, routing_req_receiver2]},
        {big_pyld_routing_tx_rx, [parallel, {repeat, 1}], [big_pyld_routing_sender, big_pyld_routing_receiver2, big_pyld_routing_receiver3]}, 
        {discard_datagram_tx_rx, [parallel, {repeat, 1}], [discarded_sender, discarded_receiver]}, 
        {no_hoplft_dst_reached_tx_rx, [parallel, {repeat, 1}], [no_hoplft_dst_reached_sender, no_hoplft_dst_reached_receiver]}, 
        {unexpected_dtg_size_tx, [sequential], [unexpected_dtg_size_sender]},
        {same_tag_different_senders, [parallel, {repeat, 1}], [same_tag_different_senders_sender, same_tag_different_senders_receiver]},
        {timeout_scenario, [parallel, {repeat, 1}], [timeout_sender, timeout_receiver]}, 
        {tag_verification_tx_rx, [parallel, {repeat, 1}], [tag_verification_sender, tag_verification_receiver]},
        {duplicate_tx_rx, [parallel, {repeat, 1}], [duplicate_sender, duplicate_receiver]}, 
        {multiple_hop_tx_rx, [parallel, {repeat, 1}], [multiple_hop_sender, multiple_hop_receiver2, multiple_hop_receiver3, multiple_hop_receiver4]},
        {nalp_tx_rx, [sequential], [nalp_sender]}, 
        {broadcast_tx_rx, [parallel, {repeat, 1}], [broadcast_sender, broadcast_receiver]}
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
init_per_group(no_hoplft_dst_reached_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?Payload, Config);
%--------------------------
init_per_group(unexpected_dtg_size_tx, Config) ->
    Payload = lowpan:generate_chunks(120),
    init_per_group_setup(?Node1Address, ?Node2Address, Payload, Config);
%--------------------------
init_per_group(same_tag_different_senders, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?Payload, Config);
%--------------------------
init_per_group(timeout_scenario, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?Payload, Config);
%--------------------------
init_per_group(tag_verification_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?BigPayload, Config);
%--------------------------
init_per_group(duplicate_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?Payload, Config);
%--------------------------
init_per_group(multiple_hop_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node4Address, ?Payload, Config);
%--------------------------
init_per_group(nalp_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, ?Node2Address, ?Payload, Config);

%--------------------------
init_per_group(broadcast_tx_rx, Config) ->
    init_per_group_setup(?Node1Address, <<16#FF02:16, 0:64, 1:16, 16#FF00:16, 16#1234:16>>, ?Payload, Config);

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
        {node4_mac_address, ?Node4MacAddress}, 
        {broadcast_mac_address, <<16#9234:16>>}, 
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

defaut_receiver4_init_per_testcase(Config, RoutingTable)->
    Network = ?config(network, Config),
    Node4MacAddress = ?config(node4_mac_address, Config),
    Callback = fun lowpan_layer:input_callback/4,
    Node = lowpan_node:boot_lowpan_node(node4, Network, Node4MacAddress, Callback, RoutingTable),
    [{node4, Node} | Config].


broadcast_receiver_init_per_testcase(Config, RoutingTable)->
    Network = ?config(network, Config),
    MacAddress = ?config(broadcast_mac_address, Config),
    Callback = fun lowpan_layer:input_callback/4,
    Node = lowpan_node:boot_lowpan_node(broadcast_node, Network, MacAddress, Callback, RoutingTable),
    [{broadcast_node, Node} | Config].

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
    Config1 = defaut_sender_init_per_testcase(Config, ?Default_routing_table),
    defaut_receiver2_init_per_testcase(Config1, ?Default_routing_table); 

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
init_per_testcase(no_hoplft_dst_reached_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Node1_routing_table); 

init_per_testcase(no_hoplft_dst_reached_receiver, Config)->
    defaut_receiver2_init_per_testcase(Config, ?Node2_routing_table); 
    
%--------------------------
init_per_testcase(unexpected_dtg_size_sender, Config)->
    defaut_sender_init_per_testcase(Config, ?Node1_routing_table); 

%--------------------------
init_per_testcase(same_tag_different_senders_sender, Config) ->
    Config1 = defaut_sender_init_per_testcase(Config, ?Default_routing_table),
    defaut_receiver2_init_per_testcase(Config1, ?Default_routing_table);

init_per_testcase(same_tag_different_senders_receiver, Config) ->
    defaut_receiver3_init_per_testcase(Config, ?Default_routing_table);

%--------------------------
init_per_testcase(timeout_sender, Config) ->
    defaut_sender_init_per_testcase(Config, ?Default_routing_table);
init_per_testcase(timeout_receiver, Config) ->
    defaut_receiver2_init_per_testcase(Config, ?Default_routing_table);

%--------------------------
init_per_testcase(tag_verification_sender, Config) ->
    defaut_sender_init_per_testcase(Config, ?Default_routing_table); 

init_per_testcase(tag_verification_receiver, Config) ->
    defaut_receiver2_init_per_testcase(Config, ?Default_routing_table);

%--------------------------
init_per_testcase(duplicate_sender, Config) ->
    defaut_sender_init_per_testcase(Config, ?Default_routing_table); 

init_per_testcase(duplicate_receiver, Config) ->
    defaut_receiver2_init_per_testcase(Config, ?Default_routing_table);

%--------------------------
init_per_testcase(multiple_hop_sender, Config) ->
    defaut_sender_init_per_testcase(Config, ?Node1_multiple_hop_routing_table);

init_per_testcase(multiple_hop_receiver2, Config)->
    defaut_receiver2_init_per_testcase(Config, ?Node2_multiple_hop_routing_table); 

init_per_testcase(multiple_hop_receiver3, Config)->
    defaut_receiver3_init_per_testcase(Config, ?Node3_multiple_hop_routing_table); 

init_per_testcase(multiple_hop_receiver4, Config) ->
    defaut_receiver4_init_per_testcase(Config, ?Node4_multiple_hop_routing_table);

%--------------------------
init_per_testcase(nalp_sender, Config) ->
    defaut_sender_init_per_testcase(Config, ?Default_routing_table); 

%--------------------------
init_per_testcase(broadcast_sender, Config) ->
    defaut_sender_init_per_testcase(Config, ?Default_routing_table); 

init_per_testcase(broadcast_receiver, Config) ->
    broadcast_receiver_init_per_testcase(Config, ?Default_routing_table);

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
    io:format("CompressedHeader ~p~n",[CompressedHeader]),
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
    {Pid2, Node2} = ?config(node2, Config),

    IPv6Pckt3 = ?config(ipv6_packet, Config),
    {error_multicast_src} = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt3]),
    ct:pal("Multicast Source address done"),
    lowpan_node:stop_lowpan_node(Node1, Pid1),
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
    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 1,
            originator_address =?node1_addr,
            final_destination_address = ?node3_addr
        },

    BinMeshHeader = lowpan:build_mesh_header(MeshHeader),

    Datagram = <<BinMeshHeader/binary, ?Payload/bitstring>>, % meshHeader + Data

    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    MacHdr = #mac_header{src_addr =?node1_addr, 
                            dest_addr = ?node2_addr},

    ok = erpc:call(Node1, lowpan_layer, tx, [Datagram, FC, MacHdr]),
    ct:pal("Packet with 1 hop left sent successfully from node1 to node3"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Discard datagram received from node 1
%-------------------------------------------------------------------------------
discarded_receiver(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    dtg_discarded = erpc:call(Node2, lowpan_layer, frame_reception, []),
    lowpan_node:stop_lowpan_node(Node2, Pid2).


%-------------------------------------------------------------------------------
% Send a datagram with 0 as value for hop left to node 2
%-------------------------------------------------------------------------------
no_hoplft_dst_reached_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 0,
            originator_address =?node1_addr,
            final_destination_address = ?node2_addr
        },

    BinMeshHeader = lowpan:build_mesh_header(MeshHeader),

    Datagram = <<BinMeshHeader/binary, ?IPV6_DHTYPE:8, ?Payload/bitstring>>, % meshHeader + Data

    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    MacHdr = #mac_header{src_addr =?node1_addr, 
                            dest_addr = ?node2_addr},

    ok = erpc:call(Node1, lowpan_layer, tx, [Datagram, FC, MacHdr]),
    ct:pal("Packet with 0 hop left sent successfully from node1 to node2"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of datagram with 0 as value for hop left 
%-------------------------------------------------------------------------------
no_hoplft_dst_reached_receiver(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    Response = erpc:call(Node2, lowpan_layer, frame_reception, []),
    Response = ?Payload,
    lowpan_node:stop_lowpan_node(Node2, Pid2).

%-------------------------------------------------------------------------------
% Check if error is return when datagram size is unexpected 
%-------------------------------------------------------------------------------
unexpected_dtg_size_sender(Config) ->
    {Pid1, Node1}  = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),
    error_frag_size = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Send payloads from node 1 and node 2 to node 3 with the same tag
%-------------------------------------------------------------------------------
same_tag_different_senders_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    {Pid2, Node2} = ?config(node2, Config),

    Data1 = <<"Hello ">>,
    Data2 = <<"World!">>,
    PayloadLen = byte_size(Data1) + byte_size(Data2),

    FragHeader1 = #frag_header{
        frag_type = ?FRAG1_DHTYPE,
        datagram_size = PayloadLen,
        datagram_tag = 25,
        datagram_offset = 0
    },
    FragHeader2 = #frag_header{
        frag_type = ?FRAGN_DHTYPE,
        datagram_size = PayloadLen,
        datagram_tag = 25,
        datagram_offset = 1
    },

    Frag1 = lowpan:build_datagram_pckt(FragHeader1, Data1),
    Frag2 = lowpan:build_datagram_pckt(FragHeader2, Data2),

    MeshHeader1 =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?node1_addr,
            final_destination_address = ?node3_addr
        },

    BinMeshHeader1 = lowpan:build_mesh_header(MeshHeader1),

    FC1 = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    MH1 = #mac_header{src_addr = ?node1_addr, 
                        dest_addr = ?node3_addr},

    MeshHeader2 =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?node2_addr,
            final_destination_address = ?node3_addr
        },

    BinMeshHeader2 = lowpan:build_mesh_header(MeshHeader2),
    FC2 = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    MH2 = #mac_header{src_addr = ?node2_addr, 
                        dest_addr = ?node3_addr},

    ok = erpc:call(Node1, lowpan_layer, tx, [<<BinMeshHeader1/binary, Frag1/bitstring>>, FC1, MH1]),
    ok = erpc:call(Node2, lowpan_layer, tx, [<<BinMeshHeader2/binary, Frag1/bitstring>>, FC2, MH2]),

    ok = erpc:call(Node1, lowpan_layer, tx, [<<BinMeshHeader1/binary, Frag2/bitstring>>, FC1, MH1]),
    ok = erpc:call(Node2, lowpan_layer, tx, [<<BinMeshHeader2/binary, Frag2/bitstring>>, FC2, MH2]),

    ct:pal("Fragments sent from node1 and node2 to node3 with the same tag"),
    lowpan_node:stop_lowpan_node(Node1, Pid1),
    lowpan_node:stop_lowpan_node(Node2, Pid2).

%-------------------------------------------------------------------------------
% Reception of payloads from node 1 and node 2 by node 3 with the same tag
%-------------------------------------------------------------------------------
same_tag_different_senders_receiver(Config) ->
    {Pid3, Node3} = ?config(node3, Config),

    % Receive and reassemble the fragments
    ReceivedData1 = erpc:call(Node3, lowpan_layer, frame_reception, []),
    ReceivedData2 = erpc:call(Node3, lowpan_layer, frame_reception, []),

    ExpectedData = <<"Hello World!">>,
    io:format("Expected: ~p~n~nReceived 1: ~p~n~nReceived 2: ~p~n", [ExpectedData, ReceivedData1, ReceivedData2]),
    
    case (ReceivedData1 == ExpectedData) andalso (ReceivedData2 == ExpectedData) of
        true ->
            ct:pal("Payloads received successfully at node3 with the same tag from different senders"),
            lowpan_node:stop_lowpan_node(Node3, Pid3);
        false ->
            ct:fail("Payloads did not match expected data"),
            lowpan_node:stop_lowpan_node(Node3, Pid3)
    end.


%-------------------------------------------------------------------------------
% Send incomplete payload from node 1 to node 2 to trigger a timeout
%-------------------------------------------------------------------------------
timeout_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),

    Data = <<"Hello World!">>,
    PayloadLen = byte_size(Data),

    FragHeader1 = #frag_header{
        frag_type = ?FRAG1_DHTYPE,
        datagram_size = PayloadLen,
        datagram_tag = 25,
        datagram_offset = 0
    },

    Frag1 = lowpan:build_datagram_pckt(FragHeader1, <<"Hello ">>),
     MeshHeader1 =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?node1_addr,
            final_destination_address = ?node2_addr
        },

    BinMeshHeader1 = lowpan:build_mesh_header(MeshHeader1),

    FC1 = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    MH1 = #mac_header{src_addr = ?node1_addr, 
                        dest_addr = ?node2_addr},
    


    ok = erpc:call(Node1, lowpan_layer, tx, [<<BinMeshHeader1/binary, Frag1/bitstring>>, FC1, MH1]),
    
    ct:pal("Incomplete payload sent from node1 to node2 to trigger a timeout"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Receiver node 2 should experience a timeout
%-------------------------------------------------------------------------------
timeout_receiver(Config) ->
    {Pid2, Node2} = ?config(node2, Config),
    reassembly_timeout = erpc:call(Node2, lowpan_layer, frame_reception, []),
    ct:pal("Timeout occurred~n"),
    lowpan_node:stop_lowpan_node(Node2, Pid2).


%-------------------------------------------------------------------------------
% Send multiple large payload from node 1 to node 2
%-------------------------------------------------------------------------------
tag_verification_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    % send 5 consecutive packet
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),

    ct:pal("Big payload sent successfully from node1 to node3"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of multiple big payload from node 1 by node 2
%-------------------------------------------------------------------------------
tag_verification_receiver(Config) ->
    {Pid2, Node2}  = ?config(node2, Config),
    ExpectedTag0 = 0, ExpectedTag1 = 1, ExpectedTag2 = 2, ExpectedTag3 = 3, ExpectedTag4 = 4,

    ExpectedTag0 = erpc:call(Node2, lowpan_layer, frame_info_rx, []),
    ExpectedTag1 = erpc:call(Node2, lowpan_layer, frame_info_rx, []),
    ExpectedTag2 = erpc:call(Node2, lowpan_layer, frame_info_rx, []),
    ExpectedTag3 = erpc:call(Node2, lowpan_layer, frame_info_rx, []),
    ExpectedTag4 = erpc:call(Node2, lowpan_layer, frame_info_rx, []),

    ct:pal("Big payload received successfully at node2"),
    lowpan_node:stop_lowpan_node(Node2, Pid2).


%-------------------------------------------------------------------------------
% Send duplicate fragment to node 2
%-------------------------------------------------------------------------------
duplicate_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),

    Data1 = <<"Hello ">>,
    Data2 = <<"World!">>,
    PayloadLen = byte_size(Data1) + byte_size(Data2),

    FragHeader1 = #frag_header{
        frag_type = ?FRAG1_DHTYPE,
        datagram_size = PayloadLen,
        datagram_tag = 25,
        datagram_offset = 0
    },
    FragHeader2 = #frag_header{
        frag_type = ?FRAGN_DHTYPE,
        datagram_size = PayloadLen,
        datagram_tag = 25,
        datagram_offset = 1
    },

    Frag1 = lowpan:build_datagram_pckt(FragHeader1, Data1),
    Frag2 = lowpan:build_datagram_pckt(FragHeader2, Data2),

    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?node1_addr,
            final_destination_address = ?node2_addr
        },

    BinMeshHeader = lowpan:build_mesh_header(MeshHeader),

    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},
    MH = #mac_header{src_addr = ?node1_addr, 
                        dest_addr = ?node2_addr},

    ok = erpc:call(Node1, lowpan_layer, tx, [<<BinMeshHeader/binary, Frag1/bitstring>>, FC, MH]),
    ok = erpc:call(Node1, lowpan_layer, tx, [<<BinMeshHeader/binary, Frag1/bitstring>>, FC, MH]), % duplicated fragment
    ok = erpc:call(Node1, lowpan_layer, tx, [<<BinMeshHeader/binary, Frag2/bitstring>>, FC, MH]),

    ct:pal("Fragments sent from node1 and node2 to node3 with the same tag"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of payloads from node 1 and node 2 by node 3 with the same tag
%-------------------------------------------------------------------------------
duplicate_receiver(Config) ->
    {Pid2, Node2} = ?config(node2, Config),

    ReceivedData1 = erpc:call(Node2, lowpan_layer, frame_reception, []),

    ExpectedData = <<"Hello World!">>,
    io:format("Expected: ~p~n~nReceived: ~p~n", [ExpectedData, ReceivedData1]),
    ReceivedData1 = ExpectedData,
    lowpan_node:stop_lowpan_node(Node2, Pid2).
 

%-------------------------------------------------------------------------------
% Send a packet that needs routing from node 1 to node 4
%-------------------------------------------------------------------------------
multiple_hop_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ct:pal("multi hop packet sent successfully from node1 to node4"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of a routed packet
%-------------------------------------------------------------------------------
multiple_hop_receiver2(Config) ->
    {Pid2, Node2} = ?config(node2, Config),
    erpc:call(Node2, lowpan_layer, frame_reception, []),
    lowpan_node:stop_lowpan_node(Node2, Pid2).


multiple_hop_receiver3(Config) ->
    {Pid3, Node3} = ?config(node3, Config),
    erpc:call(Node3, lowpan_layer, frame_reception, []),
    lowpan_node:stop_lowpan_node(Node3, Pid3).

multiple_hop_receiver4(Config) ->
    {Pid4, Node4}  = ?config(node4, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    {CompressedHeader, _} = lowpan:compress_ipv6_header(IPv6Pckt),
    PcktInfo = lowpan:get_ipv6_pckt_info(IPv6Pckt),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node4, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Routed packet received successfully at node4"),
    lowpan_node:stop_lowpan_node(Node4, Pid4).


%-------------------------------------------------------------------------------
% Send a none lowpan frame to node 2
%-------------------------------------------------------------------------------
nalp_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    Frame = <<?NALP_DHTYPE, IPv6Pckt/bitstring>>,

    FC = #frame_control{ack_req = ?ENABLED, 
                        frame_type = ?FTYPE_DATA,
                        src_addr_mode = ?EXTENDED,
                        dest_addr_mode = ?EXTENDED},

    MH = #mac_header{src_addr = ?node1_addr, 
        dest_addr = ?node2_addr},
        
    error_nalp = erpc:call(Node1, lowpan_layer, tx, [Frame, FC, MH]),
    ct:pal("NALP error correctly received"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).


%-------------------------------------------------------------------------------
% Send a broadcast packet 
%-------------------------------------------------------------------------------
broadcast_sender(Config) ->
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),
    ok = erpc:call(Node1, lowpan_layer, send_packet, [IPv6Pckt]),
    ct:pal("Broadcast packet sent successfully"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).

%-------------------------------------------------------------------------------
% Reception of a broadcasted packet
%-------------------------------------------------------------------------------
broadcast_receiver(Config) ->
    {Pid2, Node2} = ?config(broadcast_node, Config),
    IPv6Pckt = ?config(ipv6_packet, Config),

    {CompressedHeader, _} = lowpan:compress_ipv6_header(IPv6Pckt),
    PcktInfo = lowpan:get_ipv6_pckt_info(IPv6Pckt),
    Payload = PcktInfo#ipv6PckInfo.payload,
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/bitstring>>,

    ReceivedData = erpc:call(Node2, lowpan_layer, frame_reception, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet, ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Routed packet received successfully at node4"),

    lowpan_node:stop_lowpan_node(Node2, Pid2).
