-module(lowpan_test_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("../src/lowpan.hrl").


-export([all/0, init_per_testcase/1, end_per_testcase/1]).
-export([
    pkt_encapsulation_test/1, fragmentation_test/1, datagram_info_test/1,
    reassemble_fragments_list_test/1, reassemble_single_fragments_test/1,
    reassemble_full_ipv6_pckt_test/1, compress_header_example1_test/1,
    compress_header_example2_test/1, link_local_addr_pckt_comp/1, 
    multicast_addr_pckt_comp/1, global_context_pckt_comp1/1, 
    global_context_pckt_comp2/1, udp_nh_pckt_comp/1, tcp_nh_pckt_comp/1, 
    icmp_nh_pckt_comp/1

]).

all() -> 
    [
        pkt_encapsulation_test, fragmentation_test, datagram_info_test,
        reassemble_fragments_list_test, reassemble_single_fragments_test,
        reassemble_full_ipv6_pckt_test, compress_header_example2_test, 
        link_local_addr_pckt_comp, multicast_addr_pckt_comp, 
        global_context_pckt_comp1, global_context_pckt_comp2, 
        udp_nh_pckt_comp, tcp_nh_pckt_comp, icmp_nh_pckt_comp

    ].

init_per_testcase(Config) ->
    % Any setup required before suite runs
    Config.

end_per_testcase(_Config) ->
    % Cleanup after suite runs
    ok.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           6LoWPAN IPv6 Packet Encapsulation
%------------------------------------------------------------------------------------------------------------------------------------------------------

pkt_encapsulation_test(_Config) ->
    Payload = <<"This is an Ipv6 pckt">>, 
    IPv6Header = #ipv6_header{version =  6, traffic_class = 0, flow_label = 0, payload_length = byte_size(Payload),
        next_header = 17, hop_limit = 64, source_address = <<1>>, destination_address = <<2>>},
    IPv6Packet = ipv6:build_ipv6_packet(IPv6Header, Payload),
    DhTypeBinary = <<?IPV6_DHTYPE:8, 0:16>>,
    ToCheck = <<DhTypeBinary/binary, IPv6Packet/binary>>,
    ToCheck = lowpan:pkt_encapsulation(IPv6Header, Payload),
    ok.


% TODO 

% Comp pckt encap with correct dispatch
% Frag pckt encap with correct dispatch
% Mesh pckt encap with correct dispatch


%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Ipv6 Packet Compression
%------------------------------------------------------------------------------------------------------------------------------------------------------

%--- Basic IPHC test case 

% Link-local address 
link_local_addr_pckt_comp(_Config)->
    Payload = <<"Testing basic IPHC compression with link-local address">>,
    IPv6Header = #ipv6_header{
        version = 6, 
        traffic_class = 0,
        flow_label = 0,
        payload_length = byte_size(Payload), 
        next_header = 0, %UDP
        hop_limit =  64, 
        source_address = <<16#FE80:16, 0:48,16#CAFEDECA00000001:64>>,
        destination_address = <<16#FE80:16, 0:48,16#CAFEDECA00000002:64>>
    },
    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload), 

    Tf = 2#11, Nh = 0, Hlim = 2#10, Cid = 0, Sac = 0, Sam = 2#01, M = 0, Dac = 0, Dam = 2#01,
    ExpectedCarriedInline = #{"SAM"=>14627373598910709761, "DAM" => 14627373598910709762,
        "NextHeader" => 0},

    ExpectedCarriedInlineList = [{"NextHeader", 0}, {"SAM", 14627373598910709761}, {"DAM", 14627373598910709762}],
    
    InlineData = lowpan:tuple_list_to_binary(ExpectedCarriedInlineList),
    ExpectedHeader = <<?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader, 
            
    ExpectedCarriedInline = CarriedInlineData,
    ok.

% Multicast address
multicast_addr_pckt_comp(_Config)->
    Payload = <<"Testing basic IPHC compression with multicast address">>,
    IPv6Header = #ipv6_header{
        version = 6, 
        traffic_class = 0,
        flow_label = 2,
        payload_length = byte_size(Payload), 
        next_header = 0, %UDP
        hop_limit =  1, 
        source_address = <<16#FE80:16, 0:48,16#CAFEDECA00000001:64>>,
        destination_address = <<16#FF02:16, 0:48,16#CAFEDECA00000002:64>>
    },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload), 

    Tf = 2#01, Nh = 0, Hlim = 2#01, Cid = 0, Sac = 0, Sam = 2#01, M = 1, Dac = 0, Dam = 2#00,
    ExpectedCarriedInline = #{"SAM"=>14627373598910709761,"DAM" => 338963523518870617260355234963057016834,
        "NextHeader" => 0,"ECN" => 0, "FlowLabel"=>2},
    %io:format("ExpectedCarriedInline: ~p~n", [ExpectedCarriedInline]),

    ExpectedCarriedInlineList = [<<0:8>>, <<2:24>>,0,<<16#CAFEDECA00000001:64>>, IPv6Header#ipv6_header.destination_address],
    InlineData = list_to_binary(ExpectedCarriedInlineList),
    io:format("ExpectedCarriedInlineList: ~p~n", [ExpectedCarriedInlineList]),
    ExpectedHeader = <<?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    CH = {?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData},
    io:format("Expected CompressedHeader ~p~n", [CH]),
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader, 
            
    ExpectedCarriedInline = CarriedInlineData,
    ok.



%---Global contexts test case, affected fields are cid, sac and dac
global_context_pckt_comp1(_Config)->
    Payload = <<"Testing basic IPHC compression with multicast address">>,
    IPv6Header = #ipv6_header{
        version = 6, 
        traffic_class = 0,
        flow_label = 3,
        payload_length = byte_size(Payload), 
        next_header = 0, %UDP
        hop_limit =  255, 
        source_address = <<16#2001:16, 0:48,16#CAFEDECA00000001:64>>,
        destination_address = <<16#2001:16, 0:48,16#CAFEDECA00000002:64>>
    },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload), 

    Tf = 2#01, Nh = 0, Hlim = 2#11, Cid = 1, Sac = 1, Sam = 2#01, M = 0, Dac = 1, Dam = 2#01,
    ExpectedCarriedInline = #{"SAM"=>14627373598910709761,
        "NextHeader" => 0, "ECN" => 0, "FlowLabel"=>3, "DAM"=>14627373598910709762, "CID"=>1},
    io:format("ExpectedCarriedInline: ~p~n", [ExpectedCarriedInline]),

    ExpectedCarriedInlineList = [1,1,<<0:8>>,<<3:24>>,0, <<14627373598910709761:64>>, <<14627373598910709762:64>>],
    io:format("ExpectedCarriedInlineList: ~p~n", [ExpectedCarriedInlineList]),
    InlineData = list_to_binary(ExpectedCarriedInlineList),
    ExpectedHeader = <<?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    CH = {?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData},
    io:format("Expected CompressedHeader ~p~n", [CH]),
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader, 
            
    ExpectedCarriedInline = CarriedInlineData,
    ok.


global_context_pckt_comp2(_Config)->
    Payload = <<"Testing basic IPHC compression with multicast address">>,
    IPv6Header = #ipv6_header{
        version = 6, 
        traffic_class = 0,
        flow_label = 3,
        payload_length = byte_size(Payload), 
        next_header = 0, %UDP
        hop_limit =  28, 
        source_address = <<16#2002:16, 0:48,16#CAFEDECA00000001:64>>,
        destination_address = <<16#2002:16, 0:48,16#CAFEDECA00000002:64>>
    },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload), 
    
    Tf = 2#01, Nh = 0, Hlim = 2#00, Cid = 1, Sac = 1, Sam = 2#00, M = 0, Dac = 1, Dam = 2#00,
    ExpectedCarriedInline = #{"SAM"=>42545680458834377602806260520540176385,
        "NextHeader" => 0, "HopLimit"=>28,"ECN" => 0, "FlowLabel"=>3, "CID"=>3},
    io:format("ExpectedCarriedInline: ~p~n", [ExpectedCarriedInline]),

    ExpectedCarriedInlineList = [3,3,<<0:8,3:24>>,17, 28, IPv6Header#ipv6_header.source_address],
    io:format("ExpectedCarriedInlineList: ~p~n", [ExpectedCarriedInlineList]),
    InlineData = list_to_binary(ExpectedCarriedInlineList),
    ExpectedHeader = <<?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    CH = {?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData},
    io:format("Expected CompressedHeader ~p~n", [CH]),
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader, 
            
    ExpectedCarriedInline = CarriedInlineData,
    ok.


%---Different types of Next Headers test case 
udp_nh_pckt_comp(_Config)->
    Payload = <<"Testing basic IPHC compression with link-local address">>,

    PayloadLength = byte_size(Payload),
    Source_address = <<16#FE80:16, 0:48,16#CAFEDECA00000001:64>>,
    Destination_address = <<16#FE80:16, 0:48,16#CAFEDECA00000002:64>>, 

    Ipv6Pckt = <<6:4, 0:8, 0:20, PayloadLength:16, 17:8, 64:8, Source_address/binary, 
                Destination_address/binary, 1:16, 1:16, 12:16, 1551:16, Payload/binary>>,

    Tf = 2#11, Nh = 0, Hlim = 2#10, Cid = 0, Sac = 0, Sam = 2#01, M = 0, Dac = 0, Dam = 2#01,
    ExpectedCarriedInline = #{"SAM"=>14627373598910709761,"DAM" => 14627373598910709762,
        "NextHeader" => 17},
    io:format("ExpectedCarriedInline: ~p~n", [ExpectedCarriedInline]),
    ExpectedCarriedInlineList = [17, <<14627373598910709761:64>>, <<14627373598910709762:64>>],
    io:format("ExpectedCarriedInlineList: ~p~n", [ExpectedCarriedInlineList]),
    InlineData = list_to_binary(ExpectedCarriedInlineList),
    ExpectedHeader = <<?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    
    CH = {?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData},
    io:format("Expected CompressedHeader ~p~n", [CH]),

    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader, 
            
    ExpectedCarriedInline = CarriedInlineData,
    ok.


tcp_nh_pckt_comp(_Config)->
    Payload = <<"Testing basic IPHC compression with link-local address">>,
    IPv6Header = #ipv6_header{
        version = 6, 
        traffic_class = 0,
        flow_label = 0,
        payload_length = byte_size(Payload), 
        next_header = 6, % TCP
        hop_limit =  64, 
        source_address = <<16#FE80:16, 0:48,16#CAFEDECA00000001:64>>,
        destination_address = <<16#FE80:16, 0:48,16#CAFEDECA00000002:64>>
    },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload), 

    Tf = 2#11, Nh = 0, Hlim = 2#10, Cid = 0, Sac = 0, Sam = 2#01, M = 0, Dac = 0, Dam = 2#01,
    ExpectedCarriedInline = #{"SAM"=>14627373598910709761,"DAM" => 14627373598910709762,
        "NextHeader" => 6},
    io:format("ExpectedCarriedInline: ~p~n", [ExpectedCarriedInline]),
    ExpectedCarriedInlineList = [6, <<14627373598910709761:64>>, <<14627373598910709762:64>>],
    io:format("ExpectedCarriedInlineList: ~p~n", [ExpectedCarriedInlineList]),
    InlineData = list_to_binary(ExpectedCarriedInlineList),
    ExpectedHeader = <<?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    CH = {?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData},
    io:format("Expected CompressedHeader ~p~n", [CH]),
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader, 
            
    ExpectedCarriedInline = CarriedInlineData,
    ok.


icmp_nh_pckt_comp(_Config)->
    Payload = <<"Testing basic IPHC compression with link-local address">>,
    IPv6Header = #ipv6_header{
        version = 6, 
        traffic_class = 0,
        flow_label = 0,
        payload_length = byte_size(Payload), 
        next_header = 58, %ICMPv6
        hop_limit =  255, 
        source_address = <<16#FE80:16, 0:48,16#CAFEDECA00000001:64>>,
        destination_address = <<16#FE80:16, 0:48,16#CAFEDECA00000002:64>>
    },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload), 

    Tf = 2#11, Nh = 0, Hlim = 2#11, Cid = 0, Sac = 0, Sam = 2#01, M = 0, Dac = 0, Dam = 2#01,
    ExpectedCarriedInline = #{"SAM"=>14627373598910709761,"DAM" => 14627373598910709762,
        "NextHeader" => 58},
    io:format("ExpectedCarriedInline: ~p~n", [ExpectedCarriedInline]),
    ExpectedCarriedInlineList = [58, <<14627373598910709761:64>>, <<14627373598910709762:64>>],
    io:format("ExpectedCarriedInlineList: ~p~n", [ExpectedCarriedInlineList]),
    InlineData = list_to_binary(ExpectedCarriedInlineList),
    ExpectedHeader = <<?IPHC_DHTYPE,Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    CH = {?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData},
    io:format("CompressedHeader ~p~n", [CH]),
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader, 
            
    ExpectedCarriedInline = CarriedInlineData,
    ok.


%---Online resource (https://www.youtube.com/watch?v=0JMVO3HN0xo&t=778s)
compress_header_example1_test(_Config)->
    Payload = <<"Hello world this is an ipv6 packet">>,
    PayloadLength = byte_size(Payload),
    Tf = 2#10, Nh = 0, Hlim = 2#11, Cid = 0, Sac = 0, Sam = 2#11, M = 1, Dac = 0, Dam = 2#11,
    ExpectedCarriedInline = #{"DAM" => 1,"NextHeader" => 58,"TrafficClass" => 224},
    InlineData = lowpan:map_to_binary(ExpectedCarriedInline),
    ExpectedHeader = <<Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    
    SrcAddress = <<16#FE80:16, 0:48,16#020164FFFE2FFC0A:64>>,
    DstAddress = <<16#FF02:16,16#00000000000:48, 16#0000000000000001:64>>, 
    Ipv6Pckt = <<6:4, 224:8, 0:20, PayloadLength:16, 58:8, 255:8, SrcAddress/binary, DstAddress/binary, Payload/binary>>,
    
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader, 
            
    ExpectedCarriedInline = CarriedInlineData,
    ok.

compress_header_example2_test(_Config)->
    Payload = <<"Hello world this is an ipv6 packet">>,
    PayloadLength = byte_size(Payload), 
    Tf = 2#11, Nh = 0, Hlim = 2#10, Cid = 1, Sac = 1, Sam = 2#01, M = 0, Dac = 1, Dam = 2#00,
    ExpectedCarriedInline = #{"CID"=>1,"SAM"=>16#0223DFFFFEA9F7AC,"NextHeader" => 6},
    ExpectedCarriedInlineList = [<<16#2001066073013728:64>>, <<16#2001A45040070803:64>>],
    io:format("ExpectedCarriedInlineList: ~p~n", [ExpectedCarriedInlineList]),
    InlineData = list_to_binary(ExpectedCarriedInlineList),
    ExpectedHeader = <<?IPHC_DHTYPE,Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    CH = {?IPHC_DHTYPE, Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData},
    io:format("Expected CompressedHeader ~p~n", [CH]),
    
    SrcAddress = <<16#2001066073013728:64, 16#0223DFFFFEA9F7AC:64>>,
    DstAddress = <<16#2001A45040070803:64, 16#0000000000001004:64>>, 
    Ipv6Pckt = <<6:4, 0:8, 0:20, PayloadLength:16, 6:8, 64:8, SrcAddress/binary, DstAddress/binary, Payload/binary>>,
    
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt), 
    io:format("Expected ~p~nActual ~p~n",[ExpectedHeader,CompressedHeader]),

    ExpectedCarriedInline = CarriedInlineData, 
    ok.



%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           6LoWPAN IPv6 Packet Fragmentation
%------------------------------------------------------------------------------------------------------------------------------------------------------

fragmentation_test(_Config) ->
    % fragmentation test based on the computation of the size of all fragment payloads
    Payload = <<"This is an Ipv6 pckt">>, 
    IPv6Header = #ipv6_header{version =  6, traffic_class = 0, flow_label = 0, payload_length = byte_size(Payload),
        next_header = 17, hop_limit = 64, source_address = <<1>>, destination_address = <<2>>},
    IPv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),
    Fragments = lowpan:fragment_ipv6_packet(IPv6Pckt),
    ReassembledSize = lists:foldl( fun({_, Fragment}, Acc)-> byte_size(Fragment) + Acc end,
                                    0,Fragments),
    Psize = byte_size(IPv6Pckt),
    Psize = ReassembledSize,
    ok.

datagram_info_test(_Config)->
    Fragment = <<0:5, 1000:11, 12345:16, 5:8, "payload">>,

    DtgInfo = lowpan:datagram_info(Fragment),
    FragType = DtgInfo#datagramInfo.fragtype, 
    DatagramSize = DtgInfo#datagramInfo.datagramSize, 
    DatagramTag = DtgInfo#datagramInfo.datagramTag, 
    DatagramOffset = DtgInfo#datagramInfo.datagramOffset, 
    Payload = DtgInfo#datagramInfo.payload,

    0 = FragType,
    1000 = DatagramSize,
    12345 = DatagramTag,
    5 = DatagramOffset,
    <<"payload">> = Payload, 
    ok.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Ipv6 Packet Reassembly
%------------------------------------------------------------------------------------------------------------------------------------------------------

reassemble_fragments_list_test(_Config)->
    Data = <<"Hello World!">>, 
    PayloadLen = byte_size(Data),
    FragHeader1 = #frag_header{
        frag_type = 24, datagram_size = PayloadLen, datagram_tag = 25, datagram_offset = 0
    },
    FragHeader2 = #frag_header{
        frag_type = 28, datagram_size = PayloadLen, datagram_tag = 25, datagram_offset = 1
    },
    Frag1 = lowpan:build_datagram_pckt(FragHeader1,<<"Hello ">>),
    Frag2 = lowpan:build_datagram_pckt(FragHeader2,<<"World!">>),
    Fragments = [Frag1, Frag2],
    Reassembled = lowpan:reassemble_datagrams(Fragments),
    <<"Hello World!">> =  Reassembled, 
    ok.

reassemble_single_fragments_test(_Config)->
    Data = <<"Hello World!">>, 
    PayloadLen = byte_size(Data),
    FragHeader1 = #frag_header{
        frag_type = 24, datagram_size = PayloadLen, datagram_tag = 25, datagram_offset = 0
    },
    FragHeader2 = #frag_header{
        frag_type = 28, datagram_size = PayloadLen, datagram_tag = 25, datagram_offset = 1
    },
    Frag1 = lowpan:build_datagram_pckt(FragHeader1, <<"Hello ">>),
    Frag2 = lowpan:build_datagram_pckt(FragHeader2, <<"World!">>),
    DatagramMap = maps:new(), 
    {notYetReassembled, IntermediateMap} = lowpan:reassemble_datagram(Frag1, DatagramMap),
    {Reassembled, _FinalMap} = lowpan:reassemble_datagram(Frag2, IntermediateMap),

    <<"Hello World!">> = Reassembled, 
    ok. 

reassemble_full_ipv6_pckt_test(_Config)->
    Payload = <<"Hello World! This is a basic Ipv6 packet">>, 
    IPv6Header = #ipv6_header{version =  6, traffic_class = 0, flow_label = 0, payload_length = byte_size(Payload),
        next_header = 17, hop_limit = 64, source_address = <<1>>, destination_address = <<2>>},
    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header,Payload), 
    io:format("Original pckt size ~p bytes~n",[byte_size(Ipv6Pckt)]),
    FragmentList = lowpan:fragment_ipv6_packet(Ipv6Pckt),
    Fragments = lists:map(fun({FragHeader, FragPayload})->
                                <<FragHeader/binary,FragPayload/binary>> 
                          end, FragmentList),
    Reassembled = lowpan:reassemble_datagrams(Fragments),
    Ipv6Pckt = Reassembled, 
    ok. 

