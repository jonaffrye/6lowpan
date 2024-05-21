%io:format("\ect").

-module(lowpan_layer_tests). 
-include_lib("eunit/include/eunit.hrl").

-include("../src/lowpan.hrl").
-include("../src/mac_frame.hrl").
-include("../src/ieee802154.hrl").


pkt_encapsulation_test()->
    Payload = <<"This is an Ipv6 pckt">>, 
    IPv6Header = #ipv6_header{version =  6, traffic_class = 0, flow_label = 0, payload_length = byte_size(Payload) div 2,
        next_header = 17, hop_limit = 64, source_address = 1,destination_address = 2},
    IPv6Packet = ipv6:build_ipv6_packet(IPv6Header, Payload),
    DhTypeBinary = <<?IPV6_DHTYPE:8, 0:16>>,
    ToCheck = <<DhTypeBinary/binary, IPv6Packet/binary>>,
    ?assertEqual(ToCheck,lowpan:pkt_encapsulation(IPv6Header, Payload)).

fragmentation_test()->
    % fragmentation test based on the computation of the size of all fragment payloads
    Payload = <<"This is an Ipv6 pckt">>, 
    IPv6Header = #ipv6_header{
        version =  6,
        traffic_class = 0, 
        flow_label = 0, 
        payload_length = byte_size(Payload) div 2,
        next_header = 17, 
        hop_limit = 64, 
        source_address = 1,
        destination_address = 2
    },
    IPv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),
    Fragments = lowpan:fragment_ipv6_packet(IPv6Pckt),

    % 
    ReassembledSize = lists:foldl(
        fun({_, Fragment}, Acc)-> byte_size(Fragment) + Acc end,
        0,Fragments),

    % reassembled size matches the original packet size
    ?assertEqual(byte_size(IPv6Pckt), ReassembledSize).

datagram_info_test()->
    Fragment = <<0:5, 1000:11, 12345:16, 5:8, "payload">>,

    DtgInfo = lowpan:datagram_info(Fragment),
    FragType = DtgInfo#datagramInfo.fragtype, 
    DatagramSize = DtgInfo#datagramInfo.datagramSize, 
    DatagramTag = DtgInfo#datagramInfo.datagramTag, 
    DatagramOffset = DtgInfo#datagramInfo.datagramOffset, 
    Payload = DtgInfo#datagramInfo.payload, 
    
    ?assertEqual(0, FragType),
    ?assertEqual(1000, DatagramSize),
    ?assertEqual(12345, DatagramTag),
    ?assertEqual(5, DatagramOffset),
    ?assertEqual(<<"payload">>, Payload).

reassemble_fragments_list_test()->
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
    ?assertEqual(<<"Hello World!">>, Reassembled).

reassemble_single_fragments_test()->
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

    ?assertEqual(<<"Hello World!">>, Reassembled).

reassemble_full_ipv6_pckt_test()->
    Payload = <<"Hello World! This is a basic Ipv6 packet">>, 

    IPv6Header = #ipv6_header{
        version =  6,
        traffic_class = 224, 
        flow_label = 0, 
        payload_length = byte_size(Payload),
        next_header = 17, 
        hop_limit = 64, 
        source_address = 2,
        destination_address = 4
    },
    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header,Payload), 
    
    FragmentList = lowpan:fragment_ipv6_packet(Ipv6Pckt),
    Fragments = lists:map(fun({FragHeader, FragPayload})->
                                <<FragHeader/binary,FragPayload/binary>> 
                          end, FragmentList),
    Reassembled = lowpan:reassemble_datagrams(Fragments),
    ?assertEqual(Ipv6Pckt, Reassembled).

compress_header_ex1_test()->
    Payload = <<"Hello world this is an ipv6 packet">>,
    PayloadLength = byte_size(Payload),
        
    Tf = 2#10,
    Nh = 0,
    Hlim = 2#11,
    Cid = 0,
    Sac = 0,
    Sam = 2#11,
    M = 1,
    Dac = 0,
    Dam = 2#11,
    Expected = {Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam},
    ExpectedCarriedInline = {224,58,1},
    io:format("Expected ~p~n", [Expected]),   
    SrcAddress = <<16#FE80:16, 0:48,16#020164FFFE2FFC0A:64>>,
    DstAddress = <<16#FF02:16,16#00000000000:48, 16#0000000000000001:64>>, 
    Ipv6Pckt = <<6:4, 224:8, 0:20, PayloadLength:16, 58:8, 255:8, SrcAddress/binary, DstAddress/binary, Payload/binary>>,
    
    {CompressedHeader,_,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt), 
    io:format("Expected ~p~nReceived ~p~n", [Expected, CompressedHeader]),
    ?assertEqual(Expected, CompressedHeader), 
            
    CarriedInlineDataOut = {maps:get("TrafficClass",CarriedInlineData),
                            maps:get("NextHeader",CarriedInlineData),
                            maps:get("DAM",CarriedInlineData) },
    
    ?assertEqual(ExpectedCarriedInline, CarriedInlineDataOut). 


compress_header_ex2_test()->
    Payload = <<"Hello world this is an ipv6 packet">>,
    PayloadLength = byte_size(Payload),
        
    Tf = 2#11,
    Nh = 0,
    Hlim = 2#10,
    Cid = 0,
    Sac = 1,
    Sam = 2#00,
    M = 0,
    Dac = 1,
    Dam = 2#00,
    Expected = {Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam},
    ExpectedCarriedInline = {6},
    
    SrcAddress = <<16#2001066073013728:64, 16#0223DFFFFEA9F7AC:64>>,
    DstAddress = <<16#2A00145040070803:64, 16#0000000000001004:64>>, 
    Ipv6Pckt = <<6:4, 0:8, 0:20, PayloadLength:16, 6:8, 64:8, SrcAddress/binary, DstAddress/binary, Payload/binary>>,
    
    {CompressedHeader,_,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt), 
    ?assertEqual(Expected, CompressedHeader), 
            
    CarriedInlineDataOut = {maps:get("NextHeader",CarriedInlineData)},
    
    ?assertEqual(ExpectedCarriedInline, CarriedInlineDataOut). 
