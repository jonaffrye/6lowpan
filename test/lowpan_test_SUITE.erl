-module(lowpan_test_SUITE).

-include("../src/utils.hrl").

-export([all/0, init_per_testcase/1, end_per_testcase/1]).
-export([
    pkt_encapsulation_test/1,
    fragmentation_test/1,
    datagram_info_test/1,
    reassemble_fragments_list_test/1,
    reassemble_single_fragments_test/1,
    reassemble_full_ipv6_pckt_test/1,
    compress_header_example1_test/1,
    compress_header_example2_test/1,
    link_local_addr_pckt_comp/1,
    multicast_addr_pckt_comp/1,
    global_context_pckt_comp1/1,
    udp_nh_pckt_comp/1,
    tcp_nh_pckt_comp/1,
    icmp_nh_pckt_comp/1,
    robot_tx/1,
    unc_ipv6/1,
    iphc_pckt/1,
    msh_pckt/1, extended_EUI64_from_64mac/1, extended_EUI64_from_48mac/1,
    extended_EUI64_from_16mac/1
]).

all() ->
    [
        pkt_encapsulation_test,
        fragmentation_test,
        datagram_info_test,
        reassemble_fragments_list_test,
        reassemble_single_fragments_test,
        reassemble_full_ipv6_pckt_test,
        compress_header_example1_test,
        compress_header_example2_test,
        link_local_addr_pckt_comp,
        multicast_addr_pckt_comp,
        global_context_pckt_comp1,
        robot_tx,
        udp_nh_pckt_comp,
        tcp_nh_pckt_comp,
        icmp_nh_pckt_comp,
        unc_ipv6,
        iphc_pckt,
        msh_pckt, extended_EUI64_from_64mac,extended_EUI64_from_48mac,
        extended_EUI64_from_16mac
    ].

init_per_testcase(Config) ->
    % Any setup required before suite runs
    Config.

end_per_testcase(_Config) ->
    % Cleanup after suite runs
    ok.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           6LoWPAN Packet Encapsulation
%------------------------------------------------------------------------------------------------------------------------------------------------------

pkt_encapsulation_test(_Config) ->
    Payload = <<"This is an Ipv6 pckt">>,
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = byte_size(Payload),
            next_header = 17,
            hop_limit = 64,
            source_address = <<1>>,
            destination_address = <<2>>
        },
    IPv6Packet = ipv6:build_ipv6_packet(IPv6Header, Payload),
    DhTypebinary = <<?IPV6_DHTYPE:8, 0:16>>,
    ToCheck = <<DhTypebinary/binary, IPv6Packet/binary>>,
    ToCheck = lowpan:pkt_encapsulation(IPv6Header, Payload),
    ok.

% TODO

% Comp pckt encap with correct dispatch

unc_ipv6(_Config) ->
    Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),

    Expected = <<?IPV6_DHTYPE:8, Ipv6Pckt/bitstring>>,
    Expected = lowpan:get_unc_ipv6(Ipv6Pckt).

iphc_pckt(_Config) ->
    InlineData = <<12:8, 14627373598910709761:64, 14627373598910709762:64>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, 3:2, 0:1, 2:2, 0:1, 0:1, 1:2, 0:1, 0:1, 1:2, InlineData/binary>>,

    % Create the IPHC packet
    {IPHC, _} = lowpan:compress_ipv6_header(?Ipv6Pckt),
    io:format("IPHC: ~p~n", [IPHC]),
    IPHC = ExpectedHeader.

msh_pckt(_Config) ->
    %Ipv6Pckt = ipv6:build_ipv6_packet(?IPv6Header, ?Payload),
    %{CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt),
    MeshHeader =
        #mesh_header{
            v_bit = 0,
            f_bit = 0,
            hops_left = 14,
            originator_address = ?Node1MacAddress,
            final_destination_address = ?Node2MacAddress
        },

    BinMeshHeader = lowpan:build_mesh_header(MeshHeader),
    ExpectedHeader =
        <<?MESH_DHTYPE:2, 0:1, 0:1, 14:4, ?Node1MacAddress/binary, ?Node2MacAddress/binary>>,

    ExpectedHeader = BinMeshHeader.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Ipv6 Packet Compression
%------------------------------------------------------------------------------------------------------------------------------------------------------

%--- Basic IPHC test case

% Link-local address
link_local_addr_pckt_comp(_Config) ->
    Payload = <<"Testing basic IPHC compression with link-local address">>,
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = byte_size(Payload),
            next_header = 0,
            hop_limit = 64,
            source_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000001:64>>,
            destination_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000002:64>>
        },
    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),

    Tf = 2#11,
    Nh = 0,
    Hlim = 2#10,
    Cid = 0,
    Sac = 0,
    Sam = 2#01,
    M = 0,
    Dac = 0,
    Dam = 2#01,
    ExpectedCarriedInline =
        #{
            "SAM" => 14627373598910709761,
            "DAM" => 14627373598910709762,
            "NextHeader" => 0
        },

    InlineData =
        <<0:8, 14627373598910709761:64,
            %lowpan:tuple_list_to_binary(ExpectedCarriedInlineList),
            14627373598910709762:64>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary>>,

    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader,

    ExpectedCarriedInline = CarriedInlineData,
    ok.

% Multicast address
multicast_addr_pckt_comp(_Config) ->
    Payload = <<"Testing basic IPHC compression with multicast address">>,
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 2,
            payload_length = byte_size(Payload),
            %UDP
            next_header = 0,
            hop_limit = 1,
            source_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000001:64>>,
            destination_address = <<16#FF02:16, 0:48, 16#CAFEDECA00000002:64>>
        },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),

    Tf = 2#01,
    Nh = 0,
    Hlim = 2#01,
    Cid = 0,
    Sac = 0,
    Sam = 2#01,
    M = 1,
    Dac = 0,
    Dam = 2#00,
    ExpectedCarriedInline =
        #{
            "SAM" => 14627373598910709761,
            "DAM" => 338963523518870617260355234963057016834,
            "NextHeader" => 0,
            "ECN" => 0,
            "FlowLabel" => 2
        },

    Dest = IPv6Header#ipv6_header.destination_address,
    InlineData =
        <<0:2, 0:2, 2:20, 0:8, 16#CAFEDECA00000001:64,
            %list_to_binary(ExpectedCarriedInlineList),
            Dest/binary>>,

    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary>>,

    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader,

    ExpectedCarriedInline = CarriedInlineData,
    ok.

%---Global contexts test case, affected fields are cid, sac and dac
global_context_pckt_comp1(_Config) ->
    Payload = <<"Testing basic IPHC compression with multicast address">>,
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 3,
            payload_length = byte_size(Payload),
            %UDP
            next_header = 0,
            hop_limit = 255,
            source_address = <<16#2001:16, 0:48, 16#CAFEDECA00000001:64>>,
            destination_address = <<16#2001:16, 0:48, 16#CAFEDECA00000002:64>>
        },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),

    Tf = 2#01,
    Nh = 0,
    Hlim = 2#11,
    Cid = 0,
    Sac = 1,
    Sam = 2#00,
    M = 0,
    Dac = 1,
    Dam = 2#00,
    ExpectedCarriedInline =
        #{
            "SAM" => 42540488161975842775177730024210956289,
            "NextHeader" => 0,
            "ECN" => 0,
            "FlowLabel" => 3,
            "DAM" => 42540488161975842775177730024210956290
        },
    io:format("ExpectedCarriedInline: ~p~n", [ExpectedCarriedInline]),

    Dest = IPv6Header#ipv6_header.destination_address,
    Src = IPv6Header#ipv6_header.source_address,
    InlineData =
        <<0:2, 0:2, 3:20, 0:8, Src/binary,
            %list_to_binary(ExpectedCarriedInlineList),
            Dest/binary>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary>>,

    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader,

    ExpectedCarriedInline = CarriedInlineData,
    ok.

%---Different types of Next Headers test case
udp_nh_pckt_comp(_Config) ->
    Payload = <<"Testing basic IPHC compression with link-local address">>,

    PayloadLength = byte_size(Payload),
    Source_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000001:64>>,
    Destination_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000002:64>>,

    UdpPckt = <<1025:16, 61617:16, 25:16, 16#f88c:16>>,

    Ipv6Pckt =
        <<6:4, 0:8, 0:20, PayloadLength:16, 17:8, 64:8, Source_address/binary, Destination_address/binary, UdpPckt/binary, Payload/binary>>,

    Tf = 2#11,
    Nh = 1,
    Hlim = 2#10,
    Cid = 0,
    Sac = 0,
    Sam = 2#01,
    M = 0,
    Dac = 0,
    Dam = 2#01,
    C = 0,
    P = 2#01,
    ExpectedCarriedInline = #{"SAM" => 14627373598910709761, "DAM" => 14627373598910709762},

    InlineData = <<14627373598910709761:64, 14627373598910709762:64>>,
    UdpInline = <<1025:16, 177:8, 63628:16>>,

    io:format("UdpInline ~p~n", [UdpInline]),
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary, ?UDP_DHTYPE:5, C:1, P:2, UdpInline/binary>>,

    Pckt = <<Ipv6Pckt/binary, UdpPckt/binary>>,
    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Pckt),

    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader,

    ExpectedCarriedInline = CarriedInlineData,
    ok.

tcp_nh_pckt_comp(_Config) ->
    Payload = <<"Testing basic IPHC compression with link-local address">>,
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = byte_size(Payload),
            % TCP
            next_header = 6,
            hop_limit = 64,
            source_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000001:64>>,
            destination_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000002:64>>
        },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),

    Tf = 2#11,
    Nh = 0,
    Hlim = 2#10,
    Cid = 0,
    Sac = 0,
    Sam = 2#01,
    M = 0,
    Dac = 0,
    Dam = 2#01,
    ExpectedCarriedInline =
        #{
            "SAM" => 14627373598910709761,
            "DAM" => 14627373598910709762,
            "NextHeader" => 6
        },

    InlineData = <<6:8, 14627373598910709761:64, 14627373598910709762:64>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary>>,

    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),

    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader,

    ExpectedCarriedInline = CarriedInlineData,
    ok.

icmp_nh_pckt_comp(_Config) ->
    Payload = <<"Testing basic IPHC compression with link-local address">>,
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = byte_size(Payload),
            %ICMPv6
            next_header = 58,
            hop_limit = 255,
            source_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000001:64>>,
            destination_address = <<16#FE80:16, 0:48, 16#CAFEDECA00000002:64>>
        },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),

    Tf = 2#11,
    Nh = 0,
    Hlim = 2#11,
    Cid = 0,
    Sac = 0,
    Sam = 2#01,
    M = 0,
    Dac = 0,
    Dam = 2#01,
    ExpectedCarriedInline =
        #{
            "SAM" => 14627373598910709761,
            "DAM" => 14627373598910709762,
            "NextHeader" => 58
        },

    InlineData = <<58:8, 14627373598910709761:64, 14627373598910709762:64>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary>>,

    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),

    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),
    ExpectedHeader = CompressedHeader,

    ExpectedCarriedInline = CarriedInlineData,
    ok.

%---Online resource (https://www.youtube.com/watch?v=0JMVO3HN0xo&t=778s)
compress_header_example1_test(_Config) ->
    Payload = <<"Hello world this is an ipv6 packet">>,
    PayloadLength = byte_size(Payload),

    SrcAddress = <<16#FE80:16, 0:48, 16#020164FFFE2FFC0A:64>>,
    DstAddress = <<16#FF02:16, 0:48, 16#0000000000000001:64>>,
    Ipv6Pckt =
        <<6:4, 224:8, 0:20, PayloadLength:16, 58:8, 255:8, SrcAddress/binary, DstAddress/binary, Payload/bitstring>>,

    Tf = 2#10,
    Nh = 0,
    Hlim = 2#11,
    Cid = 0,
    Sac = 0,
    Sam = 2#11,
    M = 1,
    Dac = 0,
    Dam = 2#11,
    ExpectedCarriedInline =
        #{
            "DAM" => 1,
            "NextHeader" => 58,
            "TrafficClass" => 224
        },
    %lowpan:map_to_binary(ExpectedCarriedInline),
    InlineData = <<0:2, 56:6, 58:8, 1:8>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary>>,

    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),

    ExpectedHeader = CompressedHeader,

    ExpectedCarriedInline = CarriedInlineData,
    ok.

compress_header_example2_test(_Config) ->
    Payload = <<"Hello world this is an ipv6 packet">>,
    PayloadLength = byte_size(Payload),

    SrcAddress = <<16#2001066073013728:64, 16#0223DFFFFEA9F7AC:64>>,
    DstAddress = <<16#2001A45040070803:64, 16#0000000000001004:64>>,
    Ipv6Pckt =
        <<6:4, 0:8, 0:20, PayloadLength:16, 6:8, 64:8, SrcAddress/binary, DstAddress/binary, Payload/binary>>,

    Tf = 2#11,
    Nh = 0,
    Hlim = 2#10,
    Cid = 0,
    Sac = 1,
    Sam = 2#00,
    M = 0,
    Dac = 1,
    Dam = 2#00,
    ExpectedCarriedInline =
        #{
            "NextHeader" => 6,
            "SAM" => 42540617497929311563404140503263475628,
            "DAM" => 42543820835219383719222373238926479364
        },
    InlineData = <<6:8, SrcAddress/bitstring, DstAddress/bitstring>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary>>,

    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nActual ~p~n", [ExpectedHeader, CompressedHeader]),

    ExpectedHeader = CompressedHeader,
    ExpectedCarriedInline = CarriedInlineData,

    ok.

robot_tx(_Config) ->
    Node1MacAddress = <<16#CAFEDECA00000001:64>>,
    Node2MacAddress = <<16#CAFEDECA00000002:64>>,

    Payload = <<"Hello world this is an ipv6 packet for testing purpose">>,
    io:format("PayLen: ~p~n", [bit_size(Payload)]),

    Node1Address = lowpan:get_default_LL_add(Node1MacAddress),
    Node2Address = lowpan:get_default_LL_add(Node2MacAddress),
    PayloadLength = byte_size(Payload),

    Ipv6Pckt =
        <<6:4, 224:8, 2:20, PayloadLength:16, 12:8, 255:8, Node1Address/binary, Node2Address/binary, Payload/bitstring>>,

    Tf = 2#00,
    Nh = 0,
    Hlim = 2#11,
    Cid = 0,
    Sac = 0,
    Sam = 2#01,
    M = 0,
    Dac = 0,
    Dam = 2#01,
    ExpectedCarriedInline =
        #{
            "SAM" => 14627373598910709761,
            "DAM" => 14627373598910709762,
            "NextHeader" => 12,
            "TrafficClass" => 224,
            "FlowLabel" => 2
        },
    InlineData =
        <<0:2, 56:6, 0:4, 2:20, 12:8, 14627373598910709761:64,
            %lowpan:map_to_binary(ExpectedCarriedInline),
            14627373598910709762:64>>,
    ExpectedHeader =
        <<?IPHC_DHTYPE:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, InlineData/binary>>,

    {CompressedHeader, CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    io:format("Expected ~p~nReceived ~p~n", [ExpectedHeader, CompressedHeader]),

    ExpectedHeader = CompressedHeader,

    ExpectedCarriedInline = CarriedInlineData,

    %%-------------------------------GETTING COMPRESSED PACKET-------------
    CompressedPacket = <<CompressedHeader/binary, Payload/bitstring>>,
    Datagram_tag = rand:uniform(65536),
    CompPcktLen = byte_size(CompressedPacket),
    UnFragPckt =
        lowpan:build_firstFrag_pckt(
            ?FRAG1_DHTYPE,
            CompPcktLen,
            Datagram_tag,
            CompressedHeader,
            Payload
        ),
    io:format("Pckt len: ~p bytes~n", [byte_size(UnFragPckt)]),

    io:format("Pckt: ~p~n", [UnFragPckt]),

    % TxBin = lowpan:print_as_binary(UnFragPckt),
    % io:format("~p~n~n",[TxBin]),
    % WiresharkData = "c04d34bf63113800000200cafedeca00000001cafedeca0000000248656c6c6f20776f726c64207468697320697320616e2069707636207061636b657420666f722074657374696e6720707572706f7365",
    % WiresharDataBin = lowpan:hex_to_binary(WiresharkData),
    % io:format("~p~n~n",[WiresharDataBin]),
    % 32 bits FragHeader,  16 bits HC1 + 168 carrInHC1 = 216
    % 432 bits payload
    % total pckt len: 81 bytes
    <<_:216, UnPayload/bitstring>> = UnFragPckt,

    io:format("Payload: ~p~n", [UnPayload]),

    ok.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                      6LoWPAN IPv6 Packet Fragmentation
%------------------------------------------------------------------------------------------------------------------------------------------------------

fragmentation_test(_Config) ->
    % fragmentation test based on the computation of the size of all fragment payloads
    Payload = <<"This is an Ipv6 pckt">>,
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = byte_size(Payload),
            next_header = 17,
            hop_limit = 64,
            source_address = <<1>>,
            destination_address = <<2>>
        },
    IPv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),
    Fragments = lowpan:fragment_ipv6_packet(IPv6Pckt, byte_size(Payload)),
    ReassembledSize =
        lists:foldl(fun({_, Fragment}, Acc) -> byte_size(Fragment) + Acc end, 0, Fragments),
    Psize = byte_size(IPv6Pckt),
    Psize = ReassembledSize,
    ok.

datagram_info_test(_Config) ->
    Data = <<"payload">>,
    Fragment = <<?FRAG1_DHTYPE:5, 1000:11, 12345:16, Data/bitstring>>,

    DtgInfo = lowpan:datagram_info(Fragment),
    FragType = DtgInfo#datagramInfo.fragtype,
    DatagramSize = DtgInfo#datagramInfo.datagramSize,
    DatagramTag = DtgInfo#datagramInfo.datagramTag,
    DatagramOffset = DtgInfo#datagramInfo.datagramOffset,
    Payload = DtgInfo#datagramInfo.payload,

    io:format("~p~n", [Payload]),

    ?FRAG1_DHTYPE = FragType,
    1000 = DatagramSize,
    12345 = DatagramTag,
    0 = DatagramOffset,
    Data = Payload,
    ok.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Ipv6 Packet Reassembly
%------------------------------------------------------------------------------------------------------------------------------------------------------

reassemble_fragments_list_test(_Config) ->
    Data = <<"Hello World!">>,
    PayloadLen = byte_size(Data),
    FragHeader1 =
        #frag_header{
            frag_type = ?FRAG1_DHTYPE,
            datagram_size = PayloadLen,
            datagram_tag = 25,
            datagram_offset = 0
        },
    FragHeader2 =
        #frag_header{
            frag_type = ?FRAGN_DHTYPE,
            datagram_size = PayloadLen,
            datagram_tag = 25,
            datagram_offset = 1
        },
    Frag1 = lowpan:build_datagram_pckt(FragHeader1, <<"Hello ">>),
    Frag2 = lowpan:build_datagram_pckt(FragHeader2, <<"World!">>),
    Fragments = [Frag1, Frag2],
    Reassembled = lowpan:reassemble_datagrams(Fragments),
    <<"Hello World!">> = Reassembled,
    ok.

reassemble_single_fragments_test(_Config) ->
    Data = <<"Hello World!">>,
    PayloadLen = byte_size(Data),
    FragHeader1 =
        #frag_header{
            frag_type = ?FRAG1_DHTYPE,
            datagram_size = PayloadLen,
            datagram_tag = 25,
            datagram_offset = 0
        },
    FragHeader2 =
        #frag_header{
            frag_type = ?FRAGN_DHTYPE,
            datagram_size = PayloadLen,
            datagram_tag = 25,
            datagram_offset = 1
        },
    Frag1 = lowpan:build_datagram_pckt(FragHeader1, <<"Hello ">>),
    Frag2 = lowpan:build_datagram_pckt(FragHeader2, <<"World!">>),
    DatagramMap = maps:new(),
    {notYetReassembled, IntermediateMap} = lowpan:reassemble_datagram(Frag1, DatagramMap),
    {Reassembled, _FinalMap} = lowpan:reassemble_datagram(Frag2, IntermediateMap),

    <<"Hello World!">> = Reassembled,
    ok.

reassemble_full_ipv6_pckt_test(_Config) ->
    Payload = lowpan:generate_chunks(),
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = byte_size(Payload),
            next_header = 17,
            hop_limit = 64,
            source_address = <<1>>,
            destination_address = <<2>>
        },

    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),
    io:format("Original pckt size ~p bytes~n", [byte_size(Ipv6Pckt)]),
    FragmentList = lowpan:fragment_ipv6_packet(Ipv6Pckt, byte_size(Ipv6Pckt)),
    Fragments =
        lists:map(
            fun({FragHeader, FragPayload}) -> <<FragHeader/binary, FragPayload/bitstring>> end,
            FragmentList
        ),
    Reassembled = lowpan:reassemble_datagrams(Fragments),
    io:format("Reassembled:  ~p~nIpv6Pckt:  ~p~n", [Reassembled, Ipv6Pckt]),
    Ipv6Pckt = Reassembled,

    ok.


%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                              Additionnal tests
%------------------------------------------------------------------------------------------------------------------------------------------------------

extended_EUI64_from_48mac(_Config)->
    MacAddr = <<16#9865FD361453:48>>, 
    Expected = <<16#9A65FDFFFE361453:64>>,
    Result = lowpan:get_EUI64_from_48bit_mac(MacAddr), 
    io:format("Expected ~p~nResult ~p~n",[Expected, Result]),
    Result =:= Expected.  

extended_EUI64_from_64mac(_Config)->
    MacAddr = <<16#00124B0006386C1A:64>>, 
    Expected = <<16#02124B0006386C1A:64>>,
    Result = lowpan:get_EUI64_from_extended_mac(MacAddr), 
    io:format("Expected ~p~nResult ~p~n",[Expected, Result]),
    Result =:= Expected. 

extended_EUI64_from_16mac(_Config)->
    MacAddr = <<16#0001:16>>, 
    Expected = <<16#FFFF:16, 0:16, 16#0001:16>>,
    Result = lowpan:get_EUI64_from_short_mac(MacAddr), 
    io:format("Expected ~p~nResult ~p~n",[Expected, Result]),
    Result =:= Expected. 
