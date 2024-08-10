-module(lowpan).

-include("lowpan.hrl").

-export([
    pkt_encapsulation/2, fragment_ipv6_packet/2,
    reassemble/1, store_fragment/8, create_iphc_pckt/2, get_ipv6_pkt/2, datagram_info/1,
    compress_ipv6_header/2, build_datagram_pckt/2, build_firstFrag_pckt/5,
    get_pckt_info/1, get_ipv6_payload/1, trigger_fragmentation/2,
    decode_ipv6_pckt/4, encode_integer/1,
    tuple_to_bin/1, build_frag_header/1, get_next_hop/6, print_as_binary/1,
    hex_to_binary/1, complete_with_padding/1, generate_chunks/0, generate_chunks/1,
    build_mesh_header/1, get_mesh_info/1, contains_mesh_header/1,
    build_first_frag_header/1, get_unc_ipv6/1, get_EUI64_mac_addr/1,
    generate_EUI64_mac_addr/1, get_EUI64_from_48bit_mac/1,
    get_EUI64_from_short_mac/1, get_EUI64_from_extended_mac/1,
    generate_LL_addr/1, create_new_mesh_header/3, create_new_mesh_datagram/3,
    remove_mesh_header/2, convert_addr_to_bin/1, 
    check_tag_unicity/2, get_16bit_mac_addr/1, generate_multicast_addr/1, get_decode_ipv6_pckt_info/1, 
    compression_ratio/2, get_next_hop/2
]).

%---------------------------------------------------------------------------------------
%% @doc return pre-built Ipv6 packet
%% @spec get_ipv6_pkt(Header, Payload) -> binary().
%---------------------------------------------------------------------------------------
-spec get_ipv6_pkt(Header, Payload) -> binary() when
      Header :: binary(),
      Payload :: binary().
get_ipv6_pkt(Header, Payload) ->
    ipv6:build_ipv6_packet(Header, Payload).

%---------------------------------------------------------------------------------------
%% @doc create an uncompressed 6lowpan packet from an Ipv6 packet
%% @spec pkt_encapsulation(Header, Payload) -> binary().
%---------------------------------------------------------------------------------------
-spec pkt_encapsulation(Header, Payload) -> binary() when
      Header :: binary(),
      Payload :: binary().
pkt_encapsulation(Header, Payload) ->
    Ipv6Pckt = get_ipv6_pkt(Header, Payload),
    DhTypebinary = <<?IPV6_DHTYPE:8, 0:16>>,
    <<DhTypebinary/binary, Ipv6Pckt/binary>>.

%---------------------------------------------------------------------------------------
%% @spec get_unc_ipv6(Ipv6Pckt) -> binary().
%---------------------------------------------------------------------------------------
-spec get_unc_ipv6(Ipv6Pckt) -> binary() when
      Ipv6Pckt :: binary().
get_unc_ipv6(Ipv6Pckt) ->
    <<?IPV6_DHTYPE:8, Ipv6Pckt/bitstring>>.

%---------------------------------------------------------------------------------------
%
%                               Header compression
%
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%% @doc compress an Ipv6 packet header according to the IPHC compression scheme
%% @spec compress_ipv6_header(Ipv6Pckt, RouteExist) -> {binary(), map()}.
%% @returns a tuple containing the compressed header, the payload and the values
%% that should be carried inline
%---------------------------------------------------------------------------------------
-spec compress_ipv6_header(Ipv6Pckt, RouteExist) -> {binary(), map()} when
      Ipv6Pckt :: binary(),
      RouteExist :: boolean().
compress_ipv6_header(Ipv6Pckt, RouteExist) ->
    PcktInfo = get_pckt_info(Ipv6Pckt),

    TrafficClass = PcktInfo#ipv6PckInfo.trafficClass,
    FlowLabel = PcktInfo#ipv6PckInfo.flowLabel,
    NextHeader = PcktInfo#ipv6PckInfo.nextHeader,
    HopLimit = PcktInfo#ipv6PckInfo.hopLimit,
    SourceAddress = PcktInfo#ipv6PckInfo.sourceAddress,
    DestAddress = PcktInfo#ipv6PckInfo.destAddress,

    Map = #{},
    List = [],

    {CID, UpdateMap0, UpdatedList0} =
        encode_cid(SourceAddress, DestAddress, Map, List),

    {TF, UpdateMap1, UpdatedList1} =
        encode_tf(TrafficClass, FlowLabel, UpdateMap0, UpdatedList0),
    
    {NH, UpdateMap2, UpdatedList2} = encode_nh(NextHeader, UpdateMap1, UpdatedList1),
    
    {HLIM, UpdateMap3, UpdatedList3} = encode_hlim(HopLimit, UpdateMap2, UpdatedList2),
    
    SAC = encode_sac(SourceAddress),
    
    {SAM, UpdateMap4, UpdatedList4} =
        encode_sam(CID, SAC, SourceAddress, UpdateMap3, UpdatedList3, RouteExist),
    
    M = encode_m(DestAddress),
    
    DAC = encode_dac(DestAddress),
    
    {DAM, CarrInlineMap, CarrInlineList} =
        encode_dam(CID, M, DAC, DestAddress, UpdateMap4, UpdatedList4, RouteExist),

    CarrInlineBin = list_to_binary(CarrInlineList),
    case NextHeader of
        ?UDP_PN ->
            UdpPckt = get_udp_data(Ipv6Pckt),
            CompressedUdpHeaderBin = compress_udp_header(UdpPckt, []),
            CompressedHeader =
                <<?IPHC_DHTYPE:3, TF:2, NH:1, HLIM:2, CID:1, SAC:1, SAM:2, M:1, DAC:1, DAM:2, CarrInlineBin/binary, CompressedUdpHeaderBin/binary>>,
            {CompressedHeader, CarrInlineMap};
        _ ->
            CompressedHeader =
                <<?IPHC_DHTYPE:3, TF:2, NH:1, HLIM:2, CID:1, SAC:1, SAM:2, M:1, DAC:1, DAM:2, CarrInlineBin/binary>>,
            {CompressedHeader, CarrInlineMap}
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode the TrafficClass and Flow label fields
%% @spec encode_tf(TrafficClass, FlowLabel, CarrInlineMap, CarrInlineList) -> {integer(), map(), list()}.
%% @returns a tuple containing the compressed values and the CarrInline values
%---------------------------------------------------------------------------------------
-spec encode_tf(TrafficClass, FlowLabel, CarrInlineMap, CarrInlineList) -> {integer(), map(), list()} when
      TrafficClass :: integer(),
      FlowLabel :: integer(),
      CarrInlineMap :: map(),
      CarrInlineList :: list().
encode_tf(TrafficClass, FlowLabel, CarrInlineMap, CarrInlineList) ->
    <<DSCP:6, ECN:2>> = <<TrafficClass:8>>,

    case {ECN, DSCP, FlowLabel} of
        {0, 0, 0} ->
            % Traffic Class and Flow Label are elided
            {2#11, CarrInlineMap, CarrInlineList};

        {_, 0, _} ->
            % DSCP is elided
            UpdatedMap = CarrInlineMap#{"ECN" => ECN, "FlowLabel" => FlowLabel},
            Bin = <<ECN:2, 0:2, FlowLabel:20>>, % 24 bits tot (RFC 6282 - pg12)
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#01, UpdatedMap, UpdatedList};

        {_, _, 0} ->
            % Flow Label is elided
            UpdatedMap = CarrInlineMap#{"TrafficClass" => TrafficClass},
            Bin = <<ECN:2, DSCP:6>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#10, UpdatedMap, UpdatedList};

        _ ->
            % ECN, DSCP, and Flow Label are carried inline
            UpdatedMap = CarrInlineMap#{"TrafficClass" => TrafficClass, "FlowLabel" => FlowLabel},
            Bin = <<ECN:2, DSCP:6, 0:4, FlowLabel:20>>, % 32 bits tot (RFC 6282 - pg12)
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#00, UpdatedMap, UpdatedList}
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode the NextHeader field
%% @spec encode_nh(NextHeader, CarrInlineMap, CarrInlineList) -> {integer(), map(), list()}.
%% @doc NextHeader specifies whether or not the next header is encoded using NHC
%% @returns a tuple containing the compressed value and the CarrInline values
%---------------------------------------------------------------------------------------
-spec encode_nh(NextHeader, CarrInlineMap, CarrInlineList) -> {integer(), map(), list()} when
      NextHeader :: integer(),
      CarrInlineMap :: map(),
      CarrInlineList :: list().
encode_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?UDP_PN ->
    {1, CarrInlineMap, CarrInlineList};
encode_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?TCP_PN ->
    Bin = <<NextHeader:8>>,
    L = [Bin],
    UpdatedList = [CarrInlineList,

 L],
    {0, CarrInlineMap#{"NextHeader" => ?TCP_PN}, UpdatedList};
encode_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?ICMP_PN ->
    Bin = <<NextHeader:8>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader" => ?ICMP_PN}, UpdatedList};
encode_nh(NextHeader, CarrInlineMap, CarrInlineList) ->
    Bin = <<NextHeader:8>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader" => NextHeader}, UpdatedList}.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode the HopLimit field
%% @spec encode_hlim(HopLimit, CarrInlineMap, CarrInlineList) -> {integer(), map(), list()}.
%% @returns a tuple containing the compressed value and the CarrInline values
%---------------------------------------------------------------------------------------
-spec encode_hlim(HopLimit, CarrInlineMap, CarrInlineList) -> {integer(), map(), list()} when
      HopLimit :: integer(),
      CarrInlineMap :: map(),
      CarrInlineList :: list().
encode_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 1 ->
    {2#01, CarrInlineMap, CarrInlineList};
encode_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 64 ->
    {2#10, CarrInlineMap, CarrInlineList};
encode_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 255 ->
    {2#11, CarrInlineMap, CarrInlineList};
encode_hlim(HopLimit, CarrInlineMap, CarrInlineList) ->
    Bin = <<HopLimit:8>>,
    L = [Bin],
    UpdatedList = CarrInlineList ++ L,
    {2#00, CarrInlineMap#{"HopLimit" => HopLimit}, UpdatedList}.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode the Context Identifier Extension field
%% @spec encode_cid(SrcAdd, DstAdd, CarrInlineMap, CarrInlineList) -> {integer(), map(), list()}.
%% @doc If this bit is 1, an 8 bit CIE field follows after the DAM field
%% @returns a tuple containing the compressed value and the CarrInline values
%---------------------------------------------------------------------------------------
-spec encode_cid(SrcAdd, DstAdd, CarrInlineMap, CarrInlineList) -> {integer(), map(), list()} when
      SrcAdd :: binary(),
      DstAdd :: binary(),
      CarrInlineMap :: map(),
      CarrInlineList :: list().
encode_cid(SrcAdd, DstAdd, CarrInlineMap, CarrInlineList) ->
    <<SrcAddPrefix:16, _/binary>> = <<SrcAdd:128>>,
    <<DstAddPrefix:16, _/binary>> = <<DstAdd:128>>,
    SrcPrefixKey = <<SrcAddPrefix:16, 0:48>>, 
    DstPrefixKey = <<DstAddPrefix:16, 0:48>>,

    % check if prefix is in contextTable
    SrcContext = maps:find(SrcPrefixKey, ?Prefixt_id_table),
    DstContext = maps:find(DstPrefixKey, ?Prefixt_id_table),

    case {SrcContext, DstContext} of
        {{ok, SrcContextId}, {ok, DstContextId}} ->
            Bin = <<SrcContextId:4, DstContextId:4>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {1, CarrInlineMap#{"SA_CID" => SrcContextId, "DA_CID" => DstContextId}, UpdatedList};

        {error, {ok, DstContextId}} ->
            Bin = <<0:4, DstContextId:4>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {1, CarrInlineMap#{"DA_CID" => DstContextId}, UpdatedList};

        {{ok, SrcContextId}, error} ->
            SrcContextId = someValue,
            Bin = <<SrcContextId:4, 0:4>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {1, CarrInlineMap#{"SA_CID" => SrcContextId}, UpdatedList};

        _-> {0, CarrInlineMap, CarrInlineList}
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode the Source Address Compression
%% @spec encode_sac(SrcAdd) -> integer().
%% @doc SAC specifies whether the compression is stateless or statefull
%% @returns the compressed value
%---------------------------------------------------------------------------------------
-spec encode_sac(SrcAdd) -> integer() when
      SrcAdd :: binary().
encode_sac(SrcAdd) ->
    <<Prefix:16, _/binary>> = <<SrcAdd:128>>,

    case Prefix of
        ?LINK_LOCAL_PREFIX ->
            0;
        ?MULTICAST_PREFIX ->
            0;
        _ ->
            1
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode for the Source Address Mode
%% @spec encode_sam(integer(), integer(), binary(), map(), list(), boolean()) -> {integer(), map(), list()}.
%% @returns a tuple containing the compressed value and the CarrInline values
%% @param CID, SAC, SrcAdd, CarrInlineMap, CarrInlineList
%---------------------------------------------------------------------------------------
-spec encode_sam(integer(), integer(), binary(), map(), list(), boolean()) -> {integer(), map(), list()}.
encode_sam(_CID, SAC, SrcAdd, CarrInlineMap, CarrInlineList, RouteExist) when SAC == 0 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case {SrcAddBits, RouteExist} of
        {<<?LINK_LOCAL_PREFIX:16, 0:48, _:24, 16#FFFE:16, _:24>>, _} ->
            % the address is fully elided
            {2#11, CarrInlineMap, CarrInlineList};
        {_, true} -> 
            {2#11, CarrInlineMap, CarrInlineList};

        {<<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>>, _} ->
            % the first 112 bits are elided, last 16 IID bits are carried in-line
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last16Bits},
            {2#10, UpdatedMap, UpdatedList};

        {<<?LINK_LOCAL_PREFIX:16, 0:48, _:64>>, _} ->
            % the first 64 bits are elided, last 64 bits (IID) are carried in-line
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Bin},
            {2#01, UpdatedMap, UpdatedList};
        {_, _} ->
            % full address is carried in-line
            Bin = <<SrcAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#00, CarrInlineMap#{"SAM" => Bin}, UpdatedList}
    end;
encode_sam(0, 1, SrcAdd, CarrInlineMap, CarrInlineList, _RouteExist) ->
    Bin = <<SrcAdd:128>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {2#00, CarrInlineMap#{"SAM" => Bin}, UpdatedList};

encode_sam(_CID, SAC, SrcAdd, CarrInlineMap, CarrInlineList, _RouteExist) when SAC == 1 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case SrcAddBits of
        <<_Prefix:16, _:48, _:24, 16#FFFE:16, _:24>> ->
            % the address is fully elided
            {2#11, CarrInlineMap, CarrInlineList};

        <<_Prefix:16, _:48, 16#000000FFFE00:48, _:16>> ->
            % the first 112 bits are elided, last 16 IID bits are carried in-line
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Bin},
            {2#10, UpdatedMap, UpdatedList};

        <<_Prefix:16, _:48, _:64>> ->
            % the first 64 bits are elided, last 64 bits (IID) are carried in-line
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Bin},
            {2#01, UpdatedMap, UpdatedList};

        <<0:128>> -> % The UNSPECIFIED address, ::
            {2#00,

 CarrInlineMap, CarrInlineList}
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode for the Multicast compression
%% @spec encode_m(DstAdd) -> integer().
%% @returns the compressed value
%---------------------------------------------------------------------------------------
-spec encode_m(DstAdd) -> integer() when
      DstAdd :: binary().
encode_m(DstAdd) ->
    <<Prefix:16, _/bitstring>> = <<DstAdd:128>>,
    case Prefix of
        ?MULTICAST_PREFIX ->
            1;
        _ ->
            0
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode for the Destination Address Compression
%% @spec encode_dac(DstAdd) -> integer().
%% @doc DAC specifies whether the compression is stateless or statefull
%% @returns the compressed value
%---------------------------------------------------------------------------------------
-spec encode_dac(DstAdd) -> integer() when
      DstAdd :: binary().
encode_dac(DstAdd) ->
    <<Prefix:16, _/binary>> = <<DstAdd:128>>,

    case Prefix of
        ?LINK_LOCAL_PREFIX ->
            0;
        ?MULTICAST_PREFIX ->
            0;
        _ ->
            1
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @doc encode for the Destination Address Mode
%% @spec encode_dam(integer(), integer(), integer(), binary(), map(), list(), boolean()) -> {integer(), map(), list()}.
%% @param Cid, M, DAC, DstAdd, CarrInlineMap
%% @returns a tuple containing the compressed value and the CarrInline values
%---------------------------------------------------------------------------------------
-spec encode_dam(integer(), integer(), integer(), binary(), map(), list(), boolean()) -> {integer(), map(), list()}.
encode_dam(0, 0, 0, DstAdd, CarrInlineMap, CarrInlineList, RouteExist) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,
    
    case {DestAddBits, RouteExist} of
        {<<?LINK_LOCAL_PREFIX:16, 0:48, _:24, 16#FFFE:16, _:24>>, _} ->
            % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
            {2#11, CarrInlineMap, CarrInlineList};
        {_, true} -> {2#11, CarrInlineMap, CarrInlineList};

        {<<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>>, _} ->
            % the first 112 bits are elided, last 16 bits are in-line
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Bin},
            {2#10, UpdatedMap, UpdatedList};

        {<<?LINK_LOCAL_PREFIX:16,  0:48, _:64>>, _} ->
            % the first 64 bits are elided, last 64 bits are in-line
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Bin},
            {2#01, UpdatedMap, UpdatedList};
        {_, _} ->
            % full address is carried in-line
            Bin = <<DstAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#00, CarrInlineMap#{"DAM" => Bin}, UpdatedList}
    end;
encode_dam(1, 0, 1, DstAdd, CarrInlineMap, CarrInlineList, _RouteExist) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,
    
    case DestAddBits of
        <<_Prefix:16, _:48, _:24, 16#FFFE:16, _:24>> ->
            % the address is fully elided
            {2#11, CarrInlineMap, CarrInlineList};

        <<_Prefix:16, _:48, 16#000000FFFE00:48, _:16>> ->
            % the first 112 bits are elided, last 16 IID bits are carried in-line
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Bin},
            {2#10, UpdatedMap, UpdatedList};

        <<_Prefix:16, _:48, _:64>> ->
            % the first 64 bits are elided, last 64 bits (IID) are carried in-line
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Bin},
            {2#01, UpdatedMap, UpdatedList}
    end;
encode_dam(0, 0, 1, DstAdd, CarrInlineMap, CarrInlineList, _RouteExist) ->
    Bin = <<DstAdd:128>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {2#00, CarrInlineMap#{"DAM" => Bin}, UpdatedList};
    
encode_dam(_CID, 1, 0, DstAdd, CarrInlineMap, CarrInlineList, _RouteExist) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:80, Last48Bits:48>> = DestAddBits,
    <<_:96, Last32Bits:32>> = DestAddBits,
    <<_:120, Last8Bits:8>> = DestAddBits,
    case DestAddBits of
        % ff02::00XX.
        <<?MULTICAST_PREFIX:16, 0:104, _:8>> ->
            Bin = <<Last8Bits:8>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Bin},
            {2#11, UpdatedMap, UpdatedList};

        % ffXX::00XX:XXXX.
        <<16#FF:8, _:8, 0:80, _:32>> ->
            Bin = <<Last32Bits:32>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Bin},
            {2#10, UpdatedMap, UpdatedList};

        % ffXX::00XX:XXXX:XXXX.
        <<16#FF:8, _:8, 0:64, _:48>> ->
            Bin = <<Last48Bits:48>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Bin},
            {2#01, UpdatedMap, UpdatedList};
        _ ->
            % full address is carried in-line
            Bin = <<DstAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#00, CarrInlineMap#{"DAM" => Bin}, UpdatedList}
    end;
encode_dam(_CID, 1, 1, DstAdd, CarrInlineMap, CarrInlineList, _RouteExist) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:80, Last48Bits:48>> = DestAddBits,
    case DestAddBits of
        <<16#FF, _:112>> ->
            Bin = <<Last48Bits:48>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Bin},
            {2#00, UpdatedMap, UpdatedList}
    end.

%---------------------------------------------------------------------------------------
%
%                       Next Header compression
%
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%                       UDP Packet Compression
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%                 Structure of a UDP Datagram Header
%
%    0                   1                   2                   3
%    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%   |       Source Port            |       Destination Port         |
%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%   |            Length            |           Checksum             |
%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%

-spec compress_udp_header(UdpPckt, CarriedInline) -> binary() when
      UdpPckt :: binary(),
      CarriedInline :: list().
compress_udp_header(UdpPckt, CarriedInline) ->
    <<SrcPort:16, DstPort:16, _Length:16, Checksum:16>> = <<UdpPckt:64>>,

    {P, CarriedInlineList} = encode_udp_ports(SrcPort, DstPort, CarriedInline),
    {C, CarriedIn} = encode_udp_checksum(Checksum, CarriedInlineList),

    Inline = list_to_binary(CarriedIn),

    CompressedUdpHeader = <<?UDP_DHTYPE:5,

 C:1, P:2, Inline/bitstring>>,
    CompressedUdpHeader.

-spec encode_udp_ports(SrcPort, DstPort, CarriedInline) -> {integer(), list()} when
      SrcPort :: integer(),
      DstPort :: integer(),
      CarriedInline :: list().
encode_udp_ports(SrcPort, DstPort, CarriedInline) ->
    case {<<SrcPort:16>>, <<DstPort:16>>} of
        {<<?Oxf0b:12, Last4S_Bits:4>>, <<?Oxf0b:12, Last4D_Bits:4>>} ->
            ToCarr = <<Last4S_Bits:4, Last4D_Bits:4>>,
            L = [ToCarr],
            CarriedInlineList = CarriedInline ++ L,
            P = 2#11,
            {P, CarriedInlineList};
        {<<?Oxf0:8, Last8S_Bits:8>>, _} ->
            ToCarr = <<Last8S_Bits:8, DstPort:16>>,
            L = [ToCarr],
            CarriedInlineList = CarriedInline ++ L,
            P = 2#10,
            {P, CarriedInlineList};
        {_, <<?Oxf0:8, Last8D_Bits:8>>} ->
            ToCarr = <<SrcPort:16, Last8D_Bits:8>>,
            L = [ToCarr],
            CarriedInlineList = CarriedInline ++ L,
            P = 2#01,
            {P, CarriedInlineList};
        {_, _} ->
            P = 2#00,
            ToCarr = <<SrcPort:16, DstPort:16>>,
            L = [ToCarr],
            CarriedInlineList = CarriedInline ++ L,
            {P, CarriedInlineList}
    end.

-spec encode_udp_checksum(Checksum, CarriedInline) -> {integer(), list()} when
      Checksum :: integer(),
      CarriedInline :: list().
encode_udp_checksum(Checksum, CarriedInline) ->
    case Checksum of
        0 ->
            {1, CarriedInline};
        %Checksum is carried inline
        _ ->
            L = [<<Checksum:16>>],
            UpdatedList = CarriedInline ++ L,
            {0, UpdatedList}
    end.

%---------------------------------------------------------------------------------------
%                       ICMP Packet Compression
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%                        TCP Packet Compression
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%                       Packet Compression Helper
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%% @spec create_iphc_pckt(IphcHeader, Payload) -> binary().
%% @doc create a compressed 6lowpan packet (with iphc compression) from an Ipv6 packet
%---------------------------------------------------------------------------------------
-spec create_iphc_pckt(IphcHeader, Payload) -> binary() when
      IphcHeader :: binary(),
      Payload :: binary().
create_iphc_pckt(IphcHeader, Payload) ->
    <<IphcHeader/binary, Payload/bitstring>>.

%---------------------------------------------------------------------------------------
%% @spec get_pckt_info(Ipv6Pckt) -> map().
%% @doc return value field of a given Ipv6 packet
%---------------------------------------------------------------------------------------
-spec get_pckt_info(Ipv6Pckt) -> map() when
      Ipv6Pckt :: binary().
get_pckt_info(Ipv6Pckt) ->
    <<Version:4, TrafficClass:8, FlowLabel:20, PayloadLength:16, NextHeader:8, HopLimit:8, SourceAddress:128, DestAddress:128, Data/bitstring>> =
        Ipv6Pckt,
    
    Payload = case NextHeader of 
                ?UDP_PN -> 
                        <<_UdpFields:64, Payld/bitstring>> = Data,
                        Payld;
                _ -> Data
             end,    
    PckInfo =
        #ipv6PckInfo{
            version = Version,
            trafficClass = TrafficClass,
            flowLabel = FlowLabel,
            payloadLength = PayloadLength,
            nextHeader = NextHeader,
            hopLimit = HopLimit,
            sourceAddress = SourceAddress,
            destAddress = DestAddress,
            payload = Payload
        },
    PckInfo.

%---------------------------------------------------------------------------------------
%% @spec get_decode_ipv6_pckt_info(Ipv6Pckt) -> map().
%---------------------------------------------------------------------------------------
-spec get_decode_ipv6_pckt_info(Ipv6Pckt) -> map() when
      Ipv6Pckt :: binary().
get_decode_ipv6_pckt_info(Ipv6Pckt) ->
    <<TrafficClass:8, FlowLabel:24, NextHeader:8, HopLimit:8, SourceAddress:128, DestAddress:128, Data/bitstring>> =
        Ipv6Pckt,
    
    Payload = case NextHeader of 
                ?UDP_PN -> 
                        <<_UdpFields:64, Payld/bitstring>> = Data,
                        Payld;
                _ -> Data
             end,    
    PckInfo =
        #ipv6PckInfo{
            version = 6,
            trafficClass = TrafficClass,
            flowLabel = FlowLabel,
            payloadLength = byte_size(Payload),
            nextHeader = NextHeader,
            hopLimit = HopLimit,
            sourceAddress = SourceAddress,
            destAddress = DestAddress,
            payload = Payload
        },
    PckInfo.

%---------------------------------------------------------------------------------------
%% @spec get_udp_data(Ipv6Pckt) -> binary().
%% @doc return UDP data from a given Ipv6 packet if it contains a UDP nextHeader
%---------------------------------------------------------------------------------------
-spec get_udp_data(Ipv6Pckt) -> binary() when
      Ipv6Pckt :: binary().
get_udp_data(Ipv6Pckt) ->
    <<_:320, UdpPckt:64, _/binary>> = Ipv6Pckt,
    UdpPckt.

%---------------------------------------------------------------------------------------
%% @spec get_ipv6_payload(Ipv6Pckt) -> binary().
%% @doc return the payload of a given Ipv6 packet
%---------------------------------------------------------------------------------------
-spec get_ipv6_payload(Ipv6Pckt) -> binary() when
      Ipv6Pckt :: binary().
get_ipv6_payload(Ipv6Pckt) ->
    <<_:192, _:128, Payload/binary>> = Ipv6Pckt,
    Payload.

%---------------------------------------------------------------------------------------
%% @spec encode_integer(I) -> binary().
%% @doc Encode an Integer value in a binary format using an appropriate amount of bit
%---------------------------------------------------------------------------------------
-spec encode_integer(I) -> binary() when
      I :: integer().
encode_integer(I) when I =< 255 ->
    <<I:8>>;
encode_integer(I) when I =< 65535 ->
    <<I:16>>;
encode_integer(I) when I =< 4294967295 ->
    <<I:32>>;
encode_integer(I) ->
    <<I:64>>.

%---------------------------------------------------------------------------------------
%
%                               Packet fragmentation
%
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%% @spec build_frag_header(FragHeader) -> binary().
%% @doc returns a binary containing fragmentation header fields
%---------------------------------------------------------------------------------------
-spec build_frag_header(FragHeader) -> binary() when
      FragHeader :: map().
build_frag_header(FragHeader) ->
    #frag_header{
        frag_type = FragType,
        datagram_size = DatagramSize,
        datagram_tag = DatagramTag,
        datagram_offset = DatagramOffset
    } = FragHeader,
    <<FragType:5, DatagramSize:11, DatagramTag:16, DatagramOffset:8>>.

%---------------------------------------------------------------------------------------
%% @spec build_first_frag_header(FragHeader) -> binary().
%---------------------------------------------------------------------------------------
-spec build_first_frag_header(FragHeader) -> binary() when
      FragHeader :: map().
build_first_frag_header(FragHeader) ->
    #frag_header{
        frag_type = FragType,
        datagram_size = DatagramSize,
        datagram_tag = DatagramTag
    } = FragHeader,
    <<FragType:5, DatagramSize:11, DatagramTag:16>>.

%---------------------------------------------------------------------------------------
%% @spec build_firstFrag_pckt(FragType, DatagramSize, DatagramTag, CompressedHeader, Payload) -> binary().
%---------------------------------------------------------------------------------------
-spec build_firstFrag_pckt(integer(), integer(), integer(), binary(), binary()) -> binary().
build_firstFrag_pckt(FragType, DatagramSize, DatagramTag, CompressedHeader, Payload) ->
    <<FragType:5, DatagramSize:11, DatagramTag:16, CompressedHeader/binary, Payload/bitstring>>.

%---------------------------------------------------------------------------------------
%% @spec build_datagram_pckt(DtgmHeader, Payload) -> binary().
%% @doc create a datagram packet (fragments)
%---------------------------------------------------------------------------------------
-spec build_datagram_pckt(map(), binary()) -> binary().
build_datagram_pckt(DtgmHeader, Payload) ->
    TYPE = DtgmHeader#frag_header.frag_type,
    case TYPE of
        ?FRAG1_DHTYPE ->
            Header = build_first_frag_header(DtgmHeader),
            <<Header/binary, Payload/bitstring>>;
        ?FRAGN_DHTYPE ->
            Header = build_frag_header(DtgmHeader),
            <<Header/binary, Payload/bitstring>>
    end.

%---------------------------------------------------------------------------------------
%% @spec trigger_fragmentation(binary(), integer()) -> {boolean(), list()} | {atom(), atom()}.
%% @doc check if a packet needs to be fragmented or not and has a valid size 
%% returns a list of fragments if yes, the orginal packet if not
%---------------------------------------------------------------------------------------
-spec trigger_fragmentation(binary(), integer()) -> {boolean(), list()} | {atom(), atom()}.
trigger_fragmentation(CompPckt, DatagramTag) when byte_size(

CompPckt) =< ?MAX_DTG_SIZE ->
    PcktLengt = byte_size(CompPckt),

    ValidLength = PcktLengt =< ?MAX_FRAME_SIZE,
    case ValidLength of
        false ->
            io:format("The received Ipv6 packet needs fragmentation to be transmitted~n"),
            Fragments = fragment_ipv6_packet(CompPckt, DatagramTag),
            {true, Fragments};
        true ->
            io:format("No fragmentation needed~n"),
            {false, CompPckt}
    end; 

trigger_fragmentation(_CompPckt, _DatagramTag) ->
    {size_err, error_frag_size}.

%---------------------------------------------------------------------------------------
%% @spec fragment_ipv6_packet(binary(), integer()) -> list().
%% @doc Fragment a given Ipv6 packet
%% @returns a list of fragmented packets having this form:
%% [{FragHeader1, Fragment1}, ..., {FragHeaderN, FragmentN}]
%---------------------------------------------------------------------------------------
-spec fragment_ipv6_packet(binary(), integer()) -> list().
fragment_ipv6_packet(CompIpv6Pckt, DatagramTag) when is_binary(CompIpv6Pckt) ->
    Size = byte_size(CompIpv6Pckt),
    frag_process(CompIpv6Pckt, DatagramTag, Size, 0, []).

%---------------------------------------------------------------------------------------
%% @private
%% @spec frag_process(binary(), integer(), integer(), integer(), list()) -> list().
%% @doc helper function to process the received packet
%% @returns a list of fragmented packets
%% [{Header1, Fragment1}, ..., {HeaderN, FragmentN}]
%% Input :
%%   Ipv6Pckt := binary
%%   Pckt size := integer
%%   DatagramTag := integer
%%   Offset := integer
%%   Accumulator : list
%---------------------------------------------------------------------------------------
-spec frag_process(binary(), integer(), integer(), integer(), list()) -> list().
frag_process(<<>>, _, _, _, Acc) ->
    lists:reverse(Acc);
frag_process(CompIpv6Pckt, DatagramTag, PacketLen, Offset, Acc) ->
    MaxSize = ?MAX_FRAG_SIZE, 
    PcktSize = byte_size(CompIpv6Pckt),
    FragmentSize = min(PcktSize, MaxSize),

    <<FragPayload:FragmentSize/binary, Rest/bitstring>> = CompIpv6Pckt,

    case Offset of
        0 ->
            Header =
                build_first_frag_header(#frag_header{
                    frag_type = ?FRAG1_DHTYPE,
                    datagram_size = PacketLen,
                    datagram_tag = DatagramTag,
                    datagram_offset = Offset
                });
        _ ->
            Header =
                build_frag_header(#frag_header{
                    frag_type = ?FRAGN_DHTYPE,
                    datagram_size = PacketLen,
                    datagram_tag = DatagramTag,
                    datagram_offset = Offset
                })
    end,

    frag_process(Rest, DatagramTag, PacketLen, Offset + 1, [{Header, FragPayload} | Acc]).

%---------------------------------------------------------------------------------------
%% @spec check_tag_unicity(map(), integer()) -> {integer(), map()}.
%% @doc Check if tag exist in the map, if so generate a new one and update the tag map
%---------------------------------------------------------------------------------------
-spec check_tag_unicity(map(), integer()) -> {integer(), map()}.
check_tag_unicity(Map, Tag) ->
    Exist = maps:is_key(Tag, Map),
    case Exist of
        true ->
            NewTag = rand:uniform(?MAX_TAG_VALUE),
            check_tag_unicity(Map, NewTag);
        false ->
            NewMap = maps:put(Tag, valid, Map),
            {Tag, NewMap}
    end.

%---------------------------------------------------------------------------------------
%
%                                Packet Decoding
%
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%% @spec decode_ipv6_pckt(boolean(), binary(), binary(), binary()) -> binary() | {atom(), atom()}.
%% @doc decompress an Ipv6 packet header commpressed according to the IPHC compression scheme
%% @returns the decompressed Ipv6 packet
%---------------------------------------------------------------------------------------
-spec decode_ipv6_pckt(boolean(), binary(), binary(), binary()) -> binary() | {atom(), atom()}.
decode_ipv6_pckt(RouteExist, OriginatorMacAddr, CurrNodeMacAdd, CompressedPacket) ->
    <<Dispatch:3, TF:2, NH:1, HLIM:2, CID:1, SAC:1, SAM:2, M:1, DAC:1, DAM:2, Rest/bitstring>> =
        CompressedPacket,
    case Dispatch of
        ?IPHC_DHTYPE -> 
            {SrcContextId, DstContextId, Rest0} = decode_cid(CID, Rest),
            {{DSCP, ECN}, FlowLabel, Rest1} = decode_tf(TF, Rest0),
            {NextHeader, Rest2} = decode_next_header(NH, Rest1),
            {HopLimit, Rest3} = decode_hlim(HLIM, Rest2),
            {SourceAddress, Rest4} = decode_sam(SAC, SAM, Rest3, OriginatorMacAddr, SrcContextId, RouteExist),
            {DestAddress, Payload} = decode_dam(M, DAC, DAM, Rest4, CurrNodeMacAdd, DstContextId, RouteExist),
            PayloadLength = byte_size(Payload),
            TrafficClass = DSCP bsl 2 + ECN,

            <<Header:5, Inline/bitstring>> = Payload,

            io:format("-----------------------------------------------------~n"),
            io:format("Decoded packet~n"), 
            io:format("-----------------------------------------------------~n"),
            DecodedPckt = 
            case Header of
                ?UDP_DHTYPE-> 
                    {SrcPort, DstPort, Checksum, UdpPayload} = decode_udp_pckt(Inline),
                    Length = byte_size(UdpPayload),
                    io:format("IPv6~n"), 
                    
                    io:format("Traffic class: ~p~nFlow label: ~p~nNext header: ~p~nHop limit: ~p~nSource address: ~p~nDestination address: ~p~n", 
                                [TrafficClass, FlowLabel, NextHeader, HopLimit, convert(SourceAddress), convert(DestAddress)]),  
                    io:format("-----------------------------------------------------~n"),
                    io:format("UDP~n"), 
                    io:format("Source port: ~p~nDestination Port: ~p~nLength: ~p~nChecksum: ~p~n",[ SrcPort, DstPort, Length, Checksum]),
                    io:format("-----------------------------------------------------~n"),
                    io:format("Data: ~p~n",[UdpPayload]),                           
                    io:format("-----------------------------------------------------~n"),
                    
                    <<6:4,TrafficClass,FlowLabel:20,PayloadLength:16,NextHeader:8,HopLimit:8,
                    SourceAddress/binary,DestAddress/binary, SrcPort:16, DstPort:16, Length:16, Checksum:16, Payload/bitstring>>;
                    
                _->
                    io:format("IPv6~n"), 
                    io:format("Traffic class: ~p~nFlow label: ~p~nPayload length: ~p~nNext header: ~p~nHop limit: ~p~nSource address: ~p~nDestination address: ~p~nData: ~p~n", [TrafficClass, FlowLabel, PayloadLength, 
                                NextHeader, HopLimit, convert(SourceAddress), convert(DestAddress), Payload]),                        
                    io:format("-----------------------------------------------------~n"),
                    <<6:4,TrafficClass,FlowLabel:20,PayloadLength:16,NextHeader:8,HopLimit:8,
                    SourceAddress/binary,DestAddress/binary, Payload/bitstring>>
            end,

            DecodedPckt;

        _-> {error_decoding}
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @spec decode_cid(integer(), binary()) -> {integer(), integer(), binary()}.
%% @doc decode process for the CID field
%% @returns the decoded ContextID
%---------------------------------------------------------------------------------------
-spec decode_cid(integer(), binary()) -> {integer(), integer(), binary()}.
decode_cid(CID, CarriedInline) when CID == 1 ->
    <<SrcContextId:4, DstContextId:4, Rest/bitstring>> = CarriedInline,
    {SrcContextId, DstContextId, Rest};
decode_cid(CID, CarriedInline) when CID == 0 ->
    DefaultPrefix = 0,
    {DefaultPrefix, DefaultPrefix, CarriedInline}.

%---------------------------------------------------------------------------------------
%% @private
%% @spec decode_tf(integer(), binary()) -> {{integer(), integer()}, integer(), binary()}.
%% @doc decode process for the TF field
%% @returns the decoded TrafficClass and FlowLabel value
%---------------------------------------------------------------------------------------
-spec decode_tf(integer(), binary()) -> {{integer(), integer()}, integer(), binary()}.
decode_tf(TF, CarriedInline) ->
    case TF of
        2#11 ->
            ECN = 0, DSCP = 0, FL = 0,
            {{DSCP, ECN}, FL, CarriedInline};
        2#01 ->
            <<ECN:2, _rsv:2, FL:20, Rest/bitstring>> = CarriedInline,
            DSCP = 0,
            {{DSCP, ECN}, FL, Rest};
        2#10 ->
            <<ECN:2, DSCP:6, Rest/bitstring>> = CarriedInline,
            FL = 0,
            {{DSCP, ECN}, FL, Rest};
        2#00 ->
            <<ECN:

2, DSCP:6, _rsv:4, FL:20, Rest/bitstring>> = CarriedInline,
            {{DSCP, ECN}, FL, Rest}
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @spec decode_next_header(integer(), binary()) -> {integer(), binary()}.
%% @doc decode process for the NH field
%% @returns the decoded NextHeader value
%---------------------------------------------------------------------------------------
-spec decode_next_header(integer(), binary()) -> {integer(), binary()}.
decode_next_header(NH, CarriedInline) when NH == 0 ->
    <<NextHeader:8, Rest/bitstring>> = CarriedInline,
    {NextHeader, Rest};
decode_next_header(NH, CarriedInline) when NH == 1 ->
    {?UDP_PN, CarriedInline}.

%---------------------------------------------------------------------------------------
%% @private
%% @spec decode_hlim(integer(), binary()) -> {integer(), binary()}.
%% @doc decode process for the HLim field
%% @returns the decoded Hop Limit value
%---------------------------------------------------------------------------------------
-spec decode_hlim(integer(), binary()) -> {integer(), binary()}.
decode_hlim(HLim, CarriedInline) ->
    <<HopLimit:8, Rest/bitstring>> = CarriedInline,
    case HLim of
        2#11 ->
            {255, CarriedInline};
        2#10 ->
            {64, CarriedInline};
        2#01 ->
            {1, CarriedInline};
        2#00 ->
            {HopLimit, Rest}
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @spec decode_sam(integer(), integer(), binary(), binary(), integer(), boolean()) -> {binary(), binary()}.
%% @doc decode process for the SAC field
%% @returns the decoded Source Address Mode value
%---------------------------------------------------------------------------------------
-spec decode_sam(integer(), integer(), binary(), binary(), integer(), boolean()) -> {binary(), binary()}.
decode_sam(SAC, SAM, CarriedInline, MacIID, _Context, RouteExist) when SAC == 0 ->
    case {SAM, RouteExist} of
        {2#11, true} ->
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, MacIID/binary>>, 
            {SrcAdd, CarriedInline};
        {2#11, false} ->
            <<_:48, IID:16>> = MacIID,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, 0:16, 16#00FF:16, 16#FE00:16, IID:16>>,
            {SrcAdd, CarriedInline};
        {2#10, _} ->
            <<Last16Bits:16, Rest/bitstring>> = CarriedInline,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, Last16Bits:16>>,
            {SrcAdd, Rest};
        {2#01, _} ->
            <<Last64Bits:64, Rest/bitstring>> = CarriedInline,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, Last64Bits:64>>,
            {SrcAdd, Rest};
        {2#00, _} ->
            <<SrcAdd:128, Rest/bitstring>> = CarriedInline,
            {SrcAdd, Rest}
    end;
decode_sam(SAC, _SAM, CarriedInline, _MacIID, 0, _RouteExist) when SAC == 1 ->
    <<SrcAdd:128, Rest/bitstring>> = CarriedInline,
    {<<SrcAdd:128>>, Rest};
decode_sam(SAC, SAM, CarriedInline, MacIID, Context, _RouteExist) when SAC == 1 ->
    SrcAddrPrefix = maps:get(Context, ?Context_id_table), 
    case SAM of
        2#11 ->
            <<_:48, IID:16>> = MacIID, 
            SrcAdd = <<SrcAddrPrefix/binary, 0:16, 16#00FF:16, 16#FE00:16, IID:16>>,
            {SrcAdd, CarriedInline}; 
        2#10 ->
            <<Last16Bits:16, Rest/bitstring>> = CarriedInline,
            SrcAdd = <<SrcAddrPrefix/binary, 16#000000FFFE00:48, Last16Bits:16>>,
            {SrcAdd, Rest};
        2#01 ->
            <<Last64Bits:64, Rest/bitstring>> = CarriedInline,
            SrcAdd = <<SrcAddrPrefix/binary, Last64Bits:64>>,
            {SrcAdd, Rest};
        2#00 ->
            SrcAdd = <<0:128>>,
            {SrcAdd, CarriedInline}
    end.

%---------------------------------------------------------------------------------------
%% @private
%% @spec decode_dam(integer(), integer(), integer(), binary(), binary(), integer(), boolean()) -> {binary(), binary()}.
%% @doc decode process for the DAC field
%% @returns the decoded Destination Address Mode value
%---------------------------------------------------------------------------------------
-spec decode_dam(integer(), integer(), integer(), binary(), binary(), integer(), boolean()) -> {binary(), binary()}.
decode_dam(0, 0, DAM, CarriedInline, MacIID, _Context, RouteExist) ->
    case {DAM, RouteExist} of
        {2#11, true} ->
            DstAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, MacIID/binary>>,
            {DstAdd, CarriedInline};
        {2#11, false} ->
            DstAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, 0:24, 16#FFFE:16, 0:24>>,
            {DstAdd, CarriedInline};
        {2#10, _} ->
            <<Last16Bits:16, Rest/bitstring>> = CarriedInline,
            DstAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, Last16Bits:16>>,
            {DstAdd, Rest};
        {2#01, _} ->
            <<Last64Bits:64, Rest/bitstring>> = CarriedInline,
            DstAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, Last64Bits:64>>,
            {DstAdd, Rest};
        {2#00, _} ->
            <<DstAdd:128, Rest/bitstring>> = CarriedInline,
            {DstAdd, Rest}
    end;
decode_dam(0, 1, _DAM, CarriedInline, _MacIID, 0, _RouteExist) ->
    <<DstAdd:128, Rest/bitstring>> = CarriedInline,
    {<<DstAdd:128>>, Rest};
decode_dam(0, 1, DAM, CarriedInline, _MacIID, Context, _RouteExist) ->
    DstAddrPrefix = maps:get(Context, ?Context_id_table), 
    case DAM of
        2#11 ->
            {<<DstAddrPrefix/binary, 0:24, 16#FFFE:16, 0:24>>, CarriedInline};
        2#10 ->
            <<Last16Bits:16, Rest/bitstring>> = CarriedInline,
            DstAdd = <<DstAddrPrefix/binary, 16#000000FFFE00:48, Last16Bits:16>>,
            {DstAdd, Rest};
        2#01 ->
            <<Last64Bits:64, Rest/bitstring>> = CarriedInline,
            DstAdd = <<DstAddrPrefix/binary, Last64Bits:64>>,
            {DstAdd, Rest};
        2#00 -> {error_reserved, CarriedInline}
    end;
decode_dam(1, 0, DAM, CarriedInline, _MacIID, _Context, _RouteExist) ->
    case DAM of
        2#11 ->
            <<Last8Bits:8, Rest/bitstring>> = CarriedInline,
            DstAdd = <<?MULTICAST_PREFIX:16, 0:104, Last8Bits>>,
            {DstAdd, Rest}; 
        2#10 ->
            <<Last32Bits:32, Rest/bitstring>> = CarriedInline,
            DstAdd = <<?MULTICAST_PREFIX:16, 0:80, Last32Bits:32>>,
            {DstAdd, Rest};
        2#01 ->
            <<Last48Bits:48, Rest/bitstring>> = CarriedInline,
            DstAdd = <<?MULTICAST_PREFIX:16, 0:64, Last48Bits:48>>,
            {DstAdd, Rest};
        2#00 ->
            <<DstAdd:128, Rest/bitstring>> = CarriedInline,
            {DstAdd, Rest}
    end;
decode_dam(1, 1, DAM, CarriedInline, _MacIID, _Context, _RouteExist) ->
    case DAM of
        2#00 ->
            <<Last48Bits:48, Rest/bitstring>> = CarriedInline,
            DstAdd = <<16#FF:16, 0:64, Last48Bits:48>>,
            {DstAdd, Rest}
    end.

-spec decode_udp_pckt(binary()) -> {integer(), integer(), integer(), binary()}.
decode_udp_pckt(Rest) ->
    <<C:1, P:2, Inline/bitstring>> = Rest, 
    {SrcPort, DstPort, Rest1} = decode_port(P, Inline), 
    {Checksum, Payload

} = decode_checksum(C, Rest1), 
    {SrcPort, DstPort, Checksum, Payload}.

-spec decode_port(integer(), binary()) -> {integer(), integer(), binary()}.
decode_port(P, Inline) ->
    case P of
        2#11 ->
            <<Last4S_Bits:4, Last4D_Bits:4, Rest/bitstring>> = Inline,
            SrcPort = <<?Oxf0b:12, Last4S_Bits:4>>,
            DstPort = <<?Oxf0b:12, Last4D_Bits:4>>,
            <<S:16>> = SrcPort,
            <<D:16>> = DstPort, 
            {S, D, Rest}; 
        2#10 -> 
            <<Last8S_Bits:8, DstPort:16, Rest/bitstring>> = Inline, 
            SrcPort = <<?Oxf0:8, Last8S_Bits:8>>, 
            <<S:16>> = SrcPort,
            {S, DstPort, Rest}; 
        2#01 -> 
            <<SrcPort:16, Last8D_Bits:8, Rest/bitstring>> = Inline, 
            DstPort = <<?Oxf0:8, Last8D_Bits:8>>, 
            <<D:16>> = DstPort,
            {SrcPort, D, Rest}; 
        2#00 -> 
            <<SrcPort:16, DstPort:16, Rest/bitstring>> = Inline, 
            {SrcPort, DstPort, Rest}
    end.

-spec decode_checksum(integer(), binary()) -> {integer(), binary()}.
decode_checksum(C, Inline) ->
    case C of 
        1 -> {0, Inline}; 
        0 ->  
            <<Checksum:16, Rest/bitstring>> = Inline, 
            {Checksum, Rest}
    end.

%---------------------------------------------------------------------------------------
%                          Packet Decompression Helper
%---------------------------------------------------------------------------------------

-spec convert_addr_to_bin(term()) -> binary().
convert_addr_to_bin(Address) ->
    DestAdd = case is_integer(Address) of
        true -> 
            encode_integer(Address);
        false ->
            Address
    end,
    DestAdd.

-spec tuple_to_bin(tuple()) -> binary().
tuple_to_bin(Tuple) ->
    Elements = tuple_to_list(Tuple),
    Binaries = [element_to_binary(Elem) || Elem <- Elements],
    list_to_binary(Binaries).

-spec element_to_binary(term()) -> binary().
element_to_binary(Elem) when is_integer(Elem) ->
    encode_integer(Elem);
element_to_binary(Elem) when is_binary(Elem) ->
    Elem;
element_to_binary(Elem) when is_tuple(Elem) ->
    tuple_to_bin(Elem);
element_to_binary(Elem) when is_list(Elem) ->
    list_to_binary(Elem).

%---------------------------------------------------------------------------------------
%
%                                Reassembly
%
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%% @spec datagram_info(binary()) -> map().
%% @doc helper function to retrieve datagram info
%% @returns a tuple containing useful datagram fields
%---------------------------------------------------------------------------------------
-spec datagram_info(binary()) -> map().
datagram_info(Fragment) ->
    <<FragType:5, Rest/bitstring>> = Fragment,
    case FragType of
        ?FRAG1_DHTYPE ->
            <<DatagramSize:11, DatagramTag:16, Payload/bitstring>> = Rest,
            FragInfo =
                #datagramInfo{
                    fragtype = FragType,
                    datagramSize = DatagramSize,
                    datagramTag = DatagramTag,
                    datagramOffset = 0,
                    payload = Payload
                },
            FragInfo;
        ?FRAGN_DHTYPE ->
            <<DatagramSize:11, DatagramTag:16, DatagramOffset:8, Payload/bitstring>> = Rest,
            FragInfo =
                #datagramInfo{
                    fragtype = FragType,
                    datagramSize = DatagramSize,
                    datagramTag = DatagramTag,
                    datagramOffset = DatagramOffset,
                    payload = Payload
                },
            FragInfo
    end.



%---------------------------------------------------------------------------------------
%% @spec store_fragment(atom(), term(), integer(), binary(), integer(), integer(), integer(), term()) -> {term(), map()}.
%% @doc Store the fragment in ETS and check if the datagram is complete
%---------------------------------------------------------------------------------------
-spec store_fragment(map(), term(), integer(), binary(), integer(), integer(), integer(), term()) -> {term(), map()}.
store_fragment(DatagramMap, Key, Offset, Payload, CurrTime, Size, Tag, _From) ->
    {Result, Map} = case ets:lookup(DatagramMap, Key) of
        [] ->
            handle_new_datagram(DatagramMap, Key, Offset, Payload, CurrTime, Size, Tag);
        [{Key, OldDatagram}] ->
            handle_existing_datagram(DatagramMap, Key, Offset, Payload, CurrTime, Size, OldDatagram)
    end,

    io:format("------------------------------------------------------~n"),
    io:format("DatagramMap after update:~n"),
    print_datagram_map(DatagramMap),
    io:format("------------------------------------------------------~n"),
    {Result, Map}.

-spec handle_new_datagram(map(), term(), integer(), binary(), integer(), integer(), integer()) -> {term(), map()}.
handle_new_datagram(DatagramMap, Key, Offset, Payload, CurrTime, Size, Tag) ->
    if byte_size(Payload) == Size ->
        ReassembledPacket = reassemble(#datagram{
            tag = Tag,
            size = Size,
            cmpt = byte_size(Payload),
            fragments = #{Offset => Payload},
            timer = CurrTime
        }),
        ets:insert(DatagramMap, {Key, ReassembledPacket}),
        {complete_first_frag, ReassembledPacket};
    true ->
        NewDatagram = #datagram{
            tag = Tag,
            size = Size,
            cmpt = byte_size(Payload),
            fragments = #{Offset => Payload},
            timer = CurrTime
        },
        ets:insert(DatagramMap, {Key, NewDatagram}),
        {incomplete_first, Key}
    end.

-spec handle_existing_datagram(map(), term(), integer(), binary(), integer(), integer(), map()) -> {term(), map()}.
handle_existing_datagram(DatagramMap, Key, Offset, Payload, CurrTime, Size, OldDatagram) ->
    Fragments = OldDatagram#datagram.fragments,
    case maps:is_key(Offset, Fragments) of
        true ->
            {duplicate, OldDatagram};
        false ->
            NewFragments = maps:put(Offset, Payload, Fragments),
            NewCmpt = OldDatagram#datagram.cmpt + byte_size(Payload),
            UpdatedDatagram = OldDatagram#datagram{
                cmpt = NewCmpt,
                fragments = NewFragments,
                timer = CurrTime
            },
            ets:insert(DatagramMap, {Key, UpdatedDatagram}),
            if NewCmpt == Size ->
                {complete, UpdatedDatagram};
            true ->
                {incomplete, UpdatedDatagram}
            end
    end.

-spec print_datagram_map(map()) -> ok.
print_datagram_map(DatagramMap) ->
    List = ets:tab2list(DatagramMap),
    lists:foreach(fun({Key, Value}) -> print_entry(Key, Value) end, List).

-spec print_entry(term(), tuple()) -> ok.
print_entry(Key, {datagram, Tag, Size, Cmpt, Timer, Fragments}) ->
    io:format("~p -> {datagram, ~p, ~p, ~p,~n    #{~n", [Key, Tag, Size, Cmpt]),
    print_fragments(Fragments),
    io:format("    }, ~p}~n", [Timer]).

-spec print_fragments(map()) -> ok.
print_fragments(Fragments) ->
    maps:fold(fun(Offset, Payload, Acc) ->
                      io:format("        ~p => ~p,~n", [Offset, Payload]),
                      Acc
              end, ok, Fragments).

%---------------------------------------------------------------------------------------
%% @spec reassemble(map()) -> binary().
%% @doc Reassemble the datagram from stored fragments
%---------------------------------------------------------------------------------------
-spec reassemble(map()) -> binary().
reassemble(Datagram) ->
    FragmentsMap = Datagram#datagram.fragments,
    SortedFragments =
        lists:sort([{Offset, Fragment} || {Offset, Fragment} <- maps:to_list(FragmentsMap)]),
    lists:foldl(
        fun({_Offset, Payload}, Acc) ->
            <<Acc/binary, Payload/binary>>
        end,
        <<>>,
        SortedFragments
    ).

%---------------------------------------------------------------------------------------
%
%                                    ROUTING
%
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
%                      Mesh Addressing Type and Header
%
%    0                   1                   2                   3
%    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%   |1 0|V|F|HopsLft|  originator address,final destination address
%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%

%---------------------------------------------------------------------------------------
%% @spec build_mesh_header(map()) -> binary().
%% @doc Creates mesh header binary
%---------------------------------------------------------------------------------------
-spec build_mesh_header(map()) -> binary().
build_mesh_header(MeshHeader) ->
    #mesh_header{


        v_bit = VBit,
        f_bit = FBit,
        hops_left = HopsLeft,
        originator_address = OriginatorAddress,
        final_destination_address = FinalDestinationAddress
    } = MeshHeader,
    <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
                 OriginatorAddress/binary, FinalDestinationAddress/binary>>.

%---------------------------------------------------------------------------------------
%% @spec create_new_mesh_datagram(binary(), binary(), binary()) -> binary().
%% @doc Creates new mesh header and returns new datagram
%---------------------------------------------------------------------------------------
-spec create_new_mesh_datagram(binary(), binary(), binary()) -> binary().
create_new_mesh_datagram(Datagram, SenderMacAdd, DstMacAdd) ->
    VBit =
        if
            byte_size(SenderMacAdd) =:= 8 -> 0;
            true -> 1
        end,
    FBit =
        if
            byte_size(DstMacAdd) =:= 8 -> 0;
            true -> 1
        end,

    MeshHeader =
        #mesh_header{
            v_bit = VBit,
            f_bit = FBit,
            hops_left = ?Max_Hops,
            originator_address = SenderMacAdd,
            final_destination_address = DstMacAdd
        },
    BinMeshHeader = build_mesh_header(MeshHeader),
    <<BinMeshHeader/binary, Datagram/bitstring>>.

%---------------------------------------------------------------------------------------
%% @spec create_new_mesh_header(binary(), binary(), boolean()) -> binary().
%% @doc Creates new mesh header
%---------------------------------------------------------------------------------------
-spec create_new_mesh_header(binary(), binary(), boolean()) -> binary().
create_new_mesh_header(SenderMacAdd, DstMacAdd, Extended_hopsleft) ->
    VBit =
        if
            byte_size(SenderMacAdd) =:= 8 -> 0;
            true -> 1
        end,
    FBit =
        if
            byte_size(DstMacAdd) =:= 8 -> 0;
            true -> 1
        end,
    
    case Extended_hopsleft of 
        true -> 
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, ?DeepHopsLeft:4, 
            SenderMacAdd/binary, DstMacAdd/binary, ?Max_DeepHopsLeft:8>>;
        false ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, ?Max_Hops:4, 
            SenderMacAdd/binary, DstMacAdd/binary>>
    end.

%---------------------------------------------------------------------------------------
%% @spec get_mesh_info(binary()) -> map().
%% @doc Returns routing info in mesh header
%---------------------------------------------------------------------------------------
-spec get_mesh_info(binary()) -> map().
get_mesh_info(Datagram) ->
    <<_:2, _V:1, _F:1, Hops_left:4, _/bitstring>> = Datagram,
    
    case Hops_left of 
        ?DeepHopsLeft ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:64, FinalDestinationAddress:64, DeepHopsLeft:8, Data/bitstring>> =
            Datagram;
        _ -> 
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:64, FinalDestinationAddress:64, Data/bitstring>> =
            Datagram, 
            DeepHopsLeft = undefined
    end,
    MeshInfo =
        #meshInfo{
            v_bit = VBit,
            f_bit = FBit,
            hops_left = HopsLeft,
            originator_address = <<OriginatorAddress:64>>,
            final_destination_address = <<FinalDestinationAddress:64>>,
            deep_hops_left =  DeepHopsLeft,
            payload = Data
        },
    MeshInfo.

%---------------------------------------------------------------------------------------
%% @spec contains_mesh_header(binary()) -> {boolean(), map()} | boolean().
%% @doc Check if datagram in mesh type, if so return true and mesh header info
%---------------------------------------------------------------------------------------
-spec contains_mesh_header(binary()) -> {boolean(), map()} | boolean().
contains_mesh_header(Datagram) ->
    case Datagram of
        <<Dispatch:2, _/bitstring>> when Dispatch == ?MESH_DHTYPE ->
            {true, get_mesh_info(Datagram)};
        _ ->
            false
    end.

%---------------------------------------------------------------------------------------
%% @spec remove_mesh_header(binary(), integer()) -> binary().
%% @doc Remove mesh header if the datagram was meshed (used in put and reasssemble)
%---------------------------------------------------------------------------------------
-spec remove_mesh_header(binary(), integer()) -> binary().
remove_mesh_header(Datagram, HopsLeft) ->
    case Datagram of
        <<?MESH_DHTYPE:2, _/bitstring>> ->
            case HopsLeft of 
                    ?DeepHopsLeft -> 
                        <<?MESH_DHTYPE:2, _Header:142, Rest/bitstring>> = Datagram,
                        Rest;
                    _->
                        <<?MESH_DHTYPE:2, _Header:134, Rest/bitstring>> = Datagram,
                        Rest
            end;
        _ ->
            Datagram
    end.

%---------------------------------------------------------------------------------------
%% @spec get_next_hop(binary(), binary(), binary(), binary(), integer(), boolean()) -> {boolean(), binary(), map()} | {boolean(), binary(), map(), map()}.
%% @doc Checks the next hop in the routing table and create new datagram with mesh
%% header if meshing is needed
%% returns a tuple {nexthop:boolean, binary, datagram, macHeader}
%---------------------------------------------------------------------------------------
-spec get_next_hop(binary(), binary(), binary(), binary(), integer(), boolean()) -> {boolean(), binary(), map()} | {boolean(), binary(), map(), map()}.
get_next_hop(CurrNodeMacAdd, SenderMacAdd, DestMacAddress, DestAddress, SeqNum, Hopsleft_extended) ->
    case <<DestAddress:128>> of 
        <<16#FF:8,_/binary>> ->
            MulticastAddr = generate_multicast_addr(<<DestAddress:128>>), 
            Multicast_EU64 = generate_EUI64_mac_addr(MulticastAddr),
            MHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = Multicast_EU64},
            BroadcastHeader = create_broadcast_header(SeqNum),
            MeshHdrBin = create_new_mesh_header(SenderMacAdd, DestMacAddress, Hopsleft_extended),
            Header = <<MeshHdrBin/bitstring, BroadcastHeader/bitstring>>,
            {false, Header, MHdr};
        _->
            case routing_table:get_route(DestMacAddress) of
                NextHopMacAddr when NextHopMacAddr =/= DestMacAddress ->
                    io:format("Next hop found: ~p~n", [NextHopMacAddr]),
                    MacHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = NextHopMacAddr},
                    MeshHdrBin = create_new_mesh_header(SenderMacAdd, DestMacAddress, Hopsleft_extended),
                    {true, MeshHdrBin, MacHdr};
                NextHopMacAddr when NextHopMacAddr == DestMacAddress ->
                    io:format("Direct link found ~n"),
                    MHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = DestMacAddress},
                    {false, <<>>, MHdr};
                _ ->
                    {false, <<>>, undefined, undefined}
            end
        end.

-spec get_next_hop(binary(), binary()) -> {boolean(), binary(), map()} | {boolean(), binary(), map(), map()}.
get_next_hop(CurrNodeMacAdd, DestMacAddress) ->
    case routing_table:get_route(DestMacAddress) of
        NextHopMacAddr when NextHopMacAddr =/= DestMacAddress ->
        MacHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = NextHopMacAddr},
        MeshHdrBin = create_new_mesh_header(CurrNodeMacAdd, DestMacAddress, ?DeepHopsLeft),
        {true, MeshHdrBin, MacHdr};
    NextHopMacAddr when NextHopMacAddr == DestMacAddress ->
        MHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = DestMacAddress},
        {false, <<>>, MHdr};
    _ ->
        {false, <<>>, undefined, undefined}
    end.

-spec generate_EUI64_mac_addr(binary()) -> binary().
generate_EUI64_mac_addr(MacAddress) when byte_size(MacAddress) == ?SHORT_ADDR_LEN ->
    get_EUI64_from_short_mac(MacAddress);
generate_EUI64_mac_addr(MacAddress) when byte_size(MacAddress) == ?EXTENDED_ADDR_LEN ->
    get_EUI64_from_extended_mac(MacAddress).

-spec get_EUI64_from_48bit_mac(binary()) -> binary().
get_EUI64_from_48bit_mac(MacAddress) ->
    <<First:24, Last:24>> = MacAddress, 
    <<A:8, Rest:16>> = <<First:24>>,
    NewA = A bxor 2,
    EUI64 = <<NewA:8, Rest:16, 16#fffe:16, Last:24>>,
    EUI64.

-spec get_EUI64_from_extended_mac(binary()) -> binary().
get_EUI64_from_extended_mac(MacAddress) ->
    <<A:8, Rest:56>> = MacAddress,  
    NewA = A bxor 2,   
    <<NewA:8, Rest:56>>.

-spec get_EUI64_from_short_mac(binary()) -> binary().
get_EUI64_from_short_mac(MacAddress) ->
    PanID = <<

16#FFFF:16>>,
    Extended48Bit = <<PanID/binary, 0:16, MacAddress/binary>>, 
    <<A:8, Rest:40>> = Extended48Bit, 
    ULBSetup = A band 16#FD,
    <<First:16, Last:24>> = <<Rest:40>>,
    EUI64 = <<ULBSetup:8, First:16, 16#FF:8, 16#FE:8, Last:24>>, 
    EUI64.

-spec generate_LL_addr(binary()) -> binary().
generate_LL_addr(MacAddress) ->
    EUI64 = generate_EUI64_mac_addr(MacAddress),
    LLAdd = <<16#FE80:16, 0:48, EUI64/binary>>,
    LLAdd.

-spec get_EUI64_mac_addr(binary()) -> binary().
get_EUI64_mac_addr(Address) ->
    <<_:64, MacAddr:64/bitstring>> = <<Address:128>>,
    MacAddr.

-spec get_16bit_mac_addr(binary()) -> binary().
get_16bit_mac_addr(Address) ->
    <<_:112, MacAddr:16/bitstring>> = <<Address:128>>,
    MacAddr.

-spec generate_multicast_addr(binary()) -> binary().
generate_multicast_addr(DestAddress) ->
    <<_:112, DST_15:8, DST_16:8>> = DestAddress,
    <<_:3, Last5Bits:5>> = <<DST_15:8>>,
    MulticastAddr = <<2#100:3, Last5Bits:5, DST_16:8>>,
    MulticastAddr.

-spec create_broadcast_header(integer()) -> binary().
create_broadcast_header(SeqNum) ->
   BC0_Header = <<?BC0_DHTYPE, SeqNum:8>>,
   BC0_Header.

%---------------------------------------------------------------------------------------
%
%                                    Metrics
%
%---------------------------------------------------------------------------------------
% compression_ratio(IPv6Header, Ipv6Pckt)->
%     {CompressedHeader, _} = compress_ipv6_header(Ipv6Pckt), 
%     OriginalHeaderLen = byte_size(ipv6:build_ipv6_header(IPv6Header)), 
%     CompressedLen = byte_size(CompressedHeader), 
%     CompressedRatio = (CompressedLen/OriginalHeaderLen)*100, 
%     io:format("CompressedRatio: ~p%~n",[CompressedRatio]),
%     CompressedRatio.

-spec compression_ratio(integer(), integer()) -> float().
compression_ratio(OrigPcktLen, CompressedPcktLen) ->
    CompressedRatio = (CompressedPcktLen / OrigPcktLen), 
    CompressedRatio.

%---------------------------------------------------------------------------------------
%
%                               Utils functions
%
%---------------------------------------------------------------------------------------

-spec print_as_binary(binary()) -> binary().
print_as_binary(Binary) ->
    Bytes = binary_to_list(Binary),
    lists:flatten([byte_to_binary(B) ++ " " || B <- Bytes]).

-spec byte_to_binary(integer()) -> binary().
byte_to_binary(B) ->
    Integer = integer_to_list(B, 2),
    pad_binary(Integer).

-spec pad_binary(binary()) -> binary().
pad_binary(Binary) ->
    case length(Binary) of
        8 ->
            Binary;
        _ ->
            pad_binary(["0" | Binary])
    end.

-spec hex_to_binary(list()) -> binary().
hex_to_binary(Hex) ->
    Binary = list_to_binary(hex_to_bytes(Hex)),
    Bytes = binary_to_list(Binary),
    lists:flatten([byte_to_binary(B) ++ " " || B <- Bytes]).

-spec hex_to_bytes(list()) -> list().
hex_to_bytes(Hex) ->
    lists:map(fun(X) -> list_to_integer([X], 16) end, Hex).

-spec complete_with_padding(binary()) -> binary().
complete_with_padding(Packet) ->
    HeaderLengthBits = bit_size(Packet),
    PaddingBits = (8 - HeaderLengthBits rem 8) rem 8,
    <<Packet/bitstring, 0:PaddingBits>>.

-spec convert(binary()) -> list().
convert(Binary) ->
    lists:flatten(
        lists:join(":",
            [io_lib:format("~2.16.0B", [B]) || <<B:8>> <= Binary]
        )
    ).

-spec generate_chunks() -> binary().
generate_chunks() ->
    NumChunks = 5,
    ChunkSize = 58,
    Chunks =
        lists:map(fun(N) -> generate_chunk(N, ChunkSize) end, lists:seq(NumChunks, 1, -1)),
    Result = lists:foldl(fun(A, B) -> <<A/binary, B/binary>> end, <<>>, Chunks),
    Result.

-spec generate_chunks(integer()) -> binary().
generate_chunks(Size) ->
    ChunkSize = 48,
    Chunks =
        lists:map(fun(N) -> generate_chunk(N, ChunkSize) end, lists:seq(Size, 1, -1)),
    Result = lists:foldl(fun(A, B) -> <<A/binary, B/binary>> end, <<>>, Chunks),
    Result.

-spec generate_chunk(integer(), integer()) -> binary().
generate_chunk(N, Size) ->
    Prefix = list_to_binary(io_lib:format("chunk_~2..0B", [N])),
    PrefixSize = byte_size(Prefix),
    PaddingSize = Size - PrefixSize,
    Padding = list_to_binary(lists:duplicate(PaddingSize, $a)),
    <<Prefix/binary, Padding/binary>>.