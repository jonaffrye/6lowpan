-module(lowpan).

-include("lowpan.hrl").

-export([
    pkt_encapsulation/2, fragment_ipv6_packet/2,
    reassemble/1, store_fragment/8,create_iphc_pckt/2, get_ipv6_pkt/2, datagram_info/1,
    compress_ipv6_header/1, build_datagram_pckt/2, build_firstFrag_pckt/5,
    get_ipv6_pckt_info/1, get_ipv6_payload/1, trigger_fragmentation/2,
    decompress_ipv6_header/2, encode_integer/1,
    tuple_to_bin/1, build_frag_header/1, get_next_hop/6, print_as_binary/1,
    hex_to_binary/1, complete_with_padding/1, generate_chunks/0,generate_chunks/1,
    build_mesh_header/1, get_mesh_info/1, contains_mesh_header/1,
    build_first_frag_header/1, get_unc_ipv6/1, get_EUI64_mac_addr/1,
    generate_EUI64_mac_addr/1, get_EUI64_from_48bit_mac/1,
    get_EUI64_from_short_mac/1, get_EUI64_from_extended_mac/1,
    generate_LL_addr/1, create_new_mesh_header/3, create_new_mesh_datagram/3,
    remove_mesh_header/2, convert_addr_to_bin/1, 
    check_tag_unicity/2, get_16bit_mac_addr/1, generate_multicast_addr/1
]).


%---------------------------------------------------------------------------------------
% return pre-built Ipv6 packet
%---------------------------------------------------------------------------------------
get_ipv6_pkt(Header, Payload) ->
    ipv6:build_ipv6_packet(Header, Payload).

%---------------------------------------------------------------------------------------
% create an uncompressed 6lowpan packet from an Ipv6 packet
%---------------------------------------------------------------------------------------
pkt_encapsulation(Header, Payload) ->
    Ipv6Pckt = get_ipv6_pkt(Header, Payload),
    DhTypebinary = <<?IPV6_DHTYPE:8, 0:16>>,
    <<DhTypebinary/binary, Ipv6Pckt/binary>>.

get_unc_ipv6(Ipv6Pckt) ->
    <<?IPV6_DHTYPE:8, Ipv6Pckt/bitstring>>.

%---------------------------------------------------------------------------------------
%
%                               Header compression
%
%---------------------------------------------------------------------------------------


%---------------------------------------------------------------------------------------
%         General form of 6Lowpan compression with UDP as nextHeader
%
%                           1                   2                   3
%      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%      |0|1|1|TF |N|HLI|C|S|SAM|M|D|DAM| SCI   | DCI   | comp. IPv6 hdr|
%      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%      | non compressed IPv6 fields .....                              |
%      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%      | LOWPAN_UDP    | non compressed UDP fields ...                 |
%      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%      | L4 data ...                                                   |
%      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


%---------------------------------------------------------------------------------------
% @doc compress an Ipv6 packet header according to the IPHC compression scheme
% @returns a tuple containing the compressed header, the payload and the values
% that should be carried inline
% @end
%---------------------------------------------------------------------------------------
compress_ipv6_header(Ipv6Pckt) ->
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),

    TrafficClass = PcktInfo#ipv6PckInfo.trafficClass,
    FlowLabel = PcktInfo#ipv6PckInfo.flowLabel,
    NextHeader = PcktInfo#ipv6PckInfo.nextHeader,
    HopLimit = PcktInfo#ipv6PckInfo.hopLimit,
    SourceAddress = PcktInfo#ipv6PckInfo.sourceAddress,
    DestAddress = PcktInfo#ipv6PckInfo.destAddress,

    Map = #{},
    List = [],

    {CID, UpdateMap0, UpdatedList0} =
        process_cid(SourceAddress, DestAddress, Map, List),

    {TF, UpdateMap1, UpdatedList1} =
        process_tf(TrafficClass, FlowLabel, UpdateMap0, UpdatedList0),
    
    {NH, UpdateMap2, UpdatedList2} = process_nh(NextHeader, UpdateMap1, UpdatedList1),
    
    {HLIM, UpdateMap3, UpdatedList3} = process_hlim(HopLimit, UpdateMap2, UpdatedList2),
    
    SAC = process_sac(SourceAddress),
    
    {SAM, UpdateMap4, UpdatedList4} =
        process_sam(SAC, CID, SourceAddress, UpdateMap3, UpdatedList3),
    
    M = process_m(DestAddress),
    
    DAC = process_dac(DestAddress),
    
    {DAM, CarrInlineMap, CarrInlineList} =
        process_dam(M, DAC, CID, DestAddress, UpdateMap4, UpdatedList4),

    CarrInlineBin = list_to_binary(CarrInlineList),
    %CH = {?IPHC_DHTYPE, TF, NH, HLIM, CID, SAC, SAM, M, DAC, DAM, CarrInlineBin},
    %io:format("CompressedHeader: ~p~n", [CH]),
    %CarrInlineLen = bit_size(CarrInlineBin),
    case NextHeader of
        ?UDP_PN ->
            UdpPckt = get_udp_data(Ipv6Pckt),
            CompressedUdpHeaderBin = compress_udp_header(UdpPckt, []),
            %CompressedUdpHeaderBinLen = bit_size(CompressedUdpHeaderBin),
            CompressedHeader =
                <<?IPHC_DHTYPE:3, TF:2, NH:1, HLIM:2, CID:1, SAC:1, SAM:2, M:1, DAC:1, DAM:2, CarrInlineBin/binary, CompressedUdpHeaderBin/binary>>,
            {CompressedHeader, CarrInlineMap};
        _ ->
            CompressedHeader =
                <<?IPHC_DHTYPE:3, TF:2, NH:1, HLIM:2, CID:1, SAC:1, SAM:2, M:1, DAC:1, DAM:2, CarrInlineBin/binary>>,
            {CompressedHeader, CarrInlineMap}
    end.

%---------------------------------------------------------------------------------------
% @private
% @doc process the TrafficClass and Flow label fields
% @returns a tuple containing the compressed values and the CarrInline values
% @end
%---------------------------------------------------------------------------------------
process_tf(TrafficClass, FlowLabel, CarrInlineMap, CarrInlineList) ->
    % TrafficClass integer to a binary
    <<DSCP:6, ECN:2>> = <<TrafficClass:8>>,

    case {ECN, DSCP, FlowLabel} of
        {0, 0, 0} ->
            % Traffic Class and Flow Label are elided
            {2#11, CarrInlineMap, CarrInlineList};

        {_, _, 0} ->
            UpdatedMap = CarrInlineMap#{"TrafficClass" => TrafficClass},
            % 8 bits tot
            Bin = <<ECN:2, DSCP:6>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            % Flow Label is elided
            {2#10, UpdatedMap, UpdatedList};

        {_, 0, _} ->
            UpdatedMap = CarrInlineMap#{"ECN" => ECN, "FlowLabel" => FlowLabel},
            % 24 bits tot
            Bin = <<ECN:2, 0:2, FlowLabel:20>>, % TODO FlowLabel should be carried on 3 bytes
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            % DSCP is elided
            {2#01, UpdatedMap, UpdatedList};

        _ ->
            UpdatedMap = CarrInlineMap#{"TrafficClass" => TrafficClass, "FlowLabel" => FlowLabel},
            % 32 bits tot
            Bin = <<ECN:2, DSCP:6, 0:4, FlowLabel:20>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            % ECN, DSCP, and Flow Label are carried inline
            {2#00, UpdatedMap, UpdatedList}
    end.

%---------------------------------------------------------------------------------------
% @private
% @doc process the NextHeader field
% @doc NextHeader specifies whether or not the next header is encoded using NHC
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%---------------------------------------------------------------------------------------
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?UDP_PN ->
    {1, CarrInlineMap, CarrInlineList};
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?TCP_PN ->
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader" => ?TCP_PN}, UpdatedList};
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?ICMP_PN ->
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader" => ?ICMP_PN}, UpdatedList};
process_nh(NextHeader, CarrInlineMap, CarrInlineList) ->
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader" => NextHeader}, UpdatedList}.

%---------------------------------------------------------------------------------------
% @private
% @doc process the HopLimit field
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%---------------------------------------------------------------------------------------
process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 1 ->
    {2#01, CarrInlineMap, CarrInlineList};
process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 64 ->
    {2#10, CarrInlineMap, CarrInlineList};
process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 255 ->
    {2#11, CarrInlineMap, CarrInlineList};
process_hlim(HopLimit, CarrInlineMap, CarrInlineList) ->
    Bin = <<HopLimit:8>>,
    L = [Bin],
    UpdatedList = CarrInlineList ++ L,
    {2#00, CarrInlineMap#{"HopLimit" => HopLimit}, UpdatedList}.

%---------------------------------------------------------------------------------------
% @private
% @doc process the Context Identifier Extension field
% @doc If this bit is 1, an 8 bit CIE field follows after the DAM field
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%---------------------------------------------------------------------------------------
process_cid(SrcAdd, DstAdd, CarrInlineMap, CarrInlineList) ->
    <<SrcAddPrefix:16, _/binary>> = <<SrcAdd:128>>,
    <<DstAddPrefix:16, _/binary>> = <<DstAdd:128>>,
    
    case {SrcAddPrefix, DstAddPrefix} of
        {?LINK_LOCAL_PREFIX, ?LINK_LOCAL_PREFIX} ->
            {0, CarrInlineMap, CarrInlineList};
        {_, ?LINK_LOCAL_PREFIX} ->
            {0, CarrInlineMap, CarrInlineList};
        {?LINK_LOCAL_PREFIX, _} ->
            {0, CarrInlineMap, CarrInlineList};

        {?MULTICAST_PREFIX, ?MULTICAST_PREFIX} ->
            {0, CarrInlineMap, CarrInlineList};
        {?MULTICAST_PREFIX, _} ->
            {0, CarrInlineMap, CarrInlineList};
        {_, ?MULTICAST_PREFIX} ->
            {0, CarrInlineMap, CarrInlineList};

        {?GLOBAL_PREFIX_1, ?GLOBAL_PREFIX_1}  ->
            {0, CarrInlineMap, CarrInlineList};
        {_, ?GLOBAL_PREFIX_1}  ->
            {0, CarrInlineMap, CarrInlineList};
        {?GLOBAL_PREFIX_1, _}  ->
            {0, CarrInlineMap, CarrInlineList};


        _-> {1, CarrInlineMap, CarrInlineList}
    end.

%---------------------------------------------------------------------------------------
% @private
% @doc process the Source Address Compression
% @doc SAC specifies whether the compression is stateless or statefull
% @returns the compressed value
% @end
%---------------------------------------------------------------------------------------
process_sac(SrcAdd) ->
    <<Prefix:16, _/binary>> = <<SrcAdd:128>>,

    case Prefix of
        ?LINK_LOCAL_PREFIX ->
            0;
        ?MULTICAST_PREFIX ->
            1;
        ?GLOBAL_PREFIX_1 ->
            1;
        %?GLOBAL_PREFIX_2 -> 1;
        ?GLOBAL_PREFIX_3 ->
            1;
        ?MESH_LOCAL_PREFIX ->
            1;
        16#0000 ->
            0;
        _ ->
            1
    end.

%---------------------------------------------------------------------------------------
% @private
% @doc process for the Source Address Mode
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%---------------------------------------------------------------------------------------
process_sam(SAC, _CID, SrcAdd, CarrInlineMap, CarrInlineList) when SAC == 0 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case SrcAddBits of
        <<?LINK_LOCAL_PREFIX:16, 0:48, _:24, 16#FFFE:16, _:24>> ->
            % the address is fully elided
            {2#11, CarrInlineMap, CarrInlineList};
        
        <<0:128>> ->
            % O bits he address is fully elided
            {2#11, CarrInlineMap, CarrInlineList};

        <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>> ->
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last16Bits},
            % the first 112 bits are elided, last 16 IID bits are carried in-line
            {2#10, UpdatedMap, UpdatedList};

        <<?LINK_LOCAL_PREFIX:16, 0:48, _:64>> ->
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last64Bits},
            % the first 64 bits are elided, last 64 bits (IID) are carried in-line
            {2#01, UpdatedMap, UpdatedList};
        _ ->
            Bin = <<SrcAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            % full address is carried in-line
            {2#00, CarrInlineMap#{"SAM" => SrcAdd}, UpdatedList}
    end;
process_sam(SAC, 0, SrcAdd, CarrInlineMap, CarrInlineList) when SAC == 1 ->
    Bin = <<SrcAdd:128>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {2#00, CarrInlineMap#{"SAM" => SrcAdd}, UpdatedList};
process_sam(SAC, 1, SrcAdd, CarrInlineMap, CarrInlineList) when SAC == 1 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case SrcAddBits of
        %TODO get context address
        <<0:128>> ->
            % the address is fully elided and derived from the context
            {2#11, CarrInlineMap, CarrInlineList};
        <<_:16, _:48, 16#000000FFFE00:48, _:16>> ->
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last16Bits},
            % the first 64 bits are derived from the context, last 16 IID bits are carried in-line
            {2#10, UpdatedMap,UpdatedList};
        %TODO how to represent first context 64 bit
        <<_:16, _:48, _:64>> ->
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last64Bits},
            % the first 64 bits are derived from the context, last 64 bits IID are carried in-line
            {2#01, UpdatedMap, UpdatedList}
    end.

% _ ->
%     {2#00,CarrInlineMap, CarrInlineList} %  the unspecified address ::

%---------------------------------------------------------------------------------------
% @private
% @doc process for the Multicast compression
% @returns the compressed value
% @end
%---------------------------------------------------------------------------------------
process_m(DstAdd) ->
    <<Prefix:16, _/bitstring>> = <<DstAdd:128>>,
    case Prefix of
        ?MULTICAST_PREFIX ->
            1;
        _ ->
            0
    end.

%---------------------------------------------------------------------------------------
% @private
% @doc process for the Destination Address Compression
% @doc DAC specifies whether the compression is stateless or statefull
% @returns the compressed value
% @end
%---------------------------------------------------------------------------------------
process_dac(DstAdd) ->
    <<Prefix:16, _/binary>> = <<DstAdd:128>>,

    case Prefix of
        ?LINK_LOCAL_PREFIX ->
            0;
        ?MULTICAST_PREFIX ->
            0;
        ?GLOBAL_PREFIX_1 ->
            1;
        %?GLOBAL_PREFIX_2 -> 1;
        ?GLOBAL_PREFIX_3 ->
            1;
        ?MESH_LOCAL_PREFIX ->
            1;
        16#0000 ->
            0;
        _ ->
            1
    end.

%---------------------------------------------------------------------------------------
% @private
% @doc process for the Destination Address Mode
% @param DAC, M, Cid, DstAdd, CarrInlineMap
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%---------------------------------------------------------------------------------------
process_dam(0, 0, _, DstAdd, CarrInlineMap, CarrInlineList) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,

    case DestAddBits of
        <<?LINK_LOCAL_PREFIX:16, 0:112>> ->
            % the address is fully elided
            {2#11, CarrInlineMap, CarrInlineList};
        <<?LINK_LOCAL_PREFIX:16, 0:48, _:24, 16#FFFE:16, _:24>> ->
            % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
            {2#11, CarrInlineMap, CarrInlineList};

        <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>> ->
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last16Bits},
            % the first 112 bits are elided, last 16 bits are in-line
            {2#10, UpdatedMap, UpdatedList};

        <<?LINK_LOCAL_PREFIX:16,  0:48, _:64>> ->
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last64Bits},
            % the first 64 bits are elided, last 64 bits are in-line
            {2#01, UpdatedMap, UpdatedList};
        _ ->
            Bin = <<DstAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            % full address is carried in-line
            {2#00, CarrInlineMap#{"DAM" => DstAdd}, UpdatedList}
    end;
%M, DAC, CID
process_dam(0, 1, 1, DstAdd, CarrInlineMap, CarrInlineList) ->
    DestAddBits = <<DstAdd:128>>,
    %<<Prefix: 8,_:120>> = DestAddBits,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,

    io:format("DestAddBits: ~p~n", [DestAddBits]),
    case DestAddBits of
        %<<?GLOBAL_PREFIX:8,_:8, _:112>> ->
        %   {2#11, CarrInlineMap, CarrInlineList}; % the address is fully elided
        <<0:128>> -> {2#11, CarrInlineMap, CarrInlineList};

        <<?GLOBAL_PREFIX_1:16, _:48, 16#000000FFFE00:48, _:16>> ->
            % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last16Bits},
            % the first 112 bits are elided, last 16 bits are in-line
            {2#10, UpdatedMap, UpdatedList};

        <<?GLOBAL_PREFIX_1:16, _:112>> ->
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last64Bits},
            % the first 64 bits are elided, last 64 bits are in-line
            {2#01, UpdatedMap, UpdatedList};
        _ ->
            %UpdatedList = CarrInlineList++[DstAdd],

            % RESERVED
            {2#00, CarrInlineMap, CarrInlineList}
    end;
%M, DAC, CID, DstAdd
process_dam(0, 1, 0, DstAdd, CarrInlineMap, CarrInlineList) ->
    Bin = <<DstAdd:128>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {2#00, CarrInlineMap#{"DAM" => DstAdd}, UpdatedList};
%M, DAC, CID
process_dam(1, 0, _, DstAdd, CarrInlineMap, CarrInlineList) ->
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
            UpdatedMap = CarrInlineMap#{"DAM" => Last8Bits},
            {2#11, UpdatedMap, UpdatedList};
        %ffXX::00XX:XXXX.
        <<16#FF:8, _:8, 0:80, _:32>> ->
            Bin = <<Last32Bits:32>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last32Bits},
            {2#10, UpdatedMap, UpdatedList};
        % ffXX::00XX:XXXX:XXXX.
        <<16#FF:8, _:8, 0:64, _:48>> ->
            Bin = <<Last48Bits:48>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last48Bits},
            {2#01, UpdatedMap, UpdatedList};
        _ ->
            Bin = <<DstAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            % full address is carried in-line
            {2#00, CarrInlineMap#{"DAM" => DstAdd}, UpdatedList}
    end;
%M, DAC
process_dam(1, 1, _, DstAdd, CarrInlineMap, CarrInlineList) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:80, Last48Bits:48>> = DestAddBits,
    case DestAddBits of
        <<16#FF, _:112>> ->
            Bin = <<Last48Bits:48>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last48Bits},
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

compress_udp_header(UdpPckt, CarriedInline) ->
    <<SrcPort:16, DstPort:16, _:16, Checksum:16>> = <<UdpPckt:64>>,

    {P, CarriedInlineList} = process_udp_ports(SrcPort, DstPort, CarriedInline),
    {C, CarriedIn} = process_udp_checksum(Checksum, CarriedInlineList),

    %io:format("C: ~p~nP: ~p~n", [C, P]),
    Inline = list_to_binary(CarriedIn),

    CompressedUdpHeader = <<?UDP_DHTYPE:5, C:1, P:2, Inline/bitstring>>,
    CompressedUdpHeader.

process_udp_ports(SrcPort, DstPort, CarriedInline) ->
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

process_udp_checksum(Checksum, CarriedInline) ->
    % TODO check checksum values
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
% create a compressed 6lowpan packet (with iphc compression) from an Ipv6 packet
%---------------------------------------------------------------------------------------
create_iphc_pckt(IphcHeader, Payload) ->
    <<IphcHeader/binary, Payload/bitstring>>.

%---------------------------------------------------------------------------------------
% @doc return value field of a given Ipv6 packet
% @end
%---------------------------------------------------------------------------------------
get_ipv6_pckt_info(Ipv6Pckt) ->
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
% @doc return UDP data from a given Ipv6 packet if it contains a UDP nextHeader
% @end
%---------------------------------------------------------------------------------------
get_udp_data(Ipv6Pckt) ->
    <<_:320, UdpPckt:64, _/binary>> = Ipv6Pckt,
    UdpPckt.

%---------------------------------------------------------------------------------------
% return the payload of a given Ipv6 packet
%---------------------------------------------------------------------------------------
get_ipv6_payload(Ipv6Pckt) ->
    <<_:192, _:128, Payload/binary>> = Ipv6Pckt,
    Payload.


%---------------------------------------------------------------------------------------
% Encode an Integer value in a binary format using an appropriate amount of bit
%---------------------------------------------------------------------------------------
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
% returns a binary containing fragmentation header fields
%---------------------------------------------------------------------------------------
build_frag_header(FragHeader) ->
    #frag_header{
        frag_type = FragType,
        datagram_size = DatagramSize,
        datagram_tag = DatagramTag,
        datagram_offset = DatagramOffset
    } = FragHeader,
    <<FragType:5, DatagramSize:11, DatagramTag:16, DatagramOffset:8>>.

build_first_frag_header(FragHeader) ->
    #frag_header{
        frag_type = FragType,
        datagram_size = DatagramSize,
        datagram_tag = DatagramTag
    } = FragHeader,
    <<FragType:5, DatagramSize:11, DatagramTag:16>>.

%---------------------------------------------------------------------------------------
build_firstFrag_pckt(FragType, DatagramSize, DatagramTag, CompressedHeader, Payload) ->
    %TODO if wireshark doesn't recongnize it, cange it to binary
    %PayloadLen = bit_size(Payload),
    <<FragType:5, DatagramSize:11, DatagramTag:16, CompressedHeader/binary, Payload/bitstring>>.

%---------------------------------------------------------------------------------------
% create a datagram packet (fragments)
%---------------------------------------------------------------------------------------
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
% check if a packet needs to be fragmented or not and has a valid size 
% returns a list of fragments if yes, the orginal packet if not
%---------------------------------------------------------------------------------------
trigger_fragmentation(CompPckt, DatagramTag) when byte_size(CompPckt) =< ?MAX_FRAG_SIZE ->
    PcktLengt = byte_size(CompPckt),

    ValidLength = PcktLengt =< ?MAX_FRAME_SIZE,
    case ValidLength of
        false ->
            io:format("The received Ipv6 packet need fragmentation to be transmitted~n"),
            Fragments = lowpan:fragment_ipv6_packet(CompPckt, DatagramTag),
            {true, Fragments};
        true ->
            io:format("No fragmentation needed~n"),
            {false, CompPckt}
    end; 

trigger_fragmentation(_CompPckt, _DatagramTag) ->
    {size_err, error_frag_size}.


%---------------------------------------------------------------------------------------
% @doc Fragment a given Ipv6 packet
% @returns a list of fragmented packets having this form:
% [{FragHeader1, Fragment1}, ..., {FragHeaderN, FragmentN}]
% @end
%---------------------------------------------------------------------------------------
% fragment_ipv6_packet(CompIpv6Pckt, PacketLen) when is_binary(CompIpv6Pckt) ->
%     DatagramTag = rand:uniform(65536),
%     frag_process(CompIpv6Pckt, DatagramTag, PacketLen, 0, []);

fragment_ipv6_packet(CompIpv6Pckt, DatagramTag) when is_binary(CompIpv6Pckt) ->
    Size = byte_size(CompIpv6Pckt),
    frag_process(CompIpv6Pckt, DatagramTag, Size, 0, []).
 
%---------------------------------------------------------------------------------------
% @private
% @doc helper function to process the received packet
% @returns a list of fragmented packets
% [{Header1, Fragment1}, ..., {HeaderN, FragmentN}]
% Input :
%   Ipv6Pckt := binary
%   Pckt size := integer
%   DatagramTag := integer
%   Offset := integer
%   Accumulator : list
% @end
%---------------------------------------------------------------------------------------
frag_process(<<>>, _, _, _, Acc) ->
    lists:reverse(Acc);
frag_process(CompIpv6Pckt, DatagramTag, PacketLen, Offset, Acc) ->
    MaxSize = ?MAX_FRAME_SIZE - ?FRAG_HEADER_SIZE,
    PcktSize = byte_size(CompIpv6Pckt),
    FragmentSize = min(PcktSize, MaxSize),

    %io:format("~p nth frag compressed size: ~p bytes~n", [Offset+1, FragmentSize]),
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
% Check if tag exist in the map, if so generate a new one and update the tag map
%---------------------------------------------------------------------------------------
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
%                                Header Decompression
%
%---------------------------------------------------------------------------------------

%get_prefix(ContextId) ->
%    maps:get(ContextId, ?CONTEXT_TABLE).

%---------------------------------------------------------------------------------------
% @doc decompress an Ipv6 packet header commpressed according
% to the IPHC compression scheme
% @returns the decompressed Ipv6 packet
% @end
%---------------------------------------------------------------------------------------
decompress_ipv6_header(CompressedPacket, EUI64) ->
    % first field is the dispatch
    <<_:8, TF:8, NH:8, HLIM:8, CID:8, SAC:8, SAM:8, M:8, DAC:8, DAM:8, Rest/binary>> =
        CompressedPacket,
    % Rest contain carriedInline values + payload
    %CompressedHeader = {TF, NH, HLIM, CID, SAC, SAM, M, DAC, DAM},
    %io:format("CompressedHeader: ~p~n", [CompressedHeader]),
    %MacIID = get_iid_from_mac(EUI64),
    % RestN represents the CarriedInline with field of interest
    {Context, Rest0} = decode_cid(CID, Rest),
    {TrafficClass, FlowLabel, Rest1} = decode_tf(TF, Rest0),
    {NextHeader, Rest2} = decode_next_header(NH, Rest1),
    {HopLimit, Rest3} = decode_hlim(HLIM, Rest2),
    {SourceAddress, Rest4} = decode_sam(SAC, SAM, Rest3, EUI64, Context),
    {DestAddress, Payload} = decode_dam(M, DAC, DAM, Rest4, EUI64, Context),
    PayloadLength = byte_size(Payload),
    DecompressedFields =
        {TrafficClass, FlowLabel, PayloadLength, NextHeader, HopLimit, SourceAddress, DestAddress, Payload},

    io:format("DecompressedFields ~p~n", [DecompressedFields]),
    DecompressedPckt = tuple_to_bin(DecompressedFields),
    %{TrafficClass, FlowLabel, NextHeader, HopLimit, SourceAddress, DestAddress, Payload}.
    DecompressedPckt.

%---------------------------------------------------------------------------------------
% @private
% @doc decode process for the CID field
% @returns the decoded ContextID
% @end
%---------------------------------------------------------------------------------------
decode_cid(CID, CarriedInline) when CID == 1 ->
    <<Context:16, Rest/binary>> = CarriedInline,
    {Context, Rest}.

%---------------------------------------------------------------------------------------
% @private
% @doc decode process for the TF field
% @returns the decoded TrafficClass and FlowLabel value
% @end
%---------------------------------------------------------------------------------------
decode_tf(TF, CarriedInline) ->
    % TODO, check max value on 20bits for FL, and infer bit split
    <<TrafficClass:8, FL1:8, FL2:8, FL3:8, Rest/bitstring>> = CarriedInline,

    FlowLabel = <<FL1, FL2, FL3>>,

    case TF of
        % everything elided
        2#11 ->
            {<<0:8>>, <<0:20>>, CarriedInline};
        % Flow Label is elided, retrieve TF value carriedInline => get first 8bit of CarriedInline
        2#10 ->
            % get 8 bits of carried inline
            <<ECN:2, DSCP:6, Rest/bitstring>> = CarriedInline,
            TrafficClass = <<ECN/binary, DSCP/binary>>,
            FlowLabel = <<0:20>>,

            {TrafficClass, FlowLabel, Rest};
        % only DSCP is elided
        2#01 ->
            % get first 24 bits of carried inline
            <<ECN_PADDING:4, FL:20, Rest/bitstring>> = CarriedInline,
            TrafficClass = <<ECN_PADDING:8>>,
            FlowLabel = <<FL:20>>,

            {TrafficClass, FlowLabel, Rest};
        % nothing elided
        2#00 ->
            %io:format("FlowLabel: ~p~n",[FlowLabel]),
            % get 32 bits of carried inline
            <<ECN:2, DSCP:6, _:4, FL:20, Rest/bitstring>> = CarriedInline,
            TrafficClass = <<ECN, DSCP>>,
            FlowLabel = <<FL:20>>,
            {TrafficClass, FlowLabel, Rest}
    end.

%---------------------------------------------------------------------------------------
% @private
% @doc decode process for the NH field
% @returns the decoded NextHeader value
% @end
%---------------------------------------------------------------------------------------
decode_next_header(_, CarriedInline) ->
    <<NextHeader:8, Rest/binary>> = CarriedInline,
    {NextHeader, Rest}.

%---------------------------------------------------------------------------------------
% @private
% @doc decode process for the HLim field
% @returns the decoded Hop Limit value
% @end
%---------------------------------------------------------------------------------------
decode_hlim(HLim, CarriedInline) ->
    <<HopLimit:8, Rest/binary>> = CarriedInline,
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
% @private
% @doc decode process for the SAC field
% @returns the decoded Source Address Mode value
% @end
%---------------------------------------------------------------------------------------
decode_sam(SAC, SAM, CarriedInline, MacIID, _) when SAC == 0 ->
    case SAM of
        2#11 ->
            % the last 64bits should be computed from the encapsulating header as shown in section 3.2.2 from rfc6282
            <<_, _, _, _, _, _, G, H>> = MacIID,
            IID = <<G, H>>,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, IID/binary>>,
            {SrcAdd, CarriedInline};
        % last 16bits carried
        2#10 ->
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A, B>>,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, Last16Bits/binary>>,
            {SrcAdd, Rest};
        % last 64bits carried
        2#01 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A, B, C, D, E, F, G, H>>,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, Last64Bits/binary>>,
            {SrcAdd, Rest};
        % full add carried
        2#00 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, A2:8, B2:8, C2:8, D2:8, E2:8, F2:8, G2:8, H2:8, Rest/binary>> =
                CarriedInline,
            SrcAdd = <<A, B, C, D, E, F, G, H, A2, B2, C2, D2, E2, F2, G2, H2>>,
            {SrcAdd, Rest}
    end;
decode_sam(SAC, SAM, CarriedInline, _, Context) when SAC == 1 ->
    case SAM of
        % 2#00 -> % the unspecified address ::
        %     SrcAdd = <<0:128>>,
        %     {SrcAdd, CarriedInline};

        % full add carried
        2#00 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, A2:8, B2:8, C2:8, D2:8, E2:8, F2:8, G2:8, H2:8, Rest/binary>> =
                CarriedInline,
            SrcAdd = <<A, B, C, D, E, F, G, H, A2, B2, C2, D2, E2, F2, G2, H2>>,
            {SrcAdd, Rest};
        % last 64bits carried
        2#01 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, Rest/binary>> = CarriedInline,
            ContextAddr = maps:get(Context, ?Context_id_table),
            Last64Bits = <<A, B, C, D, E, F, G, H>>,
            SrcAdd = <<ContextAddr/binary, Last64Bits/binary>>,
            {SrcAdd, Rest};
        % last 16bits carried
        2#10 ->
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A, B>>,
            ContextAddr = maps:get(Context, ?Context_id_table),
            SrcAdd = <<ContextAddr/binary, 16#000000FFFE00:48, Last16Bits/binary>>,
            {SrcAdd, Rest};
        2#11 ->
            % the address is fully derived from the context
            %<<_,_,_,_,_,_,G,H>> = MacIID,
            %IID = <<G,H>>,
            ContextAddr = maps:get(Context, ?Context_id_table),
            SrcAdd = <<ContextAddr/binary>>,
            {SrcAdd, CarriedInline}
    end.

%---------------------------------------------------------------------------------------
% @private
% @doc decode process for the DAC field
% @returns the decoded Destination Address Mode value
% @end
%---------------------------------------------------------------------------------------
decode_dam(M, DAC, DAM, CarriedInline, _, _) when M == 0; DAC == 0 ->
    case DAM of
        2#11 ->
            {<<?LINK_LOCAL_PREFIX:16, 0:112>>, CarriedInline};
        % last 16bits carried
        2#10 ->
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A, B>>,
            DstAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, Last16Bits/binary>>,
            {DstAdd, Rest};
        % last 64bits carried
        2#01 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A, B, C, D, E, F, G, H>>,
            DstAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, Last64Bits/binary>>,
            {DstAdd, Rest};
        % full add carried
        2#00 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, A2:8, B2:8, C2:8, D2:8, E2:8, F2:8, G2:8, H2:8, Rest/binary>> =
                CarriedInline,
            DstAdd = <<A, B, C, D, E, F, G, H, A2, B2, C2, D2, E2, F2, G2, H2>>,
            {DstAdd, Rest}
    end;
decode_dam(M, DAC, DAM, CarriedInline, _, Context) when M == 0; DAC == 1 ->
    case DAM of
        2#11 ->
            {<<?GLOBAL_PREFIX_1, 0:112>>, CarriedInline};
        % last 16bits carried
        2#10 ->
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A, B>>,
            ContextAddr = maps:get(Context, ?Context_id_table),
            DstAdd = <<ContextAddr/binary, 16#000000FFFE00:48, Last16Bits/binary>>,
            {DstAdd, Rest};
        % last 64bits carried
        2#01 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A, B, C, D, E, F, G, H>>,
            ContextAddr = maps:get(Context, ?Context_id_table),
            DstAdd = <<ContextAddr/binary, Last64Bits/binary>>,
            {DstAdd, Rest};
        % full add carried
        2#00 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, A2:8, B2:8, C2:8, D2:8, E2:8, F2:8, G2:8, H2:8, Rest/binary>> =
                CarriedInline,
            DstAdd = <<A, B, C, D, E, F, G, H, A2, B2, C2, D2, E2, F2, G2, H2>>,
            {DstAdd, Rest}
    end;
% 2#00 -> {error_reserved, CarriedInline}
decode_dam(M, DAC, DAM, CarriedInline, _, _) when M == 1; DAC == 0 ->
    case DAM of
        2#00 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, A2:8, B2:8, C2:8, D2:8, E2:8, F2:8, G2:8, H2:8, Rest/binary>> =
                CarriedInline,
            DstAdd = <<A, B, C, D, E, F, G, H, A2, B2, C2, D2, E2, F2, G2, H2>>,
            {DstAdd, Rest};
        % last 48bits carried
        2#01 ->
            <<_:8, _:8, C:8, D:8, E:8, F:8, G:8, H:8, Rest/binary>> = CarriedInline,
            Last48Bits = <<C, D, E, F, G, H>>,
            DstAdd = <<?MULTICAST_PREFIX:16, 0:64, Last48Bits/binary>>,
            {DstAdd, Rest};
        % last 32bits carried
        2#10 ->
            <<A:8, B:8, C:8, D:8, Rest/binary>> = CarriedInline,
            Last32Bits = <<A, B, C, D>>,
            DstAdd = <<?MULTICAST_PREFIX, 0:80, Last32Bits/binary>>,
            {DstAdd, Rest};
        % last 8bits carried
        2#11 ->
            <<Last8Bits:8, Rest/binary>> = CarriedInline,
            DstAdd = <<16#FF02:16, 0:104, Last8Bits>>,
            {DstAdd, Rest}
    end;
decode_dam(M, DAC, DAM, CarriedInline, _, _) when M == 1; DAC == 1 ->
    case DAM of
        % last 48bits carried
        2#00 ->
            <<A:8, B:8, C:8, D:8, E:8, F:8, Rest/binary>> = CarriedInline,
            Last48Bits = <<A, B, C, D, E, F>>,
            DstAdd = <<16#FF, 0:64, Last48Bits/binary>>,
            {DstAdd, Rest}
    end.


%---------------------------------------------------------------------------------------
%                          Packet Decompression Helper
%---------------------------------------------------------------------------------------

convert_addr_to_bin(Address)->
    DestAdd = case is_integer(Address) of
        true -> 
            lowpan:encode_integer(Address);
        false ->
            Address
    end,
    DestAdd.

%---------------------------------------------------------------------------------------
% Encode a tuple in a binary format
%---------------------------------------------------------------------------------------
tuple_to_bin(Tuple) ->
    Elements = tuple_to_list(Tuple),
    Binaries = [element_to_binary(Elem) || Elem <- Elements],
    list_to_binary(Binaries).

%---------------------------------------------------------------------------------------
% Encode an Integer to a binary
%---------------------------------------------------------------------------------------
element_to_binary(Elem) when is_integer(Elem) ->
    encode_integer(Elem);
element_to_binary(Elem) when is_binary(Elem) ->
    Elem;
element_to_binary(Elem) when is_tuple(Elem) ->
    tuple_to_bin(Elem);
element_to_binary(Elem) when is_list(Elem) ->
    list_to_binary(Elem).



%----------------------------------------------------------------------------------------
%
%                                Reassembly
%
%---------------------------------------------------------------------------------------

%---------------------------------------------------------------------------------------
% @doc helper function to retrieve datagram info
% @returns a tuple containing useful datagram fields
% @end
%---------------------------------------------------------------------------------------
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
% Store the fragment in ETS and check if the datagram is complete
%---------------------------------------------------------------------------------------
store_fragment(DatagramMap, Key, Offset, Payload, CurrTime, Size, Tag, _From) ->
    {Result, Map} = case ets:lookup(DatagramMap, Key) of
        [] ->
            % Datagram not in map
            handle_new_datagram(DatagramMap, Key, Offset, Payload, CurrTime, Size, Tag);
        [{Key, OldDatagram}] ->
            handle_existing_datagram(DatagramMap, Key, Offset, Payload, CurrTime, Size, OldDatagram)
    end,

    io:format("------------------------------------------------------~n"),
    io:format("DatagramMap after update:~n"),
    print_datagram_map(DatagramMap),
    io:format("------------------------------------------------------~n"),
    {Result, Map}.

handle_new_datagram(DatagramMap, Key, Offset, Payload, CurrTime, Size, Tag) ->
    if byte_size(Payload) == Size ->
        % Complete datagram in a single fragment
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


print_datagram_map(DatagramMap) ->
    List = ets:tab2list(DatagramMap),
    lists:foreach(fun({Key, Value}) -> print_entry(Key, Value) end, List).

print_entry(Key, {datagram, Tag, Size, Cmpt, Timer, Fragments}) ->
    io:format("~p -> {datagram, ~p, ~p, ~p,~n    #{~n", [Key, Tag, Size, Cmpt]),
    print_fragments(Fragments),
    io:format("    }, ~p}~n", [Timer]).

print_fragments(Fragments) ->
    maps:fold(fun(Offset, Payload, Acc) ->
                      io:format("        ~p => ~p,~n", [Offset, Payload]),
                      Acc
              end, ok, Fragments).

%---------------------------------------------------------------------------------------
% Reassemble the datagram from stored fragments
%---------------------------------------------------------------------------------------
reassemble(Datagram) ->
    FragmentsMap = Datagram#datagram.fragments,
    % Sort fragments by offset and extract the binary data
    SortedFragments =
        lists:sort([{Offset, Fragment} || {Offset, Fragment} <- maps:to_list(FragmentsMap)]),
    % Concatenate the fragments
    lists:foldl(
        fun({_Offset, Payload}, Acc) ->
            % Append new payload to the end
            <<Acc/binary, Payload/binary>>
        end,
        <<>>, % <<>> is the initial value of the accumulator
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
% Creates mesh header binary
%---------------------------------------------------------------------------------------
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

    % case {VBit, FBit} of
    %     {0, 0} -> % TODO, depending on VBit and FBit => 16 or 64 bit addr
    %         <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
    %             OriginatorAddress:64, FinalDestinationAddress:64>>;
    %     {0, 1} ->
    %         <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
    %             OriginatorAddress:64, FinalDestinationAddress:16>>;
    %     {1, 0} ->
    %         <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
    %             OriginatorAddress:16, FinalDestinationAddress:64>>;
    %     {1, 1} ->
    %         <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
    %             OriginatorAddress:16, FinalDestinationAddress:16>>
    % end.

%---------------------------------------------------------------------------------------
% Creates new mesh header and returns new datagram
%---------------------------------------------------------------------------------------
create_new_mesh_datagram(Datagram, SenderMacAdd, DstMacAdd) ->
    io:format("Building new mesh header~n"),
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
    BinMeshHeader = lowpan:build_mesh_header(MeshHeader),
    <<BinMeshHeader/binary, Datagram/bitstring>>.

%---------------------------------------------------------------------------------------
% Creates new mesh header
%---------------------------------------------------------------------------------------
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
    
    MeshHeader =
                #mesh_header{
                    v_bit = VBit,
                    f_bit = FBit,
                    hops_left = ?Max_Hops,
                    originator_address = SenderMacAdd,
                    final_destination_address = DstMacAdd
                
                },
    case Extended_hopsleft of 
        true -> 
            io:format("New mesh header created, DeepHopsLeft: ~p~n",[?Max_DeepHopsLeft]),
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, ?DeepHopsLeft:4, 
            SenderMacAdd/binary, DstMacAdd/binary, ?Max_DeepHopsLeft:8>>;
        false ->
            io:format("New mesh header created: ~p~n",[MeshHeader]),
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, ?Max_Hops:4, 
            SenderMacAdd/binary, DstMacAdd/binary>>
    end.

%---------------------------------------------------------------------------------------
% Returns routing info in mesh header
%---------------------------------------------------------------------------------------
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
    % case {V, F} of
    %     {0, 0} ->
    %         <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:64, FinalDestinationAddress:64, Data/bitstring>> =
    %             Datagram;
    %     {0, 1} ->
    %         <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:64, FinalDestinationAddress:16, Data/bitstring>> =
    %             Datagram;
    %     {1, 0} ->
    %         <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:16, FinalDestinationAddress:64, Data/bitstring>> =
    %             Datagram;
    %     {1, 1} ->
    %         <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:16, FinalDestinationAddress:16, Data/bitstring>> =
    %             Datagram
    % end,

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
% Check if datagram in mesh type, if so return true and mesh header info
%---------------------------------------------------------------------------------------
contains_mesh_header(Datagram) ->
    case Datagram of
        <<Dispatch:2, _/bitstring>> when Dispatch == ?MESH_DHTYPE ->
            {true, lowpan:get_mesh_info(Datagram)};
        _ ->
            false
    end.

%---------------------------------------------------------------------------------------
% Remove mesh header if the datagram was meshed (used in put and reasssemble)
%---------------------------------------------------------------------------------------
remove_mesh_header(Datagram, HopsLeft) ->

    case Datagram of
        <<?MESH_DHTYPE:2, _/bitstring>> -> % meshed datagram 

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
% Checks the next hop in the routing table and create new datagram with mesh
% header if meshing is needed
% returns a tuple {nexthop:boolean, binary, datagram, macHeader}
%---------------------------------------------------------------------------------------
get_next_hop(CurrNodeMacAdd, SenderMacAdd, DestMacAddress, DestAddress, SeqNum, Hopsleft_extended) ->

    case <<DestAddress:128>> of 
        <<16#FF:8,_/binary>> -> % multicast Ipv6 address
            io:format("Multicast request~n"),
            MulticastAddr = generate_multicast_addr(<<DestAddress:128>>), 
            Multicast_EU64 = generate_EUI64_mac_addr(MulticastAddr),
            MHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = Multicast_EU64},
            BroadcastHeader = create_broadcast_header(SeqNum),
            MeshHdrBin = lowpan:create_new_mesh_header(SenderMacAdd, DestMacAddress, Hopsleft_extended),
            Header = <<MeshHdrBin/bitstring, BroadcastHeader/bitstring>>,
            {false, Header, MHdr};
        _->
            case routing_table:get_route(DestMacAddress) of
                NextHopMacAddr when NextHopMacAddr =/= DestMacAddress -> % No direct link
                    io:format("Next hop found: ~p~n", [NextHopMacAddr]),
                    MacHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = NextHopMacAddr},
                    MeshHdrBin = lowpan:create_new_mesh_header(SenderMacAdd, DestMacAddress, Hopsleft_extended),
                    {true, MeshHdrBin, MacHdr};

                NextHopMacAddr when NextHopMacAddr == DestMacAddress -> % Direct link, no meshing needed
                    io:format("Direct link found ~n"),
                    MHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = DestMacAddress},
                    {false, <<>>, MHdr};

                _ ->
                    % Not reachable from node, handle as broadcast?
                    io:format("There is no direct link ~n"),
                    {false, <<>>, undefined, undefined}
            end
            
    end.
    

%---------------------------------------------------------------------------------------
% Generate a EUI64 address from the mac address
%---------------------------------------------------------------------------------------
generate_EUI64_mac_addr(MacAddress) when byte_size(MacAddress) == ?SHORT_ADDR_LEN->
    %io:format("Converting short 16bit addr...~n"),
    get_EUI64_from_short_mac(MacAddress);
generate_EUI64_mac_addr(MacAddress) when byte_size(MacAddress) == ?EXTENDED_ADDR_LEN->
    %io:format("Converting extended 64bit addr...~n"), 
    get_EUI64_from_extended_mac(MacAddress).
            
%---------------------------------------------------------------------------------------
% Generate a EUI64 address from the 48bit mac address
%---------------------------------------------------------------------------------------
get_EUI64_from_48bit_mac(MacAddress)->
    <<First:24, Last:24>> = MacAddress, 
    <<A:8, Rest:16>> = <<First:24>>,
    NewA = A bxor 2, % invert the 7th bit of the first byte
    EUI64 = <<NewA:8, Rest:16, 16#fffe:16, Last:24>>,
    EUI64.

%---------------------------------------------------------------------------------------
% Generate a EUI64 address from the 64bit extended mac address
%---------------------------------------------------------------------------------------
get_EUI64_from_extended_mac(MacAddress)->
    <<A:8, Rest:56>> = MacAddress,  
    NewA = A bxor 2,   
    <<NewA:8, Rest:56>>.

%---------------------------------------------------------------------------------------
% Generate a EUI64 address from the 16bit short mac address
%---------------------------------------------------------------------------------------
get_EUI64_from_short_mac(MacAddress)->
    PanID = <<16#FFFF:16>>,%ieee802154:get_pib_attribute(mac_pan_id),
    Extended48Bit = <<PanID/binary, 0:16, MacAddress/binary>>, 
    <<A:8, Rest:40>> = Extended48Bit, 
    ULBSetup = A band 16#FD, % replace 7th bit of first byte (U/L) by 0
    <<First:16, Last:24>> = <<Rest:40>>,
    EUI64 = <<ULBSetup:8, First:16, 16#FF:8, 16#FE:8, Last:24>>, 
    EUI64.

%---------------------------------------------------------------------------------------
% Stateless link local address generation
%---------------------------------------------------------------------------------------
generate_LL_addr(MacAddress)->
    EUI64 = generate_EUI64_mac_addr(MacAddress),
    LLAdd = <<16#FE80:16, 0:48, EUI64/binary>>,
    LLAdd.

%---------------------------------------------------------------------------------------
% Retrieve mac extended address from Ipv6 address
%---------------------------------------------------------------------------------------
get_EUI64_mac_addr(Address) ->
    <<_:64, MacAddr:64/bitstring>> = <<Address:128>>,
    MacAddr.

%---------------------------------------------------------------------------------------
% Retrieve mac shor address from Ipv6 address
%---------------------------------------------------------------------------------------
get_16bit_mac_addr(Address) ->
    <<_:112, MacAddr:16/bitstring>> = <<Address:128>>,
    MacAddr.



%---------------------------------------------------------------------------------------
%      Multicast Address Mapping
%
%     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%    |1 0 0| DST[15]*|   DST[16]     |
%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

generate_multicast_addr(DestAddress)->
    <<_:112, DST_15:8, DST_16:8>> = DestAddress,
    <<_:3, Last5Bits:5>> = <<DST_15:8>>,
    MulticastAddr = <<2#100:3, Last5Bits:5, DST_16:8>>,
    MulticastAddr.


%---------------------------------------------------------------------------------------
%     Broadcast Header
%
%    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%    |0|1|LOWPAN_BC0 |Sequence Number|
%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

create_broadcast_header(SeqNum)->
   BC0_Header = <<?BC0_DHTYPE, SeqNum:8>>,
   BC0_Header.


%---------------------------------------------------------------------------------------
%
%                               Utils functions
%
%---------------------------------------------------------------------------------------

print_as_binary(Binary) ->
    Bytes = binary_to_list(Binary),
    lists:flatten([byte_to_binary(B) ++ " " || B <- Bytes]).

byte_to_binary(B) ->
    Integer = integer_to_list(B, 2),
    pad_binary(Integer).

pad_binary(Binary) ->
    case length(Binary) of
        8 ->
            Binary;
        _ ->
            pad_binary(["0" | Binary])
    end.

hex_to_binary(Hex) ->
    Binary = list_to_binary(hex_to_bytes(Hex)),
    Bytes = binary_to_list(Binary),
    lists:flatten([byte_to_binary(B) ++ " " || B <- Bytes]).

hex_to_bytes(Hex) ->
    lists:map(fun(X) -> list_to_integer([X], 16) end, Hex).

complete_with_padding(Packet) ->
    HeaderLengthBits = bit_size(Packet),
    % determine the exact nbr of bit necessary
    PaddingBits = (8 - HeaderLengthBits rem 8) rem 8,

    <<Packet/bitstring, 0:PaddingBits>>.

generate_chunks() ->
    NumChunks = 5,
    ChunkSize = 75,
    Chunks =
        lists:map(fun(N) -> generate_chunk(N, ChunkSize) end, lists:seq(NumChunks, 1, -1)),
    Result = lists:foldl(fun(A, B) -> <<A/binary, B/binary>> end, <<>>, Chunks),
    Result.

generate_chunks(Size) ->
    NumChunks = Size,
    ChunkSize = 75,
    Chunks =
        lists:map(fun(N) -> generate_chunk(N, ChunkSize) end, lists:seq(NumChunks, 1, -1)),
    Result = lists:foldl(fun(A, B) -> <<A/binary, B/binary>> end, <<>>, Chunks),
    Result.

generate_chunk(N, Size) ->
    Prefix = list_to_binary(io_lib:format("chunk_~2..0B", [N])),
    PrefixSize = byte_size(Prefix),
    PaddingSize = Size - PrefixSize,
    % Filler character 'a'
    Padding = list_to_binary(lists:duplicate(PaddingSize, $a)),
    <<Prefix/binary, Padding/binary>>.

% generate_comment(Text) ->
%     TotalLength = 80,  %total length of the comment
%     TextLength = length(Text), %length of the initial text
%     %number of dashes needed to reach the total length
%     DashCount = TotalLength - TextLength - 6,

%     Dashes = lists:duplicate(DashCount, $-),% generate the string of dashes

%     % Concatenate the initial text, dashes, and percentage signs
%     Comment =
%         lists:flatten(
%             io_lib:format("~s---------- ~s ~s", ["%", Text, Dashes])),

%     Comment.
