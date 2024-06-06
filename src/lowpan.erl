-module(lowpan).

-include("lowpan.hrl").

%-include("mac_layer.hrl").
%-include("ieee802154.hrl").

-export([
    pkt_encapsulation/2,
    create_iphc_pckt/2,
    fragment_ipv6_packet/2,
    fragment_ipv6_packet/1,
    reassemble_datagram/2,
    reassemble_datagrams/1,
    reassemble/2,
    build_iphc_header/1,
    get_ipv6_pkt/2,
    datagram_info/1,
    compress_ipv6_header/1,
    build_datagram_pckt/2,
    build_firstFrag_pckt/5, build_firstFrag_pckt/4,
    convert_iphc_tuple_to_bin/1,
    get_ipv6_pckt_info/1,
    get_ipv6_payload/1,
    trigger_fragmentation/2, trigger_fragmentation/1,
    map_to_binary/1,
    tuple_list_to_binary/1,
    binary_to_lis/1,
    decompress_ipv6_header/2,
    get_default_LL_add/1,
    encode_integer/1,
    tuple_to_bin/1,
    build_frag_header/1,
    get_next_hop/3,
    print_as_binary/1,
    hex_to_binary/1,
    complete_with_padding/1,
    generate_chunks/0,
    build_mesh_header/1,
    get_mesh_info/1,
    contains_mesh_header/1,
    build_first_frag_header/1,
    get_unc_ipv6/1,
    get_EUI64_mac_addr/1,generate_EUI64_mac_addr/1, get_EUI64_from_48bit_mac/1,
    get_EUI64_from_short_mac/1, get_EUI64_from_extended_mac/1,generate_LL_addr/1,
    create_new_mesh_header/2,
    create_new_mesh_datagram/3,
    check_duplicate_frag/5, remove_mesh_header/1, build_mesh_packet/6
]).

%-------------------------------------------------------------------------------
% return pre-built Ipv6 packet
%-------------------------------------------------------------------------------
get_ipv6_pkt(Header, Payload) ->
    ipv6:build_ipv6_packet(Header, Payload).

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                             FROM IPv6 to Mac layer
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
% create an uncompressed 6lowpan packet from an Ipv6 packet
%-------------------------------------------------------------------------------
pkt_encapsulation(Header, Payload) ->
    Ipv6Pckt = get_ipv6_pkt(Header, Payload),
    DhTypebinary = <<?IPV6_DHTYPE:8, 0:16>>,
    <<DhTypebinary/binary, Ipv6Pckt/binary>>.

get_unc_ipv6(Ipv6Pckt) ->
    <<?IPV6_DHTYPE:8, Ipv6Pckt/bitstring>>.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                               Header compression
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
% @doc Creates an Iphc binary header
% @param IphcHeader: Ipv6 header
% @returns a binary containing IPHC header fields
% @end
%-------------------------------------------------------------------------------
build_iphc_header(IphcHeader) ->
    #iphc_header{
        dispatch = Dispatch,
        tf = Tf,
        nh = Nh,
        hlim = Hlim,
        cid = Cid,
        sac = Sac,
        sam = Sam,
        m = M,
        dac = Dac,
        dam = Dam
    } =
        IphcHeader,

    <<Dispatch:3, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2>>.

%-------------------------------------------------------------------------------
% create a compressed 6lowpan packet (with iphc compression) from an Ipv6 packet
%-------------------------------------------------------------------------------
create_iphc_pckt(IphcHeader, Payload) ->
    <<IphcHeader/binary, Payload/bitstring>>.

%-------------------------------------------------------------------------------
% @doc return value field of a given Ipv6 packet in a record form
% @end
%-------------------------------------------------------------------------------
get_ipv6_pckt_info(Ipv6Pckt) ->
    <<Version:4, TrafficClass:8, FlowLabel:20, PayloadLength:16, NextHeader:8, HopLimit:8, SourceAddress:128, DestAddress:128, Payload/bitstring>> =
        Ipv6Pckt,
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

%-------------------------------------------------------------------------------
% @doc return UDP data from a given Ipv6 packet if it contains a UDP nextHeader
% @end
%-------------------------------------------------------------------------------
get_udp_data(Ipv6Pckt) ->
    <<_:320, UdpPckt:64, _/binary>> = Ipv6Pckt,
    UdpPckt.

%-------------------------------------------------------------------------------
% return the payload of a given Ipv6 packet
%-------------------------------------------------------------------------------
get_ipv6_payload(Ipv6Pckt) ->
    <<_:192, _:128, Payload/binary>> = Ipv6Pckt,
    Payload.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Packet Compression Helper
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
% Encode a list in a binary format
%-------------------------------------------------------------------------------
encode_list_to_bin(List) ->
    EncodedValues = [encode_integer(I) || I <- List],
    %% Use to optimize encoding
    list_to_bin(EncodedValues).

%-------------------------------------------------------------------------------
% Encode an Integer value in a binary format using an appropriate amount of bit
%-------------------------------------------------------------------------------
encode_integer(I) when I =< 255 ->
    <<I:8>>;
encode_integer(I) when I =< 65535 ->
    <<I:16>>;
encode_integer(I) when I =< 4294967295 ->
    <<I:32>>;
encode_integer(I) ->
    <<I:64>>.

%-------------------------------------------------------------------------------
% Convert a list in a binary format
%-------------------------------------------------------------------------------
list_to_bin(List) ->
    list_to_bin(List, <<>>).

list_to_bin([H | T], Acc) ->
    list_to_bin(T, <<Acc/binary, H/binary>>);
list_to_bin([], Acc) ->
    Acc.

%-------------------------------------------------------------------------------
% Convert a map in a binary format
%-------------------------------------------------------------------------------
map_to_binary(CarriedInlineMap) ->
    % get value from map
    Values = maps:values(CarriedInlineMap),
    binaryValues = encode_list_to_bin(lists:reverse(Values)),
    %-------------------------------------------------------------------------------
    binaryValues.
% Convert a map to a tupple
%-------------------------------------------------------------------------------
%map_to_tuple(CarriedInlineMap) ->
%    Values = maps:values(CarriedInlineMap), %get value from map
%    %io:format("Recovered values: ~p~n", [Values]),
%    Tuple = erlang:list_to_tuple(Values),

%    Tuple.

%-------------------------------------------------------------------------------
% Convert a binary to a tuple format
%-------------------------------------------------------------------------------
%binary_to_tuple(Bin)->
%    erlang:list_to_tuple(binary_to_lis(Bin)).

%-------------------------------------------------------------------------------
% Convert a binary to a list
%-------------------------------------------------------------------------------
binary_to_lis(BinaryValues) ->
    % binary to integer list conversion
    Values = erlang:binary_to_list(BinaryValues),
    Values.

%-------------------------------------------------------------------------------
% Convert an Iphc header in tuple form in a binary format
%-------------------------------------------------------------------------------
convert_iphc_tuple_to_bin(IphcHeaderTuple) ->
    {Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam} = IphcHeaderTuple,

    % we add 3 padding bits to make it a multiple of 8
    binary =
        <<?IPHC_DHTYPE, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, 0:3>>,
    binary.

%-------------------------------------------------------------------------------
% Convert a list of tuple to binary format
%-------------------------------------------------------------------------------
tuple_list_to_binary(CarriedInlineList) ->
    io:format("Tuple list to bin: ~p~n", [CarriedInlineList]),
    % Extract while preserving the order
    Values = [Value || {_, Value} <- CarriedInlineList],
    binaryValues = encode_list_to_bin(Values),
    binaryValues.

%-------------------------------------------------------------------------------
% Generate a EUI64 address from the mac address
%-------------------------------------------------------------------------------
generate_EUI64_mac_addr(MacAddress)->
    case byte_size(MacAddress) of
        ?SHORT_ADD_LEN -> 
            io:format("Convert short 16bit addr~n"),
            get_EUI64_from_short_mac(MacAddress);
        ?EXTENDED_ADD_LEN ->
            io:format("Convert extended 64bit addr~n"), 
            get_EUI64_from_extended_mac(MacAddress)
            
    end. 

%-------------------------------------------------------------------------------
% Generate a EUI64 address from the 48bit mac address
%-------------------------------------------------------------------------------
get_EUI64_from_48bit_mac(MacAddress)->
    <<First:24, Last:24>> = MacAddress, 
    <<A:8, Rest:16>> = <<First:24>>,
    NewA = A bxor 2, % invert the 7th bit of the first byte
    EUI64 = <<NewA:8, Rest:16, 16#fffe:16, Last:24>>,
    EUI64.

%-------------------------------------------------------------------------------
% Generate a EUI64 address from the 64bit extended mac address
%-------------------------------------------------------------------------------
get_EUI64_from_extended_mac(MacAddress)->
    <<A:8, Rest:56>> = MacAddress,  
    NewA = A bxor 2,   
    <<NewA:8, Rest:56>>.

%-------------------------------------------------------------------------------
% Generate a EUI64 address from the 16bit short mac address
%-------------------------------------------------------------------------------
get_EUI64_from_short_mac(MacAddress)->
    PanID = <<16#FFFF:16>>,%ieee802154:get_pib_attribute(mac_pan_id),
    Extended48Bit = <<PanID/binary, 0:16, MacAddress/binary>>, 
    <<A:8, Rest:40>> = Extended48Bit, 
    ULBSetup = A band 16#FD, % replace 7th bit of first byte by 0
    <<First:16, Last:24>> = <<Rest:40>>,
    EUI64 = <<ULBSetup:8, First:16, 16#FF:8, 16#FE:8, Last:24>>, 
    EUI64.

%-------------------------------------------------------------------------------
% Generate a link-local address by adding 0 padding to the mac adress
%-------------------------------------------------------------------------------
get_default_LL_add(MacAddr)->
    LLAdd = <<16#FE80:16, 0:48, MacAddr/binary>>,
    LLAdd.

%-------------------------------------------------------------------------------
% Stateless link local address generation
%-------------------------------------------------------------------------------
generate_LL_addr(MacAddress)->
    EUI64 = generate_EUI64_mac_addr(MacAddress),
    LLAdd = <<16#FE80:16, 0:46, EUI64/binary>>,
    LLAdd.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           End of PC Helper
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
%         General form of 6Lowpan compression with UDP as nextHeader
%
%                           1                   2                   3
%    *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%    * |0|1|1|TF |N|HLI|C|S|SAM|M|D|DAM| SCI   | DCI   | comp. IPv6 hdr|
%    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%    * | non compressed IPv6 fields .....                                  |
%    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%    * | LOWPAN_UDP    | non compressed UDP fields ...                 |
%    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%    * | L4 data ...                                                   |
%    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

%-------------------------------------------------------------------------------
% @doc compress an Ipv6 packet header according to the IPHC compression scheme
% @returns a tuple containing the compressed header, the payload and the values
% that should be carried inline
% @end
%-------------------------------------------------------------------------------
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
        process_cid(
            SourceAddress,
            DestAddress,
            Map,
            % first one because context identifier extension should follow DAM
            List
        ),
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
    CH = {?IPHC_DHTYPE, TF, NH, HLIM, CID, SAC, SAM, M, DAC, DAM, CarrInlineBin},
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

%-------------------------------------------------------------------------------
% @private
% @doc process the TrafficClass and Flow label fields
% @returns a tuple containing the compressed values and the CarrInline values
% @end
%-------------------------------------------------------------------------------
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
            Bin = <<ECN:2, 0:2, FlowLabel:20>>,
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

%-------------------------------------------------------------------------------
% @private
% @doc process the NextHeader field
% @doc NextHeader specifies whether or not the next header is encoded using NHC
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?UDP_PN ->
    % TODO after implementing NHC, modify return value for UDP, TCP and ICMP
    %Bin = <<NextHeader>>,
    %L = [Bin],
    %UpdatedList = [CarrInlineList, L],

    % UDP %TODO check compression for UDP
    {1, CarrInlineMap, CarrInlineList};
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?TCP_PN ->
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    % TCP
    {0, CarrInlineMap#{"NextHeader" => ?TCP_PN}, UpdatedList};
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?ICMP_PN ->
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    % ICMPv6
    {0, CarrInlineMap#{"NextHeader" => ?ICMP_PN}, UpdatedList};
process_nh(NextHeader, CarrInlineMap, CarrInlineList) ->
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader" => NextHeader}, UpdatedList}.

%-------------------------------------------------------------------------------
% @private
% @doc process the HopLimit field
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 1 ->
    % UDP
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

%-------------------------------------------------------------------------------
% @private
% @doc process the Context Identifier Extension field
% @doc If this bit is 1, an 8 bit CIE field follows after the DAM field
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_cid(SrcAdd, _, CarrInlineMap, CarrInlineList) ->
    <<SrcAddPrefix:16, _/binary>> = <<SrcAdd:128>>,
    %<<DstAddPrefix:16, _/binary>> = <<DstAdd:128>>, %TODO Check for the DestAddr
    case SrcAddPrefix of
        ?LINK_LOCAL_PREFIX ->
            {0, CarrInlineMap, CarrInlineList};
        ?MULTICAST_PREFIX ->
            {0, CarrInlineMap, CarrInlineList};
        ?GLOBAL_PREFIX_1 ->
            {0, CarrInlineMap, CarrInlineList};
        _-> {1, CarrInlineMap, CarrInlineList}
    end.

% ?MESH_LOCAL_PREFIX ->
%     Bin = <<0:8,0:8>>,
%     L = [Bin],
%     UpdatedList = [CarrInlineList, L],
%     UpdatedMap = CarrInlineMap#{"CID"=>0},
%     {1, UpdatedMap, UpdatedList})

% ?GLOBAL_PREFIX_1 ->
%     Bin = <<1:8, 1:8>>,
%     L = [Bin],
%     UpdatedList = [CarrInlineList, L],
%     UpdatedMap = CarrInlineMap#{"CID"=>1},
%     {1, UpdatedMap, UpdatedList};

%?GLOBAL_PREFIX_2  ->
%   Bin = <<2:8, 2:8>>,

%  L = [Bin],
% UpdatedList = [CarrInlineList, L],

%UpdatedMap = CarrInlineMap#{"CID"=>2},
%{1, UpdatedMap, UpdatedList};

% ?GLOBAL_PREFIX_3  ->
%     Bin = <<3:8, 3:8>>,
%     L = [Bin],
%     UpdatedList = [CarrInlineList, L],
%     UpdatedMap = CarrInlineMap#{"CID"=>3},
%     {1, UpdatedMap, UpdatedList}

%-------------------------------------------------------------------------------
% @private
% @doc process the Source Address Compression
% @doc SAC specifies whether the compression is stateless or statefull
% @returns the compressed value
% @end
%-------------------------------------------------------------------------------
process_sac(SrcAdd) ->
    <<Prefix:16, _/binary>> = <<SrcAdd:128>>,

    case Prefix of
        ?LINK_LOCAL_PREFIX ->
            % link-local
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

%-------------------------------------------------------------------------------
% @private
% @doc process for the Source Address Mode
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_sam(SAC, _, SrcAdd, CarrInlineMap, CarrInlineList) when SAC == 0 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case SrcAddBits of
        <<?LINK_LOCAL_PREFIX:16, 0:48, _:24, 16#FFFE:16, _:24>> ->
            % the address is fully elided
            {2#11, CarrInlineMap, CarrInlineList};
        <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>> ->
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last16Bits},
            {2#10, UpdatedMap,
                % the first 112 bits are elided, last 16 IID bits are carried in-line
                UpdatedList};
        <<?LINK_LOCAL_PREFIX:16, 0:48, _:64>> ->
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last64Bits},
            {2#01, UpdatedMap,
                % the first 64 bits are elided, last 64 bits (IID) are carried in-line
                UpdatedList};
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
            {2#11, CarrInlineMap,
                % the address is fully elided and derived from the context
                CarrInlineList};
        <<_:16, _:48, 16#000000FFFE00:48, _:16>> ->
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last16Bits},
            {2#10, UpdatedMap,
                % the first 64 bits are derived from the context, last 16 IID bits are carried in-line
                UpdatedList};
        %TODO how to represente first context 64 bit
        <<_:16, _:48, _:64>> ->
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM" => Last64Bits},
            {2#01, UpdatedMap,
                % the first 64 bits are derived from the context, last 64 bits IID are carried in-line
                UpdatedList}
    end.

% _ ->
%     {2#00,CarrInlineMap, CarrInlineList} %  the unspecified address ::

%-------------------------------------------------------------------------------
% @private
% @doc process for the Multicast compression
% @returns the compressed value
% @end
%-------------------------------------------------------------------------------
process_m(DstAdd) ->
    <<Prefix:16, _/bitstring>> = <<DstAdd:128>>,
    case Prefix of
        ?MULTICAST_PREFIX ->
            1;
        _ ->
            0
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Destination Address Compression
% @doc DAC specifies whether the compression is stateless or statefull
% @returns the compressed value
% @end
%-------------------------------------------------------------------------------
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

%-------------------------------------------------------------------------------
% @private
% @doc process for the Destination Address Mode
% @param DAC, M, DstAdd, CarrInlineMap
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_dam(0, 0, _, DstAdd, CarrInlineMap, CarrInlineList) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,

    case DestAddBits of
        <<?LINK_LOCAL_PREFIX:16, 0:112>> ->
            % the address is fully elided
            {2#11, CarrInlineMap, CarrInlineList};
        <<?LINK_LOCAL_PREFIX:16, 0:48, _:24, 16#FFFE:16, _:24>> ->
            {2#11, CarrInlineMap,
                % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
                CarrInlineList};
        <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>> ->
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last16Bits},
            {2#10, UpdatedMap,
                % the first 112 bits are elided, last 16 bits are in-line
                UpdatedList};
        <<?LINK_LOCAL_PREFIX:16, _:112>> ->
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last64Bits},
            {2#01, UpdatedMap,
                % the first 64 bits are elided, last 64 bits are in-line
                UpdatedList};
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
        <<0:128>> ->
            {2#11, CarrInlineMap, CarrInlineList};
        <<?GLOBAL_PREFIX_1:16, _:48, 16#000000FFFE00:48,
            % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
            _:16>> ->
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last16Bits},
            {2#10, UpdatedMap,
                % the first 112 bits are elided, last 16 bits are in-line
                UpdatedList};
        <<?GLOBAL_PREFIX_1:16, _:112>> ->
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM" => Last64Bits},
            {2#01, UpdatedMap,
                % the first 64 bits are elided, last 64 bits are in-line
                UpdatedList};
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

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                              Next Header compression
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           UDP Packet Compression
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
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

    io:format("C: ~p~nP: ~p~n", [C, P]),
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

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           ICMP Packet Compression
%------------------------------------------------------------------------------------------------------------------------------------------------------

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           TCP Packet Compression
%------------------------------------------------------------------------------------------------------------------------------------------------------

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                       Packet fragmentation
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
% returns a binary containing fragmentation header fields
%-------------------------------------------------------------------------------
build_frag_header(FragHeader) ->
    #frag_header{
        frag_type = FragType,
        datagram_size = DatagramSize,
        datagram_tag = DatagramTag,
        datagram_offset = DatagramOffset
    } =
        FragHeader,
    <<FragType:5, DatagramSize:11, DatagramTag:16, DatagramOffset:8>>.

build_first_frag_header(FragHeader) ->
    #frag_header{
        frag_type = FragType,
        datagram_size = DatagramSize,
        datagram_tag = DatagramTag
    } =
        FragHeader,
    <<FragType:5, DatagramSize:11, DatagramTag:16>>.

%-------------------------------------------------------------------------------
build_firstFrag_pckt(FragType, DatagramSize, DatagramTag, CompressedHeader, Payload) ->
    %TODO if wireshark doesn't recongnize it, cange it to binary
    %PayloadLen = bit_size(Payload),
    <<FragType:5, DatagramSize:11, DatagramTag:16, CompressedHeader/binary, Payload/bitstring>>.

build_firstFrag_pckt(FragType, DatagramSize, DatagramTag, Payload) ->
    %TODO if wireshark doesn't recongnize it, cange it to binary
    %PayloadLen = bit_size(Payload),
    <<FragType:5, DatagramSize:11, DatagramTag:16, Payload/bitstring>>.

%-------------------------------------------------------------------------------
% create a datagram packet (fragments)
%-------------------------------------------------------------------------------
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

%-------------------------------------------------------------------------------
% @doc Fragment a given Ipv6 packet
% @returns a list of fragmented packets having this form:
% [{FragHeader1, Fragment1}, ..., {FragHeaderN, FragmentN}]
% @end
%-------------------------------------------------------------------------------
fragment_ipv6_packet(CompIpv6Pckt, PacketLen) when is_binary(CompIpv6Pckt) ->
    % TODO Check unicity
    DatagramTag = rand:uniform(65536),
    frag_process(CompIpv6Pckt, DatagramTag, PacketLen, 0, []).

fragment_ipv6_packet(CompIpv6Pckt) when is_binary(CompIpv6Pckt) ->
    % TODO Check unicity
    DatagramTag = rand:uniform(65536),
    Size = byte_size(CompIpv6Pckt),
    frag_process(CompIpv6Pckt, DatagramTag, Size, 0, []).

%-------------------------------------------------------------------------------
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
%-------------------------------------------------------------------------------
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

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Packet Fragmentation Helper
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
% check if a packet needs to be compressed or not
% returns a list of fragments if yes, the orginal packet if not
%-------------------------------------------------------------------------------
trigger_fragmentation(CompPckt, PcktLengt) ->
    CompPcktLengt = byte_size(CompPckt),

    ValidLength = CompPcktLengt =< 127,
    case ValidLength of
        false ->
            io:format("The received Ipv6 packet need fragmentation to be transmitted~n"),
            Fragments = lowpan:fragment_ipv6_packet(CompPckt, PcktLengt),
            {true, Fragments};
        true ->
            io:format("No fragmentation needed~n"),
            false
    end.

trigger_fragmentation(CompPckt) ->
    PcktLengt = byte_size(CompPckt),

    ValidLength = PcktLengt =< 127,
    case ValidLength of
        false ->
            io:format("The received Ipv6 packet need fragmentation to be transmitted~n"),
            Fragments = lowpan:fragment_ipv6_packet(CompPckt),
            {true, Fragments};
        true ->
            io:format("No fragmentation needed~n"),
            {false, CompPckt}
    end.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                           Header Decompression
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%get_prefix(ContextId) ->
%    maps:get(ContextId, ?CONTEXT_TABLE).

%-------------------------------------------------------------------------------
% @doc decompress an Ipv6 packet header commpressed according
% to the IPHC compression scheme
% @returns the decompressed Ipv6 packet
% @end
%-------------------------------------------------------------------------------
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

%-------------------------------------------------------------------------------
% @private
% @doc decode process for the CID field
% @returns the decoded ContextID
% @end
%-------------------------------------------------------------------------------
decode_cid(CID, CarriedInline) when CID == 1 ->
    <<Context:16, Rest/binary>> = CarriedInline,
    {Context, Rest}.

%-------------------------------------------------------------------------------
% @private
% @doc decode process for the TF field
% @returns the decoded TrafficClass and FlowLabel value
% @end
%-------------------------------------------------------------------------------
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

%-------------------------------------------------------------------------------
% @private
% @doc decode process for the NH field
% @returns the decoded NextHeader value
% @end
%-------------------------------------------------------------------------------
decode_next_header(_, CarriedInline) ->
    <<NextHeader:8, Rest/binary>> = CarriedInline,
    {NextHeader, Rest}.

%-------------------------------------------------------------------------------
% @private
% @doc decode process for the HLim field
% @returns the decoded Hop Limit value
% @end
%-------------------------------------------------------------------------------
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

%-------------------------------------------------------------------------------
% @private
% @doc decode process for the SAC field
% @returns the decoded Source Address Mode value
% @end
%-------------------------------------------------------------------------------
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

%-------------------------------------------------------------------------------
% @private
% @doc decode process for the DAC field
% @returns the decoded Destination Address Mode value
% @end
%-------------------------------------------------------------------------------
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

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Packet Decompression Helper
%------------------------------------------------------------------------------------------------------------------------------------------------------



%-------------------------------------------------------------------------------
% Encode a tuple in a binary format
%-------------------------------------------------------------------------------
tuple_to_bin(Tuple) ->
    Elements = tuple_to_list(Tuple),
    Binaries = [element_to_binary(Elem) || Elem <- Elements],
    list_to_binary(Binaries).

%-------------------------------------------------------------------------------
% Encode an Integer to a binary
%-------------------------------------------------------------------------------
element_to_binary(Elem) when is_integer(Elem) ->
    encode_integer(Elem);
element_to_binary(Elem) when is_binary(Elem) ->
    Elem;
element_to_binary(Elem) when is_tuple(Elem) ->
    tuple_to_bin(Elem);
element_to_binary(Elem) when is_list(Elem) ->
    list_to_binary(Elem).

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                         FROM Mac layer to 6LoWPAN
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                               Reassembly
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
% @doc helper function to retrieve datagram info
% @returns a tuple containing useful datagram fields
% @end
%-------------------------------------------------------------------------------
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

%-------------------------------------------------------------------------------
% @doc launch the reassembly process
% @param Fragments: list [{Header1, Fragment1}, ..., {HeaderN, FragmentN}]
% @returns the reassembled ipv6 packet
% @end
%-------------------------------------------------------------------------------
reassemble_datagrams(Fragments) when is_list(Fragments) ->
    [FirstFragment | _] = Fragments,

    DtgInfo = lowpan:datagram_info(FirstFragment),
    Size = DtgInfo#datagramInfo.datagramSize,
    Tag = DtgInfo#datagramInfo.datagramTag,

    Datagram = #datagram{tag = Tag, size = Size},
    DatagramMap =
        % add retrieve info to the datagram map
        maps:put(Tag, Datagram, ?DATAGRAMS_MAP),

    {ReassembledPacket, _NewMap} = process_fragments(Fragments, DatagramMap, undefined),
    ReassembledPacket.

%-------------------------------------------------------------------------------
% @doc launch the reassembly process for a single fragment
% @param Fragment: single Fragment
% @param DatagramMap: the current state of the datagram map
% @returns a tuple containing the reassembled packet (if complete) or the atom
%          `notYetReassembled` and the updated DatagramMap
% @end
%-------------------------------------------------------------------------------
reassemble_datagram(Fragment, DatagramMap) ->
    DtgInfo = lowpan:datagram_info(Fragment),
    Size = DtgInfo#datagramInfo.datagramSize,
    Tag = DtgInfo#datagramInfo.datagramTag,

    case maps:find(Tag, DatagramMap) of
        {ok, _} ->
            process_fragment(Fragment, DatagramMap);
        error ->
            % first fragment
            Datagram = #datagram{tag = Tag, size = Size},
            UpdatedMap = maps:put(Tag, Datagram, DatagramMap),
            process_fragment(Fragment, UpdatedMap)
    end.

%-------------------------------------------------------------------------------
% @private
% @doc helper function for the reassembly process
% @returns a tuple containing the reassembled packet and the final DatagramMap state
% @end
%-------------------------------------------------------------------------------
process_fragments([], Map, ReassembledPacket) ->
    {ReassembledPacket,
        % when the list is empty, returns the last payload and the final map state
        Map};
process_fragments([HeadFrag | TailFrags], DatagramMap, _Payload) ->
    {ReassembledPacket, UpdatedMap} = process_fragment(HeadFrag, DatagramMap),
    process_fragments(TailFrags, UpdatedMap, ReassembledPacket).

%-------------------------------------------------------------------------------
% @private
% @doc process the first fragment, launch timer, and add it to the DatagramMap
% the reassembly if last fragment is received
% @end
%-------------------------------------------------------------------------------
process_fragment(<<?FRAG1_DHTYPE:5, Size:11, Tag:16, Payload/binary>>, Map) ->
    NewFragment = #{0 => Payload},
    CurrSize = byte_size(Payload),
    Datagram =
        #datagram{
            tag = Tag,
            size = Size,
            cmpt = CurrSize,
            fragments = NewFragment
        },
    UpdatedMap = maps:put(Tag, Datagram, Map),
    case CurrSize == Size of
        true ->
            ReassembledPacket = reassemble(Tag, UpdatedMap),
            {ReassembledPacket, UpdatedMap};
        false ->
            {notYetReassembled, UpdatedMap}
    end;
%-------------------------------------------------------------------------------
% @private
% @doc process the subsequent fragments, add them to the DatagramMap and launch
% the reassembly if last fragment is received
% @end
%-------------------------------------------------------------------------------
process_fragment(<<?FRAGN_DHTYPE:5, Size:11, Tag:16, Offset:8, Payload/binary>>, Map) ->
    case maps:find(Tag, Map) of
        {ok, OldDatagram} ->
            CurrSize = byte_size(Payload),
            % update size cmpt
            UpdatedCmpt = OldDatagram#datagram.cmpt + CurrSize,
            % get fragmentMap
            FragmentsMap = OldDatagram#datagram.fragments,
            % put new fragment to fragmentMap
            NewFragments = FragmentsMap#{Offset => Payload},
            UpdatedDatagram =
                OldDatagram#datagram{
                    cmpt = UpdatedCmpt,
                    % update datagram
                    fragments = NewFragments
                },
            % update DatagramMap
            UpdatedMap = maps:put(Tag, UpdatedDatagram, Map),
            case UpdatedCmpt == Size of
                true ->
                    ReassembledPacket = reassemble(Tag, UpdatedMap),
                    {ReassembledPacket, UpdatedMap};
                false ->
                    {notYetReassembled, UpdatedMap}
            end;
        error ->
            {undefined, Map}
    end.

%-------------------------------------------------------------------------------
% check if the received fragment already exist, if not update the datagram map
%-------------------------------------------------------------------------------
check_duplicate_frag(Map, Tag, Offset, Size, Payload) ->
    Datagram = maps:get(Tag, Map),
    FragmentsMap = Datagram#datagram.fragments,
    KnownFragment = maps:is_key(Offset, FragmentsMap),

    case KnownFragment of
        true ->
            io:format("Duplicate frame detected~n"),
            {Map, false};
        false ->
            io:format("Not a Duplicated frame~n"),
            update_datagram_map(Size, Tag, Offset, Payload, Map)
    end.

%-------------------------------------------------------------------------------
% Update the datagram map by adding the new fragment to the fragments's map
% and update the counter, if currSize matches the datagramsize,
% then all fragments have been received
%-------------------------------------------------------------------------------
update_datagram_map(Size, Tag, Offset, Payload, Map) ->
    OldDatagram = maps:get(Tag, Map),
    CurrSize = byte_size(Payload),
    UpdatedCmpt = OldDatagram#datagram.cmpt + CurrSize,
    FragmentsMap = OldDatagram#datagram.fragments,
    NewFragments = FragmentsMap#{Offset => Payload},
    UpdatedDatagram = OldDatagram#datagram{cmpt = UpdatedCmpt, fragments = NewFragments},
    NewMap = maps:put(Tag, UpdatedDatagram, Map),
    AllReceived = UpdatedCmpt == Size,
    io:format("Pckt Size: ~p bytes ~n", [Size]),
    io:format("Current pckt len: ~p bytes~n", [UpdatedCmpt]),
    {NewMap, AllReceived}.

%-------------------------------------------------------------------------------
% @private
% @doc helper function to reassembled all received fragments based on the Tag
% @end
%-------------------------------------------------------------------------------
reassemble(Tag, UpdatedMap) ->
    %io:format("Complete for pckt ~p~n~p~n", [Tag, UpdatedMap]),
    Datagram = maps:get(Tag, UpdatedMap),
    FragmentsMap = Datagram#datagram.fragments,
    % sort fragments by offset and extract the binary data
    SortedFragments =
        lists:sort([{Offset, Fragment} || {Offset, Fragment} <- maps:to_list(FragmentsMap)]),
    % concatenate the fragments
    ReassembledPacket =
        lists:foldl(
            fun({_Offset, Payload}, Acc) ->
                % append new payload to the end
                <<Acc/binary, Payload/binary>>
            end,
            <<>>,
            %% <<>> is the initial value of the accumulator
            SortedFragments
        ),
    % discard tag so it can be reused
    discard_datagram(Tag, UpdatedMap),
    ReassembledPacket.

discard_datagram(Tag, Map) ->
    maps:remove(Tag, Map).

%discard_fragment(Offset, Fragments)->
%    maps:remove(Offset,Fragments).

%-------------------------------------------------------------------------------
% @private
% @doc helper function to discard stored fragments when timer exceed the limit
% @end
%-------------------------------------------------------------------------------
%duplicate_frag(Offset, Datagram)->
%    Fragments = Datagram#datagram.fragments,
%    case maps:is_key(Offset, Fragments) of
%        true-> true;
%        false-> false
%    end.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                             ROUTING
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%-------------------------------------------------------------------------------
%                      Mesh Addressing Type and Header
%
%    0                   1                   2                   3
%    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%   |1 0|V|F|HopsLft|  originator address,final destination address
%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%

build_mesh_header(MeshHeader) ->
    #mesh_header{
        v_bit = VBit,
        f_bit = FBit,
        hops_left = HopsLeft,
        originator_address = OriginatorAddress,
        final_destination_address = FinalDestinationAddress
    } = MeshHeader,

    case {VBit, FBit} of
        {0, 0} ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
                OriginatorAddress:64/bitstring, FinalDestinationAddress:64/bitstring>>;
        {0, 1} ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
                OriginatorAddress:64/binary, FinalDestinationAddress:16/binary>>;
        {1, 0} ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
                OriginatorAddress:16/binary, FinalDestinationAddress:64/binary>>;
        {1, 1} ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
                OriginatorAddress:16/binary, FinalDestinationAddress:16/binary>>
    end.


build_mesh_packet(VBit, FBit, HopsLeft, OrigAddress, FinalDestAddress, Payload) ->
        <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, 
            OrigAddress/binary, FinalDestAddress/binary, Payload/bitstring>>. 

get_mesh_info(Datagram) ->
    <<_:2, V:1, F:1, _/bitstring>> = Datagram,

    case {V, F} of
        {0, 0} ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:64, FinalDestinationAddress:64, Data/bitstring>> =
                Datagram;
        {0, 1} ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:64, FinalDestinationAddress:16, Data/bitstring>> =
                Datagram;
        {1, 0} ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:16, FinalDestinationAddress:64, Data/bitstring>> =
                Datagram;
        {1, 1} ->
            <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:16, FinalDestinationAddress:16, Data/bitstring>> =
                Datagram
    end,

    MeshInfo =
        #meshInfo{
            v_bit = VBit,
            f_bit = FBit,
            hops_left = HopsLeft,
            originator_address = OriginatorAddress,
            final_destination_address = FinalDestinationAddress,
            payload = Data
        },
    MeshInfo.

%-------------------------------------------------------------------------------
% Check if datagram in mesh type, if so return true and mesh header info
%-------------------------------------------------------------------------------
contains_mesh_header(Datagram) ->
    case Datagram of
        <<Dispatch:2, _/bitstring>> when Dispatch == ?MESH_DHTYPE ->
            {true, lowpan:get_mesh_info(Datagram)};
        _ ->
            false
    end.

%-------------------------------------------------------------------------------
% Remove mesh header if the datagram was meshed (used in put and reasssemble)
%-------------------------------------------------------------------------------
remove_mesh_header(Datagram) ->
    <<Type:2, _RestOfHeader:134, Rest/bitstring>> = Datagram,
    case Type of
        ?MESH_DHTYPE ->
            Rest;
        _ ->
            Datagram
    end.

%-------------------------------------------------------------------------------
% Checks the next hop in the routing table and create new datagram with mesh
% header if meshing is needed
% returns a tuple {boolean, binary, datagram, macHeader}
%-------------------------------------------------------------------------------
get_next_hop(CurrNodeMacAdd, SenderMacAdd, DestMacAddress) ->
    case routing_table:get_route(DestMacAddress) of
        NextHopMacAddr when NextHopMacAddr =/= DestMacAddress -> % No direct link
            io:format("Next hop found: ~p~n", [NextHopMacAddr]),
            MacHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = NextHopMacAddr},
            MeshHdrBin = lowpan:create_new_mesh_header(SenderMacAdd, DestMacAddress),
            {true, MeshHdrBin, MacHdr};

        NextHopMacAddr when NextHopMacAddr == DestMacAddress -> % Direct link, no meshing needed
            io:format("Direct link found ~n"),
            MHdr = #mac_header{src_addr = CurrNodeMacAdd, dest_addr = DestMacAddress},
            {false, <<>>, MHdr};

        _ ->
            % Not reachable from node, handle as broadcast?
            io:format("There is no direct link ~n"),
            {false, <<>>, undefined}
    end.



%-------------------------------------------------------------------------------
% Retrieve mac extended address from Ipv6 address
%-------------------------------------------------------------------------------
get_EUI64_mac_addr(Address) ->
    <<_:64, MacAddr:64/bitstring>> = <<Address:128>>,
    MacAddr.

%-------------------------------------------------------------------------------
% Creates new mesh header and returns new datagram
%-------------------------------------------------------------------------------
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

%-------------------------------------------------------------------------------
% Creates new mesh header
%-------------------------------------------------------------------------------
create_new_mesh_header(SenderMacAdd, DstMacAdd) ->
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
        io:format("New mesh header created: ~p~n",[MeshHeader]),
    lowpan:build_mesh_header(MeshHeader).

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                             Utils functions
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

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
    % Determine the exact nbr of bit necessary
    PaddingBits = (8 - HeaderLengthBits rem 8) rem 8,

    <<Packet/bitstring, 0:PaddingBits>>.

generate_chunks() ->
    NumChunks = 2,
    ChunkSize = 75,
    Chunks =
        lists:map(fun(N) -> generate_chunk(N, ChunkSize) end, lists:seq(NumChunks, 1, -1)),
    Result = lists:foldl(fun(A, B) -> <<A/binary, B/binary>> end, <<>>, Chunks),
    Result.

%io:format("Generated text:~n~s~n", [Result]).

generate_chunk(N, Size) ->
    Prefix = list_to_binary(io_lib:format("chunk_~2..0B", [N])),
    PrefixSize = byte_size(Prefix),
    PaddingSize = Size - PrefixSize,
    % Filler character 'a'
    Padding = list_to_binary(lists:duplicate(PaddingSize, $a)),
    <<Prefix/binary, Padding/binary>>.

generate_comment(Text) ->
    TotalLength = 80,  %total length of the comment
    TextLength = length(Text), %length of the initial text
    %number of dashes needed to reach the total length
    DashCount = TotalLength - TextLength - 6,

    Dashes = lists:duplicate(DashCount, $-),% generate the string of dashes

    % Concatenate the initial text, dashes, and percentage signs
    Comment =
        lists:flatten(
            io_lib:format("~s---------- ~s ~s", ["%", Text, Dashes])),

    Comment.
