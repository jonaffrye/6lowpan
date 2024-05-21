- module(lowpan). 

-include("lowpan.hrl").
%-include("mac_layer.hrl").
%-include("ieee802154.hrl").

-export([pkt_encapsulation/2,create_iphc_pckt/2,fragment_ipv6_packet/1,reassemble_datagram/2,reassemble_datagrams/1,
        reassemble/2,build_iphc_header/1,get_ipv6_pkt/2,datagram_info/1,compress_ipv6_header/1, build_datagram_pckt/2,build_firstFrag_pckt/4,
        convert_iphc_tuple_to_bin/1, get_ipv6_pckt_info/1, get_ipv6_payload/1,trigger_fragmentation/1,map_to_binary/1, tuple_list_to_binary/1, 
        binary_to_lis/1, decompress_ipv6_header/2, get_default_LL_add/1, encode_integer/1, tuple_to_bin/1, build_frag_header/1, get_next_hop/1]).


%-------------------------------------------------------------------------------
% return pre-built Ipv6 packet
%-------------------------------------------------------------------------------
get_ipv6_pkt(Header, Payload)->
    ipv6:build_ipv6_packet(Header, Payload).

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                             FROM IPv6 to Mac layer  
%
%------------------------------------------------------------------------------------------------------------------------------------------------------


%-------------------------------------------------------------------------------
% create an uncompressed 6lowpan packet from an Ipv6 packet
%-------------------------------------------------------------------------------
pkt_encapsulation(Header, Payload)->
    Ipv6Pckt = get_ipv6_pkt(Header, Payload), 
    DhTypeBinary = <<?IPV6_DHTYPE:8, 0:16>>, 
    <<DhTypeBinary/binary, Ipv6Pckt/binary>>.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                               Header compression
%
%------------------------------------------------------------------------------------------------------------------------------------------------------


%-------------------------------------------------------------------------------
% @doc Creates an Iphc binary header  
% @param IphcHeader: Ipv6 header
% @returns a bitstring containing IPHC header fields
% @end
%-------------------------------------------------------------------------------
build_iphc_header(IphcHeader)->
    #iphc_header{
        dispatch = Dispatch, tf = Tf, nh = Nh, hlim = Hlim, cid = Cid,
        sac = Sac, sam = Sam, m = M, dac = Dac, dam = Dam
    } = IphcHeader,

    <<Dispatch:8,Tf:2,Nh:1,Hlim:2,Cid:1,Sac:1,Sam:2,M:1,Dac:1,Dam:2>>.


%-------------------------------------------------------------------------------
% create a compressed 6lowpan packet (with iphc compression) from an Ipv6 packet
%-------------------------------------------------------------------------------
create_iphc_pckt(IphcHeader, Payload)->
    <<IphcHeader/bitstring,Payload/bitstring>>.

%-------------------------------------------------------------------------------
% @doc return value field of a given Ipv6 packet in a record form
% @end
%-------------------------------------------------------------------------------
get_ipv6_pckt_info(Ipv6Pckt) ->
    <<Version:4, TrafficClass:8, FlowLabel:20, PayloadLength:16, NextHeader:8, HopLimit:8,
      SourceAddress:128, DestAddress:128, Payload/binary>> = Ipv6Pckt,
    PckInfo = #ipv6PckInfo{
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
    list_to_bin(EncodedValues).
%% Use to optimize encoding 

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
list_to_bin([H|T], Acc) ->
    list_to_bin(T, <<Acc/binary,H/binary>>);
list_to_bin([], Acc) ->
    Acc.
%-------------------------------------------------------------------------------
% Convert a map in a binary format
%-------------------------------------------------------------------------------
map_to_binary(CarriedInlineMap) ->
    Values = maps:values(CarriedInlineMap), % get value from map
    BinaryValues = encode_list_to_bin(lists:reverse(Values)), 
    BinaryValues.
%-------------------------------------------------------------------------------
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
    Values = erlang:binary_to_list(BinaryValues), % binary to integer list conversion
    Values.

%-------------------------------------------------------------------------------
% Convert an Iphc header in tuple form in a binary format
%-------------------------------------------------------------------------------
convert_iphc_tuple_to_bin(IphcHeaderTuple)->
    {Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam} = IphcHeaderTuple,

    % we add 3 padding bits to make it a multiple of 8
    Binary = <<?IPHC_DHTYPE, Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, 0:3>>,
    Binary.


%-------------------------------------------------------------------------------
% Convert a list of tuple to binary format
%-------------------------------------------------------------------------------
tuple_list_to_binary(CarriedInlineList) ->
    io:format("Tuple list to bin: ~p~n", [CarriedInlineList]),
    Values = [Value || {_, Value} <- CarriedInlineList], % Extract while preserving the order 
    BinaryValues = encode_list_to_bin(Values),
    BinaryValues.


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
compress_ipv6_header(Ipv6Pckt)->
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),

    TrafficClass = PcktInfo#ipv6PckInfo.trafficClass, 
    FlowLabel = PcktInfo#ipv6PckInfo.flowLabel, 
    NextHeader = PcktInfo#ipv6PckInfo.nextHeader, 
    HopLimit = PcktInfo#ipv6PckInfo.hopLimit, 
    SourceAddress = PcktInfo#ipv6PckInfo.sourceAddress, 
    DestAddress = PcktInfo#ipv6PckInfo.destAddress, 
    
    Map = #{},
    List = [], 

    {CID, UpdateMap0, UpdatedList0} = process_cid(SourceAddress, DestAddress, Map, List), % first one because context identifier extension should follow DAM
    {TF, UpdateMap1, UpdatedList1} = process_tf(TrafficClass, FlowLabel,UpdateMap0, UpdatedList0),
    {NH, UpdateMap2, UpdatedList2} = process_nh(NextHeader, UpdateMap1, UpdatedList1),
    {HLIM, UpdateMap3, UpdatedList3} = process_hlim(HopLimit, UpdateMap2, UpdatedList2),
    SAC = process_sac(SourceAddress),
    {SAM, UpdateMap4, UpdatedList4} = process_sam(SAC, SourceAddress, UpdateMap3, UpdatedList3),
    M = process_m(DestAddress),
    DAC = process_dac(DestAddress),
    {DAM, CarrInlineMap, CarrInlineList} = process_dam(M, DAC, DestAddress, UpdateMap4, UpdatedList4),


    CarrInlineBin = list_to_binary(CarrInlineList),%encode_list_to_bin(CarrInlineList),
    CH = {?IPHC_DHTYPE,TF, NH, HLIM, CID, SAC, SAM, M, DAC, DAM,CarrInlineBin},
    io:format("CompressedHeader in lowpan ~p~n", [CH]),

    %io:format("CarrInlineMap: ~p~n", [CarrInlineMap]),
    %io:format("CarrInlineList: ~p~n", [CarrInlineList]),
    
    %io:format("CarrInlineBin ~p~n", [CarrInlineBin]),

    
    case NextHeader of 
        ?UDP_PN -> 
            UdpPckt = get_udp_data(Ipv6Pckt), 
            io:format("UdpPckt ~p~n", [UdpPckt]),
            CompressedUdpHeaderBin = compress_udp_header(UdpPckt, CarrInlineList),
            CompressedHeader = <<?IPHC_DHTYPE:3, TF:2, NH:1, HLIM:2, CID:1, SAC:1, SAM:2, M:1, DAC:1, DAM:2,CarrInlineBin/binary, CompressedUdpHeaderBin/binary>>, 
            {CompressedHeader, CarrInlineMap};
        _ -> 
            CompressedHeader = <<?IPHC_DHTYPE:3, TF:2, NH:1, HLIM:2, CID:1, SAC:1, SAM:2, M:1, DAC:1, DAM:2,CarrInlineBin/binary>>, 
            {CompressedHeader, CarrInlineMap}
    end.


%-------------------------------------------------------------------------------
% @private
% @doc process the TrafficClass and Flow label fields 
% @returns a tuple containing the compressed values and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_tf(TrafficClass, FlowLabel, CarrInlineMap, CarrInlineList) ->
    <<DSCP:6, ECN:2>> = <<TrafficClass:8>>, % TrafficClass integer to a bitstring
    case {ECN, DSCP, FlowLabel} of
        {0, 0, 0} -> 
            {2#11, CarrInlineMap, CarrInlineList}; % Traffic Class and Flow Label are elided

        {_, _, 0} -> 
            UpdatedMap = CarrInlineMap#{"TrafficClass"=>TrafficClass},
            Bin = <<TrafficClass:8>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#10, UpdatedMap, UpdatedList};% Flow Label is elided
            
        {_, 0, _} -> 
            UpdatedMap = CarrInlineMap#{"ECN"=>ECN,"FlowLabel"=>FlowLabel},
            Bin = <<ECN:8, FlowLabel:24>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#01, UpdatedMap, UpdatedList}; % DSCP is elided
        _ -> 
            UpdatedMap = CarrInlineMap#{"TrafficClass"=>TrafficClass,"FlowLabel"=>FlowLabel},
            Bin = <<TrafficClass:8, FlowLabel:24>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#00, UpdatedMap,UpdatedList}  % ECN, DSCP, and Flow Label are carried inline

    end.

%-------------------------------------------------------------------------------
% @private
% @doc process the NextHeader field
% @doc NextHeader specifies whether or not the next header is encoded using NHC
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_nh(NextHeader, CarrInlineMap,CarrInlineList) when NextHeader == ?UDP_PN -> 
% TODO after implementing NHC, modify return value for UDP, TCP and ICMP
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader"=>?UDP_PN}, UpdatedList}; % UDP %TODO check compression for UDP
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?TCP_PN -> 
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader"=>?TCP_PN},UpdatedList}; % TCP
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == ?ICMP_PN -> 
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader"=>?ICMP_PN},UpdatedList}; % ICMPv6
process_nh(NextHeader, CarrInlineMap, CarrInlineList)  -> 
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = [CarrInlineList, L],
    {0, CarrInlineMap#{"NextHeader"=>NextHeader},UpdatedList}.

%-------------------------------------------------------------------------------
% @private
% @doc process the HopLimit field 
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 1  -> 
    {2#01, CarrInlineMap,CarrInlineList }; % UDP

process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 64  -> 
    {2#10, CarrInlineMap, CarrInlineList};

process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 255 -> 
    {2#11, CarrInlineMap, CarrInlineList};

process_hlim(HopLimit, CarrInlineMap, CarrInlineList)-> 
    Bin = <<HopLimit:8>>,
    L = [Bin],
    UpdatedList = CarrInlineList++L,
    {2#00, CarrInlineMap#{"HopLimit"=> HopLimit}, UpdatedList}.

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
        ?LINK_LOCAL_PREFIX -> {0, CarrInlineMap, CarrInlineList}; 
        ?MULTICAST_PREFIX -> {0, CarrInlineMap, CarrInlineList};

        ?MESH_LOCAL_PREFIX ->
            Bin = <<0:8,0:8>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"CID"=>0},
            {1, UpdatedMap, UpdatedList}; 

        ?GLOBAL_PREFIX_1 -> 
            Bin = <<1:8, 1:8>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"CID"=>1},
            {1, UpdatedMap, UpdatedList}; 

        %?GLOBAL_PREFIX_2  -> 
         %   Bin = <<2:8, 2:8>>,
          %  L = [Bin],
           % UpdatedList = [CarrInlineList, L],
            %UpdatedMap = CarrInlineMap#{"CID"=>2},
            %{1, UpdatedMap, UpdatedList};

        ?GLOBAL_PREFIX_3  -> 
            Bin = <<3:8, 3:8>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"CID"=>3},
            {1, UpdatedMap, UpdatedList} 
    end.

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
        ?LINK_LOCAL_PREFIX -> 0; % link-local
        ?MULTICAST_PREFIX -> 0;
        ?GLOBAL_PREFIX_1 -> 1;
        %?GLOBAL_PREFIX_2 -> 1;
        ?GLOBAL_PREFIX_3 -> 1; 
        ?MESH_LOCAL_PREFIX -> 1;
        16#0000 -> 0;
        _ -> 1
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Source Address Mode 
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_sam(SAC, SrcAdd, CarrInlineMap, CarrInlineList) when SAC == 0 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case SrcAddBits of
        <<0:128>> -> 
            {2#11,CarrInlineMap, CarrInlineList}; % the address is fully elided

        <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>> -> 
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM"=>Last16Bits},
            {2#10, UpdatedMap, UpdatedList}; % the first 112 bits are elided, last 16 IID bits are carried in-line

        <<?LINK_LOCAL_PREFIX:16, 0:48, _:64>> -> 
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM"=>Last64Bits},
            {2#01, UpdatedMap, UpdatedList}; % the first 64 bits are elided, last 64 bits (IID) are carried in-line
        _ -> 
            Bin = <<SrcAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#00, CarrInlineMap#{"SAM"=>SrcAdd}, UpdatedList} % full address is carried in-line
    end;

process_sam(SAC, SrcAdd, CarrInlineMap, CarrInlineList) when SAC == 1 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case SrcAddBits of
        <<0:128>> -> 
            {2#00,CarrInlineMap, CarrInlineList}; %  the unspecified address ::

        <<?GLOBAL_PREFIX_1:16, _:48, _:64>> -> 
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM"=>Last64Bits},
            {2#01, UpdatedMap, UpdatedList}; % the first 64 bits are derived from the context, last 64 bits IID are carried in-line

        <<?GLOBAL_PREFIX_1:16, _:48, 16#000000FFFE00:48, _:16>> -> 
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"SAM"=>Last16Bits},
            {2#10, UpdatedMap, UpdatedList}; % the first 64 bits are derived from the context, last 16 IID bits are carried in-line

        _ -> 
            {2#11,CarrInlineMap, CarrInlineList} % the address is fully elided and derived from the context
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Multicast compression 
% @returns the compressed value
% @end
%-------------------------------------------------------------------------------
process_m(DstAdd) ->
    <<Prefix:16, _/binary>> = <<DstAdd:128>>,
    case Prefix of
        ?MULTICAST_PREFIX -> 1;
        _ -> 0
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
        ?LINK_LOCAL_PREFIX -> 0; 
        ?MULTICAST_PREFIX -> 0;
        ?GLOBAL_PREFIX_1 -> 1;
        %?GLOBAL_PREFIX_2 -> 1;
        ?GLOBAL_PREFIX_3 -> 1; 
        ?MESH_LOCAL_PREFIX -> 1;
        16#0000 -> 0;
        _ -> 1
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Destination Address Mode
% @param DAC, M, DstAdd, CarrInlineMap
% @returns a tuple containing the compressed value and the CarrInline values
% @end
%-------------------------------------------------------------------------------
process_dam(M, DAC , DstAdd, CarrInlineMap, CarrInlineList) when  M == 0; DAC == 0 ->
    DestAddBits = <<DstAdd:128>>,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,
    
    case DestAddBits of
        <<?LINK_LOCAL_PREFIX:16, 0:112>> -> 
            {2#11, CarrInlineMap, CarrInlineList}; % the address is fully elided
        <<?LINK_LOCAL_PREFIX:16, 0:48,_:24, 16#FFFE:16,_:24>> -> 
            {2#11, CarrInlineMap, CarrInlineList}; % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
        <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>> -> 
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM"=>Last16Bits},
            {2#10, UpdatedMap, UpdatedList}; % the first 112 bits are elided, last 16 bits are in-line
        <<?LINK_LOCAL_PREFIX:16, _:112>> -> 
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM"=>Last64Bits},
            {2#01, UpdatedMap, UpdatedList}; % the first 64 bits are elided, last 64 bits are in-line
        _ -> 
            Bin = <<DstAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#00, CarrInlineMap#{"DAM"=>DstAdd}, UpdatedList} % full address is carried in-line
    end;

process_dam(M, DAC, DstAdd, CarrInlineMap, CarrInlineList) when  M == 0; DAC == 1 ->
    DestAddBits = <<DstAdd:128>>,
    %<<Prefix: 8,_:120>> = DestAddBits,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,

    io:format("DestAddBits: ~p~n",[DestAddBits]),
    case DestAddBits of
        %<<?GLOBAL_PREFIX:8,_:8, _:112>> -> 
         %   {2#11, CarrInlineMap, CarrInlineList}; % the address is fully elided
        <<0:128>> -> 
            {2#11, CarrInlineMap, CarrInlineList};
        <<?GLOBAL_PREFIX_1:16, _:48, 16#000000FFFE00:48, _:16>> ->  % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM"=>Last16Bits},
            {2#10, UpdatedMap, UpdatedList}; % the first 112 bits are elided, last 16 bits are in-line
        <<16#2001:16, _:112>> -> 
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM"=>Last64Bits},
            {2#01, UpdatedMap, UpdatedList}; % the first 64 bits are elided, last 64 bits are in-line
        _ -> 
            %UpdatedList = CarrInlineList++[DstAdd],
            {2#00, CarrInlineMap, CarrInlineList} % RESERVED
    end;

process_dam(M, DAC, DstAdd, CarrInlineMap, CarrInlineList) when  M == 1; DAC == 0->
    DestAddBits = <<DstAdd:128>>,
    <<_:80, Last48Bits:48>> = DestAddBits,
    <<_:96, Last32Bits:32>> = DestAddBits,
    <<_:120, Last8Bits:8>> = DestAddBits,
    case DestAddBits of
        <<16#FF02:16, 0:104, _:8>> -> % ff02::00XX.
            Bin = <<Last8Bits:8>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM"=>Last8Bits},
            {2#11, UpdatedMap, UpdatedList};
        <<16#FF:8, _:8, 0:80, _:32>> -> %ffXX::00XX:XXXX.
            Bin = <<Last32Bits:32>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM"=>Last32Bits},
            {2#10, UpdatedMap, UpdatedList};
        <<16#FF:8, _:8, 0:64, _:48>> -> % ffXX::00XX:XXXX:XXXX.
            Bin = <<Last48Bits:48>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM"=>Last48Bits},
            {2#01, UpdatedMap, UpdatedList}; 
        
        _ -> 
            Bin = <<DstAdd:128>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            {2#00, CarrInlineMap#{"DAM"=>DstAdd}, UpdatedList} % full address is carried in-line
    end; 

process_dam(M, DAC, DstAdd, CarrInlineMap, CarrInlineList) when  M == 1; DAC == 1->
    DestAddBits = <<DstAdd:128>>,
    <<_:80, Last48Bits:48>> = DestAddBits,
    case DestAddBits of
        <<16#FF, _:112>> ->
            Bin = <<Last48Bits:48>>,
            L = [Bin],
            UpdatedList = [CarrInlineList, L],
            UpdatedMap = CarrInlineMap#{"DAM"=>Last48Bits},
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
compress_udp_header(UdpPckt, CarriedInline)->
    <<SrcPort:16, DstPort:16, _:16, Checksum:16>> = <<UdpPckt:64>>,

    {P, CarriedInlineList} = process_udp_ports(SrcPort, DstPort, CarriedInline), 
    {C, CarriedInlineList} = process_udp_schecksum(Checksum, CarriedInline),

    io:format("UDP carried: ~p~n", [CarriedInlineList]),

    CompressedUdpHeader = <<?UDP_DHTYPE,C/binary,P/binary>>, 
    CompressedUdpHeader. 


process_udp_schecksum(Checksum, CarriedInline)->
    case Checksum of % TODO check checksum values
        0 -> 1;
        _-> CarriedInline  
    end.

process_udp_ports(SrcPort, DstPort, CarriedInline)->
    %Oxf0b = 2#111100001011,
    %Oxf0 = 2#11110000, 

    case {SrcPort, DstPort} of 
        {<<?Oxf0b: 12, Last4S_Bits:4>>, <<?Oxf0b: 12, Last4D_Bits:4>>} ->
            ToCarr = <<Last4S_Bits, Last4D_Bits>>,
            CarriedInlineList = [CarriedInline, ToCarr], 
            P = 11, 
            {P, CarriedInlineList}; 

        {<<?Oxf0:8, Last8S_Bits:8>>, _} ->
            ToCarr = <<Last8S_Bits, DstPort>>,
            CarriedInlineList = [CarriedInline, ToCarr], 
            P = 10, 
            {P, CarriedInlineList}; 

        {_, <<?Oxf0:8, Last8D_Bits:8>>} ->
            ToCarr = <<SrcPort, Last8D_Bits>>,
            CarriedInlineList = [CarriedInline, ToCarr], 
            P = 01, 
            {P, CarriedInlineList}; 

        {_,_} -> 
            P = 00, 
            ToCarr = <<SrcPort, DstPort>>,
            CarriedInlineList = [CarriedInline, ToCarr], 
            {P, CarriedInlineList}
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
% returns a bitstring containing fragmentation header fields
%-------------------------------------------------------------------------------
build_frag_header(#frag_header{frag_type = FragType, datagram_size = DatagramSize, datagram_tag = DatagramTag, datagram_offset = DatagramOffset}) ->
    <<FragType:5, DatagramSize:11, DatagramTag:16, DatagramOffset:8>>.

%-------------------------------------------------------------------------------
build_firstFrag_pckt(FragType, DatagramSize, DatagramTag, Payload) ->
    %TODO if wireshark doesn't recongnize it, cange it to binary
    <<FragType:5, DatagramSize:11, DatagramTag:16,Payload/binary>>.

%-------------------------------------------------------------------------------
% create a datagram packet (fragments)
%-------------------------------------------------------------------------------
build_datagram_pckt(DtgmHeader, Payload) ->
    Header = build_frag_header(DtgmHeader),
    <<Header/bitstring, Payload/bitstring>>.

%-------------------------------------------------------------------------------
% @doc Fragment a given Ipv6 packet 
% @returns a list of fragmented packets having this form: 
% [{FragHeader1, Fragment1}, ..., {FragHeaderN, FragmentN}]
% @end
%-------------------------------------------------------------------------------
fragment_ipv6_packet(CompIpv6Pckt) when is_binary(CompIpv6Pckt) ->
    DatagramTag = rand:uniform(65536), % TODO Check unicity 
    Size = byte_size(CompIpv6Pckt),
    frag_process(CompIpv6Pckt,Size, DatagramTag, 0, []).

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
frag_process(<<>>,_, _, _, Acc) ->
    lists:reverse(Acc);

frag_process(CompIpv6Pckt, Size, DatagramTag, Offset, Acc) ->
    MaxSize = ?MAX_FRAME_SIZE - ?FRAG_HEADER_SIZE,
    PcktSize = byte_size(CompIpv6Pckt), 
    FragmentSize = min(PcktSize, MaxSize),
    %io:format("~p nth frag compressed size: ~p bytes~n", [Offset+1, FragmentSize]),
    
    <<FragPayload:FragmentSize/binary, Rest/binary>> = CompIpv6Pckt,
    Header = build_frag_header(#frag_header{
        frag_type = if Offset == 0 -> ?FRAG1_DHTYPE; true -> ?FRAGN_DHTYPE end,
        datagram_size = Size,% + Offset,
        datagram_tag = DatagramTag,
        datagram_offset = Offset
    }),
    frag_process(Rest, Size, DatagramTag, Offset + 1, [{Header, FragPayload} | Acc]).



%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Packet Fragmentation Helper
%------------------------------------------------------------------------------------------------------------------------------------------------------


%-------------------------------------------------------------------------------
% check if a packet needs to be compressed or not
%-------------------------------------------------------------------------------
trigger_fragmentation(CompPckt)->
    PcktLengt = byte_size(CompPckt), 
    
    ValidLength = PcktLengt =< 127,
    case ValidLength of 
        false-> io:format("The received Ipv6 packet need fragmentation to be transmitted~n"),
                Fragments = lowpan:fragment_ipv6_packet(CompPckt),
                {true, Fragments};
        true -> io:format("No fragmentation needed~n"), 
                false
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
    <<_:8,TF:8, NH:8, HLIM:8, CID:8, SAC:8, SAM:8, M:8, DAC:8, DAM:8, Rest/binary>> = CompressedPacket,
    % Rest contain carriedInline values + payload 

    %CompressedHeader = {TF, NH, HLIM, CID, SAC, SAM, M, DAC, DAM},
    %io:format("CompressedHeader: ~p~n", [CompressedHeader]),
    %MacIID = get_iid_from_mac(EUI64),
    % RestN represents the CarriedInline with field of interest 
    {Context, Rest0} = decode_cid(CID, Rest),
    {TrafficClass, FlowLabel, Rest1} = decode_tf(TF, Rest0), 
    {NextHeader,Rest2}  = decode_next_header(NH, Rest1),
    {HopLimit,Rest3} = decode_hlim(HLIM, Rest2),
    {SourceAddress,Rest4} = decode_sam(SAC, SAM, Rest3,EUI64, Context),
    {DestAddress,Payload} = decode_dam(M, DAC, DAM, Rest4,EUI64, Context),
    PayloadLength = byte_size(Payload),
    DecompressedFields = {TrafficClass, FlowLabel, PayloadLength, NextHeader, HopLimit,SourceAddress,DestAddress, Payload}, 
    
    io:format("DecompressedFields ~p~n", [DecompressedFields]),
    DecompressedPckt = tuple_to_bin(DecompressedFields),
    DecompressedPckt.
    %{TrafficClass, FlowLabel, NextHeader, HopLimit, SourceAddress, DestAddress, Payload}.


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
    <<TrafficClass:8, FL1:8, FL2:8,FL3:8, Rest/binary>> = CarriedInline,

    FlowLabel = <<FL1,FL2,FL3>>,

     case TF of
        2#11 -> % everything elided
            {<<0:8>>, <<0:20>>, CarriedInline};

        2#10 -> % Flow Label is elided, retrieve TF value carriedInline => get first 8bit of CarriedInline 
            {TrafficClass,<<0:20>>, Rest};

        2#01 -> % only DSCP is elided
            {TrafficClass,FlowLabel, Rest};
            
        2#00 -> % nothing elided
            %io:format("FlowLabel: ~p~n",[FlowLabel]),
            {TrafficClass,FlowLabel, Rest}
    end.

%-------------------------------------------------------------------------------
% @private
% @doc decode process for the NH field
% @returns the decoded NextHeader value 
% @end
%-------------------------------------------------------------------------------
decode_next_header(_, CarriedInline)->
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
        2#11 -> {255, CarriedInline};
        2#10 -> {64, CarriedInline};
        2#01 -> {1, CarriedInline};
        2#00 -> {HopLimit, Rest}
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
            <<_,_,_,_,_,_,G,H>> = MacIID,
            IID = <<G,H>>,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48,16#000000FFFE00:48,IID/binary>>,
            {SrcAdd, CarriedInline};
        2#10 -> % last 16bits carried
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A,B>>,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48,16#000000FFFE00:48,Last16Bits/binary>>,
            {SrcAdd, Rest};
        2#01 -> % last 64bits carried
            <<A:8,B:8,C:8,D:8,E:8,F:8,G:8,H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A,B,C,D,E,F,G,H>>,
             SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, Last64Bits/binary>>,
            {SrcAdd, Rest};
        2#00 -> % full add carried
            <<A:8,B:8,C:8,D:8,E:8,F:8,G:8,H:8,A2:8,B2:8,C2:8,D2:8,E2:8,F2:8,G2:8,H2:8, Rest/binary>> = CarriedInline,
            SrcAdd = <<A,B,C,D,E,F,G,H,A2,B2,C2,D2,E2,F2,G2,H2>>,
            {SrcAdd, Rest}
    end; 

decode_sam(SAC, SAM, CarriedInline, _, Context) when SAC == 1->
    case SAM of
        2#00 -> % the unspecified address ::
            SrcAdd = <<0:128>>,
            {SrcAdd, CarriedInline}; 
        
        2#01 -> % last 64bits carried
            <<A:8,B:8,C:8,D:8,E:8,F:8,G:8,H:8, Rest/binary>> = CarriedInline,
            ContextAddr = maps:get(Context, ?Context_id_table),
            Last64Bits = <<A,B,C,D,E,F,G,H>>,
             SrcAdd = <<ContextAddr/binary, Last64Bits/binary>>,
            {SrcAdd, Rest};

        2#10 -> % last 16bits carried
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A,B>>,
            ContextAddr = maps:get(Context, ?Context_id_table),
            SrcAdd = <<ContextAddr/binary,16#000000FFFE00:48,Last16Bits/binary>>,
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
decode_dam(M, DAC, DAM, CarriedInline, _, _) when  M == 0; DAC == 0 ->
    case DAM of
        2#11 -> {<<?LINK_LOCAL_PREFIX:16, 0:112>>, CarriedInline};
        2#10 -> % last 16bits carried
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A,B>>,
            DstAdd =  <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, Last16Bits/binary>>,
            {DstAdd, Rest};
        2#01 -> % last 64bits carried
            <<A:8,B:8,C:8,D:8,E:8,F:8,G:8,H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A,B,C,D,E,F,G,H>>, 
            DstAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, Last64Bits/binary>>,
            {DstAdd, Rest};
        2#00 -> % full add carried
            <<A:8,B:8,C:8,D:8,E:8,F:8,G:8,H:8,A2:8,B2:8,C2:8,D2:8,E2:8,F2:8,G2:8,H2:8, Rest/binary>> = CarriedInline,
            DstAdd = <<A,B,C,D,E,F,G,H,A2,B2,C2,D2,E2,F2,G2,H2>>,
            {DstAdd, Rest}
    end;

decode_dam(M, DAC, DAM, CarriedInline, _, Context) when  M == 0; DAC == 1->
    case DAM of
        2#11 -> {<<?GLOBAL_PREFIX_1, 0:112>>, CarriedInline};
        2#10 -> % last 16bits carried
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A,B>>,
            ContextAddr = maps:get(Context, ?Context_id_table),
            DstAdd =  <<ContextAddr/binary, 16#000000FFFE00:48, Last16Bits/binary>>,
            {DstAdd, Rest};
        2#01 -> % last 64bits carried
            <<A:8,B:8,C:8,D:8,E:8,F:8,G:8,H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A,B,C,D,E,F,G,H>>, 
            ContextAddr = maps:get(Context, ?Context_id_table),
            DstAdd = <<ContextAddr/binary, Last64Bits/binary>>,
            {DstAdd, Rest};
        2#00 -> {error_reserved, CarriedInline}
    end;


decode_dam(M, DAC, DAM, CarriedInline, _, _) when M == 1; DAC == 0->
    case DAM of
        2#00 -> 
            <<A:8,B:8,C:8,D:8,E:8,F:8,G:8,H:8,A2:8,B2:8,C2:8,D2:8,E2:8,F2:8,G2:8,H2:8, Rest/binary>> = CarriedInline,
            DstAdd = <<A,B,C,D,E,F,G,H,A2,B2,C2,D2,E2,F2,G2,H2>>,
            {DstAdd, Rest};
        2#01 -> % last 48bits carried
            <<_:8, _:8, C:8, D:8, E:8, F:8, G:8, H:8, Rest/binary>> = CarriedInline,
            Last48Bits = <<C,D,E,F,G,H>>,
            DstAdd = <<?MULTICAST_PREFIX:16,0:64, Last48Bits/binary>>,
            {DstAdd, Rest};
        2#10 -> % last 32bits carried
            <<A:8, B:8,C:8, D:8, Rest/binary>> = CarriedInline,
            Last32Bits = <<A,B,C,D>>,
            DstAdd = <<?MULTICAST_PREFIX, 0:80, Last32Bits/binary>>,
            {DstAdd, Rest};
        2#11 -> % last 8bits carried
            <<Last8Bits:8, Rest/binary>> = CarriedInline,
            DstAdd = <<16#FF02:16, 0:104, Last8Bits>>,
            {DstAdd, Rest}
    end;

decode_dam(M, DAC, DAM, CarriedInline, _, _) when M == 1; DAC == 1->
    case DAM of
        2#00 -> % last 48bits carried
            <<A:8, B:8, C:8, D:8, E:8, F:8, Rest/binary>> = CarriedInline,
            Last48Bits = <<A,B,C,D,E,F>>,
            DstAdd = <<16#FF, 0:64, Last48Bits/binary>>,
            {DstAdd, Rest}
    end.


%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Packet Decompression Helper
%------------------------------------------------------------------------------------------------------------------------------------------------------
%get_iid_from_mac(MacAdd) ->
%    %io:format("Received mac add: ~p~n", [MacAdd]),
%    <<A1:8, A2:8, A3:8, A4:8, A5:8, A6:8>> = MacAdd,
%    Mask = 2#00000010,
%    ULBLit = A1 bxor Mask, % Invert 7th bit
%    %io:format("Before: ~p~nAfter: ~p~n", [MacAdd,ULBLit]),
%    IID = <<ULBLit:8, A2:8, A3:8, 16#FF:8, 16#FE:8, A4:8, A5:8, A6:8>>,
%    %io:format("Result: ~p~n", [IID]),
%    IID.

%-------------------------------------------------------------------------------
% @doc return default Ipv6 address of a node (Link-local address)
% @end
%-------------------------------------------------------------------------------
get_default_LL_add(MacAdd)->
    %IID = get_iid_from_mac(MacAdd), %TODO verify correctness
    LLAdd = <<16#FE80:16, 0:48,MacAdd/binary>>,
    %io:format("LLAdd: ~p~n", [LLAdd]),
    LLAdd.

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


% upon receive fragment event: 
% - start timer
% - start counter = counter+receive frag size, stop when counter = datagram_orig_size
% - from header, add payload and offset to a map tag => {offset, payload}
% if timout, discard datagram => remove it from map 

%-------------------------------------------------------------------------------
% @doc helper function to retrieve datagram info 
% @returns a tuple containing useful datagram fields
% @end
%-------------------------------------------------------------------------------
datagram_info(Fragment)->
    <<FragType:5, DatagramSize:11, DatagramTag:16, DatagramOffset:8, Payload/binary>> = Fragment,
    FragInfo = #datagramInfo{fragtype = FragType, datagramSize = DatagramSize, 
        datagramTag = DatagramTag, datagramOffset = DatagramOffset, payload = Payload},
    FragInfo. 

    %{FragType, DatagramSize, DatagramTag, DatagramOffset, Payload}.

%start_reassembly_timer(DatagramTag, Map)->
%    erlang:send_after(?REASSEMBLY_TIMEOUT, self(), {timeout, DatagramTag, Map}).

%-------------------------------------------------------------------------------
% @doc launch the reassembly process
% @param Fragments: list [{Header1, Fragment1}, ..., {HeaderN, FragmentN}]
% @returns the reassembled ipv6 packet
% @end
%-------------------------------------------------------------------------------
reassemble_datagrams(Fragments) when is_list(Fragments)->
    [FirstFragment | _] = Fragments, 

    DtgInfo = lowpan:datagram_info(FirstFragment),
    Size = DtgInfo#datagramInfo.datagramSize, 
    Tag = DtgInfo#datagramInfo.datagramTag, 


    Datagram = #datagram{tag = Tag, size = Size},
    DatagramMap = maps:put(Tag, Datagram, ?DATAGRAMS_MAP), % add retrieve info to the datagram map 

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
process_fragments([], Map, ReassembledPacket)->
    {ReassembledPacket, Map};  % when the list is empty, returns the last payload and the final map state

process_fragments([HeadFrag | TailFrags], DatagramMap, _Payload)->
    {ReassembledPacket, UpdatedMap} = process_fragment(HeadFrag, DatagramMap),
    process_fragments(TailFrags, UpdatedMap, ReassembledPacket).

%-------------------------------------------------------------------------------
% @private
% @doc process the first fragment, launch timer, and add it to the DatagramMap  
% the reassembly if last fragment is received 
% @end
%-------------------------------------------------------------------------------
process_fragment(<<?FRAG1_DHTYPE:5, Size:11, Tag:16, Offset:8, Payload/binary>>, Map) ->
    NewFragment = #{Offset => Payload},
    CurrSize = byte_size(Payload),
    Datagram = #datagram{tag = Tag, size = Size, cmpt=CurrSize, fragments = NewFragment},
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
            UpdatedCmpt = OldDatagram#datagram.cmpt + CurrSize, % update size cmpt
            FragmentsMap = OldDatagram#datagram.fragments, % get fragmentMap
            NewFragments = FragmentsMap#{Offset => Payload}, % put new fragment to fragmentMap
            UpdatedDatagram = OldDatagram#datagram{cmpt = UpdatedCmpt, fragments = NewFragments}, % update datagram
            UpdatedMap = maps:put(Tag, UpdatedDatagram, Map), % update DatagramMap
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
% @private
% @doc helper function to reassembled all received fragments based on the Tag
% @end
%-------------------------------------------------------------------------------
reassemble(Tag,UpdatedMap)->
    %io:format("Complete for pckt ~p~n~p~n", [Tag, UpdatedMap]),
    Datagram = maps:get(Tag, UpdatedMap),
    FragmentsMap = Datagram#datagram.fragments,
    % sort fragments by offset and extract the binary data
    SortedFragments = lists:sort([ {Offset, Fragment} || {Offset, Fragment} <- maps:to_list(FragmentsMap) ]),
    % concatenate the fragments
    ReassembledPacket = lists:foldl(fun({_Offset, Payload}, Acc)-> 
                                        <<Acc/binary, Payload/binary>> % append new payload to the end   
                                    end, <<>>, SortedFragments), %% <<>> is the initial value of the accumulator
    discard_datagram(Tag,UpdatedMap), % discard tag so it can be reused
    ReassembledPacket.


discard_datagram(Tag, Map)->
    maps:remove(Tag,Map).

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


% 0                   1                   2                   3
% 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
% |1 0|V|F|HopsLft| originator address, final address ... 
% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


build_mesh_header(MeshHeader)->
   #mesh_header{
       mesh_type = MeshType, v_bit = VBit, f_bit = FBit, hops_left = HopsLeft,
       originator_address = OriginatorAddress, final_destination_address = FinalDestinationAddress
   } = MeshHeader,
   <<?MESH_DHTYPE:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress/bitstring,FinalDestinationAddress/bitstring>>.



%-------------------------------------------------------------------------------
% Retrieve next hop from routing table
%-------------------------------------------------------------------------------
get_next_hop(DestAddress)->
    Next_Hop =  maps:get(?Routing_table, DestAddress),
    Next_Hop. 


