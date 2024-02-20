% @doc 6LoWPAN header

%----------------------------------------------Dispatch Type and Header---------------------------------------------

%@doc dispatch value bit pattern from rfc4944, DH stands for dispatch header

-define(NALP_DHTYPE, 2#00). % Not a LoWPAN frame, such packet shall be discarded
-define(IPV6_DHTYPE, 2#01000001). % Uncompressed IPv6 Addresses 
-define(HC1_DHTYPE, 2#01000010). %  LOWPAN_HC1 compressed IPv6 
-define(HC_DHTYPE, 2#011).      %  LOWPAN_HC1 compressed IPv6 
-define(BC0_DHTYPE, 2#01010000). % LOWPAN_BC0 broadcast
-define(ESC_DHTYPE, 2#01111111). % Additional Dispatch byte follows 
-define(MESH_DHTYPE, 2#10). % Mesh Header 
-define(FRAG1_DHTYPE,2#11000). % Frist fragmentation Header 
-define(FRAGN_DHTYPE,2#11100). % Subsequent fragmentation Header
%-define(UDP,2#11110).

-type dispatch_type() :: ?NALP_DHTYPE | ?IPV6_DHTYPE | ?HC1_DHTYPE | ?BC0_DHTYPE | ?ESC_DHTYPE |?MESH_DHTYPE | ?FRAG1_DHTYPE | ?FRAGN_DHTYPE.


%---------------------------------------Mesh Addressing Type and Header---------------------------------------------

-define(V_64BIT, 0). % originator is an IEEE extended 64-bit address (EUI-64)
-define(V_16BIT, 1). % 16-bit short address
-define(F_64BIT, 0). % final dest is an IEEE extended 64-bit address EUI-64
-define(F_16BIT, 1). % 16-bit short address
-define(HOPS_LEFT, 4#1111). % SHALL be decremented by each forwarding node before sending this packet towards its next hop
-define(HOPS_LEFT_DEEP, 16#F).


-type mesh_type() :: ?MESH_DHTYPE.
-type v_field() :: ?V_64BIT | ?V_16BIT.
-type f_field() :: ?F_64BIT | ?F_16BIT.
-type hl_field() :: 0..?HOPS_LEFT | ?HOPS_LEFT_DEEP.
-type o_add_field() :: binary().
-type f_add_field() :: binary().

-record(mesh_header, {
    mesh_type = ?MESH_DHTYPE,
    v_bit = ?V_64BIT :: v_field(),
    f_bit = ?V_64BIT :: f_field(),
    hops_left = ?HOPS_LEFT :: hl_field(),
    originator_address = <<0:16/unit:1>>,
    final_destination_address = <<0:16/unit:1>>
}).


%-----------------------------------------Fragmentation Type and Header----------------------------------------------------

-define(DEF_OFFSET,0).

-type frag_type() :: ?FRAG1_DHTYPE | ?FRAGN_DHTYPE.

-record(frag_header, {
    frag_type =  ?FRAG1_DHTYPE :: frag_type(),
    datagram_size, % 0..2047, 11 bit field to encode IP packet size bfr fragmentation
    datagram_tag, % 0..65535,  16 bit to tag a specific 
    datagram_offset %0..255 % 8-bit field for datagram offset
}).

-record(datagram, {
    timer,
    tag,
    size,
    cmpt,
    fragments
}).

-define(MAX_FRAME_SIZE, 33). 
-define(REASSEMBLY_TIMEOUT, 60000). % 60 sec
-define(FRAG_HEADER_SIZE, 5). % 5 bytes including frag_type, datagram_size, datagram_tag, and datagram_offset
-define(DATAGRAMS_MAP, #{}).

%--------------------------------------------------IPv6 Link Local Address--------------------------------------------------

-record(ipv6_LL_header, {
    prefix = 2#1111111010,
    padd = <<0:54/unit:1>>, % 54 bit full of zeros 
    identifier = <<0:64/unit:1>> %64 bits for interface identifier
}).


%----------------------------------------------------Header Compression------------------------------------------------------
% TODO: move to ipv6.hrl later

-record(ipv6_header, {
    version = 2#0110, % 4-bit Internet Protocol version number = 6
    traffic_class, % 8-bit traffic class field
    flow_label, % 20-bit flow label
    payload_length, % 16-bit unsigned integer
    next_header, % 8-bit selector
    hop_limit, % 8-bit unsigned integer
    source_address, % 128-bit address of the originator of the packet
    destination_address % 128-bit address of the intended recipient of the
}).

-record(lowpan_hc1_header, {
    hc_type = ?HC1_DHTYPE,
    hc1_encoding = <<0:8/unit:1>>, % 8-bit field for HC1 encoding
    pi :: 0..1, % Prefix carried in-line
    pc :: 0..1, % Prefix compressed
    ii :: 0..1, % Interface identifier carried in-line
    ic :: 0..1, % Interface identifier elided
    traffic_class_and_flow_label = 2#0, % 1-bit field for Traffic Class and Flow Label
    next_header = 2#00, % 2-bit field for Next Header
    hc2_encoding :: 0..1 % HC2 encoding flag
}).


-record(iphc_header, {
    dispatch = ?HC1_DHTYPE, % 3-bit dispatch value
    tf, % 2-bit field for Traffic Class and Flow Control compression options
    nh, % 1-bit field for Next Header encoding using NHC
    hlim, % 2-bit field for Hop Limit compression
    cid, % 1-bit field for Context Identifier Extension
    sac, % 1-bit field for Source Address Compression (stateless or stateful)
    sam, % 2-bit field for Source Address Mode
    m, % 1-bit field for Multicast Compression
    dac, % 1-bit field for Destination Address Compression (stateless or stateful)
    dam % 2-bit field for Destination Address Mode
}).


-define(LINK_LOCAL_PREFIX,16#FE80). 
-define(GLOBAL_PREFIX,16#2001). 
-define(LOCAL_MULTICAST,16#FFXX). 



-define(CONTEXT_TABLE, #{
    0 => "16#2001", % globale prefix
    1 => "16#FD00", % ULA prefix 
    % add more context prefix
}).


%-type lowpan_parameters() :: #lowpan_parameters{}.