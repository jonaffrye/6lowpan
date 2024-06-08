% @doc 6LoWPAN header
-include("ieee802154.hrl").
-include("mac_frame.hrl").

%----------------------------------------------Useful records structure---------------------------------------------
-record(ipv6PckInfo,
        {version = 6,
         trafficClass,
         flowLabel,
         payloadLength,
         nextHeader,
         hopLimit,
         sourceAddress,
         destAddress,
         payload}).
-record(datagramInfo, {fragtype, datagramSize, datagramTag, datagramOffset, payload}).


%----------------------------------------------Dispatch Type and Header---------------------------------------------

%@doc dispatch value bit pattern from rfc4944, DH stands for dispatch header

-define(NALP_DHTYPE, 2#00). % Not a LoWPAN frame, such packet shall be discarded
-define(IPV6_DHTYPE, 2#01000001). % Uncompressed IPv6 Addresses
-define(HC1_DHTYPE, 2#01000010). %  LOWPAN_HC1 compressed IPv6
-define(IPHC_DHTYPE, 2#011).      %  LOWPAN_IPHC compressed IPv6 (RFC6282)
-define(BC0_DHTYPE, 2#01010000). % LOWPAN_BC0 broadcast
-define(ESC_DHTYPE, 2#01111111). % Additional Dispatch byte follows
-define(MESH_DHTYPE, 2#10). % Mesh Header
-define(FRAG1_DHTYPE, 2#11000). % Frist fragmentation Header
-define(FRAGN_DHTYPE, 2#11100). % Subsequent fragmentation Header
-define(UDP_DHTYPE, 2#11110). % UDP header compression

-define(Oxf0b, 2#111100001011).
-define(Oxf0, 2#11110000).

-type dispatch_type() ::
    ?NALP_DHTYPE |
    ?IPV6_DHTYPE |
    ?HC1_DHTYPE |
    ?IPHC_DHTYPE |
    ?BC0_DHTYPE |
    ?ESC_DHTYPE |
    ?MESH_DHTYPE |
    ?FRAG1_DHTYPE |
    ?FRAGN_DHTYPE.

%---------------------------------------- Fragmentation Type and Header ---------------------------------------------------

-type frag_type() :: ?FRAG1_DHTYPE | ?FRAGN_DHTYPE.

-record(frag_header,
        {frag_type = ?FRAG1_DHTYPE :: frag_type(),
         datagram_size, % 11 bits field to encode IP packet size bfr fragmentation
         datagram_tag, % 16 bits to tag a specific
         datagram_offset}). % 8-bits field for datagram offset
-record(datagram,
        {%timer,
         tag,
         size,
         cmpt,
         fragments}).

-define(MAX_FRAME_SIZE,80). % since IEEE 802.15.4 leaves approximately 80-100 bytes of payload!
-define(MAX_FRAG_SIZE, 2047). % 11 bits datagram_size
-define(REASSEMBLY_TIMEOUT, 60000). % 60 sec
-define(FRAG_HEADER_SIZE,5). % 5 bytes including frag_type, datagram_size, datagram_tag, and datagram_offset
-define(DATAGRAMS_MAP,#{}). % map of received datagrams, the keys are the tag of datagrams
-define(MAX_TAG_VALUE, 65535).

%--------------------------------------------------- Header Compression -----------------------------------------------------
-record(ipv6_header,
        {version = 2#0110, % 4-bit Internet Protocol version number = 6
         traffic_class, % 8-bit traffic class field
         flow_label, % 20-bit flow label
         payload_length, % 16-bit unsigned integer
         next_header, % 8-bit selector
         hop_limit, % 8-bit unsigned integer
         source_address, % 128-bit address of the originator of the packet
         destination_address}). % 128-bit address of the intended recipient of the
-record(udp_header,
        {source_port, % 16-bit identifies the sender's port
         destination_port,  % 16-bit identifies the receiver's port and is required
         length,  % 16-bit indicates the length in bytes of the UDP header and UDP data
         checksum}). % 16-bitfield may be used for error-checking of the header and data
-record(iphc_header,
        {dispatch = ?IPHC_DHTYPE, % 3-bit dispatch value
         tf, % 2-bit field for Traffic Class and Flow Control compression options
         nh, % 1-bit field for Next Header encoding using NHC
         hlim, % 2-bit field for Hop Limit compression
         cid, % 1-bit field for Context Identifier Extension
         sac, % 1-bit field for Source Address Compression (stateless or stateful)
         sam, % 2-bit field for Source Address Mode
         m, % 1-bit field for Multicast Compression
         dac, % 1-bit field for Destination Address Compression (stateless or stateful)
         dam}). % 2-bit field for Destination Address Mode

-define(LINK_LOCAL_PREFIX, 16#FE80).
-define(MULTICAST_PREFIX, 16#FF02).
%-define(GLOBAL_PREFIX,16#20).
%-define(GLOBAL_PREFIX_1,16#2000).
-define(GLOBAL_PREFIX_1, 16#2001).
-define(GLOBAL_PREFIX_3, 16#2003).
-define(MESH_LOCAL_PREFIX, 16#FD00).
-define(UDP_PN, 17). %PN stands for Protocol Number
-define(TCP_PN, 6).
-define(ICMP_PN, 58).
-define(Context_id_table,
        #{0 => <<16#FD00:16, 0:48>>, % mesh local prefix
          1 => <<16#2000:16, 0:48>>, % global prefix 1
          2 => <<16#2001:16, 0:48>>, % global prefix 2
          3 => <<16#2002:16, 0:48>>}). % global prefix 3
                                                                                                                                                                                                                                                                                                                                                          % add more context prefix
-define(SHORT_ADD_LEN, 2).
-define(EXTENDED_ADD_LEN, 8).

%---------------------------------------------------- Routing ----------------------------------------------------------------
-define(BroadcastAdd, <<"ÿÿ">>).
-define(ACK_FRAME, <<>>).

-record(mesh_header,
        {mesh_type = ?MESH_DHTYPE,
         v_bit,
         f_bit,
         hops_left,
         originator_address,
         final_destination_address}).

-record(meshInfo,
        {version = 6,
         v_bit,
         f_bit,
         hops_left,
         originator_address,
         final_destination_address,
         payload}).


-define(Max_Hops, 10).
-define(node1_addr, <<16#CAFEDECA00000001:64>>).
-define(node2_addr, <<16#CAFEDECA00000002:64>>).
-define(node3_addr, <<16#CAFEDECA00000003:64>>).

-define(Default_routing_table,
        #{?node1_addr => ?node1_addr,
          ?node2_addr => ?node2_addr,
          ?node3_addr => ?node3_addr}).

-define(Node1_routing_table,
        #{?node1_addr => ?node1_addr,
          ?node2_addr => ?node3_addr,
          ?node3_addr => ?node2_addr}).

-define(Node2_routing_table,
        #{?node1_addr => ?node1_addr,
          ?node2_addr => ?node2_addr,
          ?node3_addr => ?node3_addr}).

-define(Node3_routing_table,
        #{?node1_addr => ?node2_addr,
          ?node2_addr => ?node2_addr,
          ?node3_addr => ?node3_addr}).


