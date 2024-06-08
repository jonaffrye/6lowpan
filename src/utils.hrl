-include("lowpan.hrl").

%----------------------------------------------Common value for testing purpose---------------------------------------------

-define(Node1MacAddress, <<16#CAFEDECA00000001:64>>).
-define(Node2MacAddress, <<16#CAFEDECA00000002:64>>).
-define(Node3MacAddress, <<16#CAFEDECA00000003:64>>).
-define(Payload, <<"Hello world this is an ipv6 packet for testing purpose">>).
-define(BigPayload, lowpan:generate_chunks()).
-define(PayloadLength, byte_size(?Payload)).
-define(Node1Address, lowpan:get_default_LL_add(?Node1MacAddress)).
-define(Node2Address, lowpan:get_default_LL_add(?Node2MacAddress)).
-define(Node3Address, lowpan:get_default_LL_add(?Node3MacAddress)).
-define(IPv6Header, #ipv6_header{
    version = 6,
    traffic_class = 0,
    flow_label = 0,
    payload_length = ?PayloadLength,
    next_header = 12,
    hop_limit = 64,
    source_address = ?Node1Address,
    destination_address = ?Node2Address
}).
-define(FrameControl, #frame_control{
    frame_type = ?FTYPE_DATA,
    src_addr_mode = ?EXTENDED,
    dest_addr_mode = ?EXTENDED
}).
-define(Ipv6Pckt, ipv6:build_ipv6_packet(?IPv6Header, ?Payload)).
-define(MacHeader, #mac_header{src_addr = ?Node1MacAddress, dest_addr = ?Node2MacAddress}).
