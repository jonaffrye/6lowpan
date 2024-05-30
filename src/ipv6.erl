-module(ipv6).
-export([build_ipv6_packet/2, build_ipv6_udp_packet/3, build_ipv6_header/1, build_udp_header/1]).

-record(ipv6_header, {
    version = 2#0110, % 4-bit Internet Protocol version number = 6
    traffic_class,  % 8-bit traffic class field
    flow_label,  % 20-bit flow label
    payload_length, % 16-bit unsigned integer
    next_header,  % 8-bit selector
    hop_limit,  % 8-bit unsigned integer
    source_address, % 128-bit address of the originator of the packet
    destination_address % 128-bit address of the intended recipient of the
}).

-record(udp_header, {
    source_port, % 16-bit identifies the sender's port
    destination_port,  % 16-bit identifies the receiver's port and is required
    length,  % 16-bit indicates the length in bytes of the UDP header and UDP data
    checksum % 16-bitfield may be used for error-checking of the header and data
}).


% Returns a Ipv6 packet in a binary format
build_ipv6_header(IPv6Header)->
    #ipv6_header{
        version =  Version,
        traffic_class = Traffic_class, 
        flow_label = Flow_label, 
        payload_length = Payload_length,
        next_header = Next_header, 
        hop_limit = Hop_limit, 
        source_address = SourceAdd,
        destination_address = DestAdd
    } = IPv6Header,

    <<Version:4,Traffic_class:8,Flow_label:20,Payload_length:16,Next_header:8,Hop_limit:8,SourceAdd/binary,DestAdd/binary>>.


build_udp_header(UdpHeader)->
    #udp_header{
        source_port =  SourcePort,
        destination_port = DestinationPort, 
        length = Length, 
        checksum = Checksum
    } = UdpHeader,

    <<SourcePort:16,DestinationPort:16,Length:16,Checksum:16>>.

build_ipv6_packet(IPv6Header, Payload)->
    Header = build_ipv6_header(IPv6Header),
    IPv6Packet = <<Header/binary, Payload/bitstring>>,
    IPv6Packet.

build_ipv6_udp_packet(IPv6Header, UdpHeader, Payload)->
    IpHeader = build_ipv6_header(IPv6Header),
    UdpH = build_udp_header(UdpHeader),
    IPv6Packet = <<IpHeader/binary, UdpH/binary, Payload/bitstring>>,
    IPv6Packet.