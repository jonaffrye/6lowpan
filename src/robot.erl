-module(robot).

-behaviour(application).

-include("mac_frame.hrl").
-include("ieee802154.hrl").
-include("lowpan.hrl").

-export([tx/0, tx_unc_ipv6/0, tx_iphc_pckt_ipv6/0, tx_frag_iphc_pckt_ipv6/0]).
-export([rx/0]).
-export([rx_on/0]).
-export([rx_off/0]).

% Benchmarking
-export([tx_benchmark/0]).
-export([rx_benchmark/0]).

% Callbacks
-export([start/2]).
-export([stop/1]).

-compile([{nowarn_unused_function, [{rx_callback, 4}]}]).

%--- Macros --------------------------------------------------------------------
-define(JAMMING_DATA, <<"JAMMING">>).
-define(DATALENGTH, byte_size(?JAMMING_DATA)).

-define(BENCHMARK_DATA, <<16#F:(111*8)>>).
-define(BENCHMARK_DATA_LENGTH, bit_size(?BENCHMARK_DATA)).

-define(PANID, <<16#CAFE:16>>).
-define(SENDER_ADDR, <<16#0001:16>>).
-define(RECEIVER_ADDR, <<16#0002:16>>).

-define(CCA_DURATION, 283).

-define(TX_ANTD, 16450).
-define(RX_ANTD, 16450).

%--- API -----------------------------------------------------------------------
% Sends/receive only 1 frame
tx() ->

    Node1MacAddress = <<16#CAFEDECA00000001:64>>, 
    Node2MacAddress = <<16#CAFEDECA00000002:64>>,

    Payload = <<"Hello world this is an ipv6 packet for testing purpose">>,
    

    Node1Address = lowpan:get_default_LL_add(Node1MacAddress),
    Node2Address = lowpan:get_default_LL_add(Node2MacAddress),
    PayloadLength = byte_size(Payload),

    Ipv6Pckt = <<6:4, 224:8, 2:20, PayloadLength:16, 12:8, 255:8, Node1Address/binary, Node2Address/binary, Payload/bitstring>>,

    lowpan_layer:snd_pckt(Ipv6Pckt).

tx_unc_ipv6()->
    Node1MacAddress = <<16#CAFEDECA00000001:64>>, 
    Node2MacAddress = <<16#CAFEDECA00000002:64>>,

    Payload = <<"Hello world this is an ipv6 packet for testing purpose">>, 

    Frame = <<?IPV6_DHTYPE:8, Payload/bitstring>>,

    io:format("Frame ~p~n",[Frame]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Frame)]),

    FrameControl = #frame_control{
            frame_type = ?FTYPE_DATA, 
            src_addr_mode = ?EXTENDED,
            dest_addr_mode = ?EXTENDED
            }, 

    MacHeader = #mac_header{
                src_addr = Node1MacAddress, 
                dest_addr = Node2MacAddress
                },
    lowpan_layer:tx(Frame, FrameControl, MacHeader).

tx_iphc_pckt_ipv6()->
    Node1MacAddress = <<16#CAFEDECA00000001:64>>, 
    Node2MacAddress = <<16#CAFEDECA00000002:64>>,

    Payload = <<"Hello world this is an ipv6 packet for testing purpose">>, 

    InlineData = <<12:8, 14627373598910709761:64, 14627373598910709762:64>>,
    ExpectedHeader = <<?IPHC_DHTYPE:3, 3:2, 12:1, 3:2, 0:1, 0:1, 1:2, 0:1, 0:1, 1:2, InlineData/binary>>,

    % Create the IPHC packet
    IPHC = lowpan:create_iphc_pckt(ExpectedHeader, Payload),
    io:format("IphcHeader ~p~n",[IPHC]),
    io:format("Fragment size: ~p bytes~n", [byte_size(IPHC)]),

    FrameControl = #frame_control{
            frame_type = ?FTYPE_DATA, 
            src_addr_mode = ?EXTENDED,
            dest_addr_mode = ?EXTENDED
            }, 

    MacHeader = #mac_header{
                src_addr = Node1MacAddress, 
                dest_addr = Node2MacAddress
                },
    lowpan_layer:tx(IPHC, FrameControl, MacHeader).

tx_frag_iphc_pckt_ipv6()->
    Node1MacAddress = <<16#CAFEDECA00000001:64>>, 
    Node2MacAddress = <<16#CAFEDECA00000002:64>>,

    Payload = <<"Hello world this is an ipv6 packet for testing purpose">>, 

    InlineData = <<12:8, 14627373598910709761:64, 14627373598910709762:64>>,
    ExpectedHeader = <<?IPHC_DHTYPE:3, 3:2, 12:1, 3:2, 0:1, 0:1, 1:2, 0:1, 0:1, 1:2, InlineData/binary>>,

    %IPHC = lowpan:create_iphc_pckt(ExpectedHeader, Payload),
    Frag = <<?FRAG1_DHTYPE:5, 1000:11, 12345:16, ExpectedHeader/bitstring>>,

    Frame = <<Frag/binary, Payload/bitstring>>, 

    io:format("Frame ~p~n",[Frame]),
    io:format("Fragment size: ~p bytes~n", [byte_size(Frame)]),

    FrameControl = #frame_control{
            frame_type = ?FTYPE_DATA, 
            src_addr_mode = ?EXTENDED,
            dest_addr_mode = ?EXTENDED
            }, 

    MacHeader = #mac_header{
                src_addr = Node1MacAddress, 
                dest_addr = Node2MacAddress
                },
    lowpan_layer:tx(Frame, FrameControl, MacHeader).


-spec rx_callback(Frame, LinkQuality, Security, Ranging) -> ok when
      Frame       :: frame(),
      LinkQuality :: integer(),
      Security    :: ieee802154:security(),
      Ranging     :: ieee802154:ranging_informations().
rx_callback({_FrameControl, _MacHeader, _Payload}, LQI, Security, Ranging) ->
    io:format("------ Frame report ------~n"),
    io:format("Link quality: ~p ~n", [LQI]),
    io:format("Security: ~w~n", [Security]),
    io:format("Ranging: ~w~n", [Ranging]),
    io:format("-------------------------~n").
    % io:format("Received frame with seqnum: ~w - Payload: ~w ~n",
    %           [_MacHeader#mac_header.seqnum, _Payload]).

rx_on() -> ieee802154:rx_on().
rx_off() -> ieee802154:rx_off().

tx(0, Total, Success, Error) -> {Success, Error, Total};
tx(N, Total, Success, Error) ->
    Seqnum = Total rem 512,
    case ieee802154:transmission({#frame_control{pan_id_compr = ?ENABLED,
                                                 ack_req = ?ENABLED},
                                  #mac_header{seqnum = Seqnum,
                                              dest_pan = ?PANID,
                                              dest_addr = ?RECEIVER_ADDR,
                                              src_addr = ?SENDER_ADDR},
                                  ?BENCHMARK_DATA}) of
        {ok, _} -> tx(N-1, Total+1, Success+1, Error);
        _ -> tx(N-1, Total+1, Success, Error+1)
    end.

tx_benchmark() ->
    ieee802154:set_pib_attribute(mac_pan_id, ?PANID),
    ieee802154:set_pib_attribute(mac_short_address, ?SENDER_ADDR),
    pmod_uwb:set_preamble_timeout(?CCA_DURATION),
    NbrFrames = 100,
    % NbrFrames = 1000,
    Start = os:timestamp(),
    {Success, Error, Total} = tx(NbrFrames, 0, 0, 0),
    End = os:timestamp(),
    Time = timer:now_diff(End, Start)/1000000,
    io:format("------------------- Report -------------------~n"),
    io:format("Sent ~w frames - Success rate ~.3f (~w/~w) - Error rate ~.3f (~w/~w)~n", [Total, Success/Total, Success, Total, Error/Total, Error, Total]),
    io:format("Data rate ~.1f b/s - ~w b in ~w s ~n", [(?BENCHMARK_DATA_LENGTH*NbrFrames)/Time, ?BENCHMARK_DATA_LENGTH*NbrFrames, Time]),
    io:format("----------------------------------------------~n").

rx_benchmark() ->
    ieee802154:set_pib_attribute(mac_pan_id, ?PANID),
    ieee802154:set_pib_attribute(mac_short_address, ?RECEIVER_ADDR),
    % rx().
    ieee802154:rx_on().

rx() ->
    ieee802154:reception(),
    rx().

start(_Type, _Args) ->
    {ok, Supervisor} = robot_sup:start_link(),
    grisp:add_device(spi2, pmod_uwb),
    pmod_uwb:write(tx_antd, #{tx_antd => ?TX_ANTD}),
    pmod_uwb:write(lde_if, #{lde_rxantd => ?RX_ANTD}),

    ieee802154:start_link(
      #ieee_parameters{duty_cycle = duty_cycle_non_beacon,
                       input_callback = fun double_sided_3_msg:rx_callback/4}
     ),

    case application:get_env(robot, pan_id) of
        {ok, PanId} -> ieee802154:set_pib_attribute(mac_pan_id, PanId);
        _ -> ok
    end,
    case application:get_env(robot, mac_addr) of
        {ok, MacAddr} -> ieee802154:set_pib_attribute(mac_short_address, MacAddr);
        _ -> ok
    end,

    ieee802154:rx_on(?ENABLED),

    Node1MacAddress = <<16#CAFEDECA00000001:64>>, 
    lowpan_layer:start(#{node_mac_addr => Node1MacAddress}),
    %tx(),
    {ok, Supervisor}.

% @private
stop(_State) -> ok.
