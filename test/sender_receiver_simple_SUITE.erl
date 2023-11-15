-module(sender_receiver_simple_SUITE).

-include("../src/ieee802154.hrl").
-include("../src/mac_frame.hrl").

-include_lib("common_test/include/ct.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2, init_per_testcase/2, end_per_testcase/2]).
-export([sender/1]).
-export([receiver/1]).
-export([outsider/1]).

all() -> [{group, simple_tx_rx}, {group, tx_rx_multiple_nodes}].

groups() -> [{simple_tx_rx, [parallel], [sender, receiver]},
             {tx_rx_multiple_nodes, [parallel], [sender, receiver, outsider]}].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_, Config) ->
    FrameControl = #frame_control{src_addr_mode = ?EXTENDED, dest_addr_mode = ?EXTENDED}, 
    MacHeader = #mac_header{src_addr = <<16#CAFEDECA00000001:64>>, dest_addr = <<16#CAFEDECA00000002:64>>}, 
    Payload = <<"Test">>,
    {NetPid, Network} = ieee_node:boot_network_node(),
    [{net_pid, NetPid}, {network, Network}, {frame_control, FrameControl}, {mac_header, MacHeader}, {payload, Payload} | Config].

end_per_group(_, Config) ->
    Network = ?config(network, Config),
    NetPid = ?config(net_pid, Config),
    ieee_node:stop_network_node(Network, NetPid).

init_per_testcase(sender, Config) ->
    Network = ?config(network, Config),
    NodeRef = ieee_node:boot_ieee802154_node(sender, Network, mac_extended_address, <<16#CAFEDECA00000001:64>>),
    [{sender, NodeRef} | Config];
init_per_testcase(receiver, Config) ->
    Network = ?config(network, Config),
    NodeRef = ieee_node:boot_ieee802154_node(receiver, Network, mac_extended_address, <<16#CAFEDECA00000002:64>>),
    [{receiver, NodeRef} | Config];
init_per_testcase(outsider, Config) ->
    Network = ?config(network, Config),
    NodeRef = ieee_node:boot_ieee802154_node(outsider, Network, mac_extended_address, <<16#CAFEDECA00000003:64>>),
    [{outsider, NodeRef} | Config];
init_per_testcase(_, Config) ->
    Config.

end_per_testcase(Name, Config) ->
    {NodePid, Node} = ?config(Name, Config),
    ieee_node:stop_ieee802154_node(Node, NodePid);
end_per_testcase(_, _Config) ->
    ok.

%--- Test cases -----------------------------------------------------------------------------

sender(Config) ->
    ct:sleep(100),
    {_, Node} = ?config(sender, Config),
    {FrameControl, MacHeader, Payload} = get_expected_frame(Config),
    erpc:call(Node, ieee802154, transmission, [FrameControl, MacHeader, Payload]).

receiver(Config) ->
    {_, Node} = ?config(receiver, Config),
    {FrameControl, MacHeader, Payload} = get_expected_frame(Config),
    {ok, {FrameControl, MacHeader, Payload}} = erpc:call(Node, ieee802154, reception, []).

outsider(Config) ->
    {_, Node} = ?config(outsider, Config),
    {error, timeout} = erpc:call(Node, ieee802154, reception, []).

%--- Internal -------------------------------------------------------------------------------

get_expected_frame(Config) ->
    {?config(frame_control, Config), ?config(mac_header, Config), ?config(payload, Config)}.
