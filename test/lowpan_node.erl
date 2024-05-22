%% @doc This module is an utility module helping in the creation of remote nodes

-module(lowpan_node).

-export([boot_network_node/0, boot_network_node/1, stop_network_node/2]).
-export([boot_lowpan_node/3, boot_lowpan_node/4, stop_lowpan_node/2]).
-export([boot_node/1]).
-export([get_project_cwd/0]).

-include_lib("common_test/include/ct.hrl").

-include("../src/ieee802154.hrl").

-define(ROBOT_LIB_DIR, "/_build/default/lib").

-type mac_address_type() :: mac_short_address | mac_extended_address.
-type mac_address() :: <<_:16>> | <<_:64>>.


%% @private
%% @doc Gets the working directory of the project.
-spec get_project_cwd() -> string().
get_project_cwd() -> 
    {ok, Path} = file:get_cwd(),
    filename:dirname(filename:dirname(filename:dirname(filename:dirname(Path)))).

%% @private
%% @doc Boots a remote node using the code of the project.
-spec boot_node(atom()) -> {pid(), node()}.
boot_node(Name) ->
    ProjectCWD = get_project_cwd(),
    Flags = ["-pa", ProjectCWD ++ ?ROBOT_LIB_DIR ++ "/robot/ebin"],
    {ok, Pid, NodeName} = ?CT_PEER(#{name => Name, args => Flags}),
    unlink(Pid),
    {Pid, NodeName}.

%% @private
%% @equiv boot_network_node(#{}).
-spec boot_network_node() -> {pid(), node()}.
boot_network_node() ->
    boot_network_node(#{}).


%% @doc Pings a remote node and waits for a 'pong' answer.
%% This can be used to check if the node has been correctly started.
-spec ping_node(atom(), node()) -> ok | error.
ping_node(RegisteredName, Node) ->
    register(ping, self()),
    {RegisteredName, Node} ! {ping, ping, node()},
    receive
        pong -> ct:pal("Node: ~w says pong", [Node])
    after 2000 ->
        error(network_node_not_started)
    end,
    unregister(ping).

%% @doc Boot the network simulation node
%% This node is necessary to simulate the real UWB physical network
%% At startup, the mock_phy_network registers itself to the network to receive the tx frames
-spec boot_network_node(map()) -> {pid(), node()}.
boot_network_node(Args) ->
    {Pid, Network} = boot_node(network),
    erpc:call(Network, network_simulation, start, [{}, Args]),
    ping_node(network_loop, Network),
    {Pid, Network}.

%% @doc Stops the network node
%% This function stops the network process and then stops the node
-spec stop_network_node(node(), pid()) -> ok.
stop_network_node(Network, NetPid) ->
    erpc:call(Network, network_simulation, stop, [{}]),
    peer:stop(NetPid).

%% @doc Boots a node and initializes a 6LoWPAN stack inside.
%% The stack will use the mock_phy_network to simulate communications over UWB.
%% The network node needs to be started before calling this function.
%% The rx callback function used is a placeholder.
%% @equiv boot_lowpan_node(Name, Network, NodeMacAddress, fun() -> ok end).
-spec boot_lowpan_node(atom(), node(), mac_address()) -> {pid(), node()}.
boot_lowpan_node(Name, Network, NodeMacAddress) ->
    boot_lowpan_node(Name, Network, NodeMacAddress, fun() -> ok end).

%% @doc Boots a node and initializes a 6LoWPAN stack inside.
%% The stack will use the mock_phy_network to simulate communications over UWB.
%% The network node needs to be started before calling this function.
%% The Callback function is used at the reception of a frame when the rx loop is used.
-spec boot_lowpan_node(atom(), node(), mac_address(), fun()) -> {pid(), node()}.
boot_lowpan_node(Name, Network, NodeMacAddress, Callback) ->
    {Pid, Node} = boot_node(Name),
    init_network_layers(Node, Network, mac_extended_address, NodeMacAddress, Callback),
    erpc:call(Node, lowpan_layer, start, [#{node_mac_addr => NodeMacAddress}]),
    {Pid, Node}.

% @private
%% @doc Initializes network layers for a node.
-spec init_network_layers(node(), node(), mac_address_type(), mac_address(), fun()) -> ok.
init_network_layers(Node, Network, MacAddressType, NodeMacAddress, Callback) ->
    erpc:call(Node, mock_phy_network, start, [spi2, #{network => Network}]), % Starting the the mock driver/physical layer
    erpc:call(Node, ieee802154, start, [#ieee_parameters{phy_layer = mock_phy_network, duty_cycle = duty_cycle_non_beacon, input_callback = Callback}]),
    erpc:call(Node, mock_top_layer, start, []),
    erpc:call(Node, ieee802154, set_pib_attribute, [MacAddressType, NodeMacAddress]).


%% @doc Stops a 6LoWPAN node.
-spec stop_lowpan_node(node(), pid()) -> ok.
stop_lowpan_node(Node, NodePid) ->
    erpc:call(Node, lowpan_layer, stop, []),
    erpc:call(Node, routing_table, stop, []),
    peer:stop(NodePid).