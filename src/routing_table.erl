-module(routing_table).
-behaviour(gen_server).

%%% API
-export([start/0, add_route/2, delete_route/1, get_route/1, update_route/2, reset_routing_table/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, terminate/2, code_change/3, stop/0]).

%%% API functions
start() ->
    gen_server:start({local, ?MODULE}, ?MODULE, [], []).


stop() -> gen_server:stop(?MODULE).

add_route(DestAddr, NextHAddr) ->
    gen_server:call(?MODULE, {add_route, DestAddr, NextHAddr}).

delete_route(DestAddr) ->
    gen_server:call(?MODULE, {delete_route, DestAddr}).

get_route(DestAddr) ->
    gen_server:call(?MODULE, {get_route, DestAddr}).

update_route(DestAddr, NextHAddr) ->
    gen_server:call(?MODULE, {update_route, DestAddr, NextHAddr}).

reset_routing_table() ->
    gen_server:call(?MODULE, reset).

%%% gen_server callbacks
init([]) ->
    {ok, #{}}.

handle_call({add_route, DestAddr, NextHAddr}, _From, MapState) ->
    NewMapState = maps:put(DestAddr, NextHAddr, MapState),
    {reply, ok, NewMapState};

handle_call({delete_route, DestAddr}, _From, MapState) ->
    NewMapState = maps:remove(DestAddr, MapState),
    {reply, ok, NewMapState};

handle_call({get_route, DestAddr}, _From, MapState) ->
    NextHAddr = maps:get(DestAddr, MapState, undefined),
    {reply, NextHAddr, MapState};

handle_call({update_route, DestAddr, NextHAddr}, _From, MapState) ->
    NewMapState = maps:put(DestAddr, NextHAddr, MapState),
    {reply, ok, NewMapState};

handle_call(reset, _From, _MapState) ->
    {reply, ok, #{}}.

handle_cast(_, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
