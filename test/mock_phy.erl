-module(mock_phy).
-behaviour(gen_server).

-export([start_link/2]).
-export([transmit/2]).
-export([reception/1]).

%%% gen_server callbacks
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).

-define(NAME, mock_phy).

% --- API -----------------------------------------

start_link(Params, State) ->
    gen_server:start_link({local, ?NAME}, ?MODULE, {Params, State}, []).

transmit(Data, Options) ->
    gen_server:call(?NAME, {transmit, Data, Options}).

reception(_) ->
    gen_server:call(?NAME, {reception}).

%%% gen_server callbacks
init({Params, State}) ->
    io:format("Mock phy created~n"),
    case State of
        perfect -> {ok, perfect};
        faulty -> {ok, faulty};
        loss -> {ok, loss}
    end.

handle_call({transmit, Data, Options}, _From, State) -> {reply, tx(Data, Options), State};
handle_call({reception}, _From, perfect) -> {reply, rx(), perfect};
handle_call({reception}, _From, faulty) -> {reply, rx_faulty(), faulty};
handle_call({reception}, _From, loss) ->
    case rand:uniform(2) of
        1 -> {reply, rx_faulty(), loss};
        2 -> {reply, rx(), loss}
    end;
handle_call(_Request, _From, _State) -> error(not_implemented).

handle_cast(_Request, _State) ->
  error(not_implemented).


% --- Internal -----------------------------------------
tx(_Data, _Options) ->
    % TODO
    ok.

rx() ->
    {14, <<16#6188:16, 0:8, 16#CADE:16, "XR", "XT", "Hello">>}.
rx_faulty() ->
    timer:sleep(2000),
    rxpto.
