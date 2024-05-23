-module(frame_handler).
-behaviour(gen_server).
-include_lib("common_test/include/ct.hrl").
-include("../src/mac_frame.hrl").
%%% API
-export([start/1]).
-export([rx_frame/4]).
-export([stop/0]).


-export([init/1]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).

%%% API functions
start(NodeMacAddress) ->
    gen_server:start({local, ?MODULE}, ?MODULE, NodeMacAddress, []).

rx_frame(Frame, _, _, _) ->
    gen_server:cast(?MODULE, {rx, Frame}).

stop() ->
    gen_server:stop(?MODULE).

%%% gen_server callbacks
init(NodeMacAddress) ->
    {ok, #{node_mac_address => NodeMacAddress, received => []}}.

handle_cast({rx, Frame}, #{node_mac_address := NodeMacAddress} = State) ->
    {_, MH, Payload} = Frame,
    io:format("New frame received~n~p~n", [Payload]),
    %io:format("New Frame len: ~p bytes~n",[byte_size(Payload)]),
    {FC, MH, Payload} = Frame,

    From = MH#mac_header.src_addr,
    %io:format("From node~p~n", [From]),   

    CurrNodeMacAdd = NodeMacAddress,
    DstMacAdd = MH#mac_header.dest_addr,
    %io:format("~nIn Callback~nCurrNodeMacAdd: ~p~nDstMacAdd: ~p~n", [CurrNodeMacAdd, DstMacAdd]),
 
    BroadcastAdd = <<"ÿÿ">>,

    case DstMacAdd of
        CurrNodeMacAdd ->
            io:format("Dest reached, Forwarding to lowpan layer~n"),
            gen_statem:cast(lowpan_layer, {new_frame, Payload});

        BroadcastAdd ->
            io:format("Ack received~n");

        _ ->
            NewMH = MH#mac_header{src_addr = CurrNodeMacAdd, dest_addr = DstMacAdd},
            NewFrame = {FC, NewMH, Payload},
            io:format("Not the dest, Keep forwarding~n"),
            ieee802154:transmission(NewFrame)
    end;

handle_cast(_, State) ->
    {noreply, State}.

handle_info(_, State) ->
    {noreply, State}.

terminate(_, _) ->
    ok.