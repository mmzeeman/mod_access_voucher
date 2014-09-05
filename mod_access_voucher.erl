%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @copyright 2014 Maas-Maarten Zeeman 
%% @doc Access a set of url's with the credentials of another user.

%% Copyright 2014 Maas-Maarten Zeeman
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.


-module(mod_access_voucher).
-author("Maas-Maarten Zeeman <mmzeeman@xs4all.nl>").
-behaviour(gen_server).

-mod_title("Access Voucher").
-mod_prio(5). 
-mod_description("Sign an URL for an user so that it can be used for accessing a set of zotonic dispatch rules.").

%% gen_server exports
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% Api
-export([
    new_voucher/2, 
    use_voucher/2, 
    start_link/1
]).

-export([
    observe_request_context/3,
    observe_acl_is_allowed/2,
    observe_acl_can_see/2,
    observe_acl_logoff/2,
    observe_acl_rcs_update_check/3
]).

-include_lib("zotonic.hrl").

-define(TOKEN_LEN, 20).
-define(SECRET_LEN, 40).
-define(VOUCHER_TABLE, voucher_table).
-define(VOUCHER_EXPIRE_INTERVAL, 30000).
-define(VOUCHER_EXPIRE_TIME, 180). % in seconds

-define(UNIX_EPOCH, 62167219200).

-record(state, {
   table 
}).

%%
%% Api
%%

new_voucher(DispatchNames, Context) ->
    case z_acl:user(Context) of
        undefined ->
            {error, no_user};
        UserId ->
            gen_server:call(name(Context), {new_voucher, UserId, DispatchNames})
    end.

use_voucher(VoucherId, Context) ->
    gen_server:call(name(Context), {use_voucher, VoucherId}).

start_link(Args) when is_list(Args) ->
    Host = proplists:get_value(host, Args),
    Name = name(?MODULE, Host),
    gen_server:start_link({local, Name}, ?MODULE, Args, []).


%% 
%% Gen server callbacks
%%

%% Gen server stuff.
init(Args) ->
    {host, Host} = proplists:lookup(host, Args),
    lager:md([{site, Host}, {module, ?MODULE}]),

    %% Create the ets table.
    TableName = z_utils:name_for_host(?VOUCHER_TABLE, Host),
    Table = ets:new(TableName, [named_table, set, {keypos, 1}, protected]),

    erlang:send_after(?VOUCHER_EXPIRE_INTERVAL, self(), expire_vouchers),

    {ok, #state{table=Table}}.

handle_call({new_voucher, UserId, DispatchRules}, _From, State) ->
    VoucherId = z_convert:to_binary(z_ids:id()),
    NotAfter = unix_time() + ?VOUCHER_EXPIRE_TIME,
    ets:insert(State#state.table, {VoucherId, UserId, DispatchRules, NotAfter}),
    {reply, {ok, VoucherId}, State};

handle_call({use_voucher, Id}, _From, State) ->
    case ets:lookup(State#state.table, Id) of
        [{Id, UserId, DispatchRules, _NotAfter}] ->
            true = ets:delete(State#state.table, Id),
            {reply, {ok, UserId, DispatchRules}, State};
        _ ->
            {reply, not_found, State}
    end;
handle_call(Message, _From, State) ->
    {stop, {unknown_call, Message}, State}.

handle_cast(Message, State) ->
    {stop, {unknown_cast, Message}, State}.

handle_info(expire_vouchers, State) ->
    Now = unix_time(),
    %% Delete expired vouchers
    ets:select_delete(State#state.table, [{{'_','_','_','$1'},[{'<','$1', Now}],[true]}]),
    erlang:send_after(?VOUCHER_EXPIRE_INTERVAL, self(), expire_vouchers),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%
%% Observe stuff
%%

observe_request_context(request_context, Context, _Context) ->
    case z_context:get_q("z_access_voucher", Context) of
        undefined -> Context;
        Voucher ->
            logon_if_voucher_ok(z_convert:to_binary(Voucher), Context)
    end.

observe_acl_is_allowed(_, Context) -> 
    delegate(Context).

observe_acl_can_see(_, Context) ->
    delegate(Context).
    
observe_acl_logoff(_, #context{session_id=SessionId}=Context) ->
    z_depcache:flush({z_access_voucher_allowed_dispatches, SessionId}, Context),
    z_session:set(z_access_voucher_allowed_dispatches, undefined, Context),
    Context.

observe_acl_rcs_update_check(_, Props, Context) ->
    case delegate(Context) of
        false -> [];
        undefined -> Props
    end.

%%
%% Helpers
%%

name(#context{}=Context) ->
    name(?MODULE, Context#context.host);
name(Host) when is_atom(Host) ->
    name(?MODULE, Host).

name(Atom, Host) when is_atom(Atom) ->
    z_utils:name_for_host(Atom, Host).

delegate(#context{session_pid=undefined}) -> 
    undefined; % no session, let other acl modules decide what to do.
delegate(Context) ->
    case get_allowed_dispatches(Context) of
        undefined -> 
            undefined; % pass, this user is not logged on with a voucher.
        DispatchList -> 
            case lists:member(z_context:get(zotonic_dispatch, Context), DispatchList) of
                true ->
                    undefined; % allow, let pass the decision;
                false ->
                    false % block it.
            end
    end.

logon_if_voucher_ok(Voucher, Context) ->
    case use_voucher(Voucher, Context) of
        not_found ->
            lager:info("Unknown voucher \"~p\"", [Voucher]),
            Context;
        {ok, UserId, DispatchNames} ->
            {ok, SessionContext} = z_session_manager:ensure_session(Context),
            {ok, LogonContext} = z_auth:logon(UserId, SessionContext),
            z_session:set(z_access_voucher_allowed_dispatches, DispatchNames, LogonContext),
            z_context:set_noindex_header(true, LogonContext)
    end.

get_allowed_dispatches(#context{session_id=SessionId}=Context) ->
    F = fun() -> 
            z_session:get(z_access_voucher_allowed_dispatches, Context) 
    end,
    z_depcache:memo(F, {z_access_voucher_allowed_dispatches, SessionId}, Context).

unix_time() ->
    datetime_to_unix_time(erlang:universaltime()).

datetime_to_unix_time({{_,_,_},{_,_,_}}=DateTime) ->
    calendar:datetime_to_gregorian_seconds(DateTime) - ?UNIX_EPOCH.

