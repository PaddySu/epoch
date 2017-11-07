%%%-------------------------------------------------------------------
%%% @copyright (C) 2017, Aeternity Anstalt
%%% @doc
%%%    A library providing Cuckoo Cycle PoW generation and verification.
%%%    A NIF interface to the C/C++ Cuckoo Cycle implementation of
%%%    John Tromp:  https://github.com/tromp/cuckoo
%%%    White paper: https://github.com/tromp/cuckoo/blob/master/doc/cuckoo.pdf?raw=true
%%% @end
%%%-------------------------------------------------------------------
-module(aec_pow_cuckoo).

-behaviour(aec_pow).

-export([generate/5,
         generate/7,
         verify/4]).

-include("pow.hrl").

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-include_lib("eunit/include/eunit.hrl").   %% FIXME: get rid of this!
-endif.

-define(CUCKOO_ALGORITHM, mean).
-define(CUCKOO_GRAPH_SIZE, 16).   %% FIXME: shall be 29
-define(CUCKOO_BUFSIZE, 80).
-define(SERVER, ?MODULE).

-record(state, {os_pid :: integer() | undefined,
                buffer = [] :: string(),
                target :: aec_pow:sci_int()}).

-type pow_cuckoo_solution() :: [integer()].


%%%=============================================================================
%%% API
%%%=============================================================================

%%%=============================================================================
%%% aec_pow API
%%%=============================================================================

%%------------------------------------------------------------------------------
%% Proof of Work generation with default settings, multiple attempts
%%
%% According to my experiments, increasing the number of trims from the default
%% 7 in John Tromp's code does not really affect speed, reducing it causes failure.
%%
%% Measured execution times (seconds) for 7 trims for threads:
%%   1: 44.61 46.92 46.41
%%   2: 15.17 15.75 19.19
%%   3:  9.35 10.92  9.73
%%   4: 10.66  7.83 10.02
%%   5:  7.41  7.47  7.32
%%  10:  7.27  6.70  6.38
%%  20:  6.25  6.74  6.41
%%
%%  Very slow below 3 threads, not improving significantly above 5, let us take 5.
%%------------------------------------------------------------------------------
-spec generate(Data :: aec_sha256:hashable(), Target :: aec_pow:sci_int(),
               Retries :: integer(), Nonce :: integer(),
               MaxNonce :: integer()) -> aec_pow:pow_result().
generate(Data, Target, Retries, Nonce, MaxNonce) ->
    generate(Data, Nonce, MaxNonce, Target, 7, 5, Retries).

%%------------------------------------------------------------------------------
%% Proof of Work generation, all params adjustable
%%------------------------------------------------------------------------------
-spec generate(Data :: aec_sha256:hashable(), Nonce :: integer(), MaxNonce :: integer(),
               Target :: aec_pow:sci_int(), Trims :: integer(),
               Threads :: integer(), Retries :: integer()) ->
                      aec_pow:pow_result().
generate(Data, Nonce, MaxNonce, Target, Trims, Threads, Retries) ->
    Hash = base64:encode(aec_sha256:hash(Data)),
    generate_int(Hash, Nonce, MaxNonce, Target, Trims, Threads, Retries).

%%------------------------------------------------------------------------------
%% Proof of Work verification (with difficulty check)
%%------------------------------------------------------------------------------
-spec verify(Data :: aec_sha256:hashable(), Nonce :: integer(),
             Evd :: aec_pow:pow_evidence(), Target :: aec_pow:sci_int()) ->
                    boolean().
verify(Data, Nonce, Evd, Target) when is_list(Evd) ->
    Hash = base64:encode_to_string(aec_sha256:hash(Data)),
    case test_target(Evd, Target) of
        true ->
            verify(Hash, Nonce, Evd);
        false ->
            false
    end.

%%%=============================================================================
%%% Internal functions
%%%=============================================================================

%%------------------------------------------------------------------------------
%% Proof of Work generation: use the hash provided and try consecutive nonces
%%------------------------------------------------------------------------------
-spec generate_int(Hash :: binary(), Nonce :: integer(), MaxNonce :: integer(),
                   Target :: aec_pow:sci_int(), Trims :: integer(),
                   Threads :: integer(), Retries :: integer()) ->
                          {'ok', Nonce2 :: integer(), Solution :: pow_cuckoo_solution()} |
                          {'error', term()}.
generate_int(_Hash, _Nonce, _MaxNonce, _Target, _Trims, _Threads, 0) ->
    {error, generation_count_exhausted};
generate_int(_Hash, MaxNonce, MaxNonce, _Target, _Trims, _Threads, _Retries) ->
    {error, nonce_range_exhausted};
generate_int(Hash, Nonce, MaxNonce, Target, Trims, Threads, Retries) when Retries > 0 ->
    %% Cuckoo uses 32-bit nonces. It generates its keys based on an 80-byte buffer.
    %% where Hash is inserted at the beginning of it and the nonce is in its last 4 bytes.
    %% We use 64-bit nonces and place it in the 8 bytes before the last 4 bytes of the
    %% buffer here. (The hash is only 43 bytes, so we do not overwrite useful data.)
    %% We always pass 0 as nonce for cuckoo as the real nonce is already included.
    NoncePos = ?CUCKOO_BUFSIZE - 12,
    HashAndNonce =
        case size(Hash) of
            Sz when Sz < NoncePos ->
                ZSz = 8*(NoncePos - Sz),
                <<Hash/binary, 0:ZSz, Nonce:64/little-unsigned-integer, 0:32>>;
            _ ->
                HSz = 8*NoncePos,
                <<H:HSz, _T/binary>> = Hash,
                <<H:HSz, Nonce:64/little-unsigned-integer, 0:32>>
        end,
    case generate_single(HashAndNonce, Target, Trims, Threads) of
        {ok, Soln} ->
            {ok, {Nonce, Soln}};
        {error, no_solutions} ->
            generate_int(Hash, next_nonce(Nonce), MaxNonce, Target,
                         Trims, Threads, Retries - 1);
        {error, _Reason} = Error ->
            %% Executable failed (segfault, not found, etc.): let miner decide
            Error
    end.

next_nonce(?MAX_NONCE) ->
    0;
next_nonce(Nonce) ->
    Nonce + 1.

binary_to_hex(<<>>, Acc) ->
    lists:flatten(lists:reverse(Acc));
binary_to_hex(<<Byte:8, T/binary>>, Acc) ->
    binary_to_hex(T, [io_lib:format("~2.16.0b", [Byte]) | Acc]).

%%------------------------------------------------------------------------------
%% Proof of Work generation, a single attempt
%%------------------------------------------------------------------------------
-spec generate_single(HeaderAndNonce :: binary(), Target :: aec_pow:sci_int(),
                      Trims :: integer(), Threads :: integer()) ->
                             {'ok', Solution :: pow_cuckoo_solution()} |
                             {'error', term()}.
generate_single(Header, Target, Trims, Threads) ->
    BinDir = filename:join([code:priv_dir(aecore), "bin"]),
    ?debugFmt("Starting exec....~n", []),
    ensure_exec_started(),
    Algo = application:get_env(aecore, cuckoo_algorithm, ?CUCKOO_ALGORITHM),
    Size = application:get_env(aecore, cuckoo_graph_size, ?CUCKOO_GRAPH_SIZE),
    SpecOpts = case Algo of
                   mean -> " -s";
                   lean -> ""
               end,
    HeaderStr = binary_to_hex(Header, []),
    ?debugFmt("Executing ~p...~n", [lists:concat(["cd ", BinDir, "; ./", Algo, Size, " -x ", HeaderStr, " -m ",
                            Trims, " -t ", Threads, SpecOpts])]),
    Res = 
        try exec:run(
              lists:concat(["cd ", BinDir, "; ./", Algo, Size, " -x ", HeaderStr, " -m ",
                            Trims, " -t ", Threads, SpecOpts]),
              [{stdout, self()},
               {stderr, self()},
               {kill_timeout, 1},
               {cd, BinDir},
               monitor]) of
            R ->
                ?debugFmt("exec:run returned ~p~n", [R]),
                R
        catch
            C:E ->
                Strace = erlang:get_stacktrace(),
                ?debugFmt("crashed: ~p, ~p~n", [{C, E}, Strace]),
                {error, {C, E}}
        end,
    ?debugFmt("Got result ~p~n", [Res]),
    {ok, _ErlPid, OsPid} = Res,
    ?debugFmt("Waiting for result...~n", []),
    wait_for_result(#state{os_pid = OsPid,
                           buffer = [],
                           target = Target}).

%%------------------------------------------------------------------------------
%% @doc
%%   Receive and process notifications about the fate of the process and its
%%   output. The receieved stdout tends to be in large chunks, we keep a buffer
%%   for the last line fragment w/o NL.
%% @end
%%------------------------------------------------------------------------------
-spec wait_for_result(#state{}) ->
                             {'ok', Solution :: pow_cuckoo_solution()} |
                             {'error', term()}.
wait_for_result(#state{os_pid = OsPid,
                      buffer = Buffer} = State) ->
    receive
        {stdout, OsPid, Msg} ->
            Str = binary_to_list(Msg),
            {Lines, NewBuffer} = handle_fragmented_lines(Str, Buffer),
            %%[?debugFmt("Got stdout: ~s~n", [L]) || L <- Lines],
            parse_result(Lines, State#state{buffer = NewBuffer});
        {stderr, OsPid, Msg} ->
            epoch_pow_cuckoo:error("ERROR: ~s~n", [Msg]),
            ?debugFmt("ERROR got stderr: ~s~n", [Msg]),
            wait_for_result(State);
        {'DOWN', OsPid, process, _, normal} ->
            %% No solution found
            epoch_pow_cuckoo:info("No cuckoo solution found~p", []),
            ?debugFmt("No cuckoo solution found~n", []),
            {error, no_solutions};
        {'DOWN', OsPid, process, _, Reason} ->
            %% Mining failed: reattempt?
            epoch_pow_cuckoo:error("Mining process died: ~p~n", [Reason]),
            ?debugFmt("Mining process died: ~p~n", [Reason]),
            {error, {mining_failed, Reason}};
        Other ->
            ?debugFmt("Something else happened: ~p~n", [Other]),
            ok
    end.

%%------------------------------------------------------------------------------
%% @doc
%%   Prepend the first new incoming line with the last line fragment stored
%%   in Buffer and replace Buffer with the possible new line fragment at the
%%   end of Str.
%% @end
%%------------------------------------------------------------------------------
-spec handle_fragmented_lines(string(), string()) -> {list(string()), string()}.
handle_fragmented_lines(Str, Buffer) ->
    Lines = string:tokens(Str, "\n"),

    %% Add previous truncated line if present to first line
    Lines2 =
        case Buffer of
            [] ->
                Lines;
            _ ->
                [Line1 | More] = Lines,
                [Buffer ++ Line1 | More]
        end,

    %% Keep last fraction (w/o NL) in buffer
    case lists:last(Str) of
        $\n ->
            {Lines2, ""};
        _ ->
            {L3, [Bf]} = lists:split(length(Lines) - 1, Lines2),
            {L3, Bf}
    end.

%%------------------------------------------------------------------------------
%% @doc
%%   Prepend the first new incoming line with the last line fragment stored
%%   in Buffer and replace Buffer with the possible new line fragment at the
%%   end of Str.
%% @end
%%------------------------------------------------------------------------------
-spec parse_result(list(string()), #state{}) ->
                          {'ok', Solution :: pow_cuckoo_solution()} |
                          {'error', term()}.
parse_result([], State) ->
    wait_for_result(State);
parse_result(["Solution" ++ ValuesStr | Rest], #state{os_pid = OsPid,
                                                      target = Target} = State) ->
    Soln = [list_to_integer(V, 16) || V <- string:tokens(ValuesStr, " ")],
    ?debugFmt("Got solution candidate: ~p~n", [Soln]),
    case test_target(Soln, Target) of
        true ->
            ?debugFmt("Target met for ~p~n", [Soln]),
            epoch_pow_cuckoo:debug("Solution found: ~p~n", [Soln]),
            case exec:stop_and_wait(OsPid, 3) of
                {error, Reason} ->
                    epoch_pow_cuckoo:error("Failed to stop mining OS process ~p: ~p~n",
                                           [OsPid, Reason]),
                    ?debugFmt("Failed to stop mining OS process ~p: ~p~n",
                              [OsPid, Reason]);
                R ->
                    epoch_pow_cuckoo:debug("Mining OS process ~p stopped: ~p~n",
                                           [OsPid, R]),
                    ?debugFmt("Mining OS process ~p stopped: ~p~n",
                              [OsPid, R])
            end,
            {ok, Soln};
        false ->
            %% failed to meet target: go on, we may find another solution
            ?debugFmt("Failed to meet target~n", []),
            epoch_pow_cuckoo:debug("Failed to meet target~n", []),
            parse_result(Rest, State)
    end;
parse_result([Msg | T], State) ->
    epoch_pow_cuckoo:debug("debug logging: ~s~n", [Msg]),
    parse_result(T, State).

%%------------------------------------------------------------------------------
%% Proof of Work verification (without difficulty check)
%%------------------------------------------------------------------------------
-spec verify(Hash :: string(), Nonce :: integer(),
             Soln :: aec_pow:pow_evidence()) -> boolean().
verify(_Hash, _Nonce, _Soln) ->
    erlang:nif_error(nif_library_not_loaded).

%%------------------------------------------------------------------------------
%% Fetch the size of solution elements
%%------------------------------------------------------------------------------
-spec get_node_size() -> integer().
get_node_size() ->
    4.

%%------------------------------------------------------------------------------
%% White paper, section 9: rather than adjusting the nodes/edges ratio, a
%% hash-based target is suggested: the sha256 hash of the cycle nonces
%% is restricted to be under the target value (0 < target < 2^256).
%%------------------------------------------------------------------------------
-spec test_target(Soln :: pow_cuckoo_solution(), Target :: aec_pow:sci_int()) ->
                             boolean().
test_target(Soln, Target) ->
    NodeSize = get_node_size(),
    Bin = solution_to_binary(lists:sort(Soln), NodeSize * 8, <<>>),
    Hash = aec_sha256:hash(Bin),
    aec_pow:test_target(Hash, Target).


%%------------------------------------------------------------------------------
%% Convert solution (a list of 42 numbers) to a binary
%% in a languauge-independent way
%%------------------------------------------------------------------------------
-spec solution_to_binary(Soln :: pow_cuckoo_solution(), Bits :: integer(),
                         Acc :: binary()) -> binary().
solution_to_binary([], _Bits, Acc) ->
    Acc;
solution_to_binary([H | T], Bits, Acc) ->
    solution_to_binary(T, Bits, <<Acc/binary, H:Bits>>).

ensure_exec_started() ->
    case exec:start([]) of
        {ok, _} ->
            ?debugFmt("started~n", []),
            ok;
        {error, {already_started, _}} ->
            ?debugFmt("already started~n", []),
            ok;
        {error, _} = Error ->
            Error
    end.
