%%%=============================================================================
%%% @copyright (C) 2017, Aeternity Anstalt
%%% @doc
%%%   Unit tests for the aec_miner
%%% @end
%%%=============================================================================
-module(aec_miner_tests).

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

-include("common.hrl").
-include("blocks.hrl").
-include("txs.hrl").

-define(TEST_MODULE, aec_miner).
%%-define(DEBUG, true).

-ifdef(DEBUG).
-define(show_miner_state(), ?debugFmt("State ~p~n",[element(1,sys:get_state(?TEST_MODULE))])).
-else.
-define(show_miner_state(), ok).
-endif.

miner_test_() ->
    {foreach,
     fun() ->
             meck:new(aec_governance, [passthrough]),
             meck:expect(aec_governance, expected_block_mine_rate,
                         fun() ->
                                 meck:passthrough([]) div 2560
                         end),
             aec_test_utils:mock_time(),
             {ok, _} = aec_tx_pool:start_link(),
             {ok, _} = aec_chain:start_link(aec_block_genesis:genesis_block()),
             TmpKeysDir = mktempd(),
             ok = application:ensure_started(crypto),
             {ok, _} = aec_keys:start_link(["mypassword", TmpKeysDir]),
             {ok, _} = ?TEST_MODULE:start_link([{autostart, true}]),
             TmpKeysDir
     end,
     fun(TmpKeysDir) ->
             ok = ?TEST_MODULE:stop(),
             ok = aec_keys:stop(),
             ok = aec_chain:stop(),
             ok = aec_tx_pool:stop(),
             ok = application:stop(crypto),
             {ok, KeyFiles} = file:list_dir(TmpKeysDir),
             %% Expect two filenames - private and public keys.
             [_KF1, _KF2] = KeyFiles,
             lists:foreach(
               fun(F) ->
                       AbsF = filename:absname_join(TmpKeysDir, F),
                       {ok, _} = {file:delete(AbsF), {F, AbsF}}
               end,
               KeyFiles),
             ok = file:del_dir(TmpKeysDir),
             ?assert(meck:validate(aec_governance)),
             meck:unload(aec_governance),
             aec_test_utils:unmock_time(),
             file:delete(TmpKeysDir)
     end,
     [fun(_) ->
              {"Suspend and resume",
               fun() ->
                       ?show_miner_state(),
                       ?assertEqual(ok, ?TEST_MODULE:suspend()),
                       ?show_miner_state(),
                       ?assertEqual(ok, ?TEST_MODULE:resume()),
                       ?show_miner_state(),
                       wait_for_running()
               end} 
      end,
      fun(_) ->
              {"Resume twice",
               fun() ->
                       ?show_miner_state(),
                       ?assertEqual(ok, ?TEST_MODULE:resume()),
                       ?show_miner_state(),
                       ?assertEqual(ok, ?TEST_MODULE:suspend()),
                       ?show_miner_state(),
                       aec_test_utils:wait_for_it(
                         fun() ->
                                 {State, _} = sys:get_state(?TEST_MODULE),
                                 (State =:= idle)
                         end, true),
                       ?assertEqual(ok, ?TEST_MODULE:resume()),
                       ?show_miner_state(),
                       ?TEST_MODULE:resume(),
                       ?show_miner_state(),
                       wait_for_running(),
                       ?assertEqual(ok, ?TEST_MODULE:suspend())
               end}
      end,
      fun(_) ->
              {"Suspend twice",
               fun() ->
                       ?show_miner_state(),
                       ?assertEqual(ok, ?TEST_MODULE:resume()),
                       ?assertEqual(ok, ?TEST_MODULE:suspend()),
                       ?assertEqual(ok, ?TEST_MODULE:suspend()),
                       ?show_miner_state()
               end}
      end,
      fun(_) ->
              {"Suspend in idle",
               fun() ->
                       ?show_miner_state(),
                       ?assertEqual(ok, ?TEST_MODULE:resume()),
                       ?assertEqual(ok, ?TEST_MODULE:suspend()),
                       ?show_miner_state(),
                       aec_test_utils:wait_for_it(
                         fun() ->
                                 {State, _} = sys:get_state(?TEST_MODULE),
                                 State
                         end, idle)
                       %% ?show_miner_state(),

                       %% ?assertEqual(ok, ?TEST_MODULE:suspend())
               end}
      end,
      fun(_) ->
              {timeout, 80,
               {"Run miner for a while",
                fun() ->
                        ?assertEqual(ok, ?TEST_MODULE:suspend()),
                        aec_test_utils:wait_for_it(
                          fun() ->
                                  {State, _} = sys:get_state(?TEST_MODULE),
                                  (State =:= idle)
                          end, true),
                       
                        meck:new(aec_chain, [passthrough]),
                        TestPid = self(),
                        meck:expect(
                          aec_chain, write_block,
                          fun(B) ->
                                  Result = meck:passthrough([B]),
                                  TestPid ! block_written_in_chain,
                                  Result
                          end),
                        ?show_miner_state(),
                        ?assertEqual(ok, ?TEST_MODULE:resume()),
                        ?show_miner_state(),
                        wait_for_running(),
                        ?show_miner_state(),
                        receive block_written_in_chain -> ok end,
                        ?show_miner_state(),
                        aec_test_utils:wait_for_it(fun() ->
                                            {ok, TopBlock} = aec_chain:top(),
                                            aec_blocks:height(TopBlock) > 0
                                    end,
                                    true),
                        ?assertEqual(ok, ?TEST_MODULE:suspend()),
                        ?show_miner_state(),
                        {ok, TopBlock} = aec_chain:top(),
                        ?assertMatch(
                           Txs when is_list(Txs) andalso length(Txs) > 0,
                           aec_blocks:txs(TopBlock)),
                        ?assertMatch(<<H:?TXS_HASH_BYTES/unit:8>> when H > 0,
                                     TopBlock#block.txs_hash),
                        ?assert(meck:validate(aec_chain)),
                        meck:unload(aec_chain)
                end}
              }
      end,
      fun(_) ->
              {timeout, 60,
               {"Remove keys while miner runs",
                fun() ->
                        ?show_miner_state(),
                        ?assertEqual(ok, ?TEST_MODULE:resume()),
                        ?show_miner_state(),
                        wait_for_running(),
                        ?show_miner_state(),
                        ?assertEqual(ok, aec_keys:delete()),
                        ?show_miner_state(),
                        aec_test_utils:wait_for_it(
                         fun () ->
                                 ?show_miner_state(),
                                 {MinerState, _Data1}
                                     = sys:get_state(aec_miner),
                                 MinerState
                         end, waiting_for_keys),
                        ?assertNotEqual(error, aec_keys:new("mynewpassword")),
                        ?show_miner_state(),
                        wait_for_running(),
                        ?show_miner_state(),
                        ok
                end}
              }
      end
     ]}.


chain_test_() ->
    {foreach,
     fun() ->
             meck:new(aec_governance, [passthrough]),
             meck:expect(aec_governance, expected_block_mine_rate,
                         fun() ->
                                 meck:passthrough([]) div 2560
                         end),
             aec_test_utils:mock_time(),
             {ok, _} = aec_tx_pool:start_link(),
             {ok, _} = aec_chain:start_link(aec_block_genesis:genesis_block()),
             TmpKeysDir = mktempd(),
             ok = application:ensure_started(crypto),
             {ok, _} = aec_keys:start_link(["mypassword", TmpKeysDir]),
             {ok, _} = ?TEST_MODULE:start_link(),
             meck:new(aec_headers, [passthrough]),
             meck:new(aec_blocks, [passthrough]),
             meck:expect(aec_headers, validate, fun(_) -> ok end),
             meck:expect(aec_blocks, validate, fun(_) -> ok end),
             TmpKeysDir
     end,
     fun(TmpKeysDir) ->
             ok = ?TEST_MODULE:stop(),
             ok = aec_keys:stop(),
             ok = aec_chain:stop(),
             ok = aec_tx_pool:stop(),
             ok = application:stop(crypto),
             {ok, KeyFiles} = file:list_dir(TmpKeysDir),
             %% Expect two filenames - private and public keys.
             [_KF1, _KF2] = KeyFiles,
             lists:foreach(
               fun(F) ->
                       AbsF = filename:absname_join(TmpKeysDir, F),
                       {ok, _} = {file:delete(AbsF), {F, AbsF}}
               end,
               KeyFiles),
             ok = file:del_dir(TmpKeysDir),
             aec_test_utils:unmock_time(),
             ?assert(meck:validate(aec_governance)),
             meck:unload(aec_governance),
             meck:unload(aec_headers),
             meck:unload(aec_blocks),
             file:delete(TmpKeysDir)
     end,
     [
      fun(_) ->
              {"Start mining add a block.",
               fun() ->
                       GB = genesis_block(),
                       %% Add a couple of blocks to the chain.
                       {ok, B0H} = aec_blocks:hash_internal_representation(GB),
                       B1  = #block{height = 1, prev_hash = B0H},
                       B1H = block_hash(B1),
                       B2  = #block{height = 2, prev_hash = B1H},
                       BH2 = aec_blocks:to_header(B2),
                       ?assertEqual(ok, ?TEST_MODULE:post_block(B1)),
                       {State1, _Data1} = sys:get_state(aec_miner),
                       ?assertEqual(configure, State1),
                       ?assertEqual(ok, ?TEST_MODULE:post_block(B2)),
                       aec_test_utils:wait_for_it(
                         fun () -> aec_chain:top_header() end,
                         {ok, BH2})
               end}
      end,
      fun(_) ->
              {"Switch to an alternative chain while mining.",
               fun() ->
                       Chain1 = build_a_chain_of_length(5),
                       [?TEST_MODULE:post_block(B)
                        || B <- Chain1],

                       [_,_,_,B5] = Chain1,
                       BH5 = aec_blocks:to_header(B5),
                       aec_test_utils:wait_for_it(
                         fun () -> aec_chain:top_header() end,
                         {ok, BH5}),
 
                       %% TODO: Add some transactions to the pool
                       %% Let the miner mine one block

                       Chain2 = build_a_chain_of_length(7),
                       [?TEST_MODULE:post_block(B)
                        || B <- Chain2],

                       [_,_,_,_,_,B7] = Chain2,
                       BH7 = aec_blocks:to_header(B7),
                       aec_test_utils:wait_for_it(
                         fun () -> aec_chain:top_header() end,
                         {ok, BH7}),

                       %% TODO: check the transaction pool
                       ok
               end
              }
      end
     ]}.


build_a_chain_of_length(N) ->
    Hash = block_hash(genesis_block()),
    build_a_chain_of_length(1, N, Hash, []).

build_a_chain_of_length(N, N, _, Blocks) -> lists:reverse(Blocks);
build_a_chain_of_length(N, Length, Parent, Blocks) ->
    B  = #block{height = N,
                prev_hash = Parent,
                %% Mocked time
                time = aeu_time:now_in_msecs(),
                txs = [] %% TODO: Add some real transactions
               },
    Hash = block_hash(B),
    build_a_chain_of_length(N+1, Length, Hash, [B|Blocks]).

genesis_block() ->
    aec_block_genesis:genesis_block().

block_hash(B) ->
    {ok, Hash} = aec_headers:hash_header(aec_blocks:to_header(B)),
    Hash.

mktempd() ->
    mktempd(os:type()).

mktempd({unix, _}) ->
    lib:nonl(?cmd("mktemp -d")).

wait_for_running() ->
    aec_test_utils:wait_for_it(
      fun() ->
              {State, _} = sys:get_state(?TEST_MODULE),
              (State =:= running)
                  orelse
                    (State =:= configure)
      end, true).

-endif.
