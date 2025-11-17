// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, sync::Arc};
use std::marker::PhantomData;
use minibytes::Bytes;

use crate::{
    block_handler::BlockHandler,
    block_store::BlockStore,
    consensus::linearizer::CommittedSubDag,
    core::Core,
    data::Data,
    metrics::{Metrics, UtilizationTimerVecExt},
    runtime::timestamp_utc,
    types::{AuthorityIndex, BlockReference, RoundNumber, StatementBlock},
};
use crate::block_handler::CommitHandler;

pub struct Syncer<H: BlockHandler, S: SyncerSignals> {
    core: Core<H>,
    force_new_block: bool,
    commit_period: u64,
    signals: S,
    pub(crate) connected_authorities: HashSet<AuthorityIndex>,
    metrics: Arc<Metrics>,
}

pub trait SyncerSignals: Send + Sync {
    fn new_block_ready(&mut self);
}

pub trait CommitObserver: Send + Sync {
    fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<Data<StatementBlock>>,
    ) -> Vec<CommittedSubDag>;

    fn aggregator_state(&self) -> Bytes;

    fn recover_committed(&mut self, committed: HashSet<BlockReference>, state: Option<Bytes>);
}

impl<H: BlockHandler, S: SyncerSignals> Syncer<H, S> {
    pub fn new(
        core: Core<H>,
        commit_period: u64,
        signals: S,
        metrics: Arc<Metrics>,
    ) -> Self {
        let committee_size = core.committee().len();
        Self {
            core,
            force_new_block: false,
            commit_period,
            signals,
            connected_authorities: HashSet::with_capacity(committee_size),
            metrics,
        }
    }

    pub fn add_blocks(&mut self, blocks: Vec<Data<StatementBlock>>) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Syncer::add_blocks");
        self.core.add_blocks(blocks);
        self.try_new_block();
    }

    pub fn force_new_block(&mut self, round: RoundNumber) -> bool {
        if self.core.last_proposed() == round {
            self.metrics.leader_timeout_total.inc();
            self.force_new_block = true;
            self.try_new_block();
            true
        } else {
            false
        }
    }

    fn try_new_block(&mut self) {
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("Syncer::try_new_block");
        if self.force_new_block
            || self
                .core
                .ready_new_block(self.commit_period, &self.connected_authorities)
        {
            if self.core.try_new_block().is_none() {
                return;
            }
            self.signals.new_block_ready();
            self.force_new_block = false;

            if self.core.epoch_closed() {
                return;
            }; // No need to commit after epoch is safe to close

            let newly_committed = self.core.try_commit();
            let utc_now = timestamp_utc();
            if !newly_committed.is_empty() {
                let committed_refs: Vec<_> = newly_committed
                    .iter()
                    .map(|block| {
                        let age = utc_now
                            .checked_sub(block.meta_creation_time())
                            .unwrap_or_default();
                        format!("{}({}ms)", block.reference(), age.as_millis())
                    })
                    .collect();
                tracing::debug!("Committed {:?}", committed_refs);
            }
            let block_store_clone = self.core.block_store().clone();

            // 2. 명시적인 스코프({})를 사용하여 commit_handler의 가변 대여(mutable borrow) 범위를 제한합니다.
            let (committed_subdag, aggregator_state) = {
                let commit_handler = self.core.commit_handler_mut();

                // 3. C-Path 폴백 실행 (클론된 block_store 사용)
                let committed_subdag = commit_handler
                    .handle_commit(&block_store_clone, newly_committed);

                // 4. C-Path 상태 가져오기
                let aggregator_state = commit_handler.aggregator_state();

                (committed_subdag, aggregator_state)
            };
            // 5. 이 지점에서 `commit_handler`의 가변 대여가 해제됩니다.

            // 6. 이제 self.core를 다시 안전하게 가변 대여할 수 있습니다.
            self.core.handle_committed_subdag(
                committed_subdag,
                &aggregator_state,
            );
        }
    }

    pub fn commit_observer_mut(&mut self) -> &mut CommitHandler {
        self.core.commit_handler_mut()
    }

    pub fn commit_observer(&self) -> &CommitHandler {
        self.core.commit_handler()
    }


    pub fn core(&self) -> &Core<H> {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut Core<H> { // ❗ 테스트 코드(simulator)에서 필요
        &mut self.core
    }

    #[cfg(test)]
    pub fn scheduler_state_id(&self) -> usize {
        self.core.authority() as usize
    }
}

impl SyncerSignals for bool {
    fn new_block_ready(&mut self) {
        *self = true;
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::Range, time::Duration};

    use rand::Rng;

    use super::*;
    use crate::{
        // ❗ TestCommitHandler -> CommitHandler
        block_handler::{TestBlockHandler, CommitHandler},
        data::Data,
        simulator::{Scheduler, Simulator, SimulatorState},
        // ❗ committee_and_syncers 헬퍼 함수도 수정 필요
        test_util::{check_commits, committee_and_syncers, rng_at_seed},
    };

    const ROUND_TIMEOUT: Duration = Duration::from_millis(1000);
    const LATENCY_RANGE: Range<Duration> = Duration::from_millis(100)..Duration::from_millis(1800);

    pub enum SyncerEvent {
        ForceNewBlock(RoundNumber),
        DeliverBlock(Data<StatementBlock>),
    }

    // -----------------------------------------------------------------
    // ❌ C 제네릭 제거
    // -----------------------------------------------------------------
    impl SimulatorState for Syncer<TestBlockHandler, bool> {
        type Event = SyncerEvent;

        fn handle_event(&mut self, event: Self::Event) {
            match event {
                SyncerEvent::ForceNewBlock(round) => {
                    if self.force_new_block(round) {
                        // eprintln!("[{:06} {}] Proposal timeout for {round}", scheduler.time_ms(), self.core.authority());
                    }
                }
                SyncerEvent::DeliverBlock(block) => {
                    // eprintln!("[{:06} {}] Deliver {block}", scheduler.time_ms(), self.core.authority());
                    self.add_blocks(vec![block]);
                }
            }

            // New block was created
            if self.signals {
                self.signals = false;
                let last_block = self.core.last_own_block().clone();
                Scheduler::schedule_event(
                    ROUND_TIMEOUT,
                    self.scheduler_state_id(),
                    SyncerEvent::ForceNewBlock(last_block.round()),
                );
                for authority in self.core.committee().authorities() {
                    if authority == self.core.authority() {
                        continue;
                    }
                    let latency =
                        Scheduler::<SyncerEvent>::with_rng(|rng| rng.gen_range(LATENCY_RANGE));
                    Scheduler::schedule_event(
                        latency,
                        authority as usize,
                        SyncerEvent::DeliverBlock(last_block.clone()),
                    );
                }
            }
        }
    }

    #[test]
    pub fn test_syncer() {
        for seed in 0..10 {
            test_syncer_at(seed);
        }
    }

    pub fn test_syncer_at(seed: u64) {
        eprintln!("Seed {seed}");
        let rng = rng_at_seed(seed);
        // ❗ committee_and_syncers가 C 제네릭 없는 Syncer를 반환하도록 수정되어야 함
        let (committee, syncers) = committee_and_syncers(4);
        let mut simulator = Simulator::new(syncers, rng);

        // Kick off process by asking validators create a block after genesis
        for authority in committee.authorities() {
            simulator.schedule_event(
                Duration::ZERO,
                authority as usize,
                SyncerEvent::ForceNewBlock(0),
            );
        }
        // Simulation awaits for first num_txn transactions proposed by each authority to certify
        let num_txn = 40;
        let mut await_transactions = vec![];
        let await_num_txn = num_txn as usize * committee.len();

        let mut iteration = 0u64;
        loop {
            iteration += 1;
            assert!(!simulator.run_one());
            // todo - we might want to wait for exactly num_txn from each authority, rather then num_txn as usize * committee.len() total
            if await_transactions.len() < await_num_txn {
                for state in simulator.states_mut() {
                    // ❗ core_mut() 사용
                    await_transactions.extend(state.core_mut().block_handler_mut().proposed.drain(..))
                }
                continue;
            }
            let not_certified: Vec<_> = simulator
                .states()
                .iter()
                .map(|syncer| {
                    await_transactions
                        .iter()
                        .map(|txid| {
                            if syncer.core.block_handler().is_certified(txid) {
                                0usize
                            } else {
                                1usize
                            }
                        })
                        .sum::<usize>()
                })
                .collect();

            if not_certified.iter().sum::<usize>() == 0 {
                let time = simulator.time();
                let rounds = simulator
                    .states()
                    .iter()
                    .map(|syncer| syncer.core.last_proposed())
                    .max()
                    .unwrap();
                eprintln!("Certified {} transactions in {time:.2?}, {rounds} rounds, {iteration} iterations", await_transactions.len());
                check_commits(simulator.states());
                break;
            } /*else if iteration % 100 == 0 {
                  eprintln!("Not certified: {not_certified:?}");
              }*/
        }
    }
}