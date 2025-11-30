// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::Mutex;

use crate::{
    block_handler::LedgerWriter,
    block_store::BlockStore,
    committee::{Committee, QuorumThreshold, StakeAggregator},
    data::Data,
    metrics::Metrics,
    runtime,
    runtime::TimeInstant,
    types::{
        AuthorityIndex, BaseStatement, BlockReference, StatementBlock, TransactionLocator, Vote,
    },
};

pub struct FinalizationInterpreter<'a, L: LedgerWriter> {
    // --- FPC Aggregators (Shared State) ---
    transaction_aggregator: &'a mut HashMap<BlockReference, HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>>,
    certificate_aggregator: &'a mut HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
    block_aggregator: &'a mut HashMap<BlockReference, HashMap<BlockReference, StakeAggregator<QuorumThreshold>>>,
    block_certificate_aggregator: &'a mut HashMap<BlockReference, StakeAggregator<QuorumThreshold>>,

    ledger_writer: &'a mut L,
    committee: Arc<Committee>,
    block_store: &'a BlockStore,
    block_level_fpc: bool,
    metrics: Arc<Metrics>,

    // --- GC / Pruning State (Shared State) ---
    // FPCService가 관리하는 영구 상태를 참조로 받아옵니다.
    blocks_by_round: &'a mut HashMap<u64, Vec<BlockReference>>,
    highest_known_round: &'a mut u64,
}

impl<'a, L: LedgerWriter> FinalizationInterpreter<'a, L> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_store: &'a BlockStore,
        committee: Arc<Committee>,
        ledger_writer: &'a mut L,
        transaction_aggregator: &'a mut HashMap<
            BlockReference,
            HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
        >,
        certificate_aggregator: &'a mut HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
        block_aggregator: &'a mut HashMap<BlockReference, HashMap<BlockReference, StakeAggregator<QuorumThreshold>>>,
        block_certificate_aggregator: &'a mut HashMap<BlockReference, StakeAggregator<QuorumThreshold>>,

        // 🌟 [신규 인자] GC 상태
        blocks_by_round: &'a mut HashMap<u64, Vec<BlockReference>>,
        highest_known_round: &'a mut u64,

        block_level_fpc: bool,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            transaction_aggregator,
            certificate_aggregator,
            block_aggregator,
            block_certificate_aggregator,
            ledger_writer,
            committee,
            block_store,
            block_level_fpc,
            metrics,
            blocks_by_round,
            highest_known_round,
        }
    }

    pub fn process_block(&mut self, block: &Data<StatementBlock>) {
        // 1. 라운드 업데이트 및 GC 수행
        self.update_round_and_prune(block);

        if self.block_level_fpc {
            self.process_block_level(block);
        } else {
            self.process_transaction_level(block);
        }
    }

    // ------------------------------------------------------------------------
    // 🌟 GC (Pruning) 로직
    // ------------------------------------------------------------------------

    fn update_round_and_prune(&mut self, block: &Data<StatementBlock>) {
        let round = block.round();

        // 1. 현재 블록을 라운드 인덱스에 등록
        self.blocks_by_round.entry(round).or_default().push(*block.reference());

        // 2. 최고 라운드 갱신
        if round > *self.highest_known_round {
            *self.highest_known_round = round;
        }

        // 3. 프루닝 임계값 설정 (최신 라운드 - 3)
        // 3라운드 이전의 데이터는 더 이상 합의에 영향을 주지 않는다고 판단하여 삭제
        let prune_threshold = self.highest_known_round.saturating_sub(3);

        // 4. 임계값보다 오래된 라운드 데이터 삭제
        // (한 번에 다 지우지 않고, 맵에 남아있는 '가장 오래된 라운드'부터 threshold까지 순차적으로 지우는 것이 안전하지만,
        //  여기서는 retain을 사용하지 않고 인덱스 기반으로 효율적으로 삭제합니다.)

        // 인덱스 맵에서 threshold 미만인 라운드 키들을 수집
        let rounds_to_prune: Vec<u64> = self.blocks_by_round.keys()
            .filter(|&r| *r < prune_threshold)
            .cloned()
            .collect();

        for r in rounds_to_prune {
            if let Some(block_refs) = self.blocks_by_round.remove(&r) {
                for bref in block_refs {
                    // [Block L1] 투표 집계 삭제
                    self.block_aggregator.remove(&bref);
                    // [Block L2] 인증서 집계 삭제
                    self.block_certificate_aggregator.remove(&bref);

                    // [Transaction L1] 이 블록이 관찰한 트랜잭션 투표 삭제
                    // (참고: TX L2인 certificate_aggregator는 트랜잭션 확정 시점까지 유지해야 하므로 여기서 지우지 않음)
                    self.transaction_aggregator.remove(&bref);
                }
                // tracing::debug!("🧹 [GC] Pruned FPC state for round {}", r);
            }
        }
    }

    // ------------------------------------------------------------------------
    // [Mode 1] 블록 단위 FPC
    // ------------------------------------------------------------------------

    fn process_block_level(&mut self, block: &Data<StatementBlock>) {
        // 🌟 [재귀 방지] 이미 프루닝된 오래된 블록은 처리하지 않음
        let prune_threshold = self.highest_known_round.saturating_sub(3);
        if block.round() < prune_threshold {
            return;
        }

        if self.block_aggregator.contains_key(block.reference()) {
            return;
        }
        self.block_aggregator.insert(*block.reference(), HashMap::new());

        // tracing::trace!("Processing block for FPC: {}", block.reference());

        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_block_level(&parent_block);

                // [최적화 3] HashMap 전체 Clone 제거
                let votes_to_cast: Vec<_> = self.block_aggregator
                    .get(parent_ref)
                    .unwrap()
                    .iter()
                    .flat_map(|(target_ref, agg)| {
                        agg.voters().map(move |voter| (*target_ref, voter))
                    })
                    .collect();

                for (target_ref, voter) in votes_to_cast {
                    self.vote_block_level(block, target_ref, voter);
                }
            }
        }

        for parent_ref in block.includes() {
            self.vote_block_level(block, *parent_ref, block.author());
        }
    }

    fn vote_block_level(
        &mut self,
        observer_block: &Data<StatementBlock>,
        target_block_ref: BlockReference,
        voter: AuthorityIndex,
    ) {
        let observer_aggs = self.block_aggregator.get_mut(observer_block.reference()).unwrap();
        let l1_state = observer_aggs.entry(target_block_ref).or_default();

        // [L1] 상태 업데이트
        l1_state.add(voter, &self.committee);
        let current_is_quorum = l1_state.is_quorum(&self.committee);

        // [L2] 진입 조건
        if current_is_quorum {
            let l2_state = self.block_certificate_aggregator.entry(target_block_ref).or_default();

            let l2_already_finalized = l2_state.is_quorum(&self.committee);
            l2_state.add(observer_block.author(), &self.committee);
            let l2_now_finalized = l2_state.is_quorum(&self.committee);

            // Edge Trigger: 확정(Finalized) 순간 커밋 수행
            if !l2_already_finalized && l2_now_finalized {
                if let Some(target_block) = self.block_store.get_block(target_block_ref) {
                    // tracing::debug!("FPC-BLOCK: Finalized block {} (all txs)", target_block_ref);
                    for (locator, _tx) in target_block.shared_transactions() {
                        if !self.ledger_writer.is_vote_finalized(&locator) {
                            self.ledger_writer.write_finalized_vote(locator, self.block_store, true);
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------------
    // [Mode 2] 트랜잭션 단위 FPC
    // ------------------------------------------------------------------------

    fn process_transaction_level(&mut self, block: &Data<StatementBlock>) {
        // 🌟 [재귀 방지]
        let prune_threshold = self.highest_known_round.saturating_sub(3);
        if block.round() < prune_threshold {
            return;
        }

        if self.transaction_aggregator.contains_key(block.reference()) { return; }
        self.transaction_aggregator.insert(*block.reference(), Default::default());

        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_transaction_level(&parent_block);

                // unwrap 안전 장치: GC로 인해 parent가 삭제되었을 수 있음
                if let Some(parent_aggregator) = self.transaction_aggregator.get(parent_ref) {
                    let parent_aggregator = parent_aggregator.clone();

                    // 부모 상태 병합
                    for (locator, agg) in parent_aggregator {
                        for voter in agg.voters() {
                            self.vote_transaction_level(block, &locator, voter);
                        }
                    }
                }
            }
        }

        for (offset, statement) in block.statements().iter().enumerate() {
            match statement {
                BaseStatement::Vote(locator, vote) => {
                    if let Vote::Accept = vote {
                        self.vote_transaction_level(block, locator, block.author());
                    }
                }
                BaseStatement::VoteRange(tx_locator_range) => {
                    for locator in tx_locator_range.locators() {
                        self.vote_transaction_level(block, &locator, block.author());
                    }
                }
                BaseStatement::Share(_) => {
                    let locator = TransactionLocator::new(*block.reference(), offset as u64);
                    self.vote_transaction_level(block, &locator, block.author());
                }
            }
        }
    }

    fn vote_transaction_level(
        &mut self,
        block: &Data<StatementBlock>,
        transaction: &TransactionLocator,
        tx_voter: AuthorityIndex,
    ) {
        if self.ledger_writer.is_vote_finalized(transaction) {
            return;
        }

        let block_transaction_aggregator = self
            .transaction_aggregator
            .get_mut(block.reference())
            .unwrap();

        let state = block_transaction_aggregator.entry(*transaction).or_default();
        state.add(tx_voter, &self.committee);
        let current_is_quorum = state.is_quorum(&self.committee);

        if !current_is_quorum || block.epoch_changed() {
            return;
        }

        let cert_aggregator = self.certificate_aggregator.entry(*transaction).or_default();
        let l2_was_quorum = cert_aggregator.is_quorum(&self.committee);
        cert_aggregator.add(block.author(), &self.committee);
        let l2_is_quorum = cert_aggregator.is_quorum(&self.committee);

        if !l2_was_quorum && l2_is_quorum {
            // tracing::debug!("FPC-TX: Finalized transaction {}", transaction);
            self.ledger_writer.write_finalized_vote(*transaction, self.block_store, true);
        }
    }
}