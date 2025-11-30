// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::Mutex;

use crate::{
    block_handler::LedgerWriter,
    block_store::BlockStore,
    committee::{Committee, QuorumThreshold, StakeAggregator},
    data::Data,
    metrics::Metrics,
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
        // 안전 마진을 조금 더 줄 수도 있지만, 여기서는 제안대로 유지
        let prune_threshold = self.highest_known_round.saturating_sub(3);

        // 4. 임계값보다 오래된 라운드 데이터 삭제
        let rounds_to_prune: Vec<u64> = self.blocks_by_round.keys()
            .filter(|&r| *r < prune_threshold)
            .cloned()
            .collect();

        for r in rounds_to_prune {
            if let Some(block_refs) = self.blocks_by_round.remove(&r) {
                for bref in block_refs {
                    self.block_aggregator.remove(&bref);
                    self.block_certificate_aggregator.remove(&bref);
                    self.transaction_aggregator.remove(&bref);
                }
            }
        }
    }

    // ------------------------------------------------------------------------
    // [Mode 1] 블록 단위 FPC (최적화 적용)
    // ------------------------------------------------------------------------

    fn process_block_level(&mut self, block: &Data<StatementBlock>) {
        let prune_threshold = self.highest_known_round.saturating_sub(3);
        if block.round() < prune_threshold {
            return;
        }

        if self.block_aggregator.contains_key(block.reference()) {
            return;
        }
        self.block_aggregator.insert(*block.reference(), HashMap::new());

        // 1. 부모 블록의 상태 전파 (Propagation)
        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_block_level(&parent_block);

                // [최적화 1] Clone 제거 & 이미 Finalized된 타겟 제외
                let votes_to_cast: Vec<_> = if let Some(parent_agg) = self.block_aggregator.get(parent_ref) {
                    parent_agg.iter()
                        .filter_map(|(target_ref, agg)| {
                            // 이미 L2 Quorum(Finalized)에 도달했다면 전파 스킵
                            if let Some(cert_agg) = self.block_certificate_aggregator.get(target_ref) {
                                if cert_agg.is_quorum(&self.committee) {
                                    return None;
                                }
                            }
                            // 아직 Final 되지 않은 것만 전파
                            Some(agg.voters().map(move |voter| (*target_ref, voter)))
                        })
                        .flatten()
                        .collect()
                } else {
                    vec![]
                };

                // 수집된 유효 투표 일괄 적용
                for (target_ref, voter) in votes_to_cast {
                    self.vote_block_level(block, target_ref, voter);
                }
            }
        }

        // 2. 부모 블록 자체에 대한 투표 (Direct Observation)
        for parent_ref in block.includes() {
            // 부모 블록 자체가 이미 Finalized 되었다면 투표 생략 가능 (선택적 최적화)
            if let Some(cert_agg) = self.block_certificate_aggregator.get(parent_ref) {
                if cert_agg.is_quorum(&self.committee) {
                    continue;
                }
            }
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
                    for (locator, _tx) in target_block.shared_transactions() {
                        if !self.ledger_writer.is_vote_finalized(&locator) {
                            self.ledger_writer.write_finalized_vote(locator, self.block_store, true);
                        }
                    }
                }

                // [최적화 2] Finalized 즉시 현재 블록의 Aggregator에서 제거
                // 이후 이 블록이 부모가 되어도 이 타겟은 전파되지 않음
                if let Some(observer_aggs) = self.block_aggregator.get_mut(observer_block.reference()) {
                    observer_aggs.remove(&target_block_ref);
                }
            }
        }
    }

    // ------------------------------------------------------------------------
    // [Mode 2] 트랜잭션 단위 FPC (최적화 적용)
    // ------------------------------------------------------------------------

    fn process_transaction_level(&mut self, block: &Data<StatementBlock>) {
        let prune_threshold = self.highest_known_round.saturating_sub(3);
        if block.round() < prune_threshold {
            return;
        }

        if self.transaction_aggregator.contains_key(block.reference()) { return; }
        self.transaction_aggregator.insert(*block.reference(), Default::default());

        // 1. 부모 블록의 상태 전파 (Propagation)
        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_transaction_level(&parent_block);

                // [최적화 1] Clone 제거 & 이미 Finalized된 Tx 제외
                let votes_to_cast: Vec<_> = if let Some(parent_agg) = self.transaction_aggregator.get(parent_ref) {
                    parent_agg.iter()
                        .filter_map(|(locator, agg)| {
                            // 이미 L2 Quorum에 도달했다면(Finalized) 전파 스킵
                            if let Some(cert_agg) = self.certificate_aggregator.get(locator) {
                                if cert_agg.is_quorum(&self.committee) {
                                    return None;
                                }
                            }
                            // 아직 Final 되지 않은 것만 전파
                            Some(agg.voters().map(move |voter| (*locator, voter)))
                        })
                        .flatten()
                        .collect()
                } else {
                    vec![]
                };

                // 수집된 유효 투표 일괄 적용
                for (locator, voter) in votes_to_cast {
                    self.vote_transaction_level(block, &locator, voter);
                }
            }
        }

        // 2. 현재 블록의 투표 (Direct Vote)
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
        // 이미 Ledger에 써졌다면 중복 처리 방지 (가장 빠른 체크)
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

        // [L2] Certificate Aggregation
        let cert_aggregator = self.certificate_aggregator.entry(*transaction).or_default();
        let l2_was_quorum = cert_aggregator.is_quorum(&self.committee);
        cert_aggregator.add(block.author(), &self.committee);
        let l2_is_quorum = cert_aggregator.is_quorum(&self.committee);

        if !l2_was_quorum && l2_is_quorum {
            self.ledger_writer.write_finalized_vote(*transaction, self.block_store, true);

            // [최적화 2] Finalized 즉시 현재 블록의 Aggregator에서 제거
            // 이렇게 하면 이 블록의 자식들은 이 Tx에 대한 투표를 더 이상 상속받지 않음
            if let Some(block_aggs) = self.transaction_aggregator.get_mut(block.reference()) {
                block_aggs.remove(transaction);
            }
        }
    }
}