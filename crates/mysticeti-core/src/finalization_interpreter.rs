// In: crates/mysticeti-core/src/finalization_interpreter.rs

// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::Arc,
};

use crate::{
    block_handler::LedgerWriter, // LedgerWriter 트레잇 임포트
    block_store::BlockStore,
    committee::{Committee, QuorumThreshold, StakeAggregator},
    data::Data,
    types::{
        AuthorityIndex,
        BaseStatement,
        BlockReference,
        StatementBlock,
        TransactionLocator,
        Vote,
    },
};

/// FPC-First 최종성을 실시간으로 처리하는 증분 처리기입니다.
/// Core가 소유한 상태에 대한 참조를 빌려와서 작동합니다.
pub struct FinalizationInterpreter<'a, L: LedgerWriter> {
    transaction_aggregator:
        &'a mut HashMap<BlockReference, HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>>,
    certificate_aggregator: &'a mut HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
    ledger_writer: &'a mut L, // 최종 장부(CommitHandler)에 대한 참조
    committee: Arc<Committee>,
    block_store: &'a BlockStore,
}

impl<'a, L: LedgerWriter> FinalizationInterpreter<'a, L> {
    pub fn new(
        block_store: &'a BlockStore,
        committee: Arc<Committee>,
        ledger_writer: &'a mut L,
        transaction_aggregator: &'a mut HashMap<
            BlockReference,
            HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
        >,
        certificate_aggregator: &'a mut HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
    ) -> Self {
        Self {
            transaction_aggregator,
            certificate_aggregator,
            ledger_writer,
            committee,
            block_store,
        }
    }

    /// 새로 수신된 블록을 처리하고, FPC 최종성이 달성된 투표를 즉시 장부에 기록합니다.
    pub fn process_block(&mut self, block: &Data<StatementBlock>) {
        // 1. Memoization: 이미 처리된 블록은 즉시 반환하여 중복 계산 방지
        if self.transaction_aggregator.contains_key(block.reference()) {
            return;
        }
        self.transaction_aggregator
            .insert(*block.reference(), Default::default());

        // 2. 부모 처리 (상태 전파):
        //    부모를 재귀적으로 먼저 처리하여 부모의 집계 상태를 상속받을 준비를 합니다.
        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_block(&parent_block);

                // 부모의 L1 집계 상태를 현재 블록으로 전파(propagate)
                let parent_aggregator =
                    std::mem::take(self.transaction_aggregator.get_mut(parent_ref).unwrap());
                for (tx_locator, parent_votes) in &parent_aggregator {
                    for voter in parent_votes.voters() {
                        self.vote(block, tx_locator, voter);
                    }
                }
                // 부모 상태 복원
                self.transaction_aggregator
                    .insert(*parent_ref, parent_aggregator);
            } else {
                tracing::warn!("Parent block {} not found for block {}", parent_ref, block.reference());
            }
        }

        // 3. 현재 블록 자체의 문(Statement)들 처리
        for (offset, statement) in block.statements().iter().enumerate() {
            match statement {
                BaseStatement::Vote(locator, vote) => {
                    if let Vote::Accept = vote {
                        self.vote(block, locator, block.author());
                    }
                }
                BaseStatement::VoteRange(tx_locator_range) => {
                    for locator in tx_locator_range.locators() {
                        self.vote(block, &locator, block.author());
                    }
                }
                BaseStatement::Share(_) => {
                    let locator = TransactionLocator::new(*block.reference(), offset as u64);
                    self.vote(block, &locator, block.author());
                }
            }
        }
    }

    /// 2단계 최종성 집계를 수행하고, 최종성이 달성되면 LedgerWriter를 호출합니다.
    fn vote(
        &mut self,
        block: &Data<StatementBlock>,      // 현재 처리 중인 블록 (잠재적 인증서)
        transaction: &TransactionLocator, // 투표 대상 트랜잭션
        tx_voter: AuthorityIndex,         // 이 투표를 한 밸리데이터
    ) {
        // 최적화: 이미 최종화된 트랜잭션은 더 이상 집계하지 않음
        if self.ledger_writer.is_vote_finalized(transaction) {
            return;
        }

        let block_transaction_aggregator = self
            .transaction_aggregator
            .get_mut(block.reference())
            .unwrap();

        // --- 1단계: 투표 집계 (인증서 생성) ---
        let state = block_transaction_aggregator
            .entry(*transaction)
            .or_default();
        if !state.add(tx_voter, &self.committee) || block.epoch_changed() {
            // 아직 L1 쿼럼(2f+1 투표)이 안됐거나, 에포크 변경 중이면 중단
            return;
        }

        // L1 쿼럼 달성! 'block'은 'transaction'에 대한 "인증서 블록"이 됨.

        // --- 2단계: 인증서 집계 (FPC 최종성) ---
        let cert_aggregator = self
            .certificate_aggregator
            .entry(*transaction)
            .or_default();

        if cert_aggregator.add(block.author(), &self.committee) {
            // L2 쿼럼(2f+1 인증서) 달성! FPC 최종성 확정!
            tracing::debug!("FPC-FIRST: Finalized transaction {}", transaction);
            self.ledger_writer
                .write_finalized_vote(*transaction, self.block_store);
        }
    }
}