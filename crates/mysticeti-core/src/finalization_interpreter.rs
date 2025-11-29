// crates/mysticeti-core/src/finalization_interpreter.rs

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::Mutex; // BlockHandler와 맞춤 (tokio::sync::Mutex일 수도 있으니 실제 코드 확인 필요)

use crate::{block_handler::LedgerWriter, block_store::BlockStore, committee::{Committee, QuorumThreshold, StakeAggregator}, data::Data, metrics::Metrics, runtime, runtime::TimeInstant, types::{
    AuthorityIndex, BaseStatement, BlockReference, StatementBlock, TransactionLocator, Vote,
}};
use crate::transactions_generator::TransactionGenerator;
use crate::types::Transaction;

pub struct FinalizationInterpreter<'a, L: LedgerWriter> {
    transaction_aggregator: &'a mut HashMap<BlockReference, HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>>,
    certificate_aggregator: &'a mut HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,

    block_aggregator: &'a mut HashMap<BlockReference, HashMap<BlockReference, StakeAggregator<QuorumThreshold>>>,
    block_certificate_aggregator: &'a mut HashMap<BlockReference, StakeAggregator<QuorumThreshold>>,

    ledger_writer: &'a mut L,
    committee: Arc<Committee>,
    block_store: &'a BlockStore,
    block_level_fpc: bool,

    // 🌟 [추가된 필드]
    metrics: Arc<Metrics>,
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
        block_level_fpc: bool,
        // 🌟 [추가된 인자]
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
            metrics,        // 초기화
        }
    }

    pub fn process_block(&mut self, block: &Data<StatementBlock>) {
        if self.block_level_fpc {
            self.process_block_level(block);
        } else {
            self.process_transaction_level(block);
        }
    }

    // 🌟 [Mode 1] 블록 단위 FPC - 메트릭 기록 로직 추가
    fn process_block_level(&mut self, block: &Data<StatementBlock>) {
        tracing::info!("블록처리");
        if self.block_aggregator.contains_key(block.reference()) {
            return;
        }
        self.block_aggregator.insert(*block.reference(), HashMap::new());

        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_block_level(&parent_block);

                // [최적화 3] HashMap 전체 Clone 제거
                // 필요한 데이터(Target Block Reference, Voters)만 벡터로 수집
                // StakeAggregator 내부 구조가 가볍다면(비트맵 등) 이 방식이 훨씬 효율적입니다.
                let votes_to_cast: Vec<_> = self.block_aggregator
                    .get(parent_ref)
                    .unwrap()
                    .iter()
                    .flat_map(|(target_ref, agg)| {
                        // agg.voters()가 참조를 반환한다면 여기서 복사하거나 collect 해야 함
                        agg.voters().map(move |voter| (*target_ref, voter))
                    })
                    .collect();

                // 수집된 투표 적용 (self를 mut로 빌려야 하므로 루프 분리)
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

        // [수정] L1 상태(votes) 업데이트만 수행 (L2 진입 조건 확인용)
        l1_state.add(voter, &self.committee);

        // L1 쿼럼 달성 여부 확인 (L2 로직의 트리거로 사용)
        let current_is_quorum = l1_state.is_quorum(&self.committee);

        // ❌ [삭제됨] L1 인증 시점 메트릭 업데이트 로직 제거
        // if !already_certified && current_is_quorum { ... }

        // --- L2: 인증서 집계 및 확정 ---
        if current_is_quorum {
            let l2_state = self.block_certificate_aggregator.entry(target_block_ref).or_default();

            // [최적화] L2 중복 실행 방지 (Edge Trigger)
            let l2_already_finalized = l2_state.is_quorum(&self.committee);

            l2_state.add(observer_block.author(), &self.committee);

            let l2_now_finalized = l2_state.is_quorum(&self.committee);

            // "이전에 확정 안 됨" && "지금 확정 됨" 인 경우에만 커밋 수행
            if !l2_already_finalized && l2_now_finalized {
                if let Some(target_block) = self.block_store.get_block(target_block_ref) {
                    tracing::debug!("FPC-BLOCK: Finalized block {} (all txs)", target_block_ref);
                    for (locator, _tx) in target_block.shared_transactions() {
                        if !self.ledger_writer.is_vote_finalized(&locator) {
                            // LedgerWriter(CommitHandler)가 내부적으로 Commit 메트릭을 기록함
                            self.ledger_writer.write_finalized_vote(locator, self.block_store, true);
                        }
                    }
                }
            }
        }
    }

    // [Mode 2] 트랜잭션 단위 - 메트릭 기록 로직 추가
    fn process_transaction_level(&mut self, block: &Data<StatementBlock>) {
        // ... (기존 로직 유지) ...
        // process_transaction_level 내부 로직은 vote_transaction_level을 호출하므로 거기만 수정하면 됨

        if self.transaction_aggregator.contains_key(block.reference()) { return; }
        self.transaction_aggregator.insert(*block.reference(), Default::default());

        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_transaction_level(&parent_block);
                let parent_aggregator = self.transaction_aggregator.get(parent_ref).unwrap().clone();
                let current_aggregator = self.transaction_aggregator.get_mut(block.reference()).unwrap(); // Unused variable warning fix

                // 부모 상태 병합 및 투표 처리
                for (locator, agg) in parent_aggregator {
                    for voter in agg.voters() {
                        self.vote_transaction_level(block, &locator, voter);
                    }
                }
            }
        }

        // 현재 블록의 Statement 처리
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

        // [수정] L1 상태 업데이트만 수행
        state.add(tx_voter, &self.committee);

        // L1 쿼럼 확인
        let current_is_quorum = state.is_quorum(&self.committee);

        // ❌ [삭제됨] L1 인증 시점 메트릭 업데이트 로직 제거
        // if !already_certified && current_is_quorum { ... }

        if !current_is_quorum || block.epoch_changed() {
            return;
        }

        // --- L2: 인증서 집계 및 확정 ---
        let cert_aggregator = self.certificate_aggregator.entry(*transaction).or_default();

        let l2_was_quorum = cert_aggregator.is_quorum(&self.committee);
        cert_aggregator.add(block.author(), &self.committee);
        let l2_is_quorum = cert_aggregator.is_quorum(&self.committee);

        if !l2_was_quorum && l2_is_quorum {
            tracing::debug!("FPC-TX: Finalized transaction {}", transaction);
            self.ledger_writer.write_finalized_vote(*transaction, self.block_store, true);
        }
    }
}

