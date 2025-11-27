// crates/mysticeti-core/src/finalization_interpreter.rs

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::Mutex; // BlockHandler와 맞춤 (tokio::sync::Mutex일 수도 있으니 실제 코드 확인 필요)

use crate::{
    block_handler::LedgerWriter,
    block_store::BlockStore,
    committee::{Committee, QuorumThreshold, StakeAggregator},
    data::Data,
    metrics::Metrics, // 🌟 추가
    runtime::TimeInstant, // 🌟 추가
    types::{
        AuthorityIndex, BaseStatement, BlockReference, StatementBlock, TransactionLocator, Vote,
    },
};

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
    transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
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
        transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
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
            transaction_time, // 초기화
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
        // 1. Memoization (기존 동일)
        if self.block_aggregator.contains_key(block.reference()) {
            return;
        }
        self.block_aggregator.insert(*block.reference(), HashMap::new());

        // 2. 부모 상태 전파 (기존 동일)
        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_block_level(&parent_block);
                let parent_aggs = self.block_aggregator.get(parent_ref).unwrap().clone();
                for (target_ref, agg) in parent_aggs {
                    for voter in agg.voters() {
                        self.vote_block_level(block, target_ref, voter);
                    }
                }
            }
        }

        // 3. 현재 블록의 투표 처리
        for parent_ref in block.includes() {
            // 🌟 vote_block_level 내부에서 메트릭 기록을 처리하도록 함
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

        // 🌟 [메트릭 로직 1] 투표 전 상태 확인
        let already_certified = l1_state.is_quorum(&self.committee);

        // 투표 추가
        if !l1_state.add(voter, &self.committee) {
            // 쿼럼 미달 상태면 반환 (이미 인증되었더라도 추가 투표는 무시 가능)
            // 단, 여기선 add가 false여도 쿼럼이 달성된 상태일 수 있으므로 아래 로직 진행
            // (StakeAggregator::add는 'threshold를 넘는 순간'에만 true를 반환할 수도 있고, 구현에 따라 다름.
            //  Mysticeti 원본은 '넘는 순간'에만 true 반환. 하지만 안전을 위해 is_quorum으로 더블 체크)
        }

        // 🌟 [메트릭 로직 2] 투표 후 상태 확인
        let current_is_quorum = l1_state.is_quorum(&self.committee);

        // 🌟 [메트릭 로직 3] "이번 투표로 인해 비로소 인증(L1)을 달성했다면" 기록
        // (이미 인증된 상태였다면 중복 기록 안 함)
        if !already_certified && current_is_quorum {
            // 타겟 블록 로드
            if let Some(target_block) = self.block_store.get_block(target_block_ref) {
                // 시간 맵 락 획득
                let guard = self.transaction_time.lock();

                // 블록 내 모든 트랜잭션에 대해 Latency 기록
                for (locator, _tx) in target_block.shared_transactions() {
                    if let Some(start_time) = guard.get(&locator) {
                        let latency = start_time.elapsed();
                        self.metrics.latency_breakdown_4_cert
                            .with_label_values(&["shared"])
                            .observe(latency.as_secs_f64());
                        self.metrics.latency_breakdown_4_cert_squared_s
                            .with_label_values(&["shared"])
                            .inc_by(latency.as_secs_f64().powi(2));
                    }
                }
            }
        }

        // --- L2: 인증서 집계 (기존 동일) ---
        // 쿼럼을 달성했다면 L2 집계기에 기여
        if current_is_quorum {
            let l2_state = self.block_certificate_aggregator.entry(target_block_ref).or_default();
            if l2_state.add(observer_block.author(), &self.committee) {
                if let Some(target_block) = self.block_store.get_block(target_block_ref) {
                    tracing::debug!("FPC-BLOCK: Finalized block {} (all txs)", target_block_ref);
                    for (locator, _tx) in target_block.shared_transactions() {
                        if !self.ledger_writer.is_vote_finalized(&locator) {
                            // is_fpc = true
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

        // 🌟 [메트릭 로직 1] 투표 전 상태 확인
        let already_certified = state.is_quorum(&self.committee);

        // 투표 추가
        // (StakeAggregator::add는 '새로 쿼럼이 되었을 때만' true를 반환할 수도 있고 아닐 수도 있으므로
        //  안전하게 상태를 직접 확인하는 것이 좋습니다)
        state.add(tx_voter, &self.committee);

        // 🌟 [메트릭 로직 2] 투표 후 상태 확인
        let current_is_quorum = state.is_quorum(&self.committee);

        // 🌟 [메트릭 로직 3] 이번 투표로 쿼럼(L1) 달성 시 기록
        if !already_certified && current_is_quorum {
            let guard = self.transaction_time.lock();
            if let Some(start_time) = guard.get(transaction) {
                let latency = start_time.elapsed();
                self.metrics.latency_breakdown_4_cert
                    .with_label_values(&["shared"])
                    .observe(latency.as_secs_f64());
                self.metrics.latency_breakdown_4_cert_squared_s
                    .with_label_values(&["shared"])
                    .inc_by(latency.as_secs_f64().powi(2));
            }
        }

        if !current_is_quorum || block.epoch_changed() {
            return;
        }

        // --- L2: 인증서 집계 (기존 동일) ---
        let cert_aggregator = self.certificate_aggregator.entry(*transaction).or_default();
        if cert_aggregator.add(block.author(), &self.committee) {
            tracing::debug!("FPC-TX: Finalized transaction {}", transaction);
            // is_fpc = true
            self.ledger_writer.write_finalized_vote(*transaction, self.block_store, true);
        }
    }
}