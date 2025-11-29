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
        if self.block_aggregator.contains_key(block.reference()) {
            return;
        }
        self.block_aggregator.insert(*block.reference(), HashMap::new());

        // 🔍 [로그 1] 블록 처리 시작 (너무 많으면 trace로 변경)
        // FPC가 해당 블록을 인지했는지 확인
        tracing::trace!("Processing block for FPC: {}", block.reference());

        for parent_ref in block.includes() {
            if let Some(parent_block) = self.block_store.get_block(*parent_ref) {
                self.process_block_level(&parent_block);

                let votes_to_cast: Vec<_> = self.block_aggregator
                    .get(parent_ref)
                    .unwrap()
                    .iter()
                    .flat_map(|(target_ref, agg)| {
                        agg.voters().map(move |voter| (*target_ref, voter))
                    })
                    .collect();

                // 🔍 [로그 2] 투표 계승(Vote Inheritance) 확인
                // 부모로부터 투표를 물려받지 못하면 L1 인증이 전파되지 않음
                // if !votes_to_cast.is_empty() {
                //     tracing::trace!("Inherited {} votes from parent {}", votes_to_cast.len(), parent_ref);
                // }

                for (target_ref, voter) in votes_to_cast {
                    self.vote_block_level(block, target_ref, voter);
                }
            } else {
                // 🚨 [로그 3] 부모 블록 누락 경고 (가장 흔한 실패 원인)
                // 이 로그가 뜨면 FPC가 Core보다 빨라서 데이터를 못 찾고 있거나, 동기화 문제입니다.
                tracing::warn!("⚠️ [FPC] Missing parent block {} required by {}", parent_ref, block.reference());
            }
        }

        // 자기 자신의 투표 처리
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

        // 1. L1 투표 추가
        let l1_was_quorum = l1_state.is_quorum(&self.committee);
        l1_state.add(voter, &self.committee);
        let l1_is_quorum = l1_state.is_quorum(&self.committee);

        // 🔍 [로그 4] L1 인증(Certification) 달성 순간
        if !l1_was_quorum && l1_is_quorum {
            tracing::debug!("🎉 [FPC] L1 Certified block {} (triggered by {})", target_block_ref, observer_block.reference());
        }

        // 2. L2 진입 (L1 인증이 완료된 상태여야 함)
        if l1_is_quorum {
            let l2_state = self.block_certificate_aggregator.entry(target_block_ref).or_default();

            // Edge Trigger 확인을 위한 이전 상태 저장
            let l2_already_finalized = l2_state.is_quorum(&self.committee);

            // L2 투표 추가 (Observer가 L1을 확인했음을 등록)
            l2_state.add(observer_block.author(), &self.committee);

            let l2_now_finalized = l2_state.is_quorum(&self.committee);

            // 🔍 [로그 5] L2 투표 진행 상황 (디버깅용, 너무 많으면 주석 처리)
            // tracing::trace!("   -> L2 Vote for {}: New Stake Added. Quorum reached? {}", target_block_ref, l2_now_finalized);

            // 3. L2 확정(Finalization) 및 커밋 수행
            if !l2_already_finalized && l2_now_finalized {
                tracing::info!("🚀 [FPC] L2 FINALIZED Block {}! Starting commit...", target_block_ref);

                if let Some(target_block) = self.block_store.get_block(target_block_ref) {
                    let stmt_count = target_block.statements().len();
                    let share_count = target_block.shared_transactions().count();

                    tracing::info!(
                    "🧐 [Inspect] Block {} content: Total Statements={}, Shared Txs={}",
                    target_block_ref, stmt_count, share_count
                );
                    // 만약 트랜잭션이 하나라도 있다면 샘플 출력
                    if share_count > 0 {
                        tracing::info!("   -> First Tx found in block.");
                    } else {
                        tracing::warn!("   -> ⚠️ WARNING: Block is EMPTY (No 'Share' statements). It implies no transactions.");

                        // (선택) Statements 타입 확인 (Vote만 들어있는지 확인)
                        for (i, stmt) in target_block.statements().iter().take(5).enumerate() {
                            tracing::info!("      Stmt[{}]: {:?}", i, stmt); // BaseStatement는 Debug 구현되어 있음
                        }
                    }
                    let mut committed_count = 0;
                    for (locator, _tx) in target_block.shared_transactions() {
                        if !self.ledger_writer.is_vote_finalized(&locator) {
                            self.ledger_writer.write_finalized_vote(locator, self.block_store, true);
                            committed_count += 1;
                        }
                    }

                    if committed_count > 0 {
                        tracing::info!("✅ [FPC] Successfully committed {} txs from block {}", committed_count, target_block_ref);
                    } else {
                        tracing::info!("ℹ️ [FPC] Block {} finalized, but all txs were already processed.", target_block_ref);
                    }
                } else {
                    // 🚨 [로그 6] 치명적 오류: 확정된 블록 본문을 찾을 수 없음
                    tracing::error!("🔥 [FPC] CRITICAL: Finalized block {} not found in store!", target_block_ref);
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

