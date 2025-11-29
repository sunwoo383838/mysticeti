// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    env,
    path::Path,
    sync::Arc,
    time::Duration,
};
use ark_bls12_381::Fr;
use minibytes::Bytes;
use parking_lot::Mutex;
use rand::seq::index::sample;
use rayon::prelude::*;
use tokio::sync::mpsc;

use crate::{
    block_store::BlockStore,
    committee::{Committee, ProcessedTransactionHandler, QuorumThreshold, TransactionAggregator},
    consensus::linearizer::{CommittedSubDag, Linearizer},
    data::Data,
    log::TransactionLog,
    metrics::{Metrics, UtilizationTimerExt, UtilizationTimerVecExt},
    runtime::{self, TimeInstant},
    syncer::CommitObserver,
    transactions_generator::TransactionGenerator,
    types::{
        AuthorityIndex,
        BaseStatement,
        BlockReference,
        StatementBlock,
        Transaction,
        TransactionLocator,
    },
};
use crate::committee::{StakeAggregator, VoteRangeBuilder};
use crate::config::{ByzantineType, FaultConfig, NodeParameters, NodePublicConfig};
use crate::mempool::{Mempool};
use crate::nullifier::NullifierDB;
use crate::types::{TransactionLocatorRange, Vote};

pub trait BlockHandler: Send + Sync {
    fn handle_blocks(
        &mut self,
        blocks: &[(Data<StatementBlock>, bool)],
        require_response: bool,
    ) -> Vec<BaseStatement>;

    fn handle_proposal(&mut self, block: &Data<StatementBlock>);

    fn state(&self) -> Bytes;

    fn recover_state(&mut self, _state: &Bytes);

    fn cleanup(&self) {}

    fn transaction_time(&self) -> Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>;
}

const REAL_BLOCK_HANDLER_TXN_SIZE: usize = 512;
const REAL_BLOCK_HANDLER_TXN_GEN_STEP: usize = 32;
const _: () = assert_constants();

#[allow(dead_code)]
const fn assert_constants() {
    if REAL_BLOCK_HANDLER_TXN_SIZE % REAL_BLOCK_HANDLER_TXN_GEN_STEP != 0 {
        panic!("REAL_BLOCK_HANDLER_TXN_SIZE % REAL_BLOCK_HANDLER_TXN_GEN_STEP != 0")
    }
}

pub struct RealBlockHandler {
    transaction_votes: TransactionAggregator<QuorumThreshold, TransactionLog>,
    pub transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
    committee: Arc<Committee>,
    authority: AuthorityIndex,
    block_store: BlockStore,
    metrics: Arc<Metrics>,
    mempool: Arc<Mempool>,
    pending_transactions: usize,
    consensus_only: bool,
    fault_config: Option<FaultConfig>,
    start_time: std::time::Instant,
}

/// The max number of transactions per block.
// todo - This value should be in bytes because it is capped by the wal entry size.
pub const SOFT_MAX_PROPOSED_PER_BLOCK: usize = 20 * 1000;

impl RealBlockHandler {
    pub fn new(
        committee: Arc<Committee>,
        authority: AuthorityIndex,
        certified_transactions_log_path: &Path,
        block_store: BlockStore,
        metrics: Arc<Metrics>,
        mempool: Arc<Mempool>,
        consensus_only: bool,
        fault_config: Option<FaultConfig>
    ) -> Self {
        let transaction_log = TransactionLog::start(certified_transactions_log_path)
            .expect("Failed to open certified transaction log for write");
        Self {
            transaction_votes: TransactionAggregator::with_handler(transaction_log),
            transaction_time: Default::default(),
            committee,
            authority,
            block_store,
            metrics,
            mempool,
            pending_transactions: 0,
            consensus_only,
            fault_config,
            start_time: std::time::Instant::now(),
        }
    }
}

impl RealBlockHandler {

    fn get_active_byzantine_behavior(&self) -> Option<&ByzantineType> {
        if let Some(FaultConfig::Byzantine { start_delay, behavior }) = &self.fault_config {
            if self.start_time.elapsed() >= *start_delay {
                return Some(behavior);
            }
        }
        None
    }

    /// Expose a metric for certified transactions.
    fn update_metrics(
        &self,
        block_creation: Option<&TimeInstant>,
        transaction: &Transaction,
        current_timestamp: &Duration,
    ) {
        if let Some(instant) = block_creation {
            let latency = instant.elapsed();
            self.metrics.transaction_certified_latency.observe(latency);
            self.metrics
                .inter_block_latency_s
                .with_label_values(&["owned"])
                .observe(latency.as_secs_f64());
        }

        let tx_submission_timestamp = TransactionGenerator::extract_timestamp(transaction);
        let latency = current_timestamp.saturating_sub(tx_submission_timestamp);
        let square_latency = latency.as_secs_f64().powf(2.0);
        self.metrics.latency_breakdown
            .with_label_values(&["4_certified"])
            .observe(latency.as_secs_f64());
        self.metrics.latency_breakdown_squared_s
            .with_label_values(&["4_certified"])
            .inc_by(square_latency);
    }
}

impl BlockHandler for RealBlockHandler {
    fn handle_blocks(
        &mut self,
        blocks: &[(Data<StatementBlock>, bool)],
        require_response: bool,
    ) -> Vec<BaseStatement> {
        let current_timestamp = runtime::timestamp_utc();
        let _timer = self
            .metrics
            .utilization_timer
            .utilization_timer("BlockHandler::handle_blocks");

        let mut response = vec![];

        if require_response {
            let available_capacity = SOFT_MAX_PROPOSED_PER_BLOCK.saturating_sub(self.pending_transactions);
            if available_capacity > 0 {
                let mut new_txs = self.mempool.get_verified_transactions(available_capacity);
                // 🌟 [비잔틴 로직 주입]
                if let Some(behavior) = self.get_active_byzantine_behavior() {
                    match behavior {
                        // 시나리오 1: 위조된 증명 (Invalid Proof) - 1/100 랜덤 위조
                        ByzantineType::InvalidProof => {
                            let total = new_txs.len();
                            if total > 0 {
                                // 1. 위조할 개수 계산 (1/100, 최소 1개 보장)
                                let corrupt_count = std::cmp::max(1, total / 100);
                                tracing::warn!(
                                    "🎭 [Byzantine] Injecting INVALID proofs to {} out of {} transactions!",
                                    corrupt_count, total
                                );
                                // 2. 무작위 인덱스 선택
                                let mut rng = rand::thread_rng();
                                let indices = sample(&mut rng, total, corrupt_count);
                                // 3. 선택된 인덱스의 트랜잭션 오염시키기
                                for i in indices.iter() {
                                    let mut corrupted_tx = new_txs[i].clone();
                                    let mut data = corrupted_tx.into_data();
                                    // 데이터의 첫 바이트를 변경하여 서명/증명 검증 실패 유도
                                    if !data.is_empty() {
                                        data[0] = data[0].wrapping_add(1);
                                    }
                                    // 오염된 트랜잭션으로 교체
                                    new_txs[i] = Transaction::new(data);
                                }
                            }
                        }

                        ByzantineType::DoubleVote => {
                            let total = new_txs.len();
                            if total > 0 {
                                // 1. 복제할 개수 계산 (1/100, 최소 1개)
                                let duplicate_count = std::cmp::max(1, total / 100);
                                tracing::warn!(
                                    "🎭 [Byzantine] Injecting DOUBLE votes for {}/{} txs",
                                    duplicate_count, total
                                );
                                // 2. 무작위 인덱스 선택
                                let mut rng = rand::thread_rng();
                                let indices = sample(&mut rng, total, duplicate_count);

                                let mut duplicates = Vec::with_capacity(duplicate_count);
                                for i in indices.iter() {
                                    duplicates.push(new_txs[i].clone());
                                }

                                // 원본 리스트에 중복 트랜잭션 추가
                                new_txs.extend(duplicates);
                            }
                        }
                    }
                }
                self.pending_transactions += new_txs.len();
                for tx in new_txs {
                    response.push(BaseStatement::Share(tx));
                }
            }
        }

        let transaction_time = self.transaction_time.lock();

        for (block, check_individual) in blocks {
            if !self.consensus_only {
                let processed =
                    self.transaction_votes
                        .process_block(block, None, &self.committee);

                for processed_locator in processed {
                    let block_creation = transaction_time.get(&processed_locator);
                    let transaction = self
                        .block_store
                        .get_transaction(&processed_locator)
                        .expect("Failed to get certified transaction");
                    self.update_metrics(block_creation, &transaction, &current_timestamp);
                }
            }

            if require_response {
                if !*check_individual {
                    for range in block.shared_ranges() {
                        response.push(BaseStatement::VoteRange(range));
                    }
                } else {
                    // [전략 2] Primitive FPC (개별 검증 + 효율적 투표)

                    // (A) 검증할 트랜잭션들을 수집합니다.
                    // shared_transactions()는 (Locator, &Transaction)을 반환합니다.
                    let txs_with_locators: Vec<_> = block.shared_transactions().collect();

                    // Mempool에 넘기기 위해 &Transaction만 별도 벡터로 추출
                    let tx_refs: Vec<&Transaction> = txs_with_locators.iter().map(|(_, tx)| *tx).collect();

                    // (B) Mempool에 배치 검증 요청 🚀
                    // 내부적으로 Rayon을 사용하며, VK/Root 로딩 오버헤드를 최소화했습니다.
                    let verification_results = self.mempool.verify_transactions(&tx_refs);

                    // (C) 검증 결과를 순회하며 VoteRange와 Reject를 구성
                    let mut vote_range_builder = VoteRangeBuilder::default();

                    // txs_with_locators와 verification_results의 길이는 같음이 보장됩니다.
                    for ((locator, _), is_valid) in txs_with_locators.into_iter().zip(verification_results.into_iter()) {
                        let offset = locator.offset();

                        if is_valid {
                            // 유효함: VoteRangeBuilder에 추가 (여기서 에러가 났던 이유는 else 블록에서 이동되었기 때문)
                            // 이제 else 블록에서 다시 살려내므로 안전합니다.
                            if let Some(range) = vote_range_builder.add(offset) {
                                let range = TransactionLocatorRange::new(*block.reference(), range);
                                response.push(BaseStatement::VoteRange(range));
                            }
                            self.metrics.transaction_votes_total.with_label_values(&["accept"]).inc();
                        } else {
                            // 유효하지 않음 (검증 실패):

                            // 1. 기존 범위 Flush (여기서 vote_range_builder의 소유권이 이동됨!)
                            let finished_range = vote_range_builder.finish();

                            // 🌟 [핵심 수정] 소유권이 이동된 변수에 새 인스턴스를 즉시 할당하여 부활시킵니다.
                            // 이렇게 해야 다음 루프의 if is_valid 블록에서 add()를 호출할 수 있습니다.
                            vote_range_builder = VoteRangeBuilder::default();

                            // Flush된 범위 처리
                            if let Some(range) = finished_range {
                                let range = TransactionLocatorRange::new(*block.reference(), range);
                                response.push(BaseStatement::VoteRange(range));
                            }

                            // 2. 명시적 Reject 투표
                            tracing::debug!("Rejecting invalid tx {}", locator);
                            response.push(BaseStatement::Vote(locator, Vote::Reject(None)));
                            self.metrics.transaction_votes_total.with_label_values(&["reject"]).inc();

                            // 3. 빌더는 위에서 새로 만들었으므로 초기화 상태입니다.
                        }
                    }

                    // (D) 루프 종료 후 남은 유효 범위 처리 (Flush remaining)
                    if let Some(range) = vote_range_builder.finish() {
                        let range = TransactionLocatorRange::new(*block.reference(), range);
                        response.push(BaseStatement::VoteRange(range));
                    }
                }
            }
        }

        self.metrics
            .block_handler_pending_certificates
            .set(self.transaction_votes.len() as i64);

        if !response.is_empty() {
            tracing::info!("📦 [BlockHandler] Generated response with {} statements", response.len());

            // 너무 많으면 앞부분만 출력 (예: 5개)
            for (i, stmt) in response.iter().take(5).enumerate() {
                // BaseStatement는 Debug 트레이트가 구현되어 있어 {:?}로 출력 가능
                tracing::info!("   -> Stmt[{}]: {:?}", i, stmt);
            }
            if response.len() > 5 {
                tracing::info!("   -> ... and {} more statements", response.len() - 5);
            }
        } else if require_response {
            // 응답이 필요한데(require_response=true) 내용이 비어있다면,
            // 멤풀에 트랜잭션이 없거나 검증에 실패한 것일 수 있음
            tracing::debug!("💤 [BlockHandler] Required response but generated EMPTY response. (Mempool empty?)");
        }
        response
    }

    fn handle_proposal(&mut self, block: &Data<StatementBlock>) {
        self.pending_transactions -= block.shared_transactions().count();
        let mut transaction_time = self.transaction_time.lock();

        let block_time = runtime::timestamp_utc();

        for (locator, tx) in block.shared_transactions() {
            transaction_time.insert(locator, TimeInstant::now());

            let tx_time = Duration::from_millis(tx.timestamp);
            let latency = block_time.saturating_sub(tx_time);
            let square_latency = latency.as_secs_f64().powf(2.0);


            self.metrics.latency_breakdown
                .with_label_values(&["3_included"])
                .observe(latency.as_secs_f64());
            self.metrics.latency_breakdown_squared_s
                .with_label_values(&["3_included"])
                .inc_by(square_latency);
        }
        if !self.consensus_only {
            for range in block.shared_ranges() {
                self.transaction_votes
                    .register(range, self.authority, &self.committee);
            }
        }
    }

    fn transaction_time(&self) -> Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>> {
        self.transaction_time.clone()
    }

    fn state(&self) -> Bytes {
        self.transaction_votes.state()
    }

    fn recover_state(&mut self, state: &Bytes) {
        self.transaction_votes.with_state(state);
    }

    fn cleanup(&self) {
        let _timer = self.metrics.block_handler_cleanup_util.utilization_timer();
        // todo - all of this should go away and we should measure tx latency differently
        let mut l = self.transaction_time.lock();
        l.retain(|_k, v| v.elapsed() < Duration::from_secs(10));
    }
}

// Immediately votes and generates new transactions
pub struct TestBlockHandler {
    last_transaction: u64,
    transaction_votes: TransactionAggregator<QuorumThreshold>,
    pub transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
    committee: Arc<Committee>,
    authority: AuthorityIndex,
    pub proposed: Vec<TransactionLocator>,

    metrics: Arc<Metrics>,
}

impl TestBlockHandler {
    pub fn new(
        last_transaction: u64,
        committee: Arc<Committee>,
        authority: AuthorityIndex,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            last_transaction,
            transaction_votes: Default::default(),
            transaction_time: Default::default(),
            committee,
            authority,
            proposed: Default::default(),
            metrics,
        }

    }

    pub fn is_certified(&self, locator: &TransactionLocator) -> bool {
        self.transaction_votes.is_processed(locator)
    }

    pub fn make_transaction(i: u64) -> Transaction {
        Transaction::new(i.to_le_bytes().to_vec())
    }
}

impl BlockHandler for TestBlockHandler {
    fn handle_blocks(
        &mut self,
        blocks: &[(Data<StatementBlock>, bool)],
        require_response: bool,
    ) -> Vec<BaseStatement> {
        // todo - this is ugly, but right now we need a way to recover self.last_transaction
        let mut response = vec![];
        if require_response {
            for (block, _) in blocks {
                if block.author() == self.authority {
                    // We can see our own block in handle_blocks - this can happen during core recovery
                    // Todo - we might also need to process pending Payload statements as well
                    for statement in block.statements() {
                        if let BaseStatement::Share(_) = statement {
                            self.last_transaction += 1;
                        }
                    }
                }
            }
            self.last_transaction += 1;
            let next_transaction = Self::make_transaction(self.last_transaction);
            response.push(BaseStatement::Share(next_transaction));
        }
        let transaction_time = self.transaction_time.lock();
        for (block, _) in blocks {
            tracing::debug!("Processing {block:?}");
            let response_option: Option<&mut Vec<BaseStatement>> = if require_response {
                Some(&mut response)
            } else {
                None
            };
            let processed =
                self.transaction_votes
                    .process_block(block, response_option, &self.committee);
            for processed_locator in processed {
                if let Some(instant) = transaction_time.get(&processed_locator) {
                    self.metrics
                        .transaction_certified_latency
                        .observe(instant.elapsed());
                }
            }
        }
        response
    }

    fn handle_proposal(&mut self, block: &Data<StatementBlock>) {
        let mut transaction_time = self.transaction_time.lock();
        for (locator, _) in block.shared_transactions() {
            transaction_time.insert(locator, TimeInstant::now());
            self.proposed.push(locator);
        }
        for range in block.shared_ranges() {
            self.transaction_votes
                .register(range, self.authority, &self.committee);
        }
    }

    fn state(&self) -> Bytes {
        let state = (&self.transaction_votes.state(), &self.last_transaction);
        let bytes =
            bincode::serialize(&state).expect("Failed to serialize transaction aggregator state");
        bytes.into()
    }

    fn transaction_time(&self) -> Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>> {
        self.transaction_time.clone()
    }

    fn recover_state(&mut self, state: &Bytes) {
        let (transaction_votes, last_transaction) = bincode::deserialize(state)
            .expect("Failed to deserialize transaction aggregator state");
        self.transaction_votes.with_state(&transaction_votes);
        self.last_transaction = last_transaction;
    }
}

pub trait LedgerWriter: Send + Sync {
    fn write_finalized_vote(&mut self, vote: TransactionLocator, block_store: &BlockStore, is_fpc: bool);
    fn is_vote_finalized(&self, vote: &TransactionLocator) -> bool;
}

pub struct CommitHandler {
    commit_interpreter: Linearizer,
    committee: Arc<Committee>,
    committed_leaders: Vec<BlockReference>,

    start_time: TimeInstant,
    transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,

    metrics: Arc<Metrics>,
    consensus_only: bool,
    enable_block_fpc: bool,

    commit_log: TransactionLog,
    nullifier_db: Arc<NullifierDB>, // << NullifierDB 필드
    finalized_cache: HashSet<TransactionLocator>,
}

impl CommitHandler {
    pub fn new(
        committee: Arc<Committee>,
        transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
        metrics: Arc<Metrics>,
        nullifier_db: Arc<NullifierDB>,
        transaction_log: TransactionLog,
        node_public_config: &NodePublicConfig,
    ) -> Self {
        let consensus_only = env::var("CONSENSUS_ONLY").is_ok();

        Self {
            commit_interpreter: Linearizer::new(),
            committee,
            committed_leaders: vec![],
            start_time: TimeInstant::now(),
            transaction_time,
            metrics,
            consensus_only,
            nullifier_db,
            finalized_cache: HashSet::new(), // 복구 로직(recover_committed)에서 채워져야 함
            commit_log: transaction_log,
            enable_block_fpc: node_public_config.parameters.enable_block_fpc,
        }
    }

    pub fn committed_leaders(&self) -> &Vec<BlockReference> {
        &self.committed_leaders
    }

    pub fn get_all_finalized_locators(&self) -> Vec<TransactionLocator> {
        // finalized_cache는 모든 최종화된 트랜잭션을 추적합니다.
        self.finalized_cache.iter().cloned().collect()
    }

    fn update_metrics(
        &self,
        block_creation: Option<&TimeInstant>,
        current_timestamp: Duration,
        transaction: &Transaction,
        is_fpc: bool,
    ) {
        if let Some(instant) = block_creation {
            let latency = instant.elapsed();
            self.metrics.transaction_committed_latency.observe(latency);
            self.metrics
                .inter_block_latency_s
                .with_label_values(&["shared"])
                .observe(latency.as_secs_f64());
        }

        let path_type = if is_fpc { "fpc" } else { "c" };

        // Record benchmark start time.
        let time_from_start = self.start_time.elapsed();
        let benchmark_duration = self.metrics.benchmark_duration.get();
        if let Some(delta) = time_from_start.as_secs().checked_sub(benchmark_duration) {
            self.metrics.benchmark_duration.inc_by(delta);
        }

        let tx_submission_timestamp = TransactionGenerator::extract_timestamp(transaction);
        let latency = current_timestamp.saturating_sub(tx_submission_timestamp);
        let square_latency = latency.as_secs_f64().powf(2.0);
        self.metrics
            .latency_s
            .with_label_values(&[path_type])
            .observe(latency.as_secs_f64());
        self.metrics
            .latency_squared_s
            .with_label_values(&[path_type])
            .inc_by(square_latency);
        
        tracing::info!("metrics update");
    }
}

impl LedgerWriter for CommitHandler {
    fn write_finalized_vote(&mut self, vote: TransactionLocator, block_store: &BlockStore, is_fpc: bool) {
        tracing::info!("finalized vote");
        if !self.finalized_cache.insert(vote) {
            return;
        }

        self.commit_log.transaction_processed(vote);

        let transaction_opt = block_store.get_transaction(&vote);
        if transaction_opt.is_none() {
            tracing::warn!("LedgerWriter: Could not find transaction for finalized locator {}", vote);
            return;
        }
        let transaction = transaction_opt.unwrap();

        let nullifier = transaction.get_vote().unwrap().nullifier;
        if let Err(e) = self.nullifier_db.commit(nullifier) {
            tracing::error!(
            "FPC-FIRST: Failed to commit nullifier for finalized locator {}: {:?}",
            vote,
            e
            );

            self.finalized_cache.remove(&vote);
            return;
        }

        let current_timestamp = runtime::timestamp_utc(); // << 현재 시간 가져오기
        let transaction_time_lock = self.transaction_time.lock(); // << Mutex 락
        let block_creation_time = transaction_time_lock.get(&vote);

        self.update_metrics(
            block_creation_time,
            current_timestamp,
            &transaction,
            is_fpc
        );
    }

    fn is_vote_finalized(&self, vote: &TransactionLocator) -> bool {
        self.finalized_cache.contains(vote)
    }


}


// C-Path Fallback 경로 (Syncer -> Core -> CommitObserver를 통해 호출됨)
impl CommitObserver for CommitHandler {
    fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<Data<StatementBlock>>,
        transaction_aggregator: &HashMap<BlockReference, HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>>,
    ) -> Vec<CommittedSubDag> {
        // 1. 함수 진입 및 처리할 리더 수 로깅
        tracing::info!("➡️ [C-PATH] handle_commit: Start processing {} committed leaders.", committed_leaders.len());

        let committed = self
            .commit_interpreter
            .handle_commit(block_store, committed_leaders);

        // 2. 커밋 인터프리터 결과 로깅
        tracing::info!("✅ [C-PATH] Commit interpreter returned {} finalized SubDag(s).", committed.len());

        let mut total_finalized_txs = 0;

        for commit in &committed {
            self.committed_leaders.push(commit.anchor);

            // 3. 서브 DAG 앵커 로깅
            tracing::info!("⚓ [C-PATH] Processing SubDag anchored at block: {}", commit.anchor);

            let mut subdag_tx_count = 0;

            for block in &commit.blocks {
                // 4. 서브 DAG 내 블록 및 트랜잭션 수 로깅
                tracing::info!("📦 [C-PATH] Processing block {} in SubDag", block.reference());

                for (locator, _transaction) in block.shared_transactions() {

                    // 1. 이미 FPC로 최종화된 트랜잭션은 스킵 (중복 실행 방지)
                    if self.is_vote_finalized(&locator) {
                        tracing::debug!("⏩ [C-PATH] Skipping already FPC-finalized transaction: {}", locator);
                        continue;
                    }

                    // 🌟 [수정 5] C-Path Fallback 로직 분기
                    let should_finalize = if self.enable_block_fpc {
                        // [전략 1: Block Level FPC]
                        tracing::debug!("💡 [C-PATH] Strategy: Block FPC enabled. Tx {} assumed valid.", locator);
                        true
                    } else {
                        // [전략 2: Transaction Level FPC]
                        if let Some(block_aggs) = transaction_aggregator.get(block.reference()) {
                            if let Some(stake_agg) = block_aggs.get(&locator) {
                                let is_quorum = stake_agg.is_quorum(&self.committee);
                                if is_quorum {
                                    tracing::debug!("👍 [C-PATH] Strategy: Tx FPC (Fallback). Quorum met for {}", locator);
                                }
                                is_quorum
                            } else {
                                // 투표 정보 없음 (Reject)
                                tracing::debug!("❌ [C-PATH] Strategy: Tx FPC (Fallback). No vote info found for {}", locator);
                                false
                            }
                        } else {
                            // 블록 정보 없음 (이 경우는 거의 없어야 함)
                            tracing::debug!("❌ [C-PATH] Strategy: Tx FPC (Fallback). No aggregator info for block {}", block.reference());
                            false
                        }
                    };

                    if should_finalize {
                        // 5. C-Path 최종 확정 성공 로깅 (기존 warn -> info로 변경하여 Commit Metric으로 사용)
                        tracing::info!("🎉 [C-PATH] FALLBACK SUCCESS: Finalizing transaction {}", locator);
                        // is_fpc = false (C-Path에 의한 커밋임을 표시)
                        self.write_finalized_vote(locator, block_store, false);
                        total_finalized_txs += 1;
                        subdag_tx_count += 1;
                    } else {
                        // 6. 최종 확정 실패 및 스킵 로깅 (enable_block_fpc=false일 때만 의미 있음)
                        if !self.enable_block_fpc {
                            tracing::info!("🚫 [C-PATH] FALLBACK FAILED: Skipping rejected transaction {}", locator);
                        }
                    }
                }
            }
            tracing::info!("📊 [C-PATH] SubDag anchored at {} finalized {} transactions.", commit.anchor, subdag_tx_count);
        }

        // 7. 최종 집계 결과 로깅
        tracing::info!("🏁 [C-PATH] handle_commit finished. Total transactions finalized: {}.", total_finalized_txs);

        committed
    }

    // C-Path Linearizer의 상태만 저장/복구
    fn aggregator_state(&self) -> Bytes {
        // `transaction_votes` 관련 로직 제거
        bincode::serialize(&self.commit_interpreter.committed)
            .expect("C-Path Linearizer state serialization failed")
            .into()
    }

    fn recover_committed(&mut self, committed_blocks: HashSet<BlockReference>, state: Option<Bytes>) {
        assert!(self.commit_interpreter.committed.is_empty());

        // C-Path Linearizer 상태 복구
        if let Some(state_bytes) = state {
            match bincode::deserialize(&state_bytes) {
                Ok(c_state) => self.commit_interpreter.committed = c_state,
                // 이전 버전 호환성 (transaction_votes.state()가 포함된 경우)
                Err(e) => {
                    tracing::warn!("Failed to deserialize C-Path state ({}). Attempting legacy state deserialization.", e);
                    if let Ok((_agg_state, c_state)) = bincode::deserialize::<(Bytes, HashSet<BlockReference>)>(&state_bytes) {
                        self.commit_interpreter.committed = c_state;
                        tracing::info!("Legacy C-Path state recovered. FPC Aggregator state ignored.");
                    } else {
                        tracing::error!("Failed to deserialize legacy C-Path state. Starting with empty state.");
                    }
                }
            }
        } else {
            assert!(committed_blocks.is_empty());
        }

        // `finalized_cache` 복구 (필수)
        // TODO: 재시작 시, NullifierDB에서 'Commit' 상태인 모든 널리파이어를
        //       읽어오거나(DB에 조회 기능 필요),
        //       `commit_log`("committed.txt") 파일을 처음부터 읽어
        //       `finalized_cache`를 재구축해야 합니다.

        tracing::warn!("`finalized_cache` recovery from commit_log not yet implemented. Re-processing of finalized votes may occur after restart!");

        // 임시 복구 (C-Path가 커밋한 블록들만 복구 - 불완전함)
        // for block_ref in &self.commit_interpreter.committed {
        //     // 이 블록을 BlockStore에서 읽어 트랜잭션을 캐시에 넣어야 함
        // }
    }
}