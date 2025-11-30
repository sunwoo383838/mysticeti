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
use parking_lot::{Mutex, RwLock};
use rand::seq::index::sample;
use rayon::prelude::*;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
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
    pub transaction_time: Arc<RwLock<HashMap<TransactionLocator, TimeInstant>>>,
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

        let transaction_time = self.transaction_time.read();

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
        let mut transaction_time = self.transaction_time.write();

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


    fn state(&self) -> Bytes {
        self.transaction_votes.state()
    }

    fn recover_state(&mut self, state: &Bytes) {
        self.transaction_votes.with_state(state);
    }

    fn cleanup(&self) {
        let _timer = self.metrics.block_handler_cleanup_util.utilization_timer();
        // todo - all of this should go away and we should measure tx latency differently
        let mut l = self.transaction_time.write();
        l.retain(|_k, v| v.elapsed() < Duration::from_secs(10));
    }
}

// Immediately votes and generates new transactions
pub struct TestBlockHandler {
    last_transaction: u64,
    transaction_votes: TransactionAggregator<QuorumThreshold>,
    pub transaction_time: Arc<RwLock<HashMap<TransactionLocator, TimeInstant>>>,
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
        let transaction_time = self.transaction_time.read();
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
        let mut transaction_time = self.transaction_time.write();
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

    fn recover_state(&mut self, state: &Bytes) {
        let (transaction_votes, last_transaction) = bincode::deserialize(state)
            .expect("Failed to deserialize transaction aggregator state");
        self.transaction_votes.with_state(&transaction_votes);
        self.last_transaction = last_transaction;
    }
}

#[derive(Clone)]
pub struct ExecutionRequest {
    pub locator: TransactionLocator,
    pub transaction: Transaction,
    pub is_fpc: bool,
}
pub struct ExecutionService {
    nullifier_db: Arc<NullifierDB>,
    metrics: Arc<Metrics>,
    transaction_time: Arc<RwLock<HashMap<TransactionLocator, TimeInstant>>>,
    finalized_cache: HashSet<TransactionLocator>,
}

impl ExecutionService {
    pub fn spawn_parallel(
        nullifier_db: Arc<NullifierDB>,
        metrics: Arc<Metrics>,
        transaction_time: Arc<RwLock<HashMap<TransactionLocator, TimeInstant>>>,
    ) -> (mpsc::Sender<ExecutionRequest>, JoinHandle<()>) {
        let (sender, receiver) = mpsc::channel(300_000);

        let service = Self {
            nullifier_db,
            metrics,
            transaction_time,
            finalized_cache: HashSet::new(),
        };

        let handle = tokio::spawn(async move {
            service.run(receiver).await;
        });

        (sender, handle)
    }

    async fn run(mut self, mut receiver: mpsc::Receiver<ExecutionRequest>) {
        tracing::info!("🚀 [ExecutionService] Batch Writer Started (RocksDB Log).");

        let mut request_batch = Vec::with_capacity(2000);
        let mut nullifier_batch = Vec::with_capacity(2000);
        let mut locator_batch = Vec::with_capacity(2000); // 🌟 추가

        while let Some(req) = receiver.recv().await {
            // 1. 중복 체크
            if self.finalized_cache.contains(&req.locator) {
                continue;
            }
            self.finalized_cache.insert(req.locator);

            request_batch.push(req);

            // 2. 배치 수집
            while request_batch.len() < 2000 {
                match receiver.try_recv() {
                    Ok(r) => {
                        if !self.finalized_cache.contains(&r.locator) {
                            self.finalized_cache.insert(r.locator);
                            request_batch.push(r);
                        }
                    }
                    Err(_) => break,
                }
            }

            // 3. 데이터 추출
            nullifier_batch.clear();
            locator_batch.clear();

            for req in &request_batch {
                locator_batch.push(req.locator); // 🌟 로케이터 수집
                if let Ok(vote_tx) = req.transaction.get_vote() {
                    nullifier_batch.push(vote_tx.nullifier);
                }
            }


            // 4. 병렬 실행을 위한 데이터 복제 (Arc 사용)
            let db = self.nullifier_db.clone();
            let metrics = self.metrics.clone();
            let tx_time = self.transaction_time.clone();

            // 배치를 통째로 이동(Move)시켜야 하므로 clone()
            let nullifiers = nullifier_batch.clone();
            let locators = locator_batch.clone();

            // 메트릭 업데이트에 필요한 데이터도 복제해서 넘김
            // (Dispatcher가 기다리지 않으므로, 메트릭 업데이트도 워커가 해야 함)
            let current_request_batch = request_batch.clone();


            tokio::task::spawn_blocking(move || {
                // [Worker Thread]

                // 1. DB 쓰기 (Blocking I/O)
                if let Err(e) = db.commit_execution_batch(nullifiers, locators) {
                    tracing::error!("💥 DB Execution Batch Failed: {:?}", e);
                    return; // 실패 시 메트릭 업데이트 건너뜀
                }

                // 2. 메트릭 업데이트 (메모리 연산)
                // 워커 스레드가 수행하므로 Dispatcher의 부하를 줄여줌
                let current_timestamp = runtime::timestamp_utc();
                {
                    let transaction_time_lock = tx_time.read();
                    for req in &current_request_batch {
                        Self::update_metrics(
                            &metrics,
                            transaction_time_lock.get(&req.locator),
                            current_timestamp,
                            &req.transaction,
                            req.is_fpc
                        );
                    }
                }
            });

            // 5. 메트릭 업데이트 (로그 파일 쓰기 제거됨)

            request_batch.clear();
        }
        tracing::warn!("⚠️ [ExecutionService] Stopped.");
    }

    // ... (update_metrics 등 유지)

    // update_metrics 함수는 ExecutionService로 이동
    fn update_metrics(
        metrics: &Arc<Metrics>,
        block_creation: Option<&TimeInstant>,
        current_timestamp: Duration,
        transaction: &Transaction,
        is_fpc: bool,
    ) {
        // ... (기존 update_metrics 로직 그대로 유지) ...
        // Latency 계산 및 메트릭 기록 로직
        if let Some(instant) = block_creation {
            let latency = instant.elapsed();
            metrics.transaction_committed_latency.observe(latency);
            metrics.inter_block_latency_s.with_label_values(&["shared"]).observe(latency.as_secs_f64());
        }
        let path_type = if is_fpc { "fpc" } else { "c" };
        let tx_submission_timestamp = TransactionGenerator::extract_timestamp(transaction);
        let latency = current_timestamp.saturating_sub(tx_submission_timestamp);
        let square_latency = latency.as_secs_f64().powf(2.0);
        metrics.latency_s.with_label_values(&[path_type]).observe(latency.as_secs_f64());
        metrics.latency_squared_s.with_label_values(&[path_type]).inc_by(square_latency);
    }
}

pub trait LedgerWriter: Send + Sync {
    fn write_finalized_vote(&mut self, vote: TransactionLocator, block_store: &BlockStore, is_fpc: bool);
    fn write_finalized_block(&mut self, block: &Data<StatementBlock>, is_fpc: bool);
    fn is_vote_finalized(&self, vote: &TransactionLocator) -> bool;
}

pub struct CommitHandler {
    commit_interpreter: Linearizer,
    committee: Arc<Committee>,
    committed_leaders: Vec<BlockReference>,

    execution_sender: mpsc::Sender<ExecutionRequest>,

    finalized_cache_shim: HashSet<TransactionLocator>,
    enable_block_fpc: bool,
}

impl CommitHandler {
    pub fn new(
        committee: Arc<Committee>,
        execution_sender: mpsc::Sender<ExecutionRequest>, // Sender 주입
        node_public_config: &NodePublicConfig,
    ) -> Self {
        Self {
            commit_interpreter: Linearizer::new(),
            committee,
            committed_leaders: vec![],
            execution_sender,
            finalized_cache_shim: HashSet::new(),
            enable_block_fpc: node_public_config.parameters.enable_block_fpc,
        }
    }

    pub fn committed_leaders(&self) -> &Vec<BlockReference> {
        &self.committed_leaders
    }

    // Tally 등에서 호출
    pub fn get_all_finalized_locators(&self) -> Vec<TransactionLocator> {
        self.finalized_cache_shim.iter().cloned().collect()
    }
}

impl LedgerWriter for CommitHandler {
    fn write_finalized_vote(&mut self, vote: TransactionLocator, block_store: &BlockStore, is_fpc: bool) {
        // 1. 1차 중복 방지 (C-Path 로직 내 중복 호출 방지용, 가벼움)
        if !self.finalized_cache_shim.insert(vote) {
            return;
        }

        // 2. 트랜잭션 조회 (메모리)
        if let Some(transaction) = block_store.get_transaction(&vote) {
            let req = ExecutionRequest {
                locator: vote,
                transaction,
                is_fpc,
            };

            // 3. 실행 서비스로 전송 (Non-blocking, 즉시 리턴)
            if let Err(e) = self.execution_sender.try_send(req) {
                // 큐가 가득 찬 경우 (Backpressure)
                tracing::warn!("Execution queue full! Dropping vote execution: {:?}", e);
            }
        }
    }

    fn write_finalized_block(&mut self, block: &Data<StatementBlock>, is_fpc: bool) {
        // 블록 내의 모든 공유 트랜잭션을 순회
        for (locator, transaction) in block.shared_transactions() {
            // 1. 중복 체크 (메모리)
            if !self.finalized_cache_shim.insert(locator) {
                continue;
            }

            // 2. 트랜잭션 데이터는 이미 block 안에 있으므로 DB 조회 불필요!
            //    즉시 복제하여 전송
            let req = ExecutionRequest {
                locator,
                transaction: transaction.clone(), // 데이터 복사 (불가피하지만 I/O보다 훨씬 빠름)
                is_fpc,
            };

            // 3. 큐 전송
            if let Err(e) = self.execution_sender.try_send(req) {
                tracing::warn!("Execution queue full! {:?}", e);
            }
        }
    }

    fn is_vote_finalized(&self, vote: &TransactionLocator) -> bool {
        self.finalized_cache_shim.contains(vote)
    }
}

impl CommitObserver for CommitHandler {
    fn handle_commit(
        &mut self,
        block_store: &BlockStore,
        committed_leaders: Vec<Data<StatementBlock>>,
        transaction_aggregator: &HashMap<BlockReference, HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>>,
    ) -> Vec<CommittedSubDag> {
        // ... (기존 로직 유지) ...

        let committed = self.commit_interpreter.handle_commit(block_store, committed_leaders);
        let mut total_finalized_txs = 0;

        for commit in &committed {
            self.committed_leaders.push(commit.anchor);
            for block in &commit.blocks {
                if self.enable_block_fpc {
                    self.write_finalized_block(block, false); // is_fpc = false
                    // (정확한 카운팅을 위해선 range len을 더해야 하지만 성능상 생략 가능)
                    total_finalized_txs += block.shared_transactions().count();
                } else {
                    // Transaction Level FPC인 경우 기존 로직 유지 (낱개 체크 필요)
                    for (locator, _) in block.shared_transactions() {
                        if self.is_vote_finalized(&locator) { continue; }

                        // ... (쿼럼 체크) ...
                        if let Some(block_aggs) = transaction_aggregator.get(block.reference()) {
                            if let Some(agg) = block_aggs.get(&locator) {
                                if agg.is_quorum(&self.committee) {
                                    self.write_finalized_vote(locator, block_store, false);
                                    total_finalized_txs += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        if total_finalized_txs > 0 {
            tracing::info!("🏁 [C-PATH] Finalized {} transactions via Fallback.", total_finalized_txs);
        }

        committed
    }

    fn aggregator_state(&self) -> minibytes::Bytes {
        bincode::serialize(&self.commit_interpreter.committed).unwrap().into()
    }

    fn recover_committed(&mut self, committed_blocks: HashSet<BlockReference>, state: Option<minibytes::Bytes>) {
        // ... (기존 복구 로직 유지) ...
        // 실제 finalized_cache 복구는 DB에서 읽어와야 완벽하지만,
        // 벤치마크 시나리오에서는 비워두고 시작해도 무방합니다.
        if let Some(bytes) = state {
            if let Ok(c) = bincode::deserialize(&bytes) {
                self.commit_interpreter.committed = c;
            }
        }
    }
}
