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
use crate::mempool::Mempool;
use crate::nullifier::NullifierDB;

pub trait BlockHandler: Send + Sync {
    fn handle_blocks(
        &mut self,
        blocks: &[Data<StatementBlock>],
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
    pub transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
    committee: Arc<Committee>,
    authority: AuthorityIndex,
    block_store: BlockStore,
    metrics: Arc<Metrics>,
    mempool: Arc<Mempool>,
    pending_transactions: usize,
    consensus_only: bool,
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
        }
    }
}

impl RealBlockHandler {

    /// Expose a metric for certified transactions.
    fn update_metrics(
        &self,
        block_creation: Option<&TimeInstant>,
        transaction: &Transaction,
        current_timestamp: &Duration,
    ) {
        // Record inter-block latency.
        if let Some(instant) = block_creation {
            let latency = instant.elapsed();
            self.metrics.transaction_certified_latency.observe(latency);
            self.metrics
                .inter_block_latency_s
                .with_label_values(&["owned"])
                .observe(latency.as_secs_f64());
        }

        // Record end-to-end latency.
        let tx_submission_timestamp = TransactionGenerator::extract_timestamp(transaction);
        let latency = current_timestamp.saturating_sub(tx_submission_timestamp);
        let square_latency = latency.as_secs_f64().powf(2.0);
        self.metrics
            .latency_s
            .with_label_values(&["owned"])
            .observe(latency.as_secs_f64());
        self.metrics
            .latency_squared_s
            .with_label_values(&["owned"])
            .inc_by(square_latency);
    }
}

impl BlockHandler for RealBlockHandler {
    fn handle_blocks(
        &mut self,
        blocks: &[Data<StatementBlock>],
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
                let new_txs = self.mempool.get_verified_transactions(available_capacity);
                self.pending_transactions += new_txs.len();
                for tx in new_txs {
                    response.push(BaseStatement::Share(tx));
                }
            }
        }
        let transaction_time = self.transaction_time.lock();
        for block in blocks {
            let response_option: Option<&mut Vec<BaseStatement>> = if require_response {
                Some(&mut response)
            } else {
                None
            };
            if !self.consensus_only {
                let processed =
                    self.transaction_votes
                        .process_block(block, response_option, &self.committee);
                for processed_locator in processed {
                    let block_creation = transaction_time.get(&processed_locator);
                    let transaction = self
                        .block_store
                        .get_transaction(&processed_locator)
                        .expect("Failed to get certified transaction");
                    self.update_metrics(block_creation, &transaction, &current_timestamp);
                }
            }
        }
        self.metrics
            .block_handler_pending_certificates
            .set(self.transaction_votes.len() as i64);
        response
    }

    fn handle_proposal(&mut self, block: &Data<StatementBlock>) {
        // todo - this is not super efficient
        self.pending_transactions -= block.shared_transactions().count();
        let mut transaction_time = self.transaction_time.lock();
        for (locator, _) in block.shared_transactions() {
            transaction_time.insert(locator, TimeInstant::now());
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
        blocks: &[Data<StatementBlock>],
        require_response: bool,
    ) -> Vec<BaseStatement> {
        // todo - this is ugly, but right now we need a way to recover self.last_transaction
        let mut response = vec![];
        if require_response {
            for block in blocks {
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
        for block in blocks {
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

    fn recover_state(&mut self, state: &Bytes) {
        let (transaction_votes, last_transaction) = bincode::deserialize(state)
            .expect("Failed to deserialize transaction aggregator state");
        self.transaction_votes.with_state(&transaction_votes);
        self.last_transaction = last_transaction;
    }
}

pub trait LedgerWriter: Send + Sync {
    fn write_finalized_vote(&mut self, vote: TransactionLocator, block_store: &BlockStore);
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
    ) {
        // Record inter-block latency.
        if let Some(instant) = block_creation {
            let latency = instant.elapsed();
            // FPC로 최종화되었는지, C-Path로 최종화되었는지 확인
            // (여기서는 block_creation 시간을 기준으로 대략적으로 구분)
            // TODO: FPC/C-Path를 명확히 구분하여 메트릭을 기록하려면
            // write_finalized_vote에 'is_fpc: bool' 플래그를 추가해야 합니다.
            self.metrics.transaction_committed_latency.observe(latency);
            self.metrics
                .inter_block_latency_s
                .with_label_values(&["shared"])
                .observe(latency.as_secs_f64());
        }

        // Record benchmark start time.
        let time_from_start = self.start_time.elapsed();
        let benchmark_duration = self.metrics.benchmark_duration.get();
        if let Some(delta) = time_from_start.as_secs().checked_sub(benchmark_duration) {
            self.metrics.benchmark_duration.inc_by(delta);
        }

        // Record end-to-end latency. The first 8 bytes of the transaction are the timestamp of the
        // transaction submission.
        let tx_submission_timestamp = TransactionGenerator::extract_timestamp(transaction);
        let latency = current_timestamp.saturating_sub(tx_submission_timestamp);
        let square_latency = latency.as_secs_f64().powf(2.0);
        self.metrics
            .latency_s
            .with_label_values(&["shared"])
            .observe(latency.as_secs_f64());
        self.metrics
            .latency_squared_s
            .with_label_values(&["shared"])
            .inc_by(square_latency);
    }
}

impl LedgerWriter for CommitHandler {
    fn write_finalized_vote(&mut self, vote: TransactionLocator, block_store: &BlockStore) {
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
    ) -> Vec<CommittedSubDag> {

        // C-Path가 순서 매긴 블록 목록을 가져옴
        let committed = self
            .commit_interpreter
            .handle_commit(block_store, committed_leaders);

        for commit in &committed {
            self.committed_leaders.push(commit.anchor);
            for block in &commit.blocks {

                // FPC 모드일 때의 'transaction_votes.process_block' 로직은 여기서 제거됨
                // (if !self.consensus_only { ... } 부분 제거)

                // C-Path로 확정된 모든 트랜잭션을 순회
                for (locator, _transaction) in block.shared_transactions() {

                    // C-Path Fallback: FPC가 이 트랜잭션을 놓쳤는지 확인
                    if !self.is_vote_finalized(&locator) {
                        // FPC가 놓쳤으므로 C-Path가 구제
                        tracing::warn!("C-PATH FALLBACK: Finalizing transaction {}", locator);

                        // LedgerWriter::write_finalized_vote 호출
                        // (이 함수가 장부/DB/메트릭을 모두 처리)
                        self.write_finalized_vote(locator, block_store);
                    }

                    // E2E 메트릭은 write_finalized_vote 내부에서 처리되므로
                    // 여기서 update_metrics를 중복 호출할 필요가 없음.
                }
            }
        }

        // FPC Aggregator가 제거되었으므로 관련 메트릭도 제거
        // self.metrics
        //     .commit_handler_pending_certificates
        //     .set(self.transaction_votes.len() as i64);

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