use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::block_handler::CommitHandler;
use crate::block_store::BlockStore;
use crate::committee::{Committee, QuorumThreshold, StakeAggregator};
use crate::data::Data;
use crate::finalization_interpreter::FinalizationInterpreter;
use crate::metrics::{Metrics, UtilizationTimerExt};
use crate::syncer::CommitObserver;
use crate::types::{BlockReference, StatementBlock, TransactionLocator};

/// FPC 서비스와 통신하기 위한 클라이언트
/// 메시지 유형별로 채널을 분리하여 우선순위 처리를 보장합니다.
#[derive(Clone)]
pub struct FpcClient {
    block_sender: mpsc::Sender<Data<StatementBlock>>,
    commit_sender: mpsc::Sender<Vec<Data<StatementBlock>>>,
    locators_sender: mpsc::Sender<oneshot::Sender<Vec<TransactionLocator>>>,
    metrics: Arc<Metrics>, // 🌟 추가됨
}

impl FpcClient {
    pub async fn send_block(&self, block: Data<StatementBlock>) {
        self.metrics.fpc_block_enqueued.inc();
        if let Err(e) = self.block_sender.send(block).await {
            tracing::warn!("Failed to send block to FPC service: {:?}", e);
        }
    }

    pub async fn send_committed_leaders(&self, leaders: Vec<Data<StatementBlock>>) {
        self.metrics.fpc_commit_enqueued.inc();
        if let Err(e) = self.commit_sender.send(leaders).await {
            tracing::error!("Failed to send committed leaders to FPC service: {:?}", e);
        }
    }

    pub async fn get_locators(&self) -> Vec<TransactionLocator> {
        let (tx, rx) = oneshot::channel();
        if self.locators_sender.send(tx).await.is_ok() {
            rx.await.unwrap_or_default()
        } else {
            vec![]
        }
    }
}

/// 내부 상태를 공유하기 위한 구조체 (Mutex로 보호됨)
struct FpcState {
    transaction_aggregator: HashMap<BlockReference, HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>>,
    certificate_aggregator: HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
    block_aggregator: HashMap<BlockReference, HashMap<BlockReference, StakeAggregator<QuorumThreshold>>>,
    block_certificate_aggregator: HashMap<BlockReference, StakeAggregator<QuorumThreshold>>,
    commit_handler: CommitHandler,

    blocks_by_round: HashMap<u64, Vec<BlockReference>>,
    highest_known_round: u64,
}

pub struct FpcService {
    // Thread-safe Shared State
    state: Arc<Mutex<FpcState>>,

    block_store: Arc<BlockStore>,
    committee: Arc<Committee>,
    metrics: Arc<Metrics>,
    block_level_fpc: bool,
}

impl FpcService {
    pub fn spawn(
        block_store: Arc<BlockStore>,
        committee: Arc<Committee>,
        commit_handler: CommitHandler,
        metrics: Arc<Metrics>,
        block_level_fpc: bool,
    ) -> (FpcClient, Vec<JoinHandle<()>>) {
        // 1. 큐 분리: 각 처리 목적에 맞는 전용 채널 생성
        // [Low Priority] FPC Block Processing (대용량)
        let (block_tx, mut block_rx) = mpsc::channel(200_000);
        // [High Priority] C-Path Commit Processing (소용량, 즉시 처리 필요)
        let (commit_tx, mut commit_rx) = mpsc::channel(10_000);
        // [Query] 조회용
        let (locators_tx, mut locators_rx) =
            mpsc::channel::<oneshot::Sender<Vec<TransactionLocator>>>(100);
        let state = Arc::new(Mutex::new(FpcState {
            transaction_aggregator: HashMap::new(),
            certificate_aggregator: HashMap::new(),
            block_aggregator: HashMap::new(),
            block_certificate_aggregator: HashMap::new(),
            commit_handler,
            blocks_by_round: HashMap::new(),
            highest_known_round: 0,
        }));

        let service = Self {
            state,
            block_store,
            committee,
            metrics: metrics.clone(),
            block_level_fpc,
        };

        tracing::info!("🚀 [FpcService] Spawning separate tasks for parallel processing...");

        let mut handles = Vec::new();

        // 2. Task 1: FPC Block Processor
        // 블록 큐만 전담하여 처리
        let s1 = service.clone();
        handles.push(tokio::spawn(async move {
            tracing::info!("✅ [FpcService] Block Processor task started.");
            while let Some(block) = block_rx.recv().await {
                // 🌟 [적용] Dequeue 및 Utilization 측정
                s1.metrics.fpc_block_dequeued.inc();
                // 이 타이머(_timer)는 process_block_internal이 끝나고
                // 루프의 이터레이션이 끝날 때 drop되면서 시간을 기록합니다.
                let _timer = s1.metrics.fpc_block_util.utilization_timer();

                s1.process_block_internal(block);
            }
            tracing::warn!("⚠️ [FpcService] Block Processor task stopped.");
        }));

        // 3. Task 2: Commit Processor (C-Path)
        // 커밋 큐만 전담하여 처리 (블록 큐가 밀려도 영향받지 않음)
        let s2 = service.clone();
        handles.push(tokio::spawn(async move {
            tracing::info!("✅ [FpcService] Commit Processor task started.");
            while let Some(leaders) = commit_rx.recv().await {
                // 🌟 [적용] Dequeue 및 Utilization 측정
                s2.metrics.fpc_commit_dequeued.inc();
                let _timer = s2.metrics.fpc_commit_util.utilization_timer();

                s2.process_committed_leaders(leaders);
            }
            tracing::warn!("⚠️ [FpcService] Commit Processor task stopped.");
        }));

        // 4. Task 3: Query Processor
        let s3 = service.clone();
        handles.push(tokio::spawn(async move {
            while let Some(sender) = locators_rx.recv().await {
                let locators = s3.state.lock().commit_handler.get_all_finalized_locators();
                sender.send(locators).ok();
            }
        }));

        let client = FpcClient {
            block_sender: block_tx,
            commit_sender: commit_tx,
            locators_sender: locators_tx,
            metrics
        };

        (client, handles)
    }

    // Arc Clone Helper
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            block_store: self.block_store.clone(),
            committee: self.committee.clone(),
            metrics: self.metrics.clone(),
            block_level_fpc: self.block_level_fpc,
        }
    }

    fn process_block_internal(&self, block: Data<StatementBlock>) {
        tracing::info!("process block internal");
        // 🔒 Mutex 획득
        let mut guard = self.state.lock();

        // 🌟 [핵심 수정] Guard를 'SharedState' 구조체에 대한 가변 참조로 변환
        // 이렇게 하면 컴파일러가 "구조체의 서로 다른 필드를 빌리는구나"라고 인식하여 허용해줍니다.
        let state = &mut *guard;

        let mut interpreter = FinalizationInterpreter::new(
            &self.block_store,
            self.committee.clone(),

            // 이제 guard 대신 state를 사용합니다.
            &mut state.commit_handler,
            &mut state.transaction_aggregator,
            &mut state.certificate_aggregator,
            &mut state.block_aggregator,
            &mut state.block_certificate_aggregator,

            // GC 상태
            &mut state.blocks_by_round,
            &mut state.highest_known_round,

            self.block_level_fpc,
            self.metrics.clone(),
        );
        interpreter.process_block(&block);
    }

    fn process_committed_leaders(&self, committed_leaders: Vec<Data<StatementBlock>>) {
        // 🔒 Mutex 획득
        let mut guard = self.state.lock();

        // 🌟 [수정됨] FPC의 Aggregator를 사용하지 않으므로 빈 맵을 생성하여 전달
        // 이렇게 하면 handle_commit 내부에서 FPC 관련 로직(전략 2)은 항상 '정보 없음'으로 처리되지만,
        // C-Path의 커밋 확정 로직은 정상 동작합니다.
        let empty_aggregator = HashMap::new();

        guard.commit_handler.handle_commit(
            &self.block_store,
            committed_leaders,
            &empty_aggregator // FPC 상태 의존성 제거
        );
    }
}
