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
use crate::metrics::Metrics;
use crate::runtime::TimeInstant;
use crate::syncer::CommitObserver;
use crate::types::{BlockReference, StatementBlock, TransactionLocator};

// ✅ 메시지 타입 확장
pub enum FpcMessage {
    ProcessBlock(Data<StatementBlock>), // FPC용 블록 처리 요청
    CommittedLeaders(Vec<Data<StatementBlock>>), // C-Path용 커밋된 리더 처리 요청
    GetLocators(oneshot::Sender<Vec<TransactionLocator>>),
}

pub struct FpcService {
    block_store: Arc<BlockStore>,
    committee: Arc<Committee>,
    // ✅ CommitHandler를 FpcService가 소유 (DB I/O 전담)
    commit_handler: CommitHandler,

    // ... (Aggregator 필드들 유지) ...
    transaction_aggregator: HashMap<BlockReference, HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>>,
    certificate_aggregator: HashMap<TransactionLocator, StakeAggregator<QuorumThreshold>>,
    block_aggregator: HashMap<BlockReference, HashMap<BlockReference, StakeAggregator<QuorumThreshold>>>,
    block_certificate_aggregator: HashMap<BlockReference, StakeAggregator<QuorumThreshold>>,

    block_level_fpc: bool,
    metrics: Arc<Metrics>,
    transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
    receiver: mpsc::Receiver<FpcMessage>,
}

impl FpcService {
    pub fn spawn(
        block_store: Arc<BlockStore>,
        committee: Arc<Committee>,
        commit_handler: CommitHandler, // 소유권 전달 받음
        metrics: Arc<Metrics>,
        transaction_time: Arc<Mutex<HashMap<TransactionLocator, TimeInstant>>>,
        block_level_fpc: bool,
    ) -> (mpsc::Sender<FpcMessage>, JoinHandle<()>) {
        let (sender, receiver) = mpsc::channel(200_000);

        let service = Self {
            block_store,
            committee,
            commit_handler,
            transaction_aggregator: HashMap::new(),
            certificate_aggregator: HashMap::new(),
            block_aggregator: HashMap::new(),
            block_certificate_aggregator: HashMap::new(),
            block_level_fpc,
            metrics,
            transaction_time,
            receiver,
        };

        let handle = tokio::spawn(async move {
            service.run().await;
        });

        (sender, handle)
    }

    async fn run(mut self) {
        tracing::info!("FpcService started.");
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                // 1. FPC 처리 (Fast Path)
                FpcMessage::ProcessBlock(block) => self.process_block_internal(block),

                // 2. C-Path 처리 (Fallback Path)
                FpcMessage::CommittedLeaders(leaders) => self.process_committed_leaders(leaders),
                FpcMessage::GetLocators(sender) => {
                    let locators = self.commit_handler.get_all_finalized_locators();
                    sender.send(locators).ok();
                }
            }
        }
    }

    fn process_block_internal(&mut self, block: Data<StatementBlock>) {
        // LedgerWriter로서 self.commit_handler를 전달
        let mut interpreter = FinalizationInterpreter::new(
            &self.block_store,
            self.committee.clone(),
            &mut self.commit_handler,
            &mut self.transaction_aggregator,
            &mut self.certificate_aggregator,
            &mut self.block_aggregator,
            &mut self.block_certificate_aggregator,
            self.block_level_fpc,
            self.metrics.clone(),
            self.transaction_time.clone(),
        );
        interpreter.process_block(&block);
    }

    // ✅ C-Path 처리 로직 (DB I/O 포함)
    fn process_committed_leaders(&mut self, committed_leaders: Vec<Data<StatementBlock>>) {
        // CommitHandler에게 위임 -> 내부적으로 Linearizer 실행 및 DB 쓰기(write_finalized_vote) 수행
        // FPC Aggregator 정보도 함께 넘겨주어 중복 처리를 방지할 수 있음
        self.commit_handler.handle_commit(
            &self.block_store,
            committed_leaders,
            &self.transaction_aggregator
        );
    }
}