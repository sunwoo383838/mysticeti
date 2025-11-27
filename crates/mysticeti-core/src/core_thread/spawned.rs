// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, sync::Arc, thread};
use ark_ed_on_bls12_381::Fr;
use tokio::sync::{mpsc, oneshot};

use crate::{
    block_handler::BlockHandler,
    data::Data,
    metrics::{Metrics, UtilizationTimerExt},
    // -----------------------------------------------------------------
    // ❌ C: CommitObserver 제네릭이 Syncer에서 제거됨
    // -----------------------------------------------------------------
    syncer::{CommitObserver, Syncer, SyncerSignals},
    types::{AuthorityIndex, BlockReference, RoundNumber, StatementBlock},
};
use crate::types::{Transaction, TransactionLocator};

// ❌ C 제거
pub struct CoreThreadDispatcher<H: BlockHandler, S: SyncerSignals> {
    sender: mpsc::Sender<CoreThreadCommand>,
    // ❌ C 제거
    join_handle: thread::JoinHandle<Syncer<H, S>>,
    metrics: Arc<Metrics>,
}

// ❌ C 제거
pub struct CoreThread<H: BlockHandler, S: SyncerSignals> {
    // ❌ C 제거
    syncer: Syncer<H, S>,
    receiver: mpsc::Receiver<CoreThreadCommand>,
}

enum CoreThreadCommand {
    AddBlocks(Vec<(Data<StatementBlock>, bool)>, oneshot::Sender<()>),
    ForceNewBlock(RoundNumber, oneshot::Sender<()>),
    Cleanup(oneshot::Sender<()>),
    /// Request missing blocks that need to be synched.
    GetMissing(oneshot::Sender<Vec<HashSet<BlockReference>>>),
    /// Indicate that a connection to an authority was established.
    ConnectionEstablished(AuthorityIndex, oneshot::Sender<()>),
    /// Indicate that a connection to an authority was dropped.
    ConnectionDropped(AuthorityIndex, oneshot::Sender<()>),
    TriggerEpochChangeBegun(oneshot::Sender<()>), // Orchestrator가 호출
    GetAllCommittedTxLocators(oneshot::Sender<Vec<TransactionLocator>>), // Tally 로직이 호출
    GetTransactions(Vec<TransactionLocator>, oneshot::Sender<Vec<Transaction>>), // Tally 로직이 호출
    GetMySecretShare(oneshot::Sender<Option<Fr>>),
}

// -----------------------------------------------------------------
// ❌ C: CommitObserver 제네릭 제거
// -----------------------------------------------------------------
impl<H: BlockHandler + 'static, S: SyncerSignals + 'static>
CoreThreadDispatcher<H, S>
{
    // ❌ C 제거
    pub fn start(syncer: Syncer<H, S>) -> Self {
        let (sender, receiver) = mpsc::channel(32);
        let metrics = syncer.core().metrics.clone();
        let core_thread = CoreThread { syncer, receiver };
        let join_handle = thread::Builder::new()
            .name("mysticeti-core".to_string())
            .spawn(move || core_thread.run())
            .unwrap();
        Self {
            sender,
            join_handle,
            metrics,
        }
    }

    // ❌ C 제거
    pub fn stop(self) -> Syncer<H, S> {
        drop(self.sender);
        self.join_handle.join().unwrap()
    }

    pub async fn add_blocks(&self, blocks: Vec<(Data<StatementBlock>, bool)>) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::AddBlocks(blocks, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop");
    }

    pub async fn force_new_block(&self, round: RoundNumber) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::ForceNewBlock(round, sender))
            .await;
        receiver.await.expect("core thread is not expected to stop");
    }

    pub async fn cleanup(&self) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::Cleanup(sender)).await;
        receiver.await.expect("core thread is not expected to stop");
    }

    pub async fn trigger_epoch_change_begun(&self) {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::TriggerEpochChangeBegun(sender)).await;
        receiver.await.expect("core thread stopped")
    }

    pub async fn get_all_committed_tx_locators(&self) -> Vec<TransactionLocator> {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::GetAllCommittedTxLocators(sender)).await;
        receiver.await.expect("core thread stopped")
    }

    // ❗ net_sync.rs의 Tally 로직이 호출할 함수
    pub async fn get_transactions(&self, locators: Vec<TransactionLocator>) -> Vec<Transaction> {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::GetTransactions(locators, sender)).await;
        receiver.await.expect("core thread stopped")
    }

    // ❗ net_sync.rs의 Tally 로직이 호출할 함수
    pub async fn get_my_secret_share(&self) -> Option<Fr> {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::GetMySecretShare(sender)).await;
        receiver.await.expect("core thread stopped")
    }

    pub async fn get_missing_blocks(&self) -> Vec<HashSet<BlockReference>> {
        let (sender, receiver) = oneshot::channel();
        self.send(CoreThreadCommand::GetMissing(sender)).await;
        receiver.await.expect("core thread is not expected to stop")
    }

    /// Update the syncer with the connection status of an authority. This function must be called
    /// whenever a connection to an authority is established or dropped.
    pub async fn authority_connection(&self, authority: AuthorityIndex, connected: bool) {
        let (sender, receiver) = oneshot::channel();
        let status = if connected {
            CoreThreadCommand::ConnectionEstablished(authority, sender)
        } else {
            CoreThreadCommand::ConnectionDropped(authority, sender)
        };
        self.send(status).await;
        receiver.await.expect("core thread is not expected to stop")
    }

    async fn send(&self, command: CoreThreadCommand) {
        self.metrics.core_lock_enqueued.inc();
        if self.sender.send(command).await.is_err() {
            panic!("core thread is not expected to stop");
        }
    }
}

// -----------------------------------------------------------------
// ❌ C: CommitObserver 제네릭 제거
// -----------------------------------------------------------------
impl<H: BlockHandler, S: SyncerSignals> CoreThread<H, S> {
    // ❌ C 제거
    pub fn run(mut self) -> Syncer<H, S> {
        tracing::info!("Started core thread with tid {}", gettid::gettid());
        let metrics = self.syncer.core().metrics.clone();
        while let Some(command) = self.receiver.blocking_recv() {
            let _timer = metrics.core_lock_util.utilization_timer();
            metrics.core_lock_dequeued.inc();
            match command {
                CoreThreadCommand::AddBlocks(blocks, sender) => {
                    self.syncer.add_blocks(blocks);
                    sender.send(()).ok();
                }
                CoreThreadCommand::ForceNewBlock(round, sender) => {
                    self.syncer.force_new_block(round);
                    sender.send(()).ok();
                }
                CoreThreadCommand::Cleanup(sender) => {
                    self.syncer.core().cleanup();
                    sender.send(()).ok();
                }
                CoreThreadCommand::GetMissing(sender) => {
                    let missing = self.syncer.core().block_manager().missing_blocks();
                    sender.send(missing.to_vec()).ok();
                }
                CoreThreadCommand::ConnectionEstablished(authority, sender) => {
                    self.syncer.connected_authorities.insert(authority);
                    sender.send(()).ok();
                }
                CoreThreadCommand::ConnectionDropped(authority, sender) => {
                    self.syncer.connected_authorities.remove(&authority);
                    sender.send(()).ok();
                }
                CoreThreadCommand::TriggerEpochChangeBegun(sender) => {
                    self.syncer.core_mut().epoch_manager_mut().epoch_change_begun();
                    sender.send(()).ok();
                }
                CoreThreadCommand::GetAllCommittedTxLocators(sender) => {
                    // ❗ `Core`의 `commit_handler()` getter (1단계에서 추가) 호출
                    let locators = self.syncer.core().commit_handler().get_all_finalized_locators(); // ❗ 이 함수는 CommitHandler에 구현 필요
                    sender.send(locators).ok();
                }
                CoreThreadCommand::GetTransactions(locators, sender) => {
                    let block_store = self.syncer.core().block_store();
                    let txs = locators.iter()
                        .filter_map(|loc| block_store.get_transaction(loc))
                        .collect();
                    sender.send(txs).ok();
                }
                CoreThreadCommand::GetMySecretShare(sender) => {
                    // ❗ `Core::get_my_secret_share()`는 async이므로 block_on 사용
                    let share = futures::executor::block_on(
                        self.syncer.core().get_my_secret_share()
                    );
                    sender.send(share).ok();
                }
            }
        }
        self.syncer
    }
}