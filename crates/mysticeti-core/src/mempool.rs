use std::cmp::min;
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::encryption::elgamal::Ciphertext;
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub};
use ark_groth16::VerifyingKey;
use ark_std::iterable::Iterable;
use libc::shutdown;
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::error;
use crypto::types::VoteTransaction;
use crate::config::{CryptoConfig, NodeParameters, NodePublicConfig};
use crate::crypto::AsBytes;
use crate::metrics::Metrics;
use crate::nullifier::NullifierDB;
use crate::types::Transaction;

pub struct Mempool {
    verified_pool: Arc<Mutex<VecDeque<Transaction>>>,
    metrics: Arc<Metrics>,
    nullifier_db: Arc<NullifierDB>,
    shutdown_signal: Arc<Notify>,
    crypto_config: CryptoConfig,
}

impl Mempool {
    pub fn new(
        metrics: Arc<Metrics>,
        nullifier_db: Arc<NullifierDB>,
        crypto_config: CryptoConfig,
    ) -> (Arc<Self>, mpsc::Sender<Vec<Transaction>>, JoinHandle<()>){

        let (sender, receiver) = mpsc::channel(1024);
        let verified_pool = Arc::new(Mutex::new(VecDeque::new()));
        let shutdown_signal = Arc::new(Notify::new()); // 🌟 Arc로 생성

        let mempool = Arc::new(Self {
            verified_pool: verified_pool.clone(),
            metrics,
            nullifier_db,
            shutdown_signal: shutdown_signal.clone(),
            crypto_config,
        });

        let handle = tokio::spawn(Self::dispatch_loop(receiver, Arc::downgrade(&mempool), shutdown_signal));
        (mempool, sender, handle)
    }

    async fn dispatch_loop(
        mut receiver: mpsc::Receiver<Vec<Transaction>>,
        mempool_weak: Weak<Self>, // 🌟 Weak<Self>로 받음
        shutdown_signal: Arc<Notify>,
    ) {
        tracing::info!("Mempool dispatch loop started.");

        let (merkle_root, verifying_key, num_candidates) = {
            let mempool = mempool_weak.upgrade().expect("Mempool dropped before dispatch loop started");
            let merkle_root = Arc::new(Fr::from_str(&mempool.crypto_config.merkle_root.clone()).unwrap());
            let verifying_key = Arc::new(mempool.crypto_config.verifying_key.clone());
            let num_candidates = mempool.crypto_config.num_candidates;
            (merkle_root, verifying_key, num_candidates)
        };

        // 🌟 제안 #8: 동시 검증 작업을 제한하기 위한 세마포어
        let num_cpus = num_cpus::get();
        let semaphore = Arc::new(Semaphore::new(num_cpus));
        tracing::info!("Mempool: Merkle 루트 및 VK 로드 완료. 동시 검증 수: {}", num_cpus);

        loop {
            let Some(mempool) = mempool_weak.upgrade() else {
                tracing::info!("Mempool was dropped, dispatch loop shutting down.");
                break;
            };

            tokio::select! {
                _ = shutdown_signal.notified() => {
                    tracing::info!("Mempool dispatch loop received shutdown signal.");
                    break;
                }

                maybe_batch = receiver.recv() => {
                    match maybe_batch {
                        Some(batch) => {
                            let batch_size = batch.len() as i64;
                            // 🌟 제안 #6: Unverified 카운터는 "받은 시점"에 증가
                            mempool.metrics.mempool_unverified_transactions.add(batch_size);
                            mempool.metrics
                                .mempool_transactions_processed_total
                                .with_label_values(&["received"])
                                .inc_by(batch_size as u64);

                            // 🌟 제안 #1: JoinSet 생성
                            let mut join_set = JoinSet::new();

                            // Arc들을 루프 밖에서 클론
                            let verified_pool_arc = mempool.verified_pool.clone();
                            let metrics_arc = mempool.metrics.clone();
                            let nullifier_db_arc = mempool.nullifier_db.clone();
                            let vk_arc = verifying_key.clone();
                            let root_arc = merkle_root.clone();

                            for tx in batch {
                                // 🌟 제안 #8: 세마포어 퍼밋 획득
                                let permit = semaphore.clone().acquire_owned().await.unwrap();

                                // 태스크에 필요한 Arc들 클론
                                let metrics = metrics_arc.clone();
                                let nullifier_db = nullifier_db_arc.clone();
                                let verifying_key = vk_arc.clone();
                                let merkle_root = root_arc.clone();

                                // 🌟 제안 #2: spawn_blocking을 JoinSet에 직접 추가
                                join_set.spawn_blocking(move || {
                                    let _permit = permit; // 🌟 퍼밋이 태스크 종료 시 자동 해제됨
                                    let result = verify(
                                        &tx,
                                        nullifier_db,
                                        num_candidates,
                                        verifying_key,
                                        merkle_root,
                                        metrics,
                                    );
                                    (tx, result) // 🌟 원본 tx와 결과 반환
                                });
                            }

                            let flush_threshold = num_cpus;
                            let mut verified_batch = Vec::new();
                            while let Some(join_result) = join_set.join_next().await {
                                metrics_arc.mempool_unverified_transactions.sub(1);

                                match join_result {
                                    Ok((tx, Ok(()))) => {
                                        verified_batch.push(tx); // 🌟 제안 #3: 로컬 버퍼에 추가
                                        if verified_batch.len() >= flush_threshold {
                                            // ✅ CPU 코어 수만큼 모였으니 한 번 flush
                                            let mut pool = verified_pool_arc.lock().await;
                                            pool.extend(verified_batch.drain(..));
                                            metrics_arc
                                                .mempool_verified_transactions
                                                .set(pool.len() as i64);
                                        }
                                    }
                                    Ok((_tx, Err(rejection_reason))) => {
                                        metrics_arc.mempool_transactions_processed_total
                                            .with_label_values(&[rejection_reason])
                                            .inc();
                                    }
                                    Err(join_error) => {
                                        // 태스크 패닉
                                        error!("Verify task panicked: {:?}", join_error);
                                        metrics_arc.mempool_transactions_processed_total
                                            .with_label_values(&["rejected_panic"])
                                            .inc();
                                    }
                                }
                            }

                            if !verified_batch.is_empty() {
                                let mut pool = verified_pool_arc.lock().await;
                                pool.extend(verified_batch);
                                metrics_arc.mempool_verified_transactions.set(pool.len() as i64);
                            }
                        }
                        None => {
                            tracing::info!("Mempool dispatch loop shutting down (channel closed).");
                            break;
                        }
                    }
                }
            }
        }
        tracing::info!("Mempool dispatch loop stopped.");
    }

    /// `BlockHandler` (동기 컨텍스트)에서 호출하는 함수.
    pub fn get_verified_transactions(&self, max_size: usize) -> Vec<Transaction> {
        let mut pool = self.verified_pool.blocking_lock();
        if pool.is_empty() {
            return Vec::new();
        }
        let count = min(max_size, pool.len());
        let batch: Vec<Transaction> = pool.drain(..count).collect();
        batch
    }

    /// `Validator` 종료 시 호출
    pub async fn shutdown(self, handle: JoinHandle<()>) {
        self.shutdown_signal.notify_one();
        if let Err(e) = handle.await {
            tracing::warn!("Mempool dispatch task panicked or was cancelled: {:?}", e);
        }
        tracing::info!("Mempool shut down complete.");
    }
}


fn verify(
    tx: &Transaction,
    nullifier_db: Arc<NullifierDB>,
    num_candidates: usize,
    verifying_key: Arc<VerifyingKey<Bls12_381>>,
    merkle_root: Arc<Fr>,
    metrics: Arc<Metrics>,
) -> Result<(), &'static str> {
    let instant = Instant::now();
    let vote_tx: VoteTransaction = match tx.get_vote() {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!("Transaction deserialize failed, dropping: {e}");
            return Err("rejected_deserialize");
        }
    };
    if vote_tx.enc_vote_vec.len() != num_candidates {
        tracing::warn!(
            "Invalid candidate count in ZK proof (expected {}, got {}), dropping tx: {:?}",
            num_candidates,
            vote_tx.enc_vote_vec.len(),
            vote_tx.nullifier
        );
        return Err("rejected_zk_candidates");
    }

    let verification_result = crypto::zkp::verify(
        &verifying_key,
        &vote_tx.proof,
        &vote_tx.enc_vote_vec,
        *merkle_root,
        vote_tx.nullifier
    );

    match verification_result {
        Ok(true) => {
            match nullifier_db.verify(vote_tx.nullifier) {
                Ok(true) => {
                    metrics.mempool_transactions_processed_total.with_label_values(&["verified"]).inc();
                    Ok(())
                }
                Ok(false) => {
                    tracing::warn!("Duplicate nullifier (already Locked or Commit), dropping tx: {:?}", vote_tx.nullifier);
                    Err("rejected_nullifier_duplicate")
                }
                Err(e) => {
                    tracing::error!("Nullifier DB transaction error: {e}, dropping tx: {:?}", vote_tx.nullifier);
                    Err("rejected_db_error")
                }
            }
        }
        Ok(false) => {
            tracing::warn!("Invalid ZK proof, dropping tx: {:?}", vote_tx.nullifier);
            Err("rejected_zk_invalid_proof")
        }
        Err(e) => {
            tracing::error!("ZK proof verification error: {e}, dropping tx: {:?}", vote_tx.nullifier);
            Err("rejected_zk_verification_error")
        }
    }
}




