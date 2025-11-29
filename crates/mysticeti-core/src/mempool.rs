use std::cmp::min;
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::Duration;
use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::encryption::elgamal::Ciphertext;
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub};
use ark_groth16::VerifyingKey;
use ark_std::iterable::Iterable;
use libc::shutdown;
use rayon::prelude::*;
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::error;
use crypto::types::VoteTransaction;
use crate::config::{CryptoConfig, NodeParameters, NodePublicConfig};
use crate::crypto::AsBytes;
use crate::metrics::Metrics;
use crate::nullifier::NullifierDB;
use crate::runtime::timestamp_utc;
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
    ) -> (Arc<Self>, mpsc::Sender<Vec<Transaction>>){

        let (sender, receiver) = mpsc::channel(1024);
        let verified_pool = Arc::new(Mutex::new(VecDeque::new()));
        let shutdown_signal = Arc::new(Notify::new());

        let mempool = Arc::new(Self {
            verified_pool: verified_pool.clone(),
            metrics,
            nullifier_db,
            shutdown_signal: shutdown_signal.clone(),
            crypto_config,
        });

        let mempool_weak = Arc::downgrade(&mempool);
        tokio::task::spawn_blocking(move || {
            Self::dispatch_loop_blocking(receiver, mempool_weak, shutdown_signal)
        });
        (mempool, sender)
    }

    fn dispatch_loop_blocking(
        mut receiver: mpsc::Receiver<Vec<Transaction>>,
        mempool_weak: Weak<Self>,
        shutdown_signal: Arc<Notify>,
    ) {
        tracing::info!("Mempool blocking dispatch loop started.");

        // (초기화 로직 동일)
        let (merkle_root, verifying_key, num_candidates) = {
            let mempool = mempool_weak.upgrade().expect("Mempool dropped...");
            let merkle_root = Arc::new(Fr::from_str(&mempool.crypto_config.merkle_root.clone()).unwrap());
            let verifying_key = Arc::new(mempool.crypto_config.verifying_key.clone());
            let num_candidates = mempool.crypto_config.num_candidates;
            (merkle_root, verifying_key, num_candidates)
        };

        loop {
            let Some(mempool) = mempool_weak.upgrade() else {
                tracing::info!("Mempool dropped, loop shutting down.");
                break;
            };

            let batch = match receiver.blocking_recv() {
                Some(b) => b,
                None => {
                    tracing::info!("Mempool channel closed.");
                    break;
                }
            };

            let batch_size = batch.len();
            if batch_size == 0 { continue; }

            mempool.metrics.mempool_unverified_transactions.add(batch_size as i64);
            mempool.metrics
                .mempool_transactions_processed_total
                .with_label_values(&["received"])
                .inc_by(batch_size as u64);

            let verified_results: Vec<(Transaction, Result<(), &'static str>)> = batch
                .into_par_iter() // Rayon Parallel Iterator
                .map(|tx| {
                    let now = timestamp_utc();
                    let tx_timestamp = Duration::from_millis(tx.timestamp);
                    let queue_latency = now.saturating_sub(tx_timestamp);
                    let square_latency = queue_latency.as_secs_f64().powf(2.0);
                    mempool.metrics.latency_breakdown
                        .with_label_values(&["1_queue"])
                        .observe(queue_latency.as_secs_f64());
                    mempool.metrics.latency_breakdown_squared_s
                        .with_label_values(&["1_queue"])
                        .inc_by(square_latency);

                    let verify_start = Instant::now();

                    let res = verify(
                        &tx,
                        mempool.nullifier_db.clone(), // Arc clone은 비용 저렴
                        num_candidates,
                        verifying_key.clone(),
                        merkle_root.clone(),
                        mempool.metrics.clone(),
                    );

                    let verify_duration = verify_start.elapsed();
                    let square_verify_latency = verify_duration.as_secs_f64().powf(2.0);
                    mempool.metrics.latency_breakdown
                        .with_label_values(&["2_verify"])
                        .observe(verify_duration.as_secs_f64());
                    mempool.metrics.latency_breakdown_squared_s
                        .with_label_values(&["2_verify"])
                        .inc_by(square_verify_latency);

                    (tx, res)
                })
                .collect();

            // 4. 결과 취합 및 저장
            let mut verified_txs = Vec::with_capacity(batch_size);
            for (tx, result) in verified_results {
                match result {
                    Ok(_) => verified_txs.push(tx),
                    Err(e) => {
                        // 실패 메트릭 기록
                        mempool.metrics.mempool_transactions_processed_total
                            .with_label_values(&[e])
                            .inc();
                    }
                }
            }

            if !verified_txs.is_empty() {
                // blocking_lock() 사용 (tokio::sync::Mutex는 blocking_lock 지원)
                let mut pool = mempool.verified_pool.blocking_lock();
                pool.extend(verified_txs);
                mempool.metrics.mempool_verified_transactions.set(pool.len() as i64);
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

    pub fn verify_transactions(&self, txs: &[&Transaction]) -> Vec<bool> {
        if txs.is_empty() {
            return vec![];
        }

        // 1. 검증에 필요한 무거운 리소스를 '한 번만' 준비합니다.
        let merkle_root = Arc::new(
            Fr::from_str(&self.crypto_config.merkle_root)
                .expect("Failed to parse merkle root")
        );
        let verifying_key = Arc::new(self.crypto_config.verifying_key.clone());
        let num_candidates = self.crypto_config.num_candidates;

        let metrics_arc = self.metrics.clone();
        let nullifier_db_arc = self.nullifier_db.clone();

        // 2. Rayon을 사용하여 병렬 검증 수행 🚀
        txs.par_iter()
            .map(|tx| {
                verify(
                    tx,
                    nullifier_db_arc.clone(), // verify 함수 시그니처에 맞춰 &NullifierDB 또는 Arc 전달
                    num_candidates,
                    verifying_key.clone(),
                    merkle_root.clone(),
                    metrics_arc.clone(),
                ).is_ok()
            })
            .collect()
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




