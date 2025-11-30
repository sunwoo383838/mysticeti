use std::{cmp::min, sync::Arc, time::Duration};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use eyre::Context;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rayon::prelude::*;
use tokio::sync::{mpsc, oneshot}; // oneshot 추가
use crypto::types::VoteTransaction;
use crate::{
    config::{ClientParameters, NodePublicConfig},
    crypto::AsBytes,
    metrics::Metrics,
    runtime::{self, timestamp_utc},
    types::{AuthorityIndex, Transaction},
};

pub struct TransactionGenerator {
    sender: mpsc::Sender<Vec<Transaction>>,
    transactions: VecDeque<Transaction>,
    client_parameters: ClientParameters,
    metrics: Arc<Metrics>,
}

impl TransactionGenerator {
    const TARGET_BLOCK_INTERVAL: Duration = Duration::from_millis(100);

    // 반환 타입 변경: void -> oneshot::Receiver<()>
    pub fn start(
        sender: mpsc::Sender<Vec<Transaction>>,
        seed: AuthorityIndex,
        client_parameters: ClientParameters,
        metrics: Arc<Metrics>,
    ) -> oneshot::Receiver<()> {
        let (notify_sender, notify_receiver) = oneshot::channel();

        // 1. 무거운 파일 로딩 및 역직렬화 작업을 Blocking Thread에서 실행
        runtime::Handle::current().spawn_blocking(move || {
            let home = dirs_next::home_dir().expect("Failed to get home directory");
            let file_path = home.join("working_dir").join(format!("validator_{}_txs.bin", seed));
            let file_path_str = file_path.display().to_string();

            let transactions = match File::open(&file_path) {
                Ok(file) => {
                    tracing::info!("Loooooading transactions from file: {}", file_path_str);
                    let reader = BufReader::new(file);

                    // Deserialize
                    let vote_txs: Vec<VoteTransaction> = bincode::deserialize_from(reader)
                        .context(format!("Failed to deserialize transactions from '{}'.", file_path_str))
                        .expect("Cannot deserialize transaction file. Exiting.");

                    tracing::info!(
                        "Deserialized {} vote transactions. Converting to Transactions in parallel...",
                        vote_txs.len()
                    );

                    let progress_counter = AtomicUsize::new(0);

                    // Parallel Convert
                    let txs: Vec<Transaction> = vote_txs
                        .into_par_iter()
                        .map(|vt| {
                            let tx = Transaction::new_vote(&vt)
                                .expect("Failed to create Transaction from VoteTransaction");
                            let count = progress_counter.fetch_add(1, Ordering::Relaxed) + 1;
                            if count % 100_000 == 0 {
                                tracing::info!("Converted {} transactions...", count);
                            }
                            tx
                        })
                        .collect();

                    tracing::info!("Conversion complete. Loaded {} transactions.", txs.len());
                    txs.into()
                }
                Err(e) => {
                    panic!(
                        "Failed to open transaction file '{}': {}. Cannot continue.",
                        file_path_str, e
                    )
                }
            };

            tracing::info!("트랜잭션 준비 완료, 제너레이터 대기 상태 진입");

            // 2. 준비 완료 신호 전송
            let _ = notify_sender.send(());

            // 3. 실제 전송 루프는 Async Task로 스폰
            runtime::Handle::current().spawn(
                Self {
                    sender,
                    transactions,
                    client_parameters,
                    metrics,
                }
                    .run(),
            );
        });

        notify_receiver
    }

    pub async fn run(mut self) {
        // (기존 run 로직과 동일)
        let load = self.client_parameters.load;
        let transactions_per_block_interval = (load + 9) / 10;

        let mut interval = runtime::TimeInterval::new(Self::TARGET_BLOCK_INTERVAL);

        tracing::info!("Sending loaded transactions at {} TPS...", load);

        loop {
            interval.tick().await;

            let mut total_sent_in_batch = 0;
            if self.transactions.is_empty() {
                tracing::info!("Finished sending all loaded transactions.");
                self.metrics.submitted_transactions.inc_by(total_sent_in_batch);
                runtime::sleep(Duration::from_secs(600)).await;
                continue;
            }

            let mut block = Vec::with_capacity(transactions_per_block_interval);

            for _ in 0..transactions_per_block_interval {
                if let Some(mut tx) = self.transactions.pop_front() {
                    tx.timestamp = timestamp_utc().as_millis() as u64;
                    block.push(tx);
                    total_sent_in_batch += 1;
                } else {
                    break;
                }
            }

            if !block.is_empty() {
                if self.sender.send(block).await.is_err() {
                    tracing::warn!("Sender channel closed, stopping transaction generator.");
                    return;
                }
            }

            if total_sent_in_batch >= 10_000 {
                self.metrics.submitted_transactions.inc_by(total_sent_in_batch);
                total_sent_in_batch = 0;
            }
        }
    }

    pub fn extract_timestamp(transaction: &Transaction) -> Duration {
        Duration::from_millis(transaction.timestamp)
    }
}