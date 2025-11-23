// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{cmp::min, sync::Arc, time::Duration};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use eyre::Context;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rayon::prelude::*;
use tokio::sync::mpsc;
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

    pub fn start(
        sender: mpsc::Sender<Vec<Transaction>>,
        seed: AuthorityIndex,
        client_parameters: ClientParameters,
        metrics: Arc<Metrics>,
    ) {
        let home = dirs_next::home_dir().expect("Failed to get home directory");
        let file_path = home.join("working_dir").join(format!("validator_{}_txs.bin", seed));
        let file_path_str = file_path.display().to_string();

        let transactions = match File::open(&file_path) {
            Ok(file) => {
                tracing::info!("Loooooading transactions from file: {}", file_path_str);

                let reader = BufReader::new(file);

                // 1. Deserialize (이 부분은 직렬 처리라 시간 좀 걸림)
                let vote_txs: Vec<VoteTransaction> = bincode::deserialize_from(reader)
                    .context(format!("Failed to deserialize transactions from '{}'.", file_path_str))
                    .expect("Cannot deserialize transaction file. Exiting.");

                tracing::info!(
                    "Deserialized {} vote transactions. Converting to Transactions in parallel...",
                    vote_txs.len()
                );

                // 2. [수정] 진행 상황 확인용 Atomic Counter 생성
                let progress_counter = AtomicUsize::new(0);

                // 3. Parallel Convert
                let txs: Vec<Transaction> = vote_txs
                    .into_par_iter()
                    .map(|vt| {
                        let tx = Transaction::new_vote(&vt)
                            .expect("Failed to create Transaction from VoteTransaction");

                        // [수정] 카운터 증가 및 로그 출력
                        // fetch_add는 이전 값을 반환하므로 1을 더해 현재 값으로 만듦
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

        tracing::info!("트랜잭션 준비 완료, 제너레이터 시작");
        runtime::Handle::current().spawn(
            Self {
                sender,
                transactions,
                client_parameters,
                metrics,
            }
                .run(),
        );
    }

    pub async fn run(mut self) {

        let load = self.client_parameters.load;
        let transactions_per_block_interval = (load + 9) / 10;

        let mut interval = runtime::TimeInterval::new(Self::TARGET_BLOCK_INTERVAL);
        runtime::sleep(self.client_parameters.initial_delay).await;

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

            let mut block= Vec::with_capacity(transactions_per_block_interval);

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
