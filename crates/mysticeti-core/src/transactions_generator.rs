// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{cmp::min, sync::Arc, time::Duration};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, Read};
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
    node_public_config: NodePublicConfig,
    metrics: Arc<Metrics>,
}

impl TransactionGenerator {
    const TARGET_BLOCK_INTERVAL: Duration = Duration::from_millis(100);

    pub fn start(
        sender: mpsc::Sender<Vec<Transaction>>,
        seed: AuthorityIndex,
        client_parameters: ClientParameters,
        node_public_config: NodePublicConfig,
        metrics: Arc<Metrics>,
    ) {
        let home = dirs_next::home_dir().expect("Failed to get home directory");
        let file_path = home.join("working_dir").join(format!("validator_{}_txs.bin", seed));
        let file_path_str = file_path.display().to_string();
        // [수정된 로직 시작]
        let transactions = match File::open(&file_path) {
            Ok(file) => {
                tracing::info!("Loading transactions from file: {}", file_path_str);

                // 1. BufReader 사용: 파일을 통째로 메모리에 올리지 않고 버퍼링하여 읽음 (메모리 절약)
                let reader = BufReader::new(file);

                // 2. Deserialize: VoteTransaction 벡터로 역직렬화
                // (bincode는 구조상 직렬화는 단일 스레드여야 하므로 이 부분은 유지)
                let vote_txs: Vec<VoteTransaction> = bincode::deserialize_from(reader)
                    .context(format!("Failed to deserialize transactions from '{}'.", file_path_str))
                    .expect("Cannot deserialize transaction file. Exiting.");

                tracing::info!(
                    "Deserialized {} vote transactions. Converting to Transactions in parallel...",
                    vote_txs.len()
                );

                // 3. Parallel Convert: Rayon을 사용하여 모든 코어에서 병렬 변환 수행 (속도 핵심)
                // .into_iter() -> .into_par_iter() 로 변경
                let txs: Vec<Transaction> = vote_txs
                    .into_par_iter()
                    .map(|vt| {
                        Transaction::new_vote(&vt)
                            .expect("Failed to create Transaction from VoteTransaction")
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
        // [수정된 로직 끝]

        tracing::info!("트랜잭션 준비 완료, 제너레이터 시작");
        runtime::Handle::current().spawn(
            Self {
                sender,
                transactions,
                client_parameters,
                node_public_config,
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
                if let Some(tx) = self.transactions.pop_front() {
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
        let bytes = transaction.as_bytes()[0..8]
            .try_into()
            .expect("Transactions should be at least 8 bytes");
        Duration::from_millis(u64::from_le_bytes(bytes))
    }
}
