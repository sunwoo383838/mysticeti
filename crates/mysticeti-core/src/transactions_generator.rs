// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{cmp::min, sync::Arc, time::Duration};
use std::collections::VecDeque;
use std::fs::File;
use std::io::Read;
use eyre::Context;
use rand::{rngs::StdRng, Rng, SeedableRng};
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
        let transactions = match File::open(&file_path) {
            Ok(mut file) => {
                tracing::info!("Loading transactions from default file: {}", file_path_str);
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)
                    .context(format!("Failed to read transaction file: {}", file_path_str))
                    .expect("Cannot read transaction file. Exiting.");

                // [수정됨] 무조건 Vec<VoteTransaction>으로 역직렬화 시도
                let vote_txs: Vec<VoteTransaction> = bincode::deserialize(&buffer)
                    .context(format!("Failed to deserialize transactions from '{}'. File is corrupt.", file_path_str))
                    .expect("Cannot deserialize transaction file. Exiting.");

                // [수정됨] VoteTransaction -> Transaction 변환
                let txs: Vec<Transaction> = vote_txs.into_iter()
                    .map(|vt| Transaction::new_vote(&vt).expect("Failed to create Transaction from VoteTransaction"))
                    .collect();

                tracing::info!("Loaded {} transactions from {}.", txs.len(), file_path_str);
                txs.into()
            }
            Err(e) => {
                panic!(
                    "Failed to open transaction file '{}': {}. Cannot continue.",
                    file_path_str, e
                )
            }
        };
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
