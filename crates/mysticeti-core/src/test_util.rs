// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    sync::Arc,
};
use ark_ed_on_bls12_381::Fr;
use ark_groth16::prepare_verifying_key;
use futures::future::join_all;
use prometheus::Registry;
use rand::{rngs::StdRng, SeedableRng};

#[cfg(feature = "simulator")]
use crate::future_simulator::OverrideNodeContext;
#[cfg(feature = "simulator")]
use crate::simulated_network::SimulatedNetwork;
use crate::{
    // ❗ TestCommitHandler 제거, CommitHandler, Log, NullifierDB 추가
    block_handler::{BlockHandler, CommitHandler, TestBlockHandler},
    block_store::{BlockStore, BlockWriter, OwnBlockData, WAL_ENTRY_BLOCK},
    committee::Committee,
    // ❗ DkgManager, CryptoConfig, Notify, Mutex 추가 (NetworkSyncer::start를 위해)
    config::{self, CryptoConfig, NodePrivateConfig, NodePublicConfig},
    core::{Core, CoreOptions},
    data::Data,
    dkg_manager::DkgManager, // ❗ 추가
    log::TransactionLog,    // ❗ 추가
    metrics::{MetricReporter, Metrics},
    net_sync::NetworkSyncer,
    network::Network,
    nullifier::NullifierDB, // ❗ 추가
    syncer::{Syncer, SyncerSignals},
    types::{format_authority_index, AuthorityIndex, BlockReference, RoundNumber, StatementBlock},
    wal::{open_file_for_wal, walf, WalPosition, WalWriter},
};
use tokio::sync::{Mutex, Notify}; // ❗ 추가

pub fn test_metrics() -> Arc<Metrics> {
    Metrics::new(&Registry::new(), None).0
}

pub fn committee(n: usize) -> Arc<Committee> {
    Committee::new_test(vec![1; n])
}

pub fn committee_and_cores(
    n: usize,
) -> (
    Arc<Committee>,
    Vec<Core<TestBlockHandler>>,
    Vec<MetricReporter>,
) {
    committee_and_cores_persisted_epoch_duration(n, None, &&NodePublicConfig::new_for_tests(n))
}

pub fn committee_and_cores_epoch_duration(
    n: usize,
    rounds_in_epoch: RoundNumber,
) -> (
    Arc<Committee>,
    Vec<Core<TestBlockHandler>>,
    Vec<MetricReporter>,
) {
    let mut config = NodePublicConfig::new_for_tests(n);
    config.parameters.rounds_in_epoch = rounds_in_epoch;
    committee_and_cores_persisted_epoch_duration(n, None, &config)
}

pub fn committee_and_cores_persisted(
    n: usize,
    path: Option<&Path>,
) -> (
    Arc<Committee>,
    Vec<Core<TestBlockHandler>>,
    Vec<MetricReporter>,
) {
    committee_and_cores_persisted_epoch_duration(n, path, &&NodePublicConfig::new_for_tests(n))
}

pub fn committee_and_cores_persisted_epoch_duration(
    n: usize,
    path: Option<&Path>,
    public_config: &NodePublicConfig,
) -> (
    Arc<Committee>,
    Vec<Core<TestBlockHandler>>,
    Vec<MetricReporter>,
) {
    let committee = committee(n);
    let crypto_config = CryptoConfig::default();
    let cores: Vec<_> = committee
        .authorities()
        .map(|authority| {
            let last_transaction = first_transaction_for_authority(authority);
            let (metrics, reporter) = Metrics::new(&Registry::new(), Some(&committee));
            let block_handler = TestBlockHandler::new(
                last_transaction,
                committee.clone(),
                authority,
                metrics.clone(),
            );
            let wal_file = if let Some(path) = path {
                let wal_path = path.join(format!("{:03}.wal", authority));
                open_file_for_wal(&wal_path).unwrap()
            } else {
                tempfile::tempfile().unwrap()
            };
            let (wal_writer, wal_reader) = walf(wal_file).expect("Failed to open wal");
            let recovered = BlockStore::open(
                authority,
                Arc::new(wal_reader),
                &wal_writer,
                metrics.clone(),
                &committee,
            );

            let private_config = NodePrivateConfig::new_for_tests(authority);

            // --- ❗ (수정) Core::open에 전달할 CommitHandler 생성 ---
            let nullifier_db = Arc::new(NullifierDB::new(metrics.clone()).unwrap());
            // 테스트 로그는 임시 파일에 저장
            let commit_log_path = tempfile::NamedTempFile::new().unwrap();
            let committed_transaction_log = TransactionLog::start(commit_log_path.path()).unwrap();

            let commit_handler = CommitHandler::new(
                committee.clone(),
                block_handler.transaction_time.clone(),
                metrics.clone(),
                nullifier_db,
                committed_transaction_log,
            );

            let dkg_complete_notify = Arc::new(Notify::new());
            let my_secret_share = Arc::new(Mutex::new(Option::<Fr>::None));
            let dkg_manager = Arc::new(Mutex::new(DkgManager::new(
                authority,
                committee.clone(),
                dkg_complete_notify.clone(),
                &crypto_config, // ❗ 테스트용 config 전달
            )));
            // --- (수정 끝) ---

            println!("Opening core {authority}");
            let core = Core::open(
                block_handler,
                authority,
                committee.clone(),
                private_config,
                public_config,
                metrics,
                recovered,
                wal_writer,
                CoreOptions::test(),
                commit_handler, // ❗ CommitHandler 인자 전달
                dkg_manager.clone(),
                dkg_complete_notify.clone(),
                my_secret_share.clone(),
            );
            (core, reporter)
        })
        .collect();
    let (cores, reporters) = cores.into_iter().unzip();
    (committee, cores, reporters)
}

fn first_transaction_for_authority(authority: AuthorityIndex) -> u64 {
    authority * 1_000_000
}

pub fn committee_and_syncers(
    n: usize,
) -> (
    Arc<Committee>,
    // ❗ TestCommitHandler -> CommitHandler
    Vec<Syncer<TestBlockHandler, bool>>,
) {
    let (committee, cores, _) = committee_and_cores(n);
    (
        committee.clone(),
        cores
            .into_iter()
            .map(|core| {
                // ❌ commit_handler 생성 로직 제거
                // let commit_handler = TestCommitHandler::new( ... );

                // ❗ Syncer::new 시그니처 변경 (commit_handler 제거)
                Syncer::new(core, 3, Default::default(), test_metrics())
            })
            .collect(),
    )
}

pub async fn networks_and_addresses(metrics: &[Arc<Metrics>]) -> (Vec<Network>, Vec<SocketAddr>) {
    let host = Ipv4Addr::LOCALHOST;
    let addresses: Vec<_> = (0..metrics.len())
        .map(|i| SocketAddr::V4(SocketAddrV4::new(host, 5001 + i as u16)))
        .collect();
    let networks =
        addresses
            .iter()
            .zip(metrics.iter())
            .enumerate()
            .map(|(i, (address, metrics))| {
                Network::from_socket_addresses(&addresses, i, *address, metrics.clone())
            });
    let networks = join_all(networks).await;
    (networks, addresses)
}

#[cfg(feature = "simulator")]
pub fn simulated_network_syncers(
    n: usize,
) -> (
    SimulatedNetwork,
    // ❗ TestCommitHandler -> CommitHandler
    Vec<NetworkSyncer<TestBlockHandler, CommitHandler>>,
    Vec<MetricReporter>,
) {
    simulated_network_syncers_with_epoch_duration(
        n,
        config::node_defaults::default_rounds_in_epoch(),
    )
}

#[cfg(feature = "simulator")]
pub fn simulated_network_syncers_with_epoch_duration(
    n: usize,
    rounds_in_epoch: RoundNumber,
) -> (
    SimulatedNetwork,
    // ❗ TestCommitHandler -> CommitHandler
    Vec<NetworkSyncer<TestBlockHandler, CommitHandler>>,
    Vec<MetricReporter>,
) {
    let (committee, cores, reporters) = committee_and_cores_epoch_duration(n, rounds_in_epoch);
    let (simulated_network, networks) = SimulatedNetwork::new(&committee);
    let mut network_syncers = vec![];
    for (network, core) in networks.into_iter().zip(cores.into_iter()) {
        // ❌ commit_handler 생성 로직 제거
        // let commit_handler = TestCommitHandler::new( ... );

        // ❗ DkgManager 생성 (NetworkSyncer::start를 위해)
        let dkg_complete_notify = Arc::new(Notify::new());
        let crypto_config = CryptoConfig::default(); // 테스트용 기본값
        let dkg_manager = Arc::new(Mutex::new(DkgManager::new(
            core.authority(),
            committee.clone(),
            dkg_complete_notify.clone(),
            &crypto_config,
        )));

        let node_context = OverrideNodeContext::enter(Some(core.authority()));

        // ❗ NetworkSyncer::start 시그니처 변경
        let network_syncer = NetworkSyncer::start(
            network,
            core,
            3,
            // commit_handler, // <- 제거
            config::node_defaults::default_shutdown_grace_period(),
            test_metrics(),
            &NodePublicConfig::new_for_tests(n),
            dkg_manager, // ❗ dkg_manager 전달
        );
        drop(node_context);
        network_syncers.push(network_syncer);
    }
    (simulated_network, network_syncers, reporters)
}

// ❗ TestCommitHandler -> CommitHandler
pub async fn network_syncers(n: usize) -> Vec<NetworkSyncer<TestBlockHandler>> {
    network_syncers_with_epoch_duration(n, config::node_defaults::default_rounds_in_epoch()).await
}

pub async fn network_syncers_with_epoch_duration(
    n: usize,
    rounds_in_epoch: RoundNumber,
    // ❗ TestCommitHandler -> CommitHandler
) -> Vec<NetworkSyncer<TestBlockHandler>> {
    let (committee, cores, _) = committee_and_cores_epoch_duration(n, rounds_in_epoch);
    let metrics: Vec<_> = cores.iter().map(|c| c.metrics.clone()).collect();
    let (networks, _) = networks_and_addresses(&metrics).await;
    let mut network_syncers = vec![];
    for (network, core) in networks.into_iter().zip(cores.into_iter()) {
        // ❌ commit_handler 생성 로직 제거
        // let commit_handler = TestCommitHandler::new( ... );

        // ❗ DkgManager 생성 (NetworkSyncer::start를 위해)
        let dkg_complete_notify = Arc::new(Notify::new());
        let crypto_config = CryptoConfig::default(); // 테스트용 기본값
        let dkg_manager = Arc::new(Mutex::new(DkgManager::new(
            core.authority(),
            committee.clone(),
            dkg_complete_notify.clone(),
            &crypto_config,
        )));
        let nullifier_db = Arc::new(NullifierDB::new(core.metrics.clone())
            .expect("Failed to open NullifierDB"));

        // ❗ NetworkSyncer::start 시그니처 변경
        let network_syncer = NetworkSyncer::start(
            network,
            core,
            3,
            // commit_handler, // <- 제거
            config::node_defaults::default_shutdown_grace_period(),
            test_metrics(),
            &NodePublicConfig::new_for_tests(n),
            dkg_manager, // ❗ dkg_manager 전달
            crypto_config,
            nullifier_db.clone()
        );
        network_syncers.push(network_syncer);
    }
    network_syncers
}

pub fn rng_at_seed(seed: u64) -> StdRng {
    let bytes = seed.to_le_bytes();
    let mut seed = [0u8; 32];
    seed[..bytes.len()].copy_from_slice(&bytes);
    StdRng::from_seed(seed)
}

// ❗ TestCommitHandler -> CommitHandler
pub fn check_commits<H: BlockHandler, S: SyncerSignals>(
    syncers: &[Syncer<H, S>],
) {
    let commits = syncers
        .iter()
        // ❗ syncer.rs 수정 시 `commit_observer()`가 &CommitHandler를 반환하도록 수정 필요
        .map(|state| state.commit_observer().committed_leaders());
    let zero_commit = vec![];
    let mut max_commit = &zero_commit;
    for commit in commits {
        if commit.len() >= max_commit.len() {
            if is_prefix(&max_commit, commit) {
                max_commit = commit;
            } else {
                panic!("[!] Commits diverged: {max_commit:?}, {commit:?}");
            }
        } else {
            if !is_prefix(&commit, &max_commit) {
                panic!("[!] Commits diverged: {max_commit:?}, {commit:?}");
            }
        }
    }
    eprintln!("Max commit sequence: {max_commit:?}");
}

#[allow(dead_code)]
// ❗ TestCommitHandler -> CommitHandler
pub fn print_stats<S: SyncerSignals>(
    syncers: &[Syncer<TestBlockHandler, S>],
    reporters: &mut [MetricReporter],
) {
    assert_eq!(syncers.len(), reporters.len());
    eprintln!("val ||    cert(ms)   ||cert commit(ms)|| tx commit(ms) |");
    eprintln!("    ||  p90  |  avg  ||  p90  |  avg  ||  p90  |  avg  |");
    syncers.iter().zip(reporters.iter_mut()).for_each(|(s, r)| {
        r.clear_receive_all();
        eprintln!(
            "  {} || {:05} | {:05} || {:05} | {:05} || {:05} | {:05} |",
            format_authority_index(s.core().authority()),
            r.transaction_certified_latency
                .histogram
                .pct(900)
                .unwrap_or_default()
                .as_millis(),
            r.transaction_certified_latency
                .histogram
                .avg()
                .unwrap_or_default()
                .as_millis(),
            r.certificate_committed_latency
                .histogram
                .pct(900)
                .unwrap_or_default()
                .as_millis(),
            r.certificate_committed_latency
                .histogram
                .avg()
                .unwrap_or_default()
                .as_millis(),
            r.transaction_committed_latency
                .histogram
                .pct(900)
                .unwrap_or_default()
                .as_millis(),
            r.transaction_committed_latency
                .histogram
                .avg()
                .unwrap_or_default()
                .as_millis(),
        )
    });
}

fn is_prefix(short: &[BlockReference], long: &[BlockReference]) -> bool {
    assert!(short.len() <= long.len());
    for (a, b) in short.iter().zip(long.iter().take(short.len())) {
        if a != b {
            return false;
        }
    }
    return true;
}

pub struct TestBlockWriter {
    block_store: BlockStore,
    wal_writer: WalWriter,
}

impl TestBlockWriter {
    pub fn new(committee: &Committee) -> Self {
        let file = tempfile::tempfile().unwrap();
        let (wal_writer, wal_reader) = walf(file).unwrap();
        let state = BlockStore::open(
            0,
            Arc::new(wal_reader),
            &wal_writer,
            test_metrics(),
            committee,
        );
        let block_store = state.block_store;
        Self {
            block_store,
            wal_writer,
        }
    }

    pub fn add_block(&mut self, block: Data<StatementBlock>) -> WalPosition {
        let pos = self
            .wal_writer
            .write(WAL_ENTRY_BLOCK, &bincode::serialize(&block).unwrap())
            .unwrap();
        self.block_store.insert_block(block, pos);
        pos
    }

    pub fn add_blocks(&mut self, blocks: Vec<Data<StatementBlock>>) {
        for block in blocks {
            self.add_block(block);
        }
    }

    pub fn into_block_store(self) -> BlockStore {
        self.block_store
    }

    pub fn block_store(&self) -> BlockStore {
        self.block_store.clone()
    }
}

impl BlockWriter for TestBlockWriter {
    fn insert_block(&mut self, block: Data<StatementBlock>) -> WalPosition {
        (&mut self.wal_writer, &self.block_store).insert_block(block)
    }

    fn insert_own_block(&mut self, block: &OwnBlockData) {
        (&mut self.wal_writer, &self.block_store).insert_own_block(block)
    }
}

/// Build a fully interconnected dag up to the specified round. This function starts building the
/// dag from the specified [`start`] references or from genesis if none are specified.
pub fn build_dag(
    committee: &Committee,
    block_writer: &mut TestBlockWriter,
    start: Option<Vec<BlockReference>>,
    stop: RoundNumber,
) -> Vec<BlockReference> {
    let mut includes = match start {
        Some(start) => {
            assert!(!start.is_empty());
            assert_eq!(
                start.iter().map(|x| x.round).max(),
                start.iter().map(|x| x.round).min()
            );
            start
        }
        None => {
            let (references, genesis): (Vec<_>, Vec<_>) = committee
                .authorities()
                .map(|index| StatementBlock::new_genesis(index))
                .map(|block| (*block.reference(), block))
                .unzip();
            block_writer.add_blocks(genesis);
            references
        }
    };

    let starting_round = includes.first().unwrap().round + 1;
    for round in starting_round..=stop {
        let (references, blocks): (Vec<_>, Vec<_>) = committee
            .authorities()
            .map(|authority| {
                let block = Data::new(StatementBlock::new(
                    authority,
                    round,
                    includes.clone(),
                    vec![],
                    0,
                    false,
                    Default::default(),
                ));
                (*block.reference(), block)
            })
            .unzip();
        block_writer.add_blocks(blocks);
        includes = references;
    }

    includes
}

pub fn build_dag_layer(
    // A list of (authority, parents) pairs. For each authority, we add a block linking to the
    // specified parents.
    connections: Vec<(AuthorityIndex, Vec<BlockReference>)>,
    block_writer: &mut TestBlockWriter,
) -> Vec<BlockReference> {
    let mut references = Vec::new();
    for (authority, parents) in connections {
        let round = parents.first().unwrap().round + 1;
        let block = Data::new(StatementBlock::new(
            authority,
            round,
            parents,
            vec![],
            0,
            false,
            Default::default(),
        ));

        references.push(*block.reference());
        block_writer.add_block(block);
    }
    references
}