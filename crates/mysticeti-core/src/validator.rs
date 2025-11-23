// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use ::prometheus::Registry;
use ark_ed_on_bls12_381::{EdwardsAffine, Fr};
use eyre::{eyre, Context, Result};
use tokio::sync::{Mutex, Notify};
use crate::{block_handler, block_handler::{RealBlockHandler, CommitHandler}, block_store::BlockStore, committee::Committee, config::{ClientParameters, NodePrivateConfig, NodePublicConfig}, core::{Core, CoreOptions}, log::TransactionLog, metrics::Metrics, net_sync::NetworkSyncer, network::Network, prometheus, runtime::{JoinError, JoinHandle}, transactions_generator::TransactionGenerator, types::AuthorityIndex, wal::{self, walf}};
use crate::config::CryptoConfig;
use crate::dkg_manager::DkgManager;
use crate::mempool::Mempool;
use crate::nullifier::NullifierDB;

pub struct Validator {
    network_synchronizer: NetworkSyncer<RealBlockHandler>,
    metrics_handle: JoinHandle<Result<(), hyper::Error>>,
}

impl Validator {
    pub async fn start(
        authority: AuthorityIndex,
        committee: Arc<Committee>,
        public_config: NodePublicConfig,
        private_config: NodePrivateConfig,
        client_parameters: ClientParameters,
        crypto_config: CryptoConfig,
    ) -> Result<Self> {
        let network_address = public_config
            .network_address(authority)
            .ok_or(eyre!("No network address for authority {authority}"))
            .wrap_err("Unknown authority")?;
        let mut binding_network_address = network_address;
        binding_network_address.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let metrics_address = public_config
            .metrics_address(authority)
            .ok_or(eyre!("No metrics address for authority {authority}"))
            .wrap_err("Unknown authority")?;
        let mut binding_metrics_address = metrics_address;
        binding_metrics_address.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        // Boot the prometheus server.
        let registry = Registry::new();
        let (metrics, reporter) = Metrics::new(&registry, Some(&committee));
        reporter.start();

        let metrics_handle =
            prometheus::start_prometheus_server(binding_metrics_address, &registry);

        // Open the block store.
        let wal_file =
            wal::open_file_for_wal(private_config.wal()).expect("Failed to open wal file");
        let (wal_writer, wal_reader) = walf(wal_file).expect("Failed to open wal");
        let recovered = BlockStore::open(
            authority,
            Arc::new(wal_reader),
            &wal_writer,
            metrics.clone(),
            &committee,
        );

        // 🌟 1. (신규) NullifierDB 생성
        let nullifier_db = Arc::new(NullifierDB::new(metrics.clone())
            .expect("Failed to open NullifierDB"));

        // 🌟 2. (신규) Mempool 생성
        // TransactionGenerator가 트랜잭션을 보낼 Sender(tx_sender_for_generator)와
        // Mempool의 dispatch_loop 태스크 핸들(mempool_handle)을 반환받습니다.
        let (mempool, tx_sender_for_generator, mempool_handle) = Mempool::new(
            &public_config.parameters,
            metrics.clone(),
            nullifier_db.clone(),
            crypto_config.clone(),   // 🌟 crypto_config 전달
        );

        // Boot the validator node.
        let block_handler = RealBlockHandler::new(
            committee.clone(),
            authority,
            &private_config.certified_transactions_log(),
            recovered.block_store.clone(),
            metrics.clone(),
            mempool.clone(),
            public_config.parameters.consensus_only,
        );

        let committed_transaction_log =
            TransactionLog::start(private_config.committed_transactions_log())
                .expect("Failed to open committed transaction log for write");
        let commit_handler = CommitHandler::new(
            committee.clone(),
            block_handler.transaction_time.clone(),
            metrics.clone(),
            nullifier_db.clone(),
            committed_transaction_log,
        );

        let dkg_complete_notify = Arc::new(Notify::new());
        let my_secret_share = Arc::new(Mutex::new(Option::<Fr>::None));

        let dkg_manager = Arc::new(Mutex::new(DkgManager::new(
            authority,
            committee.clone(),
            dkg_complete_notify.clone(),
            &crypto_config,
        )));
        let core = Core::open(
            block_handler,
            authority,
            committee.clone(),
            private_config,
            &public_config,
            metrics.clone(),
            recovered,
            wal_writer,
            CoreOptions::default(),
            commit_handler,
            dkg_manager.clone(), // ❗ 전달
            dkg_complete_notify.clone(), // ❗ 전달
            my_secret_share.clone(), // ❗ 전달
        );
        let network = Network::load(
            &public_config,
            authority,
            binding_network_address,
            metrics.clone(),
        )
        .await;

        let network_synchronizer = NetworkSyncer::start(
            network,
            core,
            public_config.parameters.wave_length,
            public_config.parameters.shutdown_grace_period,
            metrics.clone(),
            &public_config,
            dkg_manager.clone(),
        );

        let core_syncer_handle = network_synchronizer.core_syncer_handle(); // CoreThreadDispatcher 핸들 복제
        let shutdown_listen_addr = "127.0.0.1:10000".parse().unwrap();

        let shutdown_server_handle = tokio::spawn(async move { // ❗ (A) 바깥쪽 태스크 (소유권 O)
            let app = axum::Router::new().route(
                "/trigger_epoch_close",
                // ❗❗❗ [수정] 여기에 "move" 키워드 추가 ❗❗❗
                axum::routing::get(move || async move { // ❗ (B) 안쪽 클로저 (소유권 O)
                    tracing::info!("Received external trigger for epoch close!");

                    // core_syncer_handle은 이제 이 클로저가 소유함
                    core_syncer_handle.trigger_epoch_change_begun().await;

                    "Epoch change triggered"
                }),
            );
            axum::Server::bind(&shutdown_listen_addr)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });

        // --- (7) (신규) DKG 프로토콜 실행 ---
        tracing::info!("[Validator {authority}] 노드 시작. DKG를 위해 모든 피어 연결 대기 중...");

        // 🔽 (신규) 모든 피어(n-1)가 연결될 때까지 대기
        network_synchronizer.wait_for_all_peers(committee.len()).await;

        tracing::info!("[Validator {authority}] 모든 피어 연결 완료. DKG 프로토콜 시작...");

        // 🔽 DKG 매니저에게 DKG 시작 명령 (1단계: 커밋 브로드캐스트 시작)
        dkg_manager.lock().await.start_dkg().await;

        // 🔽 DKG 매니저가 완료 신호를 줄 때까지 대기
        dkg_complete_notify.notified().await;

        // 🔽 DKG 결과(키)를 로컬에 저장
        let (_, sk) = dkg_manager.lock().await.get_keys().expect("DKG failed or keys not set");
        *my_secret_share.lock().await = Some(sk);

        tracing::info!("[Validator {authority}] DKG 완료. 마스터 공개키 저장됨.");

        TransactionGenerator::start(
            tx_sender_for_generator,
            authority,
            client_parameters,
            metrics.clone(),
        );

        tracing::info!("Validator {authority} listening on {network_address}");
        tracing::info!("Validator {authority} exposing metrics on {metrics_address}");

        Ok(Self {
            network_synchronizer,
            metrics_handle,
        })
    }

    pub async fn await_completion(
        self,
    ) -> (
        Result<(), JoinError>,
        Result<Result<(), hyper::Error>, JoinError>,
    ) {
        tokio::join!(
            self.network_synchronizer.await_completion(),
            self.metrics_handle
        )
    }

    pub async fn stop(self) {
        self.network_synchronizer.shutdown().await;
    }
}

#[cfg(test)]
mod smoke_tests {
    use std::{collections::VecDeque, fs, net::SocketAddr, time::Duration};

    use tempdir::TempDir;
    use tokio::time;

    use super::Validator;
    use crate::{
        committee::Committee,
        config::{self, ClientParameters, NodePrivateConfig, NodePublicConfig},
        prometheus,
        types::AuthorityIndex,
    };
    use crate::config::CryptoConfig;

    /// Check whether the validator specified by its metrics address has committed at least once.
    async fn check_commit(address: &SocketAddr) -> Result<bool, reqwest::Error> {
        let route = prometheus::METRICS_ROUTE;
        let res = reqwest::get(format! {"http://{address}{route}"}).await?;
        let string = res.text().await?;
        let commit = string.contains("committed_leaders_total");
        Ok(commit)
    }

    /// Await for all the validators specified by their metrics addresses to commit.
    async fn await_for_commits(addresses: Vec<SocketAddr>) {
        let mut queue = VecDeque::from(addresses);
        while let Some(address) = queue.pop_front() {
            time::sleep(Duration::from_millis(100)).await;
            match check_commit(&address).await {
                Ok(commits) if commits => (),
                _ => queue.push_back(address),
            }
        }
    }

    /// Ensure that a committee of honest validators commits.
    #[tokio::test]
    async fn validator_commit() {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config = NodePublicConfig::new_for_tests(committee_size).with_port_offset(0);
        let client_parameters = ClientParameters::default();
        let crypto_config = CryptoConfig::default();

        let mut handles = Vec::new();
        let dir = TempDir::new("validator_commit").unwrap();
        let private_configs = NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size);
        private_configs.iter().for_each(|private_config| {
            fs::create_dir_all(&private_config.storage_path).unwrap();
        });

        for (i, private_config) in private_configs.into_iter().enumerate() {
            let authority = i as AuthorityIndex;

            let validator = Validator::start(
                authority,
                committee.clone(),
                public_config.clone(),
                private_config,
                client_parameters.clone(),
                crypto_config.clone(),
            )
            .await
            .unwrap();
            handles.push(validator.await_completion());
        }

        let addresses = public_config
            .all_metric_addresses()
            .map(|address| address.to_owned())
            .collect();
        let timeout = config::node_defaults::default_leader_timeout() * 5;

        tokio::select! {
            _ = await_for_commits(addresses) => (),
            _ = time::sleep(timeout) => panic!("Failed to gather commits within a few timeouts"),
        }
    }

    /// Ensure validators can sync missing blocks
    #[tokio::test]
    async fn validator_sync() {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config = NodePublicConfig::new_for_tests(committee_size).with_port_offset(100);
        let client_parameters = ClientParameters::default();
        let crypto_config = CryptoConfig::default();


        let mut handles = Vec::new();
        let dir = TempDir::new("validator_sync").unwrap();
        let private_configs = NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size);
        private_configs.iter().for_each(|private_config| {
            fs::create_dir_all(&private_config.storage_path).unwrap();
        });

        // Boot all validators but one.
        for (i, private_config) in private_configs.into_iter().enumerate() {
            if i == 0 {
                continue;
            }
            let authority = i as AuthorityIndex;
            let validator = Validator::start(
                authority,
                committee.clone(),
                public_config.clone(),
                private_config,
                client_parameters.clone(),
                crypto_config.clone(),
            )
            .await
            .unwrap();
            handles.push(validator.await_completion());
        }

        // Boot the last validator after they others commit.
        let addresses = public_config
            .all_metric_addresses()
            .skip(1)
            .map(|address| address.to_owned())
            .collect();
        let timeout = config::node_defaults::default_leader_timeout() * 5;
        tokio::select! {
            _ = await_for_commits(addresses) => (),
            _ = time::sleep(timeout) => panic!("Failed to gather commits within a few timeouts"),
        }

        // Boot the last validator.
        let authority = 0;
        let private_config =
            NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size).remove(authority);
        let validator = Validator::start(
            authority as AuthorityIndex,
            committee.clone(),
            public_config.clone(),
            private_config,
            client_parameters,
            crypto_config.clone(),
        )
        .await
        .unwrap();
        handles.push(validator.await_completion());

        // Ensure the last validator commits.
        let address = public_config
            .all_metric_addresses()
            .next()
            .map(|address| address.to_owned())
            .unwrap();
        let timeout = config::node_defaults::default_leader_timeout() * 5;
        tokio::select! {
            _ = await_for_commits(vec![address]) => (),
            _ = time::sleep(timeout) => panic!("Failed to gather commits within a few timeouts"),
        }
    }

    // Ensure that honest validators commit despite the presence of a crash fault.
    #[tokio::test]
    async fn validator_crash_faults() {
        let committee_size = 4;
        let committee = Committee::new_for_benchmarks(committee_size);
        let public_config = NodePublicConfig::new_for_tests(committee_size).with_port_offset(200);
        let client_parameters = ClientParameters::default();
        let crypto_config = CryptoConfig::default();

        let mut handles = Vec::new();
        let dir = TempDir::new("validator_crash_faults").unwrap();
        let private_configs = NodePrivateConfig::new_for_benchmarks(dir.as_ref(), committee_size);
        private_configs.iter().for_each(|private_config| {
            fs::create_dir_all(&private_config.storage_path).unwrap();
        });

        for (i, private_config) in private_configs.into_iter().enumerate() {
            if i == 0 {
                continue;
            }

            let authority = i as AuthorityIndex;
            let validator = Validator::start(
                authority,
                committee.clone(),
                public_config.clone(),
                private_config,
                client_parameters.clone(),
                crypto_config.clone(),
            )
            .await
            .unwrap();
            handles.push(validator.await_completion());
        }

        let addresses = public_config
            .all_metric_addresses()
            .skip(1)
            .map(|address| address.to_owned())
            .collect();
        let timeout = config::node_defaults::default_leader_timeout() * 15;

        tokio::select! {
            _ = await_for_commits(addresses) => (),
            _ = time::sleep(timeout) => panic!("Failed to gather commits within a few timeouts"),
        }
    }
}
