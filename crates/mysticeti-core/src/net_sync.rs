// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use std::str::FromStr;
use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::encryption::elgamal::Ciphertext;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub, Fr as JubJubFr};
use ark_ff::Zero;
use ark_groth16::{prepare_verifying_key, PreparedVerifyingKey};
use ark_serialize::{serialize_to_vec, CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use eyre::eyre;
use futures::future::join_all;
use rayon::prelude::*;
use tokio::{
    select,
    sync::{mpsc, oneshot, Notify},
};
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;
use crypto::elgamal;
use crypto::elgamal::decode_vote;
use crypto::types::ZKElgamalCiphertext;
use crypto::zkp::{batch_verify, prepare_public_inputs};
use crate::{
    block_handler::BlockHandler,
    block_store::BlockStore,
    committee::Committee,
    config::NodePublicConfig,
    core::Core,
    core_thread::CoreThreadDispatcher,
    metrics::Metrics,
    network::{Connection, Network, NetworkMessage},
    runtime::{self, timestamp_utc, Handle, JoinError, JoinHandle},
    syncer::{CommitObserver, Syncer, SyncerSignals},
    synchronizer::{BlockDisseminator, BlockFetcher, SynchronizerParameters},
    types::{format_authority_index, AuthorityIndex},
    wal::WalSyncer,
};
use crate::config::CryptoConfig;
use crate::data::Data;
use crate::dkg_manager::DkgManager;
use crate::nullifier::NullifierDB;
use crate::types::{BaseStatement, StatementBlock, Transaction};

/// The maximum number of blocks that can be requested in a single message.
pub const MAXIMUM_BLOCK_REQUEST: usize = 10;

pub struct NetworkSyncer<H: BlockHandler> {
    inner: Arc<NetworkSyncerInner<H>>,
    main_task: JoinHandle<()>,
    syncer_task: oneshot::Receiver<()>,
    stop: mpsc::Receiver<()>,
}

pub struct NetworkSyncerInner<H: BlockHandler> {
    pub syncer: Arc<CoreThreadDispatcher<H, Arc<Notify>>>,
    pub block_store: BlockStore,
    pub notify: Arc<Notify>,
    committee: Arc<Committee>,
    stop: mpsc::Sender<()>,
    epoch_close_signal: mpsc::Sender<()>,
    pub epoch_closing_time: Arc<AtomicU64>,
    dkg_manager: Arc<Mutex<DkgManager>>,
    prepared_verifying_key: PreparedVerifyingKey<Bls12_381>,
    crypto_config: CryptoConfig,
    nullifier_db: Arc<NullifierDB>,
    block_level_fpc: bool,
    metrics: Arc<Metrics>,
}

impl<H: BlockHandler + 'static> NetworkSyncer<H> {
    pub fn start(
        network: Network,
        core: Core<H>,
        commit_period: u64,
        shutdown_grace_period: Duration,
        metrics: Arc<Metrics>,
        public_config: &NodePublicConfig,
        dkg_manager: Arc<Mutex<DkgManager>>,
        crypto_config: CryptoConfig,
        nullifier_db: Arc<NullifierDB>
    ) -> Self {
        let authority_index = core.authority();
        let handle = Handle::current();
        let notify = Arc::new(Notify::new());
        // todo - ugly, probably need to merge syncer and core
        let committee = core.committee().clone();
        let wal_syncer = core.wal_syncer();
        let block_store = core.block_store().clone();
        let epoch_closing_time = core.epoch_closing_time();
        let mut syncer = Syncer::new(
            core,
            commit_period,
            notify.clone(),
            metrics.clone(),
        );
        syncer.force_new_block(0);
        let syncer = Arc::new(CoreThreadDispatcher::start(syncer));
        let (stop_sender, stop_receiver) = mpsc::channel(1);
        stop_sender.try_send(()).unwrap(); // occupy the only available permit, so that all other calls to send() will block
        let (epoch_sender, epoch_receiver) = mpsc::channel(1);
        let prepared_verifying_key = prepare_verifying_key(&crypto_config.verifying_key);
        let inner = Arc::new(NetworkSyncerInner {
            notify,
            syncer,
            block_store,
            committee,
            stop: stop_sender.clone(),
            epoch_close_signal: epoch_sender,
            epoch_closing_time,
            dkg_manager,
            prepared_verifying_key,
            crypto_config,
            nullifier_db,
            block_level_fpc: public_config.parameters.enable_block_fpc,
            metrics: metrics.clone(),
        });
        let block_fetcher = Arc::new(BlockFetcher::start(
            authority_index,
            inner.clone(),
            metrics.clone(),
            public_config.parameters.enable_synchronizer,
        ));
        let main_task = handle.spawn(Self::run(
            network,
            inner.clone(),
            epoch_receiver,
            shutdown_grace_period,
            block_fetcher,
            metrics.clone(),
        ));
        let syncer_task = AsyncWalSyncer::start(wal_syncer, stop_sender);
        Self {
            inner,
            main_task,
            stop: stop_receiver,
            syncer_task,
        }
    }

    pub fn core_syncer_handle(&self) -> Arc<CoreThreadDispatcher<H, Arc<Notify>>> {
        self.inner.syncer.clone()
    }

    pub async fn wait_for_all_peers(&self, committee_size: usize) {
        loop {
            // DkgManager에 등록된 피어 수 확인
            let connected_count = self.inner.dkg_manager.lock().await.get_connected_peer_count();


            if connected_count >= committee_size - 1 {
                tracing::info!("All {connected_count} peers connected for DKG.");
                break;
            }
            tracing::debug!("Waiting for peers... ({connected_count}/{})", committee_size - 1);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn shutdown(self) -> Syncer<H, Arc<Notify>> {
        drop(self.stop);
        // todo - wait for network shutdown as well
        self.main_task.await.ok();
        self.syncer_task.await.ok();
        let Ok(inner) = Arc::try_unwrap(self.inner) else {
            panic!("Shutdown failed - not all resources are freed after main task is completed");
        };
        let Ok(dispatcher) = Arc::try_unwrap(inner.syncer) else {
            panic!("Shutdown failed - CoreThreadDispatcher is still referenced elsewhere (e.g., HTTP server)");
        };

        dispatcher.stop()
    }

    async fn run(
        mut network: Network,
        inner: Arc<NetworkSyncerInner<H>>,
        epoch_close_signal: mpsc::Receiver<()>,
        shutdown_grace_period: Duration,
        block_fetcher: Arc<BlockFetcher>,
        metrics: Arc<Metrics>,
    ) {
        let mut connections: HashMap<usize, JoinHandle<Option<()>>> = HashMap::new();
        let handle = Handle::current();
        let leader_timeout_task = handle.spawn(Self::leader_timeout_task(
            inner.clone(),
            epoch_close_signal,
            shutdown_grace_period,
        ));
        let cleanup_task = handle.spawn(Self::cleanup_task(inner.clone()));
        while let Some(connection) = inner.recv_or_stopped(network.connection_receiver()).await {
            let peer_id = connection.peer_id;
            if let Some(task) = connections.remove(&peer_id) {
                // wait until previous sync task completes
                task.await.ok();
            }

            let sender = connection.sender.clone();
            let authority = peer_id as AuthorityIndex;
            block_fetcher.register_authority(authority, sender).await;

            inner.dkg_manager.lock().await.register_peer(authority, connection.sender.clone());

            let task = handle.spawn(Self::connection_task(
                connection,
                inner.clone(),
                block_fetcher.clone(),
                metrics.clone(),
            ));
            connections.insert(peer_id, task);
        }
        join_all(
            connections
                .into_values()
                .chain([leader_timeout_task, cleanup_task].into_iter()),
        )
        .await;
        Arc::try_unwrap(block_fetcher)
            .unwrap_or_else(|_| panic!("Failed to drop all connections"))
            .shutdown()
            .await;
    }

    async fn connection_task(
        mut connection: Connection,
        inner: Arc<NetworkSyncerInner<H>>,
        block_fetcher: Arc<BlockFetcher>,
        metrics: Arc<Metrics>,
    ) -> Option<()> {
        let last_seen = inner
            .block_store
            .last_seen_by_authority(connection.peer_id as AuthorityIndex);
        connection
            .sender
            .send(NetworkMessage::SubscribeOwnFrom(last_seen))
            .await
            .ok()?;

        let mut disseminator = BlockDisseminator::new(
            connection.sender.clone(),
            inner.clone(),
            SynchronizerParameters::default(),
            metrics.clone(),
        );

        let id = connection.peer_id as AuthorityIndex;
        inner.syncer.authority_connection(id, true).await;

        let peer = format_authority_index(id);
        while let Some(message) = inner.recv_or_stopped(&mut connection.receiver).await {
            match message {
                NetworkMessage::SubscribeOwnFrom(round) => {
                    disseminator.disseminate_own_blocks(round).await
                }
                NetworkMessage::Block(block) => {
                    tracing::debug!("Received {} from {}", block.reference(), peer);
                    if let Err(e) = block.verify(&inner.committee) {
                        tracing::warn!(
                            "Rejected incorrect block {} from {}: {:?}",
                            block.reference(),
                            peer,
                            e
                        );
                        break;
                    }

                    if let Err(e) = Self::verify_block_batch(inner.clone(), block.clone()).await {
                        if inner.block_level_fpc {
                            tracing::warn!(
                            "Rejected invalid block content (ZK/Nullifier fail) {} from {}: {:?}",
                            block.reference(),
                            peer,
                            e
                            );
                            break;
                        } else {
                            tracing::debug!("Block {} batch verify failed. Marking for individual verification.", block.reference());
                            inner.syncer.add_blocks(vec![(block.clone(), true)]).await;
                        }
                    }

                    inner.syncer.add_blocks(vec![(block, false)]).await;
                }
                NetworkMessage::RequestBlocks(references) => {
                    if references.len() > MAXIMUM_BLOCK_REQUEST {
                        // Terminate connection on receiving invalid message.
                        break;
                    }
                    let authority = connection.peer_id as AuthorityIndex;
                    if disseminator
                        .send_blocks(authority, references)
                        .await
                        .is_none()
                    {
                        break;
                    }
                }
                NetworkMessage::BlockNotFound(_references) => {
                    // TODO: leverage this signal to request blocks from other peers
                }
                NetworkMessage::DkgCommitment(commits) => {
                    inner.dkg_manager.lock().await.handle_commitment(id, commits);
                }
                NetworkMessage::DkgShare(share) => {
                    inner.dkg_manager.lock().await.handle_share(id, share);
                }
                NetworkMessage::PartialDecryptionShare(share_bytes) => {
                    // ❗ DkgManager 락을 잡고 *동기* 함수 호출
                    inner.dkg_manager.lock().await
                        .handle_partial_decryption(id, share_bytes).await;
                }
            }
        }
        inner.dkg_manager.lock().await.unregister_peer(id);

        inner.syncer.authority_connection(id, false).await;
        disseminator.shutdown().await;
        block_fetcher.remove_authority(id).await;
        None
    }

    async fn leader_timeout_task(
        inner: Arc<NetworkSyncerInner<H>>,
        mut epoch_close_signal: mpsc::Receiver<()>, // ❗ Receiver
        shutdown_grace_period: Duration,
    ) -> Option<()> {
        let leader_timeout = Duration::from_secs(1);
        let mut tallying_started = false;

        loop {
            let notified = inner.notify.notified();
            let round = inner
                .block_store
                .last_own_block_ref()
                .map(|b| b.round())
                .unwrap_or_default();

            let effective_leader_timeout = if tallying_started {
                Duration::MAX
            } else {
                leader_timeout
            };

            let closing_time = inner.epoch_closing_time.load(Ordering::Relaxed);
            let shutdown_duration = if closing_time != 0 {
                let elapsed_since_close = timestamp_utc().saturating_sub(Duration::from_millis(closing_time));
                shutdown_grace_period.saturating_sub(elapsed_since_close)
            } else {
                Duration::MAX
            };

            // -----------------------------------------------------------------
            // ❌ ❗ `if Duration::is_zero(...)` 블록 전체를 삭제합니다.
            // (E0382 오류의 원인. select!가 이 경우를 자동으로 처리합니다.)
            // -----------------------------------------------------------------

            select! {
                _sleep = runtime::sleep(effective_leader_timeout) => {
                    tracing::debug!("Timeout {round}");
                    inner.syncer.force_new_block(round).await;
                }
                _notified = notified, if !tallying_started => {
                    // (FPC 블록 생성 알림) Tally 중에는 무시
                }

                // ❗ (핵심 트리거)
                // shutdown_duration이 0이 되어도 이 브랜치가 즉시 실행됩니다.
                _epoch_shutdown = runtime::sleep(shutdown_duration), if !tallying_started => {
                    tallying_started = true;
                    // ❗ Inner의 Sender는 Arc로 감싸져 있지 않으므로,
                    // ❗ Tally 태스크가 Sender를 소유하도록 전달할 수 없음.
                    // ❗ Tally 태스크가 inner를 받아 Sender를 drop하게 해야 함.

                    // [최종 수정] Tally가 완료되면 `leader_timeout_task`가
                    // `Receiver`를 `drop`하여 스스로 종료하고,
                    // `recv_or_stopped`는 `leader_timeout_task`가 종료되면
                    // `epoch_close_signal.send()`가 실패하여 종료되도록 해야 함.

                    // ❗ Tally 태스크 실행 (Sender 복제본 전달)
                    Handle::current().spawn(Self::run_tally_protocol(
                        inner.clone(),
                        inner.epoch_close_signal.clone(), // ❗ Sender 복제본 전달
                    ));
                    // Receiver는 계속 이 태스크가 소유합니다.
                }

                // ❗ Tally가 완료되어 Sender가 drop되면, recv()가 None을 반환합니다.
                _tally_completed = epoch_close_signal.recv() => {
                    tracing::info!("Tally protocol completed (channel closed). Shutting down leader_timeout_task.");
                    return None; // ❗ Tally 완료 후 종료
                }

                _stopped = inner.stopped() => {
                    // 외부에서 Stop 신호를 받음 (Tally 완료 시에도 트리거됨)
                    return None;
                }
            }
        }
    }

    // --- ❗ (신규) Tally 프로토콜 헬퍼 함수 ---
    async fn run_tally_protocol( // ❗ H 제네릭 추가
        inner: Arc<NetworkSyncerInner<H>>,
        epoch_close_signal_sender: mpsc::Sender<()>, // ❗ Sender 복제본
    ) {
        // 1. Core에 모든 커밋된 트랜잭션 요청
        let all_committed_tx_locators = inner.syncer
            .get_all_committed_tx_locators().await;

        // 2. 트랜잭션 데이터(암호문) 가져오기
        let encrypted_votes = inner.syncer
            .get_transactions(all_committed_tx_locators).await;

        // 3. 동형암호 집계 (HE Aggregation)
        let aggregated_ciphertext = Self::perform_he_aggregation(encrypted_votes).await;

        // 4. Core에서 내 DKG 비밀 키 가져오기
        let my_share = inner.syncer.get_my_secret_share().await
            .expect("DKG key is not available for Tally protocol");

        // 5. 부분 복호화
        let partial_decryption = Self::perform_partial_decryption(&aggregated_ciphertext, &my_share).await;

        // 6. 부분 복호화 결과 브로드캐스트
        inner.dkg_manager.lock().await
            .broadcast_partial_decryption(partial_decryption).await;

        // 7. 2f+1개의 부분 복호화 결과 수집
        let all_shares = inner.dkg_manager.lock().await
            .collect_partial_decryptions().await;

        // 8. 최종 복호화 (집계)
        let final_tally_result = Self::perform_full_decryption(
            &aggregated_ciphertext, // ❗ 1. 집계된 암호문(C2 포함)
            all_shares              // ❗ 2. 부분 셰어 목록
        ).await;

        // 9. 결과 로깅
        tracing::info!("--- 🏁 FINAL TALLY RESULT 🏁 ---");
        tracing::info!("{:?}", final_tally_result);
        tracing::info!("-----------------------------------");

        // 10. ❗ 모든 작업 완료 후, *Sender*를 drop하여 채널을 닫음
        tracing::info!("Tallying complete. Shutting down network sync.");
        drop(epoch_close_signal_sender); // ❗ Inner의 Sender를 drop
    }

    async fn perform_he_aggregation(txs: Vec<Transaction>) -> Vec<u8> {
        spawn_blocking(move || {
            tracing::info!("Aggregating {} encrypted transactions...", txs.len());

            let mut all_ballots: Vec<Vec<ZKElgamalCiphertext>> = Vec::new();
            let mut num_candidates = 0;

            for (i, tx) in txs.iter().enumerate() {
                // ❗ (수정) `tx.data`를 `VoteTransaction`으로 비직렬화
                match tx.get_vote() {
                    Ok(vote_tx) => {
                        if i == 0 {
                            num_candidates = vote_tx.enc_vote_vec.len();
                            if num_candidates == 0 {
                                tracing::warn!("Transaction 0 has no candidates, skipping aggregation.");
                                return bincode::serialize(&Vec::<ZKElgamalCiphertext>::new()).unwrap();
                            }
                        } else if vote_tx.enc_vote_vec.len() != num_candidates {
                            tracing::warn!("Ballot size mismatch! Skipping tx {}.", i);
                            continue;
                        }
                        // ❗ `enc_vote_vec` (Vec<ZKElgamalCiphertext>) 추출
                        all_ballots.push(vote_tx.enc_vote_vec);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize VoteTransaction: {}", e);
                    }
                }
            }

            if all_ballots.is_empty() {
                tracing::warn!("No valid ballots found for aggregation.");
                return bincode::serialize(&Vec::<ZKElgamalCiphertext>::new()).unwrap();
            }

            // 후보자별로 암호문 집계
            let mut final_tallies: Vec<ZKElgamalCiphertext> = Vec::with_capacity(num_candidates);
            for i in 0..num_candidates {
                // ❗ `ZKElgamalCiphertext`에는 Affine 포인트가 들어있음
                let candidate_ciphertexts: Vec<&ZKElgamalCiphertext> =
                    all_ballots.iter().map(|b| &b[i]).collect();

                // ❗ Affine 포인트를 Projective로 변환하며 합산
                let mut c1_agg = JubJub::zero();
                let mut c2_agg = JubJub::zero();
                for zkc in candidate_ciphertexts {
                    c1_agg += zkc.c1.into_group();
                    c2_agg += zkc.c2.into_group();
                }

                final_tallies.push(ZKElgamalCiphertext {
                    c1: c1_agg.into_affine(),
                    c2: c2_agg.into_affine(),
                });
            }

            tracing::info!("Aggregation complete for {} candidates.", num_candidates);
            // ❗ `Vec<ZKElgamalCiphertext>`를 직렬화하여 반환
            bincode::serialize(&final_tallies).unwrap()
        })
            .await
            .unwrap()
    }

    pub async fn verify_block_batch(
        inner: Arc<NetworkSyncerInner<H>>,
        block: Data<StatementBlock>
    ) -> eyre::Result<()> {
        spawn_blocking(move || {
            let mut vote_txs = Vec::new();
            let mut nullifiers = Vec::new();

            if vote_txs.is_empty() {
                return Ok(());
            }

            for statement in block.statements() {
                if let BaseStatement::Share(tx) = statement {
                    let vote_tx = match tx.get_vote() {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("Transaction deserialize failed: {e}");
                            return Err(eyre!("rejected_deserialize"));
                        }
                    };
                    if vote_tx.enc_vote_vec.len() != inner.crypto_config.num_candidates {
                        tracing::warn!("Invalid candidate count");
                        return Err(eyre!("rejected_zk_candidates"));
                    }
                    nullifiers.push(vote_tx.nullifier);
                    vote_txs.push(vote_tx);
                }
            }

            let merkle_root = Fr::from_str(&inner.crypto_config.merkle_root).unwrap();
            let prepare_results: Result<Vec<_>, _> = vote_txs.par_iter()
                .map(|tx| {
                    prepare_public_inputs(
                        &tx.enc_vote_vec,
                        merkle_root,
                        tx.nullifier
                    )
                })
                .collect();

            let public_inputs = match prepare_results {
                Ok(inputs) => inputs,
                Err(e) => return Err(eyre!("ZK input preparation failed: {:?}", e)),
            };

            let proofs: Vec<_> = vote_txs.iter().map(|tx| tx.proof.clone()).collect();
            let zk_valid = batch_verify(
                &inner.prepared_verifying_key,
                &proofs,
                &public_inputs
            ).map_err(|e| eyre!("ZK verification error: {:?}", e))?;

            if !zk_valid {
                tracing::warn!("Invalid ZK Batch Proof in block {}", block.reference());
                return Err(eyre!("rejected_zk_invalid_batch_proof"));
            }

            let db_valid = inner.nullifier_db.verify_batch(&nullifiers)
                .map_err(|e| eyre!("Nullifier DB error: {:?}", e))?;
            if !db_valid {
                tracing::warn!("Block contains duplicate nullifiers: {}", block.reference());
                return Err(eyre!("rejected_nullifier_duplicate"));
            }
            Ok(())
        }).await?
    }


    async fn perform_partial_decryption(ciphertext: &[u8], share: &JubJubFr) -> Vec<u8> {
        let share = *share;
        let ciphertext = ciphertext.to_vec();

        spawn_blocking(move || {
            tracing::info!("Performing partial decryption...");

            // 1. 집계된 암호문(Vec<ZKElgamalCiphertext>) 비직렬화 (bincode)
            let final_tallies: Vec<ZKElgamalCiphertext> = bincode::deserialize(&ciphertext)
                .expect("Failed to deserialize aggregated ciphertext");

            // ❗ [수정] 반환 타입은 `Vec<JubJubAffine>` (래퍼 없음)
            let mut partial_shares: Vec<JubJubAffine> = Vec::with_capacity(final_tallies.len());

            // 2. 각 후보자별로 D_i 계산
            for zkc in final_tallies {
                // [라이브러리 호출] D_i = s_i * C1
                let d_i_point = elgamal::partial_decrypt_share(&zkc.c1, share);
                partial_shares.push(d_i_point);
            }

            // 3. ❗ [수정] `Vec<JubJubAffine>`를 `ark-serialize`로 직접 직렬화
            let mut bytes = Vec::new();
            partial_shares.serialize_with_mode(&mut bytes, Compress::Yes)
                .expect("Failed to serialize partial shares");
            bytes
        })
            .await
            .unwrap()
    }

    async fn perform_full_decryption(
        aggregated_ciphertext: &[u8],
        all_shares: Vec<(AuthorityIndex, Vec<u8>)>, // (인덱스, ark-serialized Vec<JubJubAffine>)
    ) -> Vec<u64> {

        let aggregated_ciphertext = aggregated_ciphertext.to_vec();

        spawn_blocking(move || {
            tracing::info!("Performing full decryption from {} shares...", all_shares.len());

            // 1. 집계된 암호문(Vec<ZKElgamalCiphertext>) 비직렬화 (bincode)
            let final_tallies: Vec<ZKElgamalCiphertext> = bincode::deserialize(&aggregated_ciphertext)
                .expect("Failed to deserialize aggregated ciphertext for C2");

            let num_candidates = final_tallies.len();
            if num_candidates == 0 { return Vec::new(); }

            // 2. ❗ (인덱스, `Vec<u8>`) -> (u64, `Vec<JubJubAffine>`) 비직렬화 (ark-deserialize)
            let mut deserialized_shares: Vec<(u64, Vec<JubJubAffine>)> = Vec::new();
            let mut chosen_indices: Vec<u64> = Vec::new();

            for (index, share_vec_u8) in all_shares {
                // ❗ [수정] `ark-deserialize`로 `Vec<JubJubAffine>` 복원
                let partial_points: Vec<JubJubAffine> =
                    Vec::<JubJubAffine>::deserialize_with_mode(&share_vec_u8[..], Compress::Yes, Validate::Yes)
                        .expect("Failed to deserialize partial share");

                if partial_points.len() != num_candidates {
                    tracing::warn!("Partial share size mismatch from authority {}, skipping.", index);
                    continue;
                }

                chosen_indices.push(index as u64);
                deserialized_shares.push((index as u64, partial_points));
            }

            if deserialized_shares.is_empty() {
                tracing::error!("Not enough shares to decrypt (0 < t)");
                return Vec::new();
            }

            const MAX_VOTES_PER_CANDIDATE: u64 = 1_000_000;
            let g = JubJubAffine::generator();
            let mut final_counts: Vec<u64> = Vec::with_capacity(num_candidates);

            // 3. 후보자별로 셰어 결합 (이후 로직은 동일)
            for i in 0..num_candidates {
                let c2 = final_tallies[i].c2;

                let shares_for_this_candidate: Vec<(u64, JubJubAffine)> = deserialized_shares
                    .iter()
                    .map(|(idx, shares)| (*idx, shares[i]))
                    .collect();

                // [라이브러리 호출]
                let decrypted_tally_point = elgamal::combine_shares_threshold(
                    &c2,
                    &shares_for_this_candidate,
                    &chosen_indices,
                );

                // [헬퍼 호출]
                let count = decode_vote(&decrypted_tally_point, &g, MAX_VOTES_PER_CANDIDATE)
                    .unwrap_or_else(|| {
                        tracing::error!("Failed to decode vote count for candidate {}!", i);
                        0
                    });

                final_counts.push(count);
            }

            final_counts
        })
            .await
            .unwrap()
    }

    async fn cleanup_task(inner: Arc<NetworkSyncerInner<H>>) -> Option<()> {
        let cleanup_interval = Duration::from_secs(10);
        loop {
            select! {
                _sleep = runtime::sleep(cleanup_interval) => {
                    // Keep read lock for everything else
                    inner.syncer.cleanup().await;
                }
                _stopped = inner.stopped() => {
                    return None;
                }
            }
        }
    }

    pub async fn await_completion(self) -> Result<(), JoinError> {
        self.main_task.await
    }
}

impl<H: BlockHandler + 'static> NetworkSyncerInner<H> {

    // Returns None either if channel is closed or NetworkSyncerInner receives stop signal
    async fn recv_or_stopped<T>(&self, channel: &mut mpsc::Receiver<T>) -> Option<T> {
        select! {
            stopped = self.stop.send(()) => {
                assert!(stopped.is_err());
                None
            }
            data = channel.recv() => {
                data
            }
        }
    }

    async fn stopped(&self) {
        select! {
            stopped = self.stop.send(()) => {
                assert!(stopped.is_err());
            }
        }
    }
}

impl SyncerSignals for Arc<Notify> {
    fn new_block_ready(&mut self) {
        self.notify_waiters();
    }
}

pub struct AsyncWalSyncer {
    wal_syncer: WalSyncer,
    stop: mpsc::Sender<()>,
    _sender: oneshot::Sender<()>,
    runtime: tokio::runtime::Handle,
}

impl AsyncWalSyncer {
    #[cfg(not(feature = "simulator"))]
    pub fn start(
        wal_syncer: WalSyncer,
        stop: mpsc::Sender<()>,
    ) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        let this = Self {
            wal_syncer,
            stop,
            _sender: sender,
            runtime: tokio::runtime::Handle::current(),
        };
        std::thread::Builder::new()
            .name("wal-syncer".to_string())
            .spawn(move || this.run())
            .expect("Failed to spawn wal-syncer");
        receiver
    }

    #[cfg(feature = "simulator")]
    pub fn start(
        _wal_syncer: WalSyncer,
        _stop: mpsc::Sender<()>,
        _epoch_signal: mpsc::Sender<()>,
    ) -> oneshot::Receiver<()> {
        oneshot::channel().1
    }

    pub fn run(mut self) {
        let runtime = self.runtime.clone();
        loop {
            if runtime.block_on(self.wait_next()) {
                return;
            }
            self.wal_syncer.sync().expect("Failed to sync wal");
        }
    }

    // Returns true to stop the task
    async fn wait_next(&mut self) -> bool {
        select! {
            _wait = runtime::sleep(Duration::from_secs(1)) => {
                false
            }
            _signal = self.stop.send(()) => {
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::test_util::{check_commits, network_syncers};

    #[tokio::test]
    async fn test_network_sync() {
        let network_syncers = network_syncers(4).await;
        println!("Started");
        tokio::time::sleep(Duration::from_secs(3)).await;
        println!("Done");
        let mut syncers = vec![];
        for network_syncer in network_syncers {
            let syncer = network_syncer.shutdown().await;
            syncers.push(syncer);
        }

        check_commits(&syncers);
    }
}

#[cfg(test)]
#[cfg(feature = "simulator")]
mod sim_tests {
    use std::{
        sync::{atomic::Ordering, Arc},
        time::Duration,
    };

    use tokio::sync::Notify;

    use super::NetworkSyncer;
    use crate::{
        block_handler::{TestBlockHandler, TestCommitHandler},
        config,
        config::NodePublicConfig,
        finalization_interpreter::FinalizationInterpreter,
        future_simulator::SimulatedExecutorState,
        runtime,
        simulator_tracing::setup_simulator_tracing,
        syncer::Syncer,
        test_util::{
            check_commits,
            print_stats,
            rng_at_seed,
            simulated_network_syncers,
            simulated_network_syncers_with_epoch_duration,
        },
    };

    async fn wait_for_epoch_to_close(
        network_syncers: Vec<NetworkSyncer<TestBlockHandler, TestCommitHandler>>,
    ) -> Vec<Syncer<TestBlockHandler, Arc<Notify>, TestCommitHandler>> {
        let mut any_closed = false;
        while !any_closed {
            for net_sync in network_syncers.iter() {
                if net_sync.inner.epoch_closing_time.load(Ordering::Relaxed) != 0 {
                    any_closed = true;
                }
            }
            runtime::sleep(Duration::from_secs(10)).await;
        }
        runtime::sleep(config::node_defaults::default_shutdown_grace_period()).await;
        let mut syncers = vec![];
        for net_sync in network_syncers {
            let syncer = net_sync.shutdown().await;
            syncers.push(syncer);
        }
        syncers
    }
    #[test]
    fn test_exact_commits_in_epoch() {
        SimulatedExecutorState::run(rng_at_seed(0), test_exact_commits_in_epoch_async());
    }

    async fn test_exact_commits_in_epoch_async() {
        let n = 4;
        let rounds_in_epoch = 3000;
        let (simulated_network, network_syncers, mut reporters) =
            simulated_network_syncers_with_epoch_duration(n, rounds_in_epoch);
        simulated_network.connect_all().await;
        let syncers = wait_for_epoch_to_close(network_syncers).await;
        let canonical_commit_seq = syncers[0].commit_observer().committed_leaders().clone();
        for syncer in &syncers {
            let commit_seq = syncer.commit_observer().committed_leaders().clone();
            assert_eq!(canonical_commit_seq, commit_seq);
        }
        print_stats(&syncers, &mut reporters);
    }

    #[test]
    fn test_finalization_epoch_safety() {
        SimulatedExecutorState::run(rng_at_seed(0), test_finalization_safety_async());
    }

    async fn test_finalization_safety_async() {
        // todo - no cleanup of block store
        let n = 4;
        let rounds_in_epoch = 10;
        let (simulated_network, network_syncers, mut reporters) =
            simulated_network_syncers_with_epoch_duration(n, rounds_in_epoch);
        simulated_network.connect_all().await;
        let syncers = wait_for_epoch_to_close(network_syncers).await;
        for syncer in &syncers {
            let block_store = syncer.core().block_store();
            let committee = syncer.core().committee().clone();
            let latest_committed_leader =
                syncer.commit_observer().committed_leaders().last().unwrap();

            println!(
                "Num of Committed leaders: {:?}",
                syncer.commit_observer().committed_leaders()
            );

            let mut finalization_interpreter = FinalizationInterpreter::new(block_store, committee);
            let finalized_tx_certifying_blocks =
                finalization_interpreter.finalized_tx_certifying_blocks();

            for (_, certificates) in finalized_tx_certifying_blocks {
                // check if at least one certificate is committed
                let mut committed = false;
                for certifying_block in certificates {
                    if block_store.linked(
                        &block_store.get_block(*latest_committed_leader).unwrap(),
                        &block_store.get_block(certifying_block).unwrap(),
                    ) {
                        committed = true;
                        break;
                    }
                }
                assert!(committed);
            }
        }
        print_stats(&syncers, &mut reporters);
    }

    #[test]
    fn test_network_sync_sim_all_up() {
        setup_simulator_tracing();
        SimulatedExecutorState::run(rng_at_seed(0), test_network_sync_sim_all_up_async());
    }

    async fn test_network_sync_sim_all_up_async() {
        let (simulated_network, network_syncers, mut reporters) = simulated_network_syncers(10);
        simulated_network.connect_all().await;
        runtime::sleep(Duration::from_secs(20)).await;
        let mut syncers = vec![];
        for network_syncer in network_syncers {
            let syncer = network_syncer.shutdown().await;
            syncers.push(syncer);
        }

        check_commits(&syncers);
        print_stats(&syncers, &mut reporters);
    }

    #[test]
    fn test_network_sync_sim_one_down() {
        setup_simulator_tracing();
        SimulatedExecutorState::run(rng_at_seed(0), test_network_sync_sim_one_down_async());
    }

    // All peers except for peer A are connected in this test
    // Peer A is disconnected from everything
    async fn test_network_sync_sim_one_down_async() {
        let (simulated_network, network_syncers, mut reporters) = simulated_network_syncers(10);
        simulated_network.connect_some(|a, _b| a != 0).await;
        println!("Started");
        runtime::sleep(Duration::from_secs(40)).await;
        println!("Done");
        let mut syncers = vec![];
        for network_syncer in network_syncers {
            let syncer = network_syncer.shutdown().await;
            syncers.push(syncer);
        }

        check_commits(&syncers);
        print_stats(&syncers, &mut reporters);
    }

    #[test]
    fn test_network_partition() {
        setup_simulator_tracing();
        SimulatedExecutorState::run(rng_at_seed(0), test_network_partition_async());
    }

    // All peers except for peer A are connected in this test. Peer A is disconnected from everyone
    // except for peer B. This test ensures that A eventually manages to commit by syncing with B.
    async fn test_network_partition_async() {
        let (simulated_network, network_syncers, mut reporters) = simulated_network_syncers(10);
        // Disconnect all A from all peers except for B.
        simulated_network
            .connect_some(|a, b| a != 0 || (a == 0 && b == 1))
            .await;

        println!("Started");
        runtime::sleep(Duration::from_secs(40)).await;
        println!("Done");
        let mut syncers = vec![];
        for network_syncer in network_syncers {
            let syncer = network_syncer.shutdown().await;
            syncers.push(syncer);
        }

        // Ensure no conflicts.
        check_commits(&syncers);
        print_stats(&syncers, &mut reporters);
    }
}
