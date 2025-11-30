
use std::collections::HashMap;
use std::sync::Arc;
use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::twisted_edwards::Affine;
use crate::types::AuthorityIndex;
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub, Fr as JubJubFr, JubjubConfig};
use ark_ff::Zero;
use ark_serialize::{serialize_to_vec, CanonicalSerialize};
use ark_std::UniformRand;
use serde::Serialize;
use tokio::sync::{mpsc, Notify};
use crypto::dkg::get_dkg_rng_for_participant;
use crypto::elgamal::{pk_from_commitments, shamir_split_with_commitments, verify_share_with_commitments, Share};
use crate::committee::{Authority, Committee};
use crate::config::{CryptoConfig, NodePublicConfig};
use crate::network::NetworkMessage;

#[derive(Debug)]
pub enum DkgState {
    Idle,
    AwaitingCommitments(HashMap<AuthorityIndex, Vec<JubJubAffine>>),
    AwaitingShares(
        HashMap<AuthorityIndex, Vec<JubJubAffine>>, // 모든 커밋 (셰어 검증용)
        HashMap<AuthorityIndex, Share>, // (i, s_ij) 셰어 (i = 보낸 사람)
    ),
    Complete,
    AwaitingPartialDecryptions(
        HashMap<AuthorityIndex, Vec<u8>>, // (i, PartialShare_i)
        Arc<Notify>, // Tally 수집 완료 알림용 Notify
    ),
}

/// DKG 프로토콜의 상태 머신 및 네트워크 통신을 관리
pub struct DkgManager {
    state: DkgState,
    my_index: AuthorityIndex,
    committee: Arc<Committee>,
    g: Affine<JubjubConfig>,
    t: usize,
    n: usize,
    dkg_complete_notify: Arc<Notify>,
    my_shares_to_send: Vec<Share>,
    my_commits: Vec<JubJubAffine>,

    pub final_pk: Option<JubJubAffine>,
    pub final_sk_share: Option<JubJubFr>,
    pending_shares: HashMap<AuthorityIndex, Share>,

    // 네트워크
    network_senders: HashMap<AuthorityIndex, mpsc::Sender<NetworkMessage>>,
    global_seed: u64
}

impl DkgManager {
    pub fn new(
        my_index: AuthorityIndex,
        committee: Arc<Committee>,
        dkg_complete_notify: Arc<Notify>,
        crypto_config: &CryptoConfig,
    ) -> Self {
        Self {
            state: DkgState::Idle,
            my_index,
            g: JubJubAffine::generator(),
            t: (committee.len() * 2 / 3) + 1,
            n: committee.len(),
            committee,
            dkg_complete_notify,
            my_shares_to_send: Vec::new(),
            my_commits: Vec::new(),
            final_pk: None,
            final_sk_share: None,
            network_senders: HashMap::new(),
            global_seed: crypto_config.global_seed,
            pending_shares: HashMap::new(), // [초기화]
        }
    }

    pub fn get_connected_peer_count(&self) -> usize {
        self.network_senders.len()
    }

    pub fn register_peer(&mut self, peer_id: AuthorityIndex, sender: mpsc::Sender<NetworkMessage>) {
        if peer_id != self.my_index {
            self.network_senders.insert(peer_id, sender.clone());

            // 🌟 [수정] 이미 DKG가 시작되어 커밋을 생성한 상태라면(my_commits가 존재),
            // 뒤늦게 연결(또는 재연결)된 피어에게 내 커밋을 다시 전송해줍니다.
            if !self.my_commits.is_empty() {
                let msg = NetworkMessage::DkgCommitment(self.my_commits.clone());
                let peer_id_clone = peer_id;

                // 비동기 전송을 위해 토키오 태스크 스폰 (블로킹 방지)
                tokio::spawn(async move {
                    if let Err(e) = sender.send(msg).await {
                        tracing::warn!("[DKG] 재연결된 {peer_id_clone}번 피어에게 커밋 재전송 실패: {e}");
                    } else {
                        tracing::info!("[DKG] 재연결된 {peer_id_clone}번 피어에게 커밋 재전송 완료");
                    }
                });
            }
        }
    }

    pub fn unregister_peer(&mut self, peer_id: AuthorityIndex) {
        self.network_senders.remove(&peer_id);
    }

    pub async fn start_dkg(&mut self) {
        match self.state {
            DkgState::Idle | DkgState::AwaitingCommitments(_) => {
                // 이미 시작했는지 확인 (my_commits가 비어있지 않으면 이미 시작한 것임)
                if !self.my_commits.is_empty() {
                    tracing::warn!("DKG start called but already generated commits. Skipping generation.");
                    return;
                }

                let global_seed = self.global_seed;
                let mut rng = get_dkg_rng_for_participant(global_seed, self.my_index);

                tracing::info!("[DKG] 1단계: (t={}, n={}) 셰어 및 커밋 생성 중...", self.t, self.n);
                let my_secret_contribution = JubJubFr::rand(&mut rng);
                let (shares, _, commits) =
                    shamir_split_with_commitments(my_secret_contribution, self.t, self.n, self.g, &mut rng);

                self.my_shares_to_send = shares;
                self.my_commits = commits.clone();

                tracing::info!("[DKG] 1단계: 생성된 커밋 브로드캐스트...");
                let msg = NetworkMessage::DkgCommitment(commits.clone());
                for (peer_id, sender) in &self.network_senders {
                    if let Err(e) = sender.send(msg.clone()).await {
                        tracing::warn!("[DKG] {peer_id}번 피어에게 커밋 전송 실패: {e}");
                    }
                }

                self.handle_commitment(self.my_index, self.my_commits.clone());
            }
            _ => {
                tracing::warn!("DKG가 이미 시작되었거나 완료되었습니다.");
                return;
            }
        }


    }

    pub fn handle_commitment(&mut self, sender_auth: AuthorityIndex, commits: Vec<JubJubAffine>) {
        let current_state_str = format!("{:?}", self.state);
        tracing::info!("[DKG] {sender_auth}번 피어로부터 커밋 수신 (현재 상태: {current_state_str})");

        if let DkgState::Idle = self.state {
            self.state = DkgState::AwaitingCommitments(HashMap::new());
        }

        if let DkgState::AwaitingCommitments(ref mut received_commits) = &mut self.state {
            if received_commits.insert(sender_auth, commits).is_some() {
                // 중복 처리
                return;
            }

            if received_commits.len() == self.n {
                tracing::info!("[DKG] 1단계 완료. 2단계(셰어 전송) 시작.");

                // 1. 셰어 전송 (기존 코드)
                let shares_to_send = self.my_shares_to_send.clone();
                let network_senders = self.network_senders.clone();
                let my_index = self.my_index;
                tokio::spawn(async move {
                    Self::send_shares(shares_to_send, network_senders, my_index, None).await;
                });

                // 2. 상태 변경 (AwaitingShares로 전이)
                // 여기서 `std::mem::take`를 사용해 커밋 맵을 가져옴
                let all_commits = std::mem::take(received_commits);
                self.state = DkgState::AwaitingShares(all_commits, HashMap::new());

                // 3. [핵심 수정] 자신의 셰어 처리
                let my_share = self.my_shares_to_send[self.my_index as usize].clone();
                self.handle_share(self.my_index, my_share);

                // 4. [핵심 수정] 버퍼링된(미리 도착한) 셰어들 재처리 (Replay)
                let pending: Vec<_> = self.pending_shares.drain().collect();
                if !pending.is_empty() {
                    tracing::info!("[DKG] 버퍼링된 {}개의 셰어를 재처리합니다.", pending.len());
                    for (sender, share) in pending {
                        self.handle_share(sender, share);
                    }
                }
            }
        }
    }

    /// 2-Helper. 각 피어에게 DkgShare 메시지를 유니캐스트 (비동기 실행)
    async fn send_shares(
        shares_to_send: Vec<Share>,
        network_senders: HashMap<AuthorityIndex, mpsc::Sender<NetworkMessage>>,
        my_index: AuthorityIndex,
        _self_sender: Option<mpsc::Sender<NetworkMessage>>, // (handle_share가 동기식으로 호출되므로 불필요)
    ) {
        for share in shares_to_send {
            let dest_auth_index = share.index - 1; // 셰어 인덱스(1-based) -> Authority 인덱스(0-based)

            if dest_auth_index == my_index {
                // (자신에게 보내는 셰어는 handle_commitment에서 동기적으로 처리했음)
                continue;
            }

            if let Some(sender) = network_senders.get(&dest_auth_index) {
                tracing::info!("[DKG] 2단계: {dest_auth_index}번 피어에게 셰어 전송 (인덱스: {})", share.index);
                if let Err(e) = sender.send(NetworkMessage::DkgShare(share)).await {
                    tracing::warn!("[DKG] {dest_auth_index}번 피어에게 셰어 전송 실패: {e}");
                }
            } else {
                tracing::warn!("[DKG] 2단계: {dest_auth_index}번 피어의 네트워크 Sender를 찾을 수 없음");
            }
        }

    }

    /// 3. `NetworkSyncer`가 DkgShare 메시지를 수신했을 때 호출
    pub fn handle_share(&mut self, sender_auth: AuthorityIndex, share: Share) {
        // 현재 상태 확인
        match &mut self.state {
            // 1. 정상 상태: 셰어를 기다리는 중
            DkgState::AwaitingShares(all_commits, received_shares) => {
                // --- 기존 검증 및 저장 로직 ---
                if share.index != self.my_index + 1 {
                    tracing::warn!("[DKG] 잘못된 인덱스 셰어 무시");
                    return;
                }

                let sender_commits = if let Some(c) = all_commits.get(&sender_auth) {
                    c
                } else {
                    tracing::error!("[DKG] {}번 피어의 커밋을 찾을 수 없음 (치명적 오류)", sender_auth);
                    return;
                };

                if !verify_share_with_commitments(&share, sender_commits, self.g) {
                    tracing::warn!("[DKG] VSS 검증 실패 from {}", sender_auth);
                    return;
                }

                if received_shares.insert(sender_auth, share).is_some() {
                    return; // 중복
                }

                // 모든 셰어 수집 완료 확인
                if received_shares.len() == self.n {
                    // 여기서 self를 mut로 빌려야 하므로, 데이터를 복제하여 함수 호출
                    let commits_clone = all_commits.clone();
                    let shares_clone = received_shares.clone();
                    self.aggregate_keys(&commits_clone, &shares_clone);
                }
            }

            // 2. 아직 준비 안 된 상태: 메시지 버퍼링
            DkgState::Idle | DkgState::AwaitingCommitments(_) => {
                tracing::info!("[DKG] 아직 셰어 수신 단계가 아님. {}번 피어의 셰어를 버퍼링합니다.", sender_auth);
                self.pending_shares.insert(sender_auth, share);
            }

            // 3. 이미 완료된 상태
            DkgState::Complete | DkgState::AwaitingPartialDecryptions(_, _) => {
                tracing::debug!("[DKG] 이미 완료된 상태에서 셰어 수신. 무시.");
            }
        }
    }

    pub async fn broadcast_partial_decryption(&mut self, partial_share_bytes: Vec<u8>) {
        if !matches!(self.state, DkgState::Complete) {
            tracing::error!("[Tally] DKG가 완료되지 않은 상태에서 부분 복호화를 시도했습니다.");
            return;
        }

        tracing::info!("[Tally] 6단계: 계산된 부분 복호화 셰어 브로드캐스트...");
        let msg = NetworkMessage::PartialDecryptionShare(partial_share_bytes.clone());

        for (peer_id, sender) in &self.network_senders {
            if let Err(e) = sender.send(msg.clone()).await {
                tracing::warn!("[Tally] {peer_id}번 피어에게 셰어 전송 실패: {e}");
            }
        }

        // ❗ 자신에게도 전송 (수집 로직을 트리거하기 위해)
        self.handle_partial_decryption(self.my_index, partial_share_bytes).await;
    }

    /// 7-Helper. `NetworkSyncer`가 `PartialDecryptionShare` 메시지를 수신했을 때 호출
    pub async fn handle_partial_decryption(
        &mut self,
        sender_auth: AuthorityIndex,
        share_bytes: Vec<u8>
    ) {
        let current_state_str = format!("{:?}", self.state);
        tracing::info!("[Tally] {sender_auth}번 피어로부터 부분 복호화 셰어 수신 (현재 상태: {current_state_str})");

        // Tally 상태가 아니면 초기화
        if !matches!(self.state, DkgState::AwaitingPartialDecryptions(_, _)) {
            if !matches!(self.state, DkgState::Complete) {
                tracing::warn!("[Tally] DKG가 완료되지 않은 상태에서 셰어를 수신했습니다. 무시합니다.");
                return;
            }
            // DKGState::Complete 상태에서 첫 셰어를 받으면 상태 전이
            self.state = DkgState::AwaitingPartialDecryptions(HashMap::new(), Arc::new(Notify::new()));
        }

        if let DkgState::AwaitingPartialDecryptions(ref mut received_shares, notify) = &mut self.state {
            if received_shares.insert(sender_auth, share_bytes).is_some() {
                tracing::warn!("[Tally] {sender_auth}번 피어로부터 중복된 부분 복호화 셰어 수신");
                return;
            }

            // ❗ 2f+1 (t) 개의 셰어를 수신했는지 확인
            if received_shares.len() >= self.t {
                tracing::info!("[Tally] 7단계 완료: {t}명 이상의 피어로부터 셰어 수신. 집계 완료.", t = self.t);
                // 대기 중인 `collect_partial_decryptions` 태스크를 깨움
                notify.notify_one();
            }
        }
    }

    /// 7. (Tally) 2f+1(t)개의 부분 복호화 셰어가 수집될 때까지 대기(await)합니다.
    pub async fn collect_partial_decryptions(&mut self) -> Vec<(AuthorityIndex, Vec<u8>)> {
        tracing::info!("[Tally] 7단계: {t}개의 부분 복호화 셰어 수집 대기 중...", t = self.t);

        let notify = match &self.state {
            DkgState::Complete => {
                // 아직 아무도 셰어를 보내지 않음. 상태를 전이시키고 Notify를 복제.
                let notify = Arc::new(Notify::new());
                self.state = DkgState::AwaitingPartialDecryptions(HashMap::new(), notify.clone());
                notify
            },
            DkgState::AwaitingPartialDecryptions(received_shares, notify) => {
                // 이미 일부 셰어를 받음.
                // 만약 이미 t개 이상을 받았다면 즉시 반환합니다.
                if received_shares.len() >= self.t {
                    tracing::info!("[Tally] 이미 {t}개 이상의 셰어를 보유 중. 즉시 반환.", t = self.t);
                    // 상태를 DKG 완료(Tally 대기) 상태로 되돌리고 셰어를 반환
                    if let DkgState::AwaitingPartialDecryptions(shares, _) = std::mem::replace(&mut self.state, DkgState::Complete) {
                        return shares.into_iter().collect();
                    } else {
                        unreachable!(); // 방금 상태를 확인했으므로
                    }
                }
                // 아직 t개가 안됐으면 Notify를 복제하여 대기
                notify.clone()
            },
            _ => {
                tracing::error!("[Tally] DKG가 완료되지 않은 상태에서 셰어 수집이 요청됨.");
                return Vec::new();
            }
        };

        // ❗ `handle_partial_decryption`에서 t개가 모여 `notify_one()`을 호출할 때까지 대기
        notify.notified().await;

        // Tally 완료 후, 상태를 다시 DKG 완료(Tally 대기) 상태로 되돌리고 셰어를 반환
        if let DkgState::AwaitingPartialDecryptions(shares, _) = std::mem::replace(&mut self.state, DkgState::Complete) {
            shares.into_iter().collect()
        } else {
            tracing::error!("[Tally] Notify 대기 후 상태가 AwaitingPartialDecryptions가 아님 (버그)");
            Vec::new()
        }
    }

    /// 3-Helper. 최종 마스터 키와 비밀 셰어 집계
    fn aggregate_keys(
        &mut self,
        all_commits: &HashMap<AuthorityIndex, Vec<JubJubAffine>>,
        all_shares: &HashMap<AuthorityIndex, Share> // (i, s_ij)
    ) {
        // 1. 최종 마스터 셰어(s_j) 계산: s_j = Σ_i s_ij (j = my_index)
        let my_final_share_value = all_shares.values()
            .map(|s| s.value)
            .sum::<JubJubFr>();

        // 2. 최종 마스터 커밋(V_k) 계산: V_k = Σ_i V_ik
        let mut final_master_commits_proj: Vec<JubJub> = vec![JubJub::zero(); self.t];
        for k in 0..self.t { // k = 0..t-1
            for i in 0..self.n as u64 { // i = 0..n-1
                final_master_commits_proj[k] += all_commits[&i][k];
            }
        }
        let final_master_commits: Vec<JubJubAffine> = final_master_commits_proj
            .iter().map(|p| p.into_affine()).collect();

        // 3. 최종 마스터 공개키(PK) 계산: PK = V_0
        let master_pk = pk_from_commitments(&final_master_commits);

        // 4. 결과 저장
        self.final_pk = Some(master_pk);
        self.final_sk_share = Some(my_final_share_value);
        self.state = DkgState::Complete;

        tracing::info!("[DKG] 3단계 완료: DKG 프로토콜 성공!");
        tracing::info!("[DKG]   > 최종 마스터 PK: {:?}", master_pk);

        // 5. Validator::start()에 대기 중인 태스크에 완료 신호 전송
        self.dkg_complete_notify.notify_one();
    }

    /// `Validator`가 최종 DKG 결과를 가져가기 위한 함수
    pub fn get_keys(&self) -> Option<(JubJubAffine, JubJubFr)> {
        if let DkgState::Complete = self.state {
            Some((self.final_pk.unwrap(), self.final_sk_share.unwrap()))
        } else {
            None
        }
    }
}
