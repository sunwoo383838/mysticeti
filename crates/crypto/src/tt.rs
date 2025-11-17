// 'threshold_elgamal.rs' 파일의 모든 코드가 이 모듈에 포함되어 있다고 가정합니다.
// mod threshold_elgamal;
// use threshold_elgamal::*;

// ... (threshold_elgamal.rs의 모든 use 문장) ...
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{
    EdwardsAffine as JubJubAffine,
    EdwardsProjective as JubJub,
    Fr,
};
use ark_ff::{PrimeField, Field, Zero, One, UniformRand};
use ark_std::{rand, test_rng};
use std::collections::HashMap;
use std::iter::Sum;
use std::ops::Mul;
use crate::elgamal::{pk_from_commitments, shamir_split_with_commitments, verify_share_with_commitments, Share};
// ... (threshold_elgamal.rs의 모든 함수: Share, eval_poly, ...) ...
//  제공된 파일의 모든 코드가 여기 있다고 가정합니다)


// --- DKG 및 ElGamal을 위한 헬퍼 함수 ---

/// 표준 ElGamal 암호화
/// C1 = r * G
/// C2 = M + r * PK
fn elgamal_encrypt<R: rand::Rng>(
    msg_point: &JubJubAffine,
    pk: &JubJubAffine,
    g: &JubJubAffine,
    rng: &mut R,
) -> (JubJubAffine, JubJubAffine) {
    let r = Fr::rand(rng); // 암호화를 위한 랜덤 스칼라 r

    // C1 = r * G
    let c1 = g.mul(r).into_affine();

    // C2 = M + r * PK
    let r_pk = pk.mul(r);
    let c2 = (msg_point.into_group() + r_pk).into_affine();

    (c1, c2)
}

/// (t, n) DKG 시뮬레이션을 실행하고 최종 키를 반환하는 헬퍼 함수.
///
/// 반환:
/// - `master_pk`: 시스템 전체의 마스터 공개키 (PK = V_0)
/// - `master_shares`: N명의 참여자 각각의 최종 비밀 셰어 (s_j)
fn run_dkg<R: rand::Rng>(
    t: usize,
    n: usize,
    g: JubJubAffine,
    rng: &mut R,
) -> (JubJubAffine, Vec<Share>) {

    // --- 1. Phase 1: Dealing & Distributing ---
    // (네트워크 통신 시뮬레이션)
    let mut all_broadcasted_commits: HashMap<u64, Vec<JubJubAffine>> = HashMap::new();
    let mut p2p_messages: Vec<(u64, u64, Fr)> = Vec::new(); // (sender_i, receiver_j, share_s_ij)

    for i in 1..=n as u64 {
        let my_secret_contribution = Fr::rand(rng);
        let (shares, _, commits) =
            shamir_split_with_commitments(my_secret_contribution, t, n, g, rng);

        all_broadcasted_commits.insert(i, commits);
        for share in shares {
            p2p_messages.push((i, share.index, share.value));
        }
    }

    // --- 2. Phase 2: Verification ---
    let mut received_shares_for_participant: Vec<Vec<Share>> = vec![Vec::new(); n + 1];
    for (i, j, s_ij) in p2p_messages {
        let share_from_i = Share { index: j, value: s_ij };
        let commits_from_i = &all_broadcasted_commits[&i];

        // VSS 검증
        let is_valid = verify_share_with_commitments(&share_from_i, commits_from_i, g);
        assert!(is_valid, "DKG 검증 실패!");

        received_shares_for_participant[j as usize].push(share_from_i);
    }

    // --- 3. Phase 3: Aggregation ---
    let mut final_master_shares: Vec<Share> = Vec::new();
    let mut final_master_commits_proj: Vec<JubJub> = vec![JubJub::zero(); t];

    // 최종 마스터 셰어(s_j) 계산
    for j in 1..=n as u64 {
        let sub_shares = &received_shares_for_participant[j as usize];
        let final_share_value = sub_shares.iter().map(|s| s.value).sum::<Fr>();
        final_master_shares.push(Share {
            index: j,
            value: final_share_value, // j의 최종 비밀 셰어
        });
    }

    // 최종 마스터 커밋(V_k) 계산
    for k in 0..t {
        for i in 1..=n as u64 {
            final_master_commits_proj[k] += all_broadcasted_commits[&i][k];
        }
    }
    let final_master_commits: Vec<JubJubAffine> = final_master_commits_proj
        .iter()
        .map(|p| p.into_affine())
        .collect();

    // DKG 완료: PK = V_0
    let master_pk = pk_from_commitments(&final_master_commits);

    (master_pk, final_master_shares)
}


// --- 새로운 헬퍼 함수들 ---

/// 투표(정수)를 타원곡선 위의 점으로 인코딩합니다.
/// 0 -> 점(0) (항등원)
/// k -> k * G
fn encode_vote(vote: u64, g: &JubJubAffine) -> JubJubAffine {
    if vote == 0 {
        JubJub::zero().into_affine()
    } else {
        g.mul(Fr::from(vote)).into_affine()
    }
}

/// 암호문 타입 별칭 (C1, C2)
type Ciphertext = (JubJubAffine, JubJubAffine);

/// (동형) 암호문들을 집계(합산)합니다.
/// (C1_a, C2_a) + (C1_b, C2_b) = (C1_a + C1_b, C2_a + C2_b)
fn aggregate_ciphertexts(ciphertexts: &[Ciphertext]) -> Ciphertext {
    let mut c1_agg = JubJub::zero();
    let mut c2_agg = JubJub::zero();

    for (c1, c2) in ciphertexts {
        c1_agg += c1.into_group();
        c2_agg += c2.into_group();
    }

    (c1_agg.into_affine(), c2_agg.into_affine())
}


// --- 메인 테스트 함수 ---

#[cfg(test)]
mod dkg_tally_test {
    use crate::elgamal::{combine_shares_threshold, ct_sum, partial_decrypt_share};
    use super::*; // 상위 모듈의 모든 항목을 가져옵니다.

    #[test]
    fn test_homomorphic_tallying_and_threshold_decrypt() {
        let mut rng = test_rng();

        // --- 0. 설정 ---
        let n = 4; // 전체 참여자 4명
        let t = 3; // 임계값 3명
        let g = JubJubAffine::generator();

        println!("--- (t,n) = ({}, {}) 동형 투표 집계 E2E 테스트 시작 ---", t, n);

        // --- 1. DKG 실행 ---
        let (master_pk, master_shares) = run_dkg(t, n, g, &mut rng);
        println!("DKG 완료. 마스터 PK 생성됨.");

        // --- 2. 투표 데이터 및 인코딩 정의 ---
        // 투표자 A, B, C의 투표 (후보1, 후보2, 후보3)
        // 요청하신 가중치 투표 [2, 6, 12]를 적용합니다.
        let vote_a = [0, 1, 0];
        let weight_a = 2;

        let vote_b = [1, 1, 0];
        let weight_b = 6;

        let vote_c = [1, 1, 1];
        let weight_c = 12;

        // --- 3. 각 유권자가 자신의 가중치 투표용지를 암호화 ---
        println!("각 유권자가 3명의 후보에 대해 *가중치*가 적용된 투표용지 생성 중...");

        // C_A = [Enc(0*2), Enc(1*2), Enc(0*2)] = [Enc(0), Enc(2), Enc(0)]
        let ballot_a: Vec<Ciphertext> = vote_a.iter()
            .map(|&v| {
                let msg_point = encode_vote(v * weight_a, &g);
                elgamal_encrypt(&msg_point, &master_pk, &g, &mut rng)
            })
            .collect();

        // C_B = [Enc(1*6), Enc(1*6), Enc(0*6)] = [Enc(6), Enc(6), Enc(0)]
        let ballot_b: Vec<Ciphertext> = vote_b.iter()
            .map(|&v| {
                let msg_point = encode_vote(v * weight_b, &g);
                elgamal_encrypt(&msg_point, &master_pk, &g, &mut rng)
            })
            .collect();

        // C_C = [Enc(1*12), Enc(1*12), Enc(1*12)] = [Enc(12), Enc(12), Enc(12)]
        let ballot_c: Vec<Ciphertext> = vote_c.iter()
            .map(|&v| {
                let msg_point = encode_vote(v * weight_c, &g);
                elgamal_encrypt(&msg_point, &master_pk, &g, &mut rng)
            })
            .collect();

        // --- 4. 집계 서버가 암호화된 투표함 집계 ---
        println!("집계 서버가 후보별로 암호화된 투표를 합산 중...");

        // 후보 1의 최종 암호문: Enc(0) + Enc(6) + Enc(12) = Enc(0 + 6 + 12) = Enc(18)
        let tally_c1 = ct_sum(&[ballot_a[0], ballot_b[0], ballot_c[0]]);

        // 후보 2의 최종 암호문: Enc(2) + Enc(6) + Enc(12) = Enc(2 + 6 + 12) = Enc(20)
        let tally_c2 = aggregate_ciphertexts(&[ballot_a[1], ballot_b[1], ballot_c[1]]);

        // 후보 3의 최종 암호문: Enc(0) + Enc(0) + Enc(12) = Enc(0 + 0 + 12) = Enc(12)
        let tally_c3 = aggregate_ciphertexts(&[ballot_a[2], ballot_b[2], ballot_c[2]]);

        let final_tallies = vec![tally_c1, tally_c2, tally_c3];
        // [0*2+1*6+1*12, 1*2+1*6+1*12, 0*2+0*6+1*12] = [18, 20, 12]
        let expected_counts = vec![18, 20, 12];

        // --- 5. 임계 복호화 (t=3명 참여) ---
        let decrypting_participants: Vec<Share> = master_shares.iter().take(t).cloned().collect();
        let chosen_indices: Vec<u64> = decrypting_participants.iter().map(|s| s.index).collect();
        println!("{}명의 복호화 참여자(인덱스: {:?})가 집계된 암호문 복호화 시작...", t, chosen_indices);

        for (i, (c1, c2)) in final_tallies.iter().enumerate() {
            let candidate_index = i + 1;
            println!("  > 후보 {}의 최종 투표함(암호문) 복호화 중...", candidate_index);

            // 5.1. 부분 복호화 셰어 계산
            let partial_shares: Vec<(u64, JubJubAffine)> = decrypting_participants.iter()
                .map(|p_share| {
                    // D_i = s_i * C1
                    let d_i = partial_decrypt_share(c1, p_share.value);
                    (p_share.index, d_i)
                })
                .collect();

            // 5.2. 셰어 결합
            // M_tally = C2 - Σ(λ_i * D_i)
            let decrypted_tally_point = combine_shares_threshold(
                c2,
                &partial_shares,
                &chosen_indices,
            );

            // --- 6. 검증 ---
            let expected_count = expected_counts[i];
            let expected_point = encode_vote(expected_count, &g);

            println!("    - 복호화 결과 (점): {:?}", decrypted_tally_point);
            println!("    - 기대한 결과 (점): {:?} ({} * G)", expected_point, expected_count);

            assert_eq!(
                decrypted_tally_point,
                expected_point,
                "!!! 집계 실패: 후보 {}의 득표수가 {}이어야 하는데 다릅니다!",
                candidate_index,
                expected_count
            );
            println!("    - [검증 성공] 후보 {}의 득표수는 {}입니다.", candidate_index, expected_count);
        }

        println!("\n[성공] 모든 후보의 *가중치* 득표수가 동형 집계 및 임계 복호화를 통해 정확히 검증되었습니다.");

        // 사용자님의 질문에 대한 구체적인 확인
        let expected_candidate_2_votes = 2 + 6 + 12; // 20
        assert_eq!(expected_counts[1], expected_candidate_2_votes, "테스트 로직 오류: 2번 후보의 기대값이 20이 아닙니다!");
        println!("\n참고: 요청하신 2번째 후보자의 득표수 [1*2, 1*6, 1*12]의 합은 {}이 맞습니다.", expected_candidate_2_votes);
    }
}