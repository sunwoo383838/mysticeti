use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
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

type AuthorityIndex = u64;

pub fn rng_at_seed(seed: u64) -> StdRng{
    let bytes = seed.to_le_bytes();
    let mut seed_arr = [0u8; 32];
    seed_arr[..bytes.len()].copy_from_slice(&bytes);
    StdRng::from_seed(seed_arr)
}
pub fn get_dkg_rng_for_participant(
    global_seed: u64,
    authority_index: AuthorityIndex,
) -> StdRng {
    let participant_seed = global_seed.wrapping_add(authority_index);
    rng_at_seed(participant_seed)
}
pub fn run_dkg_simulation_for_data_generator(
    n: usize,
    t: usize,
    global_dkg_seed: u64,
) -> JubJubAffine {

    let g = JubJubAffine::generator();

    // (네트워크 시뮬레이션용 임시 저장소)
    let mut all_broadcasted_commits: HashMap<u64, Vec<JubJubAffine>> = HashMap::new();
    let mut p2p_messages: Vec<(u64, u64, Fr)> = Vec::new(); // (sender_i, receiver_j, share_s_ij)

    println!("--- (t,n)=({},{}) DKG 시뮬레이션 (Data-Gen) 시작 ---", t, n);
    println!("  Global Seed: {}", global_dkg_seed);

    // --- 1. Phase 1: Dealing (n명의 딜러 시뮬레이션) ---
    // 각 참여자 i (0..n-1)는 고유한 RNG를 가짐
    for i_auth_idx in 0..n as AuthorityIndex {

        // `shamir_split_with_commitments`는 1-based 인덱스(1..=n)를 사용합니다.
        // DKG 참여자 인덱스(1-based)
        let i_participant_idx = i_auth_idx + 1;

        // 'i'번 참여자의 결정론적 RNG 생성
        let mut local_rng = get_dkg_rng_for_participant(global_dkg_seed, i_auth_idx);

        // 이 RNG로 비밀 기여분(a_i,0) 생성
        let my_secret_contribution = Fr::rand(&mut local_rng);

        // *동일한* RNG로 나머지 계수(a_i,k) 및 셰어 생성
        // 셰어링 함수는 n명의 참여자(1..=n)를 대상으로 셰어를 생성합니다.
        let (shares_to_send, _, my_commits) =
            shamir_split_with_commitments(my_secret_contribution, t, n, g, &mut local_rng);

        // (네트워크 시뮬레이션)
        all_broadcasted_commits.insert(i_participant_idx, my_commits);
        for share in shares_to_send {
            p2p_messages.push((i_participant_idx, share.index, share.value));
        }
    }
    println!("Phase 1: {}명의 참여자가 각자 결정론적 셰어/커밋 생성 완료.", n);


    // --- 2. Phase 2: Verification (n명의 참여자 시뮬레이션) ---
    // `received_shares_for_participant[j]`는 j번(1-based) 참여자가 받은 셰어 목록
    let mut received_shares_for_participant: Vec<Vec<Share>> = vec![Vec::new(); n + 1];

    for (i, j, s_ij) in p2p_messages {
        let share_from_i = Share { index: j, value: s_ij };
        let commits_from_i = &all_broadcasted_commits[&i];

        let is_valid = verify_share_with_commitments(&share_from_i, commits_from_i, g);
        assert!(is_valid, "DKG 검증 실패! [Data Generator]");

        received_shares_for_participant[j as usize].push(share_from_i);
    }
    println!("Phase 2: 모든 P2P 셰어 VSS 검증 완료.");


    // --- 3. Phase 3: Aggregation (n명의 참여자 시뮬레이션) ---
    let mut final_master_commits_proj: Vec<JubJub> = vec![JubJub::zero(); t];

    // 모든 참여자는 공통의 마스터 커밋 V_k를 계산
    for k in 0..t {
        for i in 1..=n as u64 {
            final_master_commits_proj[k] += all_broadcasted_commits[&i][k];
        }
    }
    let final_master_commits: Vec<JubJubAffine> = final_master_commits_proj
        .iter()
        .map(|p| p.into_affine())
        .collect();

    println!("Phase 3: 최종 마스터 셰어 및 마스터 커밋 집계 완료.");

    // --- 4. 최종 키 반환 ---
    let master_pk = pk_from_commitments(&final_master_commits);

    // (master_shares는 index 0 -> 1번 참여자, index 39 -> 40번 참여자 셰어)
    master_pk
}


// --- 이 함수를 검증하기 위한 테스트 ---
#[cfg(test)]
mod tests {
    use ark_std::rand::prelude::SliceRandom;
    use super::*;
    use ark_std::test_rng;
    use crate::elgamal::reconstruct_secret;
    // 테스트 RNG가 아닌 결정론적 RNG를 사용해야 함

    #[test]
    fn test_deterministic_dkg_simulation() {
        let n = 40;
        let t = (n * 2 / 3) + 1; // 2f+1 임계값 (f=13, t=27)
        let global_seed_1 = 12345_u64;
        let global_seed_2 = 67890_u64;

        println!("--- 1차 실행 (Seed: {}) ---", global_seed_1);
        let pk1 = run_dkg_simulation_for_data_generator(n, t, global_seed_1);

        println!("--- 2차 실행 (Seed: {}) ---", global_seed_1);
        let pk2 = run_dkg_simulation_for_data_generator(n, t, global_seed_1);

        println!("--- 3차 실행 (Seed: {}) ---", global_seed_2);
        let pk3 = run_dkg_simulation_for_data_generator(n, t, global_seed_2);

        // 1. 동일한 시드는 동일한 PK를 생성해야 함
        assert_eq!(pk1, pk2, "동일한 시드로 DKG를 실행했으나 PK가 다릅니다!");
        println!("\n[검증 1] 동일 시드 실행 시 PK 일치 확인.");


        assert_ne!(pk1, pk3, "다른 시드로 DKG를 실행했으나 PK가 같습니다!");
        println!("[검증 3] 다른 시드 실행 시 PK 불일치 확인.");

        println!("\n[성공] 결정론적 DKG 시뮬레이션 검증 완료.");

   
    }
}
