// 'threshold_elgamal.rs' 파일의 모든 코드가 이 모듈에 포함되어 있다고 가정합니다.
// mod threshold_elgamal;
// use threshold_elgamal::*;

// ... (threshold_elgamal.rs의 모든 use 문장) ...
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{
    EdwardsAffine as JubJubAffine,
    EdwardsProjective as JubJub,
};
use ark_ff::{PrimeField, Field, Zero, One, UniformRand};
use ark_std::{rand, test_rng};
use std::collections::HashMap;
use std::iter::Sum;
use std::ops::Mul;
use crate::elgamal::{pk_from_commitments, shamir_split_with_commitments, verify_share_with_commitments, Share};
// ... (threshold_elgamal.rs의 모든 함수: Share, eval_poly, ...) ...
//  제공된 파일의 모든 코드가 여기 있다고 가정합니다)


#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::run_dkg_simulation_for_data_generator;
    use crate::elgamal::{elgamal_encrypt, encode_vote};
    use ark_ec::{CurveGroup, AffineRepr};
    use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub, Fr as JubJubFr};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;
    use std::sync::Arc;
    use ark_bls12_381::Fr;
    use ark_crypto_primitives::crh::CRHScheme;
    use ark_crypto_primitives::crh::poseidon::CRH;
    use ark_crypto_primitives::encryption::elgamal::Ciphertext;
    use ark_crypto_primitives::merkle_tree::MerkleTree;
    use ark_ff::{BigInteger, ToConstraintField};
    use crate::zkp::{prove, setup, setup_poseidon_params, verify, MerkleTreePoseidonConfig};

    #[test]
    fn test_integration_dkg_and_zk_flow() {
        // 1. [설정] 파라미터 정의 (실제 환경과 유사하게 설정)
        let n = 10; // 위원회 크기
        let t = 3;  // 임계값
        let num_voters = 10; // 테스트용 유권자 수
        let num_candidates = 3; // 후보자 수
        let global_seed = 1234567890; // 고정 시드
        let g = JubJubAffine::generator();
        let election_id = "test-election-2025";
        let election_id_fr = Fr::from_le_bytes_mod_order(election_id.as_bytes());


        println!("\n=== [Test] 1. DKG 시뮬레이션 시작 ===");
        // 실제 data-generator에서 사용하는 함수 호출
        let master_pk = run_dkg_simulation_for_data_generator(n, t, global_seed);
        println!("=== [Test] Master PK 생성 완료: {:?} ===", master_pk);

        println!("\n=== [Test] 2. ZK Setup 시작 ===");
        let merkle_height = 4; // num_voters=10 이므로 충분한 높이 설정
        let (pk, vk) = setup(
            num_candidates,
            merkle_height,
            master_pk, // DKG로 만든 키 사용
            g,
            election_id_fr
        ).expect("ZK Setup failed");
        println!("=== [Test] ZK Setup 완료 ===");

        println!("\n=== [Test] 3. 유권자 및 머클 트리 구성 ===");
        let (params_leaf, params_merkle, params_nullifier) = setup_poseidon_params();

        // 유권자 데이터 생성
        let mut voter_data = Vec::new();
        let mut leaves = Vec::new();

        // 결정론적 RNG 사용 (재현성 위해)
        let mut data_rng = StdRng::seed_from_u64(999);

        for _ in 0..num_voters {
            let cred = Fr::rand(&mut data_rng);
            let leaf = CRH::evaluate(&params_leaf, [cred, election_id_fr]).unwrap();
            voter_data.push((cred, leaf));
            leaves.push(leaf);
        }

        // 패딩 및 트리 생성
        let num_leaves = 2_usize.pow(merkle_height as u32);
        leaves.resize(num_leaves, Fr::zero());
        let tree = MerkleTree::<MerkleTreePoseidonConfig>::new_with_leaf_digest(
            &params_leaf,
            &params_merkle,
            leaves
        ).unwrap();
        let root = tree.root();
        println!("=== [Test] Merkle Root: {:?} ===", root);

        println!("\n=== [Test] 4. 투표 트랜잭션 생성 및 증명 (Prove) ===");
        // 첫 번째 유권자가 투표한다고 가정
        let (cred, _leaf) = voter_data[0];
        let merkle_path = tree.generate_proof(0).unwrap();

        let mut vote_rng = StdRng::seed_from_u64(1111);
        let vote_idx = 1; // 1번 후보에게 투표
        let mut vote_u8 = vec![0u8; num_candidates];
        vote_u8[vote_idx] = 1;

        // ElGamal 암호화 (Affine 결과)
        let r = JubJubFr::rand(&mut vote_rng);
        let mut enc_vote_vec_affine = Vec::new(); // (Affine, Affine)

        for i in 0..num_candidates {
            let is_selected = i == vote_idx;
            let vote_val = if is_selected { 1 } else { 0 };
            let vote_point = encode_vote(vote_val, &g);
            let (c1, c2) = elgamal_encrypt(&vote_point, &master_pk, &g, r);
            enc_vote_vec_affine.push((c1, c2));
        }

        // [중요] Prove 함수는 현재 Projective 타입을 요구함. 변환 수행.
        let enc_vote_vec_projective: Vec<Ciphertext<JubJub>> = enc_vote_vec_affine
            .iter()
            .map(|(c1, c2)| (c1.into_group().into_affine(), c2.into_group().into_affine()))
            .collect();

        let (proof, public_inputs) = prove(
            &pk,
            &cred.into_bigint().to_bytes_le(),
            merkle_path,
            vote_u8,
            r,
            election_id,
            root,
            enc_vote_vec_projective.clone(), // Projective 주입
            master_pk, // PublicKey<JubJub> = EdwardsProjective
            g,
            &mut vote_rng
        ).expect("Prove failed");
        println!("=== [Test] 증명 생성 성공 ===");

        // Nullifier 계산 (검증용)
        let nf_constant = Fr::from_le_bytes_mod_order(b"NF");
        let nullifier = CRH::evaluate(&params_nullifier, [nf_constant, cred]).unwrap();

        println!("\n=== [Test] 5. 검증 (Verify) ===");
        // Verify 함수도 현재 Projective 타입을 요구함
        let is_valid = verify(
            &vk,
            &proof,
            &enc_vote_vec_projective, // Projective 주입
            root,
            nullifier
        ).expect("Verify function error");

        if is_valid {
            println!(">>> [SUCCESS] 검증 성공! DKG 키와 ZK 증명이 일치합니다.");
        } else {
            println!(">>> [FAILURE] 검증 실패! Invalid ZK Proof.");
            // 실패 시 Affine 변환 문제일 가능성이 큼
            panic!("Verification failed with current code structure");
        }
    }
}
