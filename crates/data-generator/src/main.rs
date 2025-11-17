use eyre::{eyre, Context, Result};
// Report는 color_eyre::install()을 위해 필요할 수 있습니다.
use color_eyre::eyre::Report;

// --- (기존 use 문장들) ---
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, SystemTime};

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_crypto_primitives::encryption;
use ark_crypto_primitives::encryption::elgamal::Ciphertext;
use ark_crypto_primitives::merkle_tree::{MerkleTree, Path};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, Fr as JubJubFr, EdwardsProjective as JubJub};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, RngCore, SeedableRng};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use elgamal::PublicKey;
use encryption::elgamal;
use futures::future::try_join_all;
use rayon::prelude::*;
use serde::Serialize;
use crypto::dkg::{get_dkg_rng_for_participant, rng_at_seed, run_dkg_simulation_for_data_generator};
use crypto::elgamal::{elgamal_encrypt, encode_vote};
// --- 2. mysticeti-core에서 가져온 타입 및 로직 ---
// (mysticeti-core의 types.rs에 이 구조체들이 정의되어 있다고 가정)
// (Cargo.toml: mysticeti-core = { path = "../mysticeti-core" })
use crypto::types::{VoteTransaction, ZKElgamalCiphertext};
use crypto::zkp::{prove, setup, setup_poseidon_params, MerkleTreePoseidonConfig};

#[derive(Parser, Debug, Serialize)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(long, default_value_t = 4)]
    committee_size: usize,
    /// 임계값 (t)
    #[clap(long, default_value_t = 3)]
    threshold: usize,
    /// 생성할 총 유권자(트랜잭션) 수
    #[clap(long, default_value_t = 1000)]
    num_voters: usize,
    /// 선거 후보자 수
    #[clap(long, default_value_t = 3)]
    num_candidates: usize,
    /// 선거 ID (문자열)
    #[clap(long, default_value = "election-2025")]
    election_id: String,
    /// 생성된 배치 파일을 저장할 디렉토리
    #[clap(long, default_value = "benchmark_batches")]
    output_dir: PathBuf,
}

#[derive(Serialize, Debug)]
struct BenchmarkMetadata<'a> {
    /// 벤치마크 생성 시각 (ISO 8601)
    generation_timestamp: String,
    /// 실행 시 사용된 파라미터
    parameters: &'a Args,
    /// DKG/RNG 시드 정보
    dkg_seed: u64,
    /// 생성된 데이터의 속성
    derived_data: DerivedData,
}

#[derive(Serialize)]
struct CryptoConfig {
    num_candidates: usize,
    merkle_root: String,
    verifying_key: String,
    global_seed: u64,
}

#[derive(Serialize, Debug)]
struct DerivedData {
    merkle_height: usize,
    merkle_root: String,
    total_transactions_generated: usize,
}

fn main() -> Result<()>{
    color_eyre::install()?;
    let args = Args::parse();

    const GLOBAL_DKG_SEED: u64 = 1234567890;


    let n = args.committee_size;
    let t = args.threshold;
    let k_max = args.num_voters;
    let num_candidates = args.num_candidates;
    let g = JubJubAffine::generator();

    let new_dir_name = format!("n{}_t{}_k{}", n, t, k_max);
    let output_dir = args.output_dir.join(new_dir_name); // PathBuf

    // --- 🌟 3. 새 디렉토리 생성 ---
    // (기존 위치에서 여기로 이동 및 경로 변경)
    create_dir_all(&output_dir)
        .wrap_err(format!("새 출력 디렉토리 생성 실패: {}", output_dir.display()))?;

    println!("--- 데이터 생성기 시작 (N={}, T={}, K_max={}) ---", n, t, k_max);

    // --- 1. DKG 실행 (결정론적) ---
    println!("1. DKG 시뮬레이션으로 마스터 공개키(PK) 생성 중 (Seed: {:?})...", GLOBAL_DKG_SEED);
    let start_dkg = Instant::now();
    let master_pk = run_dkg_simulation_for_data_generator(n, t, GLOBAL_DKG_SEED);
    println!("   > Master PK 생성 완료 ({:?}).", start_dkg.elapsed());

    if k_max == 0 {
        return Err(eyre!("num_voters는 1 이상이어야 합니다."));
    }
    let merkle_height = if k_max == 1 {
        1
    } else {
        (k_max as u64 - 1).ilog2() as usize + 1
    };
    println!("   > (num_voters: {} 기준, Merkle Height: {} ({}개 leaf)로 자동 설정)", k_max, merkle_height, 2_u64.pow(merkle_height as u32));

    // --- 2. ZK-SNARK Proving Key (PK) 생성 ---
    println!("2. ZK-SNARK Proving Key (PK) 생성 중 (시간 소요)...");
    let start_setup = Instant::now();
    let (pk, vk) = setup(
        num_candidates,
        merkle_height,
        master_pk.clone(), // DKG 키를 ElGamal PK로 사용
        g,
    ).unwrap();

    let mut vk_bytes_compressed = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes_compressed)
        .wrap_err("VK Base64 직렬화 실패")?;
    let vk_base64 = STANDARD.encode(vk_bytes_compressed);
    println!("   > 검증키(VK) Base64 인코딩 완료.");

    let pk = Arc::new(pk);
    let master_pk = Arc::new(master_pk);
    println!("   > Proving Key 생성 완료 ({:?}).", start_setup.elapsed());

    // --- 3. 유권자 자격증명(cred) 및 Merkle Tree 생성 ---
    println!("3. {}명의 유권자 자격증명(cred) 및 Merkle Tree 생성 중...", k_max);
    let start_merkle = Instant::now();

    let (params_leaf, params_merkle, _) = setup_poseidon_params();
    let election_id_fr = Fr::from_le_bytes_mod_order(args.election_id.as_bytes());
    let params_leaf_arc = Arc::new(params_leaf);

    let (voter_data, mut leaves): (Vec<Fr>, Vec<Fr>) = (0..k_max)
        .into_par_iter()
        .map(|_| {
            // 🌟 각 병렬 작업은 독립적인 RNG가 필요합니다.
            let mut rng = StdRng::from_entropy();
            let cred = Fr::rand(&mut rng);
            // 🌟 Arc를 통해 params_leaf에 접근합니다.
            let leaf = CRH::evaluate(&params_leaf_arc, [cred, election_id_fr]).unwrap();
            (cred, leaf) // (cred, leaf) 튜플을 반환합니다.
        })
        .unzip(); // 🌟 unzip()을 사용해 두 개의 Vec으로 효율적으로 분리합니다.
    println!("   > {}/{} (cred/leaf) 병렬 생성 완료.", voter_data.len(), leaves.len());

    let num_leaves = 2_usize.pow(merkle_height as u32);
    if leaves.len() < num_leaves {
        println!("   > {}개의 빈 leaf로 패딩 중...", num_leaves - leaves.len());
        leaves.resize(num_leaves, Fr::zero()); // 0으로 패딩
    }

    let tree = MerkleTree::<MerkleTreePoseidonConfig>::new_with_leaf_digest(
        &params_leaf_arc,
        &params_merkle,
        leaves
    ).unwrap(); // [수정] `?` 사용
    let merkle_root = tree.root();

    let tree_arc = Arc::new(tree);


    println!("   > Merkle Root: {:?}", merkle_root);
    println!("   > Merkle Tree 및 Path 생성 완료 ({:?}).", start_merkle.elapsed());

    // --- 4. 작업 분배 및 병렬 증명 생성 ---
    println!("4. {}개 태스크로 {}개 트랜잭션 병렬 생성 시작...", n, k_max);

    // [🌟 수정 1]
    // (Fr, Path) Vec 대신, (usize, Fr) Vec을 생성합니다.
    // (index, cred) 쌍을 만듭니다. 이 Vec은 약 1GB 정도로 메모리에 부담이 없습니다.
    let voter_data_with_index: Vec<(usize, Fr)> = voter_data
        .into_iter()
        .enumerate()
        .collect();

    // [🌟 수정 2]
    // (Fr, Path) 청크가 아닌, (usize, Fr) 청크를 생성합니다.
    let chunks: Vec<Vec<(usize, Fr)>> =
        voter_data_with_index // 🌟 입력 변경
            .chunks((k_max + n - 1) / n) // (k_max / n)을 올림
            .map(|chunk| chunk.to_vec())
            .collect();

    let start_proving = Instant::now();

    let results: Vec<Result<PathBuf>> = chunks
        .into_par_iter() // 1. 청크(n개)를 병렬로 처리
        .enumerate()
        .map(|(authority_index, chunk)| {
            // 이 블록은 각 청크(n개)에 대해 병렬로 실행됩니다.
            let pk_clone = Arc::clone(&pk);
            let master_pk_clone = Arc::clone(&master_pk);
            let election_id = args.election_id.clone();
            let output_dir = output_dir.clone();
            let tree_arc_clone = Arc::clone(&tree_arc);

            let task_start = Instant::now();
            let chunk_len = chunk.len();
            let g = JubJubAffine::generator();

            let progress_counter = Arc::new(AtomicUsize::new(0));
            let log_interval = (chunk_len / 10).max(1);

            // 🌟 2. 청크 *내부*의 증명 생성을 다시 Rayon으로 병렬 처리 (중첩 병렬성)
            // `chunk.into_iter()` 대신 `chunk.par_iter()` 사용
            let transactions: Vec<VoteTransaction> = chunk
                .par_iter() // 2. 청크 내부의 모든 아이템을 병렬로 처리
                .enumerate()
                .map(|(local_index, (global_index, cred))| -> Result<VoteTransaction> {
                    // 이 블록은 개별 증명(k_max / n 개)에 대해 병렬로 실행됩니다.
                    // Rayon의 워크 스틸링이 모든 코어를 활용합니다.

                    // 🌟 각 병렬 작업은 독립적인 RNG가 필요합니다.
                    let mut vote_rng = StdRng::from_entropy();

                    // (a) 랜덤 투표 생성
                    let mut vote_bits = vec![false; num_candidates];
                    let mut vote_u8 = vec![0u8; num_candidates];
                    let vote_idx = vote_rng.gen_range(0..num_candidates);
                    vote_bits[vote_idx] = true;
                    vote_u8[vote_idx] = 1;

                    // (b) ElGamal 암호화
                    let r = JubJubFr::rand(&mut vote_rng);
                    let mut enc_vote_vec_projective = Vec::with_capacity(num_candidates);
                    let mut env_vote_vec_affine = Vec::with_capacity(num_candidates);
                    for &bit in vote_bits.iter() {
                        let vote_point = encode_vote(if bit { 1 } else { 0 }, &g);
                        let (c1, c2) = elgamal_encrypt(
                            &vote_point,
                            &master_pk_clone, // Arc 참조 사용
                            &g,
                            r
                        );
                        env_vote_vec_affine.push((
                            c1.into_group().into_affine(),
                            c2.into_group().into_affine()
                        ));
                        enc_vote_vec_projective.push(ZKElgamalCiphertext {
                            c1,
                            c2
                        })
                    }
                    let merkle_path = tree_arc_clone.generate_proof(*global_index)
                        .map_err(|e| eyre!("Merkle path 생성 실패: (auth: {}, item: {}): {}", authority_index, local_index, e))?;

                    // (c) ZK 증명 생성
                    let (proof, public_inputs) = prove(
                        &pk_clone, // Arc 참조 사용
                        &cred.into_bigint().to_bytes_le(),
                        merkle_path.clone(), // 🌟 `par_iter`는 참조를 사용하므로 Path 복제
                        vote_u8,
                        r,
                        &election_id,
                        merkle_root,
                        env_vote_vec_affine,
                        *master_pk_clone, // Arc 참조 사용
                        g,
                        &mut vote_rng,
                    ).map_err(|e| eyre!("ZK Prove 실패 (auth: {}, item: {}): {}", authority_index, local_index, e))?;

                    let nullifier = public_inputs.last().cloned()
                        .ok_or_else(|| eyre!("public_inputs가 비어있습니다 (auth: {}, item: {})", authority_index, local_index))?;

                    // (d) VoteTransaction 구조체 생성
                    let vote_tx = VoteTransaction {
                        proof,
                        nullifier,
                        enc_vote_vec: enc_vote_vec_projective,
                    };

                    // 🌟 3. (수정) 원자 카운터를 1 증가시키고, 현재 완료 개수를 가져옴
                    let current_count = progress_counter.fetch_add(1, Ordering::Relaxed) + 1;

                    // 🌟 4. (수정) 10% 간격(log_interval)에 도달했는지 확인
                    // (current_count == chunk_len, 즉 100%일 때는 "태스크 X 완료" 메시지와 중복되므로 제외)
                    if current_count % log_interval == 0 && current_count < chunk_len {
                        println!(
                            "     > 태스크 {}: 약 {}% ({}/{}) 증명 생성 중...",
                            authority_index,
                            (current_count * 100) / chunk_len, // 현재 %
                            current_count,
                            chunk_len
                        );
                    }

                    Ok(vote_tx) // 개별 트랜잭션 반환
                })
                .collect::<Result<Vec<VoteTransaction>>>()?; // 🌟 청크 내부의 모든 트랜잭션을 수집 (에러 시 `?`로 즉시 반환)


            // (f) 파일로 저장 (청크 단위로 병렬 실행됨)
            let filename = output_dir.join(format!("validator_{}_txs.bin", authority_index));
            let serialized_data = bincode::serialize(&transactions)
                .wrap_err("최종 배치 bincode 직렬화 실패")?;

            let mut file = File::create(&filename)
                .wrap_err(format!("파일 생성 실패: {:?}", filename))?;

            file.write_all(&serialized_data)
                .wrap_err(format!("파일 쓰기 실패: {:?}", filename))?;

            println!("   > 태스크 {} 완료 ({:?}). 파일 저장: {:?}",
                     authority_index, task_start.elapsed(), filename);

            Ok(filename) // 청크(태스크)의 결과(파일 경로) 반환
        })
        .collect(); // 🌟 모든 청크(n개)의 결과를 수집

    // 2. 타임스탬프
    let timestamp = chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true); // (chrono 크레이트 필요)
    // chrono가 없다면:
    // let timestamp = format!("{:?}", SystemTime::now());

    // 3. Merkle Root (Fr)를 문자열로 변환
    let merkle_root_str = merkle_root.to_string(); // (ark-ff의 to_string() 사용)

    // 4. 메타데이터 구조체 채우기
    let metadata = BenchmarkMetadata {
        generation_timestamp: timestamp,
        parameters: &args,
        dkg_seed: GLOBAL_DKG_SEED,
        derived_data: DerivedData {
            merkle_height: merkle_height,
            merkle_root: merkle_root_str.clone(),
            total_transactions_generated: k_max,
        },

    };

    // 5. JSON으로 직렬화 (Pretty format)
    let json_data = serde_json::to_string_pretty(&metadata)
        .wrap_err("메타데이터 JSON 직렬화 실패")?;
    // 6. 파일로 저장
    let metadata_filename = output_dir.join("_metadata.json");
    let mut file = File::create(&metadata_filename)
        .wrap_err("메타데이터 파일 생성 실패")?;

    file.write_all(json_data.as_bytes())
        .wrap_err("메타데이터 파일 쓰기 실패")?;

    println!("메타데이터 저장 완료: {:?}", metadata_filename);
    println!("{:#?}", metadata); // 터미널에도 예쁘게 출력

    // 🌟 5c. crypto-config.yaml 생성 (새로운 로직)
    println!("--- CryptoConfig 파일 생성 중 ---");
    let crypto_config = CryptoConfig {
        num_candidates: args.num_candidates, // 1. num_candidates
        merkle_root: merkle_root_str,      // 2. merkle_root (String)
        verifying_key: vk_base64,          // 3. verifying_key (Base64 String)
        global_seed: GLOBAL_DKG_SEED
    };

    let yaml_data = serde_yaml::to_string(&crypto_config)
        .wrap_err("CryptoConfig YAML 직렬화 실패")?;

    let crypto_config_filename = output_dir.join("crypto-config.yaml");
    let mut file = File::create(&crypto_config_filename)
        .wrap_err(format!("CryptoConfig 파일 생성 실패: {:?}", crypto_config_filename))?;

    file.write_all(yaml_data.as_bytes())
        .wrap_err(format!("CryptoConfig 파일 쓰기 실패: {:?}", crypto_config_filename))?;

    println!("CryptoConfig 저장 완료: {:?}", crypto_config_filename);

    // --- 6. [🌟 RAYON 변경] 결과 집계 ---
    // 🌟 `try_join_all.await` 대신 `results` 벡터를 순회하며 오류 확인
    println!("--- 모든 증명 생성 및 파일 저장 완료 ({:?}) ---", start_proving.elapsed());

    let mut had_error = false;
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(filename) => {
                println!("   - 태스크 {}: 성공. 파일 저장: {:?}", i, filename);
            }
            Err(e) => {
                eprintln!("   - 태스크 {} 실패: {:?}", i, e);
                had_error = true;
            }
        }
    }

    if had_error {
        return Err(eyre!("하나 이상의 병렬 증명 생성 태스크에서 오류가 발생했습니다."));
    }
    Ok(()) // [수정] 최종 Ok 반환
}
