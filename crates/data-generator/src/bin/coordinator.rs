use std::fs::{copy, create_dir_all, remove_file, File};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};
use std::str::FromStr;

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use eyre::{eyre, Context, Result};

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_crypto_primitives::merkle_tree::{MerkleTree, Path};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsAffine, Fr as JubJubFr};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng};
use ark_std::UniformRand;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use rayon::prelude::*;

use chrono::SecondsFormat;

use aws_sdk_ec2::{Client as Ec2Client, types::InstanceType};
use aws_config;

use crypto::dkg::run_dkg_simulation_for_data_generator;
use crypto::elgamal::{elgamal_encrypt, encode_vote};
use crypto::types::{VoteTransaction, ZKElgamalCiphertext};
use crypto::zkp::{prove, setup, setup_poseidon_params, MerkleTreePoseidonConfig};

const GLOBAL_DKG_SEED: u64 = 1234567890;

use aws_sdk_globalaccelerator::{
    Client as AgaClient,
    types::EndpointConfiguration,
};
// ==================== CLI ====================

#[derive(Copy, Clone, Debug, Serialize, ValueEnum)]
enum RunMode {
    /// 로컬에서 공통 데이터 생성 + AWS 인스턴스 띄우고 작업 분산
    Coordinator,
    /// AWS 인스턴스 안에서, 전달된 파일들을 이용해 증명만 생성
    Worker,
}

#[derive(Serialize, Debug)]
struct DerivedData {
    merkle_height: usize,
    merkle_root: String,
    total_transactions_generated: usize,
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

#[derive(Serialize, Deserialize)]
struct CryptoConfig {
    num_candidates: usize,
    merkle_root: String,
    verifying_key: String,
    global_seed: u64,
}

#[derive(Parser, Debug, Serialize, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 실행 모드 (coordinator / worker)
    #[clap(long, value_enum, default_value_t = RunMode::Coordinator)]
    mode: RunMode,

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

    /// 생성된 배치 파일을 저장할 디렉토리 (로컬 기준, coordinator 기준)
    #[clap(long, default_value = "benchmark_batches")]
    output_dir: PathBuf,

    // --- Worker 모드용 옵션 ---
    /// Worker 모드에서 읽어올 입력 디렉토리 (validator_i_input.bin, proving_key.bin 등)
    #[clap(long, default_value = ".")]
    input_dir: PathBuf,

    /// Worker 모드에서 결과 txs.bin 파일을 저장할 디렉토리
    #[clap(long, default_value = ".")]
    worker_output_dir: PathBuf,

    /// 이 워커가 처리할 validator index 시작 (예: 0)
    #[clap(long, default_value_t = 0)]
    validator_start: usize,

    /// 이 워커가 처리할 validator index 끝 (예: 4)
    #[clap(long, default_value_t = 4)]
    validator_end: usize,

    // --- Coordinator 모드용 AWS/SSH 옵션 ---
    /// Ohio(us-east-2) AMI ID (Ubuntu 22.04 LTS arm64)
    #[clap(long, default_value = "ami-032f62ff67d149091")]
    aws_ami_ohio: String,

    /// Oregon(us-west-2) AMI ID (실제 값으로 교체 필요)
    #[clap(long, default_value = "ami-0dd60ee743e1107f9")]
    aws_ami_oregon: String,

    /// AWS EC2 키페어 이름
    #[clap(long, default_value = "prover-key-global")]
    aws_key_name: String,

    /// SSH 접속에 사용할 private key 경로 (~/.ssh/xxx.pem)
    #[clap(long, default_value = "~/.ssh/aws-prover-key")]
    ssh_key_path: PathBuf,

    #[clap(long, default_value = "arn:aws:globalaccelerator::286430881698:accelerator/befe2fa3-8ee0-4637-8243-ffd7d89cec74/listener/793ac0da/endpoint-group/fc50499b5300")]
    aga_ohio_arn: String,

    /// Ohio AGA DNS 주소 (예: a0b7...awsglobalaccelerator.com)
    #[clap(long, default_value = "a0b7be1539244ca45.awsglobalaccelerator.com")]
    aga_ohio_dns: String,

    // ✨ [추가] Oregon AGA 설정
    /// Oregon Global Accelerator의 Endpoint Group ARN
    #[clap(long, default_value = "arn:aws:globalaccelerator::286430881698:accelerator/09013207-e596-48b9-897e-660bd7285720/listener/44236199/endpoint-group/d68357ba3005")]
    aga_oregon_arn: String,

    /// Oregon AGA DNS 주소
    #[clap(long, default_value = "a740353730ac140f5.awsglobalaccelerator.com")]
    aga_oregon_dns: String,

    /// SSH 접속 시 유저명 (Ubuntu 공식 AMI면 ubuntu)
    #[clap(long, default_value = "ubuntu")]
    ssh_user: String,

    /// 원격 인스턴스에 업로드할 arm64 실행 파일 경로
    #[clap(long, default_value = "./target/aarch64-unknown-linux-gnu/release/coordinator")]
    worker_binary_path: PathBuf,
}

// coordinator.rs 상단

// ✨ [추가] 이 함수를 추가하세요.
async fn register_to_aga(
    region: &str,
    group_arn: &str,
    instance_id: &str
) -> Result<()> {
    if group_arn.is_empty() {
        println!("[AGA] {} 리전: ARN이 비어있어 AGA 등록을 건너뜁니다.", region);
        return Ok(());
    }

    println!("[AGA] {} 리전: 인스턴스 {} 를 Endpoint Group에 등록 중...", region, instance_id);

    // AGA 클라이언트 생성 (us-west-2 엔드포인트 사용)
    let config = aws_config::from_env()
        .region(aws_sdk_ec2::config::Region::new("us-west-2"))
        .load()
        .await;

    // ✨ [수정] 긴 경로 대신 AgaClient 사용
    let client = AgaClient::new(&config);

    // Endpoint 업데이트 (기존 목록 덮어쓰기)
    client.update_endpoint_group()
        .endpoint_group_arn(group_arn)
        .endpoint_configurations(
            // ✨ [수정] 긴 경로 대신 EndpointConfiguration 사용
            EndpointConfiguration::builder()
                .endpoint_id(instance_id)
                .weight(128)
                .client_ip_preservation_enabled(true) // SSH 접속을 위해 필수!
                .build()
        )
        .send()
        .await
        .wrap_err(format!("{} AGA 등록 실패", region))?;

    println!("[AGA] {} 리전 등록 성공!", region);
    Ok(())
}
// (파일 상단 use 선언부에도 추가해 주세요)
// use aws_sdk_ec2::{Client as Ec2Client};
// use eyre::Result;

// main 함수 바깥이나 별도 모듈에 추가
struct InstanceTerminator {
    client: Ec2Client,
    instance_id: String,
    region_name: String, // 로그 출력을 위해 추가
}

impl InstanceTerminator {
    fn new(client: Ec2Client, instance_id: String, region_name: String) -> Self {
        Self { client, instance_id, region_name }
    }
}

impl Drop for InstanceTerminator {
    fn drop(&mut self) {
        println!("[COORD] {} ({}) 인스턴스 자동 정리 시작...", self.region_name, self.instance_id);

        // `drop`은 동기 함수이므로, 비동기 terminate 함수를
        // `tokio::spawn`으로 별도 태스크에서 실행합니다.
        let client = self.client.clone();
        let instance_id = self.instance_id.clone();

        tokio::spawn(async move {
            // terminate_instance 함수를 그대로 재사용합니다.
            match terminate_instance(&client, &instance_id).await {
                Ok(_) => println!("[COORD] ({}) 인스턴스 자동 종료 요청 성공.", instance_id),
                Err(e) => eprintln!("[COORD] ({}) 인스턴스 자동 종료 실패: {}", instance_id, e),
            }
        });
    }
}

// `terminate_instance` 함수는 이미 존재하므로 그대로 둡니다.
// async fn terminate_instance(ec2: &Ec2Client, instance_id: &str) -> Result<()> { ... }
// ==================== main ====================

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    match args.mode {
        RunMode::Coordinator => run_coordinator(&args).await,
        RunMode::Worker => run_worker(&args),
    }
}

// ==================== WORKER ====================

fn run_worker(args: &Args) -> Result<()> {
    let n = args.committee_size;
    let k_max = args.num_voters;
    let num_candidates = args.num_candidates;
    let election_id = args.election_id.clone();
    let input_dir = args.input_dir.clone();
    let output_dir = args.worker_output_dir.clone();

    create_dir_all(&output_dir)
        .wrap_err(format!("Worker output dir 생성 실패: {}", output_dir.display()))?;

    println!(
        "[WORKER] start (validators {}..={}, k_max={}, n={})",
        args.validator_start, args.validator_end, k_max, n
    );

    // --- 1. ProvingKey / master_pk / merkle_root 로드 ---

    // 1-1. proving_key.bin
    let pk_path = input_dir.join("proving_key.bin");
    println!("[WORKER] proving_key.bin 로딩: {:?}", pk_path);
    let mut pk_bytes = Vec::new();
    File::open(&pk_path)
        .wrap_err("proving_key.bin 파일 열기 실패")?
        .read_to_end(&mut pk_bytes)
        .wrap_err("proving_key.bin 읽기 실패")?;
    let mut pk_cursor = &pk_bytes[..];
    let pk: ProvingKey<Bls12_381> =
        CanonicalDeserialize::deserialize_uncompressed(&mut pk_cursor)
            .wrap_err("ProvingKey CanonicalDeserialize 실패")?;
    let pk = Arc::new(pk);

    // 1-2. master_pk.bin
    let mpk_path = input_dir.join("master_pk.bin");
    println!("[WORKER] master_pk.bin 로딩: {:?}", mpk_path);
    let mut mpk_bytes = Vec::new();
    File::open(&mpk_path)
        .wrap_err("master_pk.bin 파일 열기 실패")?
        .read_to_end(&mut mpk_bytes)
        .wrap_err("master_pk.bin 읽기 실패")?;
    let mut mpk_cursor = &mpk_bytes[..];
    let master_pk: EdwardsAffine =
        CanonicalDeserialize::deserialize_uncompressed(&mut mpk_cursor)
            .wrap_err("master_pk CanonicalDeserialize 실패")?;
    let master_pk = Arc::new(master_pk);

    // 1-3. merkle_root (crypto-config.yaml 에 string으로 들어있다고 가정)
    let crypto_conf_path = input_dir.join("crypto-config.yaml");
    println!("[WORKER] crypto-config.yaml 로딩: {:?}", crypto_conf_path);
    let crypto_yaml = std::fs::read_to_string(&crypto_conf_path)
        .wrap_err("crypto-config.yaml 읽기 실패")?;
    let crypto_cfg: CryptoConfig = serde_yaml::from_str(&crypto_yaml)
        .wrap_err("crypto-config.yaml 파싱 실패")?;
    let merkle_root = Fr::from_str(&crypto_cfg.merkle_root)
        .map_err(|_| eyre!("merkle_root 문자열에서 Fr 파싱 실패"))?;

    println!("[WORKER] merkle_root: {:?}", merkle_root);

    let g = JubJubAffine::generator();

    // --- 2. validator 구간별로 input 파일 로딩 + Prove ---

    for validator_idx in args.validator_start..=args.validator_end {
        let input_file = input_dir.join(format!("validator_{}_input.bin", validator_idx));
        println!("[WORKER] validator {} input 로딩: {:?}", validator_idx, input_file);

        let mut input_bytes = Vec::new();
        File::open(&input_file)
            .wrap_err(format!("validator input 파일 열기 실패: {:?}", input_file))?
            .read_to_end(&mut input_bytes)
            .wrap_err("validator input 파일 읽기 실패")?;
        let mut input_cursor = &input_bytes[..];

        // Vec<(Fr, Path<MerkleTreePoseidonConfig>)> 역직렬화
        let cred_path_vec: Vec<(Fr, Path<MerkleTreePoseidonConfig>)> =
            CanonicalDeserialize::deserialize_uncompressed(&mut input_cursor)
                .wrap_err("validator input CanonicalDeserialize 실패")?;

        let chunk_len = cred_path_vec.len();
        println!(
            "[WORKER] validator {}: {}개의 (cred, path) 로딩 완료.",
            validator_idx, chunk_len
        );

        let pk_clone = Arc::clone(&pk);
        let master_pk_clone = Arc::clone(&master_pk);
        let election_id_clone = election_id.clone();

        let progress_counter = Arc::new(AtomicUsize::new(0));
        let log_interval = (chunk_len / 10).max(1);

        let task_start = Instant::now();

        let transactions: Vec<VoteTransaction> = cred_path_vec
            .into_par_iter()
            .enumerate()
            .map(|(local_index, (cred, merkle_path))| -> Result<VoteTransaction> {
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
                        &master_pk_clone,
                        &g,
                        r,
                    );
                    env_vote_vec_affine.push((
                        c1.into_group().into_affine(),
                        c2.into_group().into_affine(),
                    ));
                    enc_vote_vec_projective.push(ZKElgamalCiphertext { c1, c2 });
                }

                // (c) ZK 증명 생성 - merkle_path는 이미 파일에서 받은 것 그대로 사용
                let (proof, public_inputs) = prove(
                    &pk_clone,
                    &cred.into_bigint().to_bytes_le(),
                    merkle_path,
                    vote_u8,
                    r,
                    &election_id_clone,
                    merkle_root,
                    env_vote_vec_affine,
                    *master_pk_clone,
                    g,
                    &mut vote_rng,
                )
                    .map_err(|e| eyre!(
                    "[WORKER] ZK Prove 실패 (validator {}, item {}): {}",
                    validator_idx,
                    local_index,
                    e
                ))?;

                let nullifier = public_inputs.last().cloned().ok_or_else(|| {
                    eyre!(
                        "[WORKER] public_inputs가 비어있습니다 (validator {}, item {})",
                        validator_idx,
                        local_index
                    )
                })?;

                let vote_tx = VoteTransaction {
                    proof,
                    nullifier,
                    enc_vote_vec: enc_vote_vec_projective,
                };

                let current_count =
                    progress_counter.fetch_add(1, Ordering::Relaxed) + 1;
                if current_count % log_interval == 0 && current_count < chunk_len {
                    println!(
                        "[WORKER] validator {}: 약 {}% ({}/{}) 증명 생성 중...",
                        validator_idx,
                        (current_count * 100) / chunk_len,
                        current_count,
                        chunk_len
                    );
                }

                Ok(vote_tx)
            })
            .collect::<Result<Vec<VoteTransaction>>>()?;

        // --- 결과 파일 저장 ---
        let out_file = output_dir.join(format!("validator_{}_txs.bin", validator_idx));
        let serialized_data = bincode::serialize(&transactions)
            .wrap_err("최종 배치 bincode 직렬화 실패")?;

        let mut f = File::create(&out_file)
            .wrap_err(format!("[WORKER] 결과 파일 생성 실패: {:?}", out_file))?;
        f.write_all(&serialized_data)
            .wrap_err(format!("[WORKER] 결과 파일 쓰기 실패: {:?}", out_file))?;

        println!(
            "[WORKER] validator {} 완료 ({:?}). 결과 파일: {:?}",
            validator_idx,
            task_start.elapsed(),
            out_file
        );
    }

    println!("[WORKER] 지정된 validator 범위 작업 모두 완료.");
    Ok(())
}

// ==================== COORDINATOR - COMMON INPUT GEN ====================

fn prepare_common_inputs(args: &Args) -> Result<PathBuf> {
    let n = args.committee_size;
    let t = args.threshold;
    let k_max = args.num_voters;
    let num_candidates = args.num_candidates;
    let g = JubJubAffine::generator();

    let new_dir_name = format!("n{}_t{}_k{}", n, t, k_max);
    let output_dir = args.output_dir.join(new_dir_name);
    create_dir_all(&output_dir)
        .wrap_err(format!("출력 디렉토리 생성 실패: {}", output_dir.display()))?;

    println!(
        "--- 공통 데이터 생성 시작 (N={}, T={}, K_max={}) ---",
        n, t, k_max
    );

    // 1. DKG
    println!(
        "1. DKG 시뮬레이션으로 마스터 공개키(PK) 생성 중 (Seed: {:?})...",
        GLOBAL_DKG_SEED
    );
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
    println!(
        "   > (num_voters: {} 기준, Merkle Height: {} ({}개 leaf)로 자동 설정)",
        k_max,
        merkle_height,
        2_u64.pow(merkle_height as u32)
    );

    // 2. ZK setup
    println!("2. ZK-SNARK Proving Key (PK) 생성 중 (시간 소요)...");
    let start_setup = Instant::now();
    let (pk, vk) = setup(num_candidates, merkle_height, master_pk.clone(), g)
        .unwrap();
    println!("   > Proving Key 생성 완료 ({:?}).", start_setup.elapsed());

    // VK Base64 (crypto-config.yaml용)
    let mut vk_bytes_compressed = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes_compressed)
        .wrap_err("VK Base64 직렬화 실패")?;
    let vk_base64 = STANDARD.encode(vk_bytes_compressed);
    println!("   > 검증키(VK) Base64 인코딩 완료.");

    // 3. cred & Merkle tree
    println!(
        "3. {}명의 유권자 자격증명(cred) 및 Merkle Tree 생성 중...",
        k_max
    );
    let start_merkle = Instant::now();

    let (params_leaf, params_merkle, _) = setup_poseidon_params();
    let election_id_fr = Fr::from_le_bytes_mod_order(args.election_id.as_bytes());
    let params_leaf_arc = Arc::new(params_leaf);

    let (voter_data, mut leaves): (Vec<Fr>, Vec<Fr>) = (0..k_max)
        .into_par_iter()
        .map(|_| {
            let mut rng = StdRng::from_entropy();
            let cred = Fr::rand(&mut rng);
            let leaf =
                CRH::evaluate(&params_leaf_arc, [cred, election_id_fr]).unwrap();
            (cred, leaf)
        })
        .unzip();

    let num_leaves = 2_usize.pow(merkle_height as u32);
    if leaves.len() < num_leaves {
        println!(
            "   > {}개의 빈 leaf로 패딩 중...",
            num_leaves - leaves.len()
        );
        leaves.resize(num_leaves, Fr::zero());
    }

    let tree = MerkleTree::<MerkleTreePoseidonConfig>::new_with_leaf_digest(
        &params_leaf_arc,
        &params_merkle,
        leaves,
    )
        .unwrap();
    let merkle_root = tree.root();
    println!("   > Merkle Root: {:?}", merkle_root);
    println!(
        "   > Merkle Tree 및 Path 생성 완료 ({:?}).",
        start_merkle.elapsed()
    );

    let tree_arc = Arc::new(tree);

    // 4. validator별 (cred, path) input 파일 생성
    println!(
        "4. Validator별 (cred, Merkle path) input 파일 생성 시작... (n={}, k_max={})",
        n, k_max
    );

    let voter_data_with_index: Vec<(usize, Fr)> = voter_data
        .iter()
        .cloned()
        .enumerate()
        .collect();

    let chunk_size = (k_max + n - 1) / n;

    for (authority_index, chunk) in voter_data_with_index.chunks(chunk_size).enumerate() {
        if authority_index >= n {
            break;
        }

        println!(
            "   > validator {}: voter index 범위 [{}, {}) ({}개)",
            authority_index,
            chunk.first().map(|(idx, _)| *idx).unwrap_or(0),
            chunk.last().map(|(idx, _)| *idx + 1).unwrap_or(0),
            chunk.len()
        );

        let mut cred_path_vec: Vec<(Fr, Path<MerkleTreePoseidonConfig>)> =
            Vec::with_capacity(chunk.len());

        for (global_index, cred) in chunk.iter() {
            let merkle_path = tree_arc
                .generate_proof(*global_index)
                .map_err(|e| eyre!(
                    "Merkle path 생성 실패: validator {}, global_index {}: {}",
                    authority_index,
                    global_index,
                    e
                ))?;

            cred_path_vec.push((*cred, merkle_path));
        }

        // validator_i_input.bin 저장
        let filename = output_dir.join(format!("validator_{}_input.bin", authority_index));
        let mut buf = Vec::new();
        cred_path_vec
            .serialize_uncompressed(&mut buf)
            .wrap_err("validator input CanonicalSerialize 실패")?;

        let mut f = File::create(&filename)
            .wrap_err(format!("validator input 파일 생성 실패: {:?}", filename))?;
        f.write_all(&buf)
            .wrap_err(format!("validator input 파일 쓰기 실패: {:?}", filename))?;

        println!("   > validator {} input 파일 저장 완료: {:?}", authority_index, filename);
    }

    // 5. proving_key.bin 저장
    println!("5. proving_key.bin 저장 중...");
    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes)
        .wrap_err("ProvingKey CanonicalSerialize 실패")?;
    {
        let mut f = File::create(output_dir.join("proving_key.bin"))
            .wrap_err("proving_key.bin 생성 실패")?;
        f.write_all(&pk_bytes)
            .wrap_err("proving_key.bin 쓰기 실패")?;
    }

    // 6. master_pk.bin 저장
    println!("6. master_pk.bin 저장 중...");
    let mut mpk_bytes = Vec::new();
    master_pk
        .serialize_uncompressed(&mut mpk_bytes)
        .wrap_err("master_pk CanonicalSerialize 실패")?;
    {
        let mut f = File::create(output_dir.join("master_pk.bin"))
            .wrap_err("master_pk.bin 생성 실패")?;
        f.write_all(&mpk_bytes)
            .wrap_err("master_pk.bin 쓰기 실패")?;
    }

    // 7. 메타데이터 + crypto-config.yaml
    let timestamp = chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
        .to_rfc3339_opts(SecondsFormat::Secs, true);

    let merkle_root_str = merkle_root.to_string();

    let metadata = BenchmarkMetadata {
        generation_timestamp: timestamp,
        parameters: args,
        dkg_seed: GLOBAL_DKG_SEED,
        derived_data: DerivedData {
            merkle_height,
            merkle_root: merkle_root_str.clone(),
            total_transactions_generated: k_max,
        },
    };

    let json_data = serde_json::to_string_pretty(&metadata)
        .wrap_err("메타데이터 JSON 직렬화 실패")?;
    {
        let metadata_filename = output_dir.join("_metadata.json");
        let mut f = File::create(&metadata_filename)
            .wrap_err("메타데이터 파일 생성 실패")?;
        f.write_all(json_data.as_bytes())
            .wrap_err("메타데이터 파일 쓰기 실패")?;
        println!("메타데이터 저장 완료: {:?}", metadata_filename);
    }

    println!("{:#?}", metadata);

    println!("--- CryptoConfig 파일 생성 중 ---");
    let crypto_config = CryptoConfig {
        num_candidates: args.num_candidates,
        merkle_root: merkle_root_str,
        verifying_key: vk_base64,
        global_seed: GLOBAL_DKG_SEED,
    };

    let yaml_data = serde_yaml::to_string(&crypto_config)
        .wrap_err("CryptoConfig YAML 직렬화 실패")?;
    {
        let crypto_config_filename = output_dir.join("crypto-config.yaml");
        let mut f = File::create(&crypto_config_filename)
            .wrap_err(format!("CryptoConfig 파일 생성 실패: {:?}", crypto_config_filename))?;
        f.write_all(yaml_data.as_bytes())
            .wrap_err(format!("CryptoConfig 파일 쓰기 실패: {:?}", crypto_config_filename))?;
        println!("CryptoConfig 저장 완료: {:?}", crypto_config_filename);
    }

    println!("--- 공통 입력 생성 완료 ---");
    Ok(output_dir)
}

// ==================== COORDINATOR - AWS CONTROL ====================

async fn run_coordinator(args: &Args) -> Result<()> {
    // 1. 공통 입력 생성 (로컬) - 이것도 CPU/IO 집약적이므로 spawn_blocking
    println!("[COORD] 공통 입력 생성 시작... (시간 소요)");
    let args_clone = args.clone(); // Arc<Args>를 쓰는 것이 더 효율적이지만, 여기서는 clone
    let output_dir = tokio::task::spawn_blocking(move || {
        prepare_common_inputs(&args_clone)
    }).await??; // .await (JoinHandle) 후 ?? (Result<Result<...>>)

    println!("[COORD] 공통 입력 생성 완료: {}", output_dir.display());

    // 2. AWS 클라이언트 (이 부분은 이미 async라 OK)
    let conf_ohio = aws_config::from_env().region(aws_sdk_ec2::config::Region::new("us-east-2")).load().await;
    let conf_oregon = aws_config::from_env().region(aws_sdk_ec2::config::Region::new("us-west-2")).load().await;
    let ec2_ohio = Ec2Client::new(&conf_ohio);
    let ec2_oregon = Ec2Client::new(&conf_oregon);

    // 3. 인스턴스 생성 (OK)
    let inst_ohio = launch_instance(&ec2_ohio, &args.aws_ami_ohio, &args.aws_key_name, "c8g.48xlarge", "sg-0cbf9484b957114ca").await?;
    let inst_oregon = launch_instance(&ec2_oregon, &args.aws_ami_oregon, &args.aws_key_name, "c8g.48xlarge", "sg-0b0cfde8f302c39b4").await?;
    println!("[COORD] Ohio instance: {}, Oregon instance: {}", inst_ohio.instance_id, inst_oregon.instance_id);

    let _ohio_guard = InstanceTerminator::new(
        ec2_ohio.clone(), // 클라이언트 복사본을 넘김
        inst_ohio.instance_id.clone(),
        "Ohio".to_string()
    );
    let _oregon_guard = InstanceTerminator::new(
        ec2_oregon.clone(), // 클라이언트 복사본을 넘김
        inst_oregon.instance_id.clone(),
        "Oregon".to_string()
    );
    // 4. public DNS 대기 (OK)
    let info_ohio = wait_for_instance_ready(&ec2_ohio, &inst_ohio.instance_id).await?;
    let info_oregon = wait_for_instance_ready(&ec2_oregon, &inst_oregon.instance_id).await?;
    println!("[COORD] Ohio DNS: {}, Oregon DNS: {}", info_ohio.public_dns, info_oregon.public_dns);


    let (r1, r2) = tokio::join!(
        register_to_aga("Ohio", &args.aga_ohio_arn, &inst_ohio.instance_id),
        register_to_aga("Oregon", &args.aga_oregon_arn, &inst_oregon.instance_id)
    );
    r1?; r2?;

    // ✨ [접속 주소 결정]
    // AGA DNS가 입력되었으면 그것을 쓰고, 없으면 기존 EC2 DNS를 씁니다.
    let ohio_host = if !args.aga_ohio_dns.is_empty() {
        println!("[COORD] Ohio 접속에 AGA DNS를 사용합니다: {}", args.aga_ohio_dns);
        args.aga_ohio_dns.clone()
    } else {
        info_ohio.public_dns.clone()
    };

    let oregon_host = if !args.aga_oregon_dns.is_empty() {
        println!("[COORD] Oregon 접속에 AGA DNS를 사용합니다: {}", args.aga_oregon_dns);
        args.aga_oregon_dns.clone()
    } else {
        info_oregon.public_dns.clone()
    };

    // ✨ [중요] 라우팅 안정화 대기 (AGA 업데이트 직후 바로 접속하면 실패할 수 있음)
    if !args.aga_ohio_dns.is_empty() {
        println!("[COORD] AGA 라우팅 전파 대기 (10초)...");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    // 5. SSH 대기 (이제 ohio_host, oregon_host 사용)
    let ohio_host_clone = ohio_host.clone();
    let oregon_host_clone = oregon_host.clone();

    let ssh_ohio = tokio::task::spawn_blocking(move || wait_for_ssh(&ohio_host_clone));
    let ssh_oregon = tokio::task::spawn_blocking(move || wait_for_ssh(&oregon_host_clone));
    let (res_ohio, res_oregon) = tokio::join!(ssh_ohio, ssh_oregon);
    res_ohio??; res_oregon??;

    println!("[COORD] SSH 접속 확인 완료.");


    // ✨ [추가] 병렬 전송 전에 공통 파일들을 미리 압축 (경쟁 상태 방지)
    println!("[COORD] 전송 속도 향상을 위해 공통 파일 압축 중...");
    let compressed_worker_bin = prepare_compressed_binary(&args.worker_binary_path)?;
    let pk_path = output_dir.join("proving_key.bin");
    let compressed_pk = gzip_compress(&pk_path)?;
    println!("[COORD] 공통 파일 압축 완료.");

    // 인자 준비
    let half = args.committee_size / 2;
    let args_clone_ohio = args.clone();
    let args_clone_oregon = args.clone();

    // ✅ 여기서 GA 호스트 복제해서 사용
    let ohio_host_for_upload = ohio_host.clone();
    let oregon_host_for_upload = oregon_host.clone();

    let output_dir_clone_ohio = output_dir.clone();
    let output_dir_clone_oregon = output_dir.clone();

    let bin_ohio = compressed_worker_bin.clone();
    let pk_ohio = compressed_pk.clone();
    let bin_oregon = compressed_worker_bin.clone();
    let pk_oregon = compressed_pk.clone();

    let upload_ohio = tokio::task::spawn_blocking(move || {
        upload_worker_files_for_range(
            &args_clone_ohio,
            &ohio_host_for_upload,              // 🔥 GA/EC2 선택된 host 사용
            &output_dir_clone_ohio,
            0,
            half - 1,
            &bin_ohio,
            &pk_ohio,
        )
    });

    let upload_oregon = tokio::task::spawn_blocking(move || {
        upload_worker_files_for_range(
            &args_clone_oregon,
            &oregon_host_for_upload,            // 🔥 GA/EC2 선택된 host 사용
            &output_dir_clone_oregon,
            half,
            args_clone_oregon.committee_size - 1,
            &bin_oregon,
            &pk_oregon,
        )
    });

    upload_ohio.await??;
    upload_oregon.await??;
    println!("[COORD] 두 인스턴스에 파일 업로드 완료.");


    let n = args.committee_size;
    let args_clone_ohio = args.clone(); // ohio_fut용
    let args_clone_oregon = args.clone(); // oregon_fut용

    let ohio_range_start = 0;
    let ohio_range_end = half - 1;
    let oregon_range_start = half;
    let oregon_range_end = n - 1;

    let output_dir_clone_ohio = output_dir.clone();
    let output_dir_clone_oregon = output_dir.clone(); // output_dir은 Arc<PathBuf>로 만드는 것이 더 좋음

    let ohio_host_for_run = ohio_host.clone();
    let oregon_host_for_run = oregon_host.clone();

    let ohio_fut = tokio::task::spawn_blocking(move || {
        println!("[COORD] (Ohio) validators {}..={} 처리 시작", ohio_range_start, ohio_range_end);

        run_remote_worker(
            &args_clone_ohio, &ohio_host_for_run, ohio_range_start, ohio_range_end
        )?;

        download_results(
            &args_clone_ohio, &ohio_host_for_run, &output_dir_clone_ohio, ohio_range_start, ohio_range_end
        )?;

        println!("[COORD] (Ohio) validators {}..={} 처리 완료", ohio_range_start, ohio_range_end);
        Ok::<(), eyre::Report>(())
    });

    let oregon_fut = tokio::task::spawn_blocking(move || {
        println!("[COORD] (Oregon) validators {}..={} 처리 시작", oregon_range_start, oregon_range_end);

        run_remote_worker(
            &args_clone_oregon, &oregon_host_for_run, oregon_range_start, oregon_range_end
        )?;

        download_results(
            &args_clone_oregon, &oregon_host_for_run, &output_dir_clone_oregon, oregon_range_start, oregon_range_end
        )?;

        println!("[COORD] (Oregon) validators {}..={} 처리 완료", oregon_range_start, oregon_range_end);
        Ok::<(), eyre::Report>(())
    });

    // 두 리전을 동시에 진행
    let (res_ohio, res_oregon) = tokio::join!(ohio_fut, oregon_fut);
    res_ohio??; // JoinHandle 에러, 그 다음 Result 에러
    res_oregon??;

    // 9. 인스턴스 종료 (OK)
    terminate_instance(&ec2_ohio, &inst_ohio.instance_id).await?;
    terminate_instance(&ec2_oregon, &inst_oregon.instance_id).await?;

    println!("[COORD] 모든 작업 완료.");
    Ok(())
}

// (참고: Args 구조체에 Clone 트레잇이 필요합니다)
// #[derive(Parser, Debug, Serialize, Clone)]
// struct Args { ... }

struct InstanceHandle {
    instance_id: String,
}

struct InstanceInfo {
    instance_id: String,
    public_dns: String,
}

async fn launch_instance(
    ec2: &Ec2Client,
    ami: &str,
    key_name: &str,
    instance_type_str: &str,
    security_group_id: &str,
) -> Result<InstanceHandle> {
    use aws_sdk_ec2::types::InstanceType;
    // ✨ [수정] 스팟 인스턴스 요청을 위해 필요한 타입들 임포트
    use aws_sdk_ec2::types::{
        InstanceMarketOptionsRequest, InstanceInterruptionBehavior, MarketType,
        SpotInstanceType, SpotMarketOptions,
    };

    let instance_type = match instance_type_str {
        "c8g.48xlarge" => InstanceType::C8g48xlarge,
        _ => InstanceType::C8g48xlarge, // 필요시 매핑 더 추가
    };

    // ✨ [수정] 스팟 인스턴스 옵션 빌드
    let spot_options = SpotMarketOptions::builder()
        .spot_instance_type(SpotInstanceType::OneTime) // 1회성 요청
        .instance_interruption_behavior(InstanceInterruptionBehavior::Terminate) // 중단 시 종료
        .build();

    let market_options = InstanceMarketOptionsRequest::builder()
        .market_type(MarketType::Spot) // 마켓 타입을 'spot'으로 지정
        .spot_options(spot_options)
        .build();

    let out = ec2
        .run_instances()
        .image_id(ami)
        .instance_type(instance_type)
        .key_name(key_name)
        .security_group_ids(security_group_id)
        .min_count(1)
        .max_count(1)
        // ✨ [수정] .instance_market_options(...) 추가
        .instance_market_options(market_options)
        .send()
        .await
        .wrap_err("run_instances 실패")?;

    // (기존 코드) out.instances()는 SDK 버전에 따라 Option<&[Instance]> 또는 &[Instance]를 반환할 수 있습니다.
    // 사용자의 원본 코드를 유지합니다.
    let instances = out.instances();
    let inst = instances
        .first()
        .ok_or_else(|| eyre!("인스턴스 생성 결과가 비어있음"))?;

    let instance_id = inst
        .instance_id()
        .ok_or_else(|| eyre!("instance_id 없음"))?
        .to_string();

    Ok(InstanceHandle { instance_id })
}

async fn wait_for_instance_ready(
    ec2: &Ec2Client,
    instance_id: &str,
) -> Result<InstanceInfo> {
    loop {
        let out = ec2
            .describe_instances()
            .instance_ids(instance_id)
            .send()
            .await
            .wrap_err("describe_instances 실패")?;

        // reservations() 는 &[Reservation] 를 리턴하므로 그대로 사용
        let reservations = out.reservations();

        let inst_opt = reservations
            .iter()
            // instances() 도 &[Instance] 를 리턴
            .flat_map(|r| r.instances())
            .find(|i| i.instance_id() == Some(instance_id));

        if let Some(inst) = inst_opt {
            let state = inst
                .state()
                .and_then(|s| s.name())
                .map(|s| format!("{:?}", s))
                .unwrap_or_else(|| "UNKNOWN".to_string());

            let public_dns = inst
                .public_dns_name()
                .unwrap_or_default()
                .to_string();

            println!(
                "[COORD] {} 상태: {}, DNS: {}",
                instance_id, state, public_dns
            );

            if state == "Running" && !public_dns.is_empty() {
                return Ok(InstanceInfo {
                    instance_id: instance_id.to_string(),
                    public_dns,
                });
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
 async fn terminate_instance(ec2: &Ec2Client, instance_id: &str) -> Result<()> {
    ec2.terminate_instances()
        .instance_ids(instance_id)
        .send()
        .await
        .wrap_err("terminate_instances 실패")?;
    println!("[COORD] 인스턴스 종료 요청: {}", instance_id);
    Ok(())
}

fn wait_for_ssh(host: &str) -> Result<()> {
    println!("[COORD] SSH 접속 가능 여부 대기: {}:22", host);
    for _ in 0..60 {
        if TcpStream::connect((host, 22)).is_ok() {
            println!("[COORD] SSH 연결 가능: {}", host);
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    Err(eyre!("SSH 포트에 연결할 수 없습니다: {}", host))
}

fn scp_upload(
    ssh_user: &str,
    key_path: &PathBuf,
    host: &str,
    local: &PathBuf,
    remote: &str,
) -> Result<()> {
    let max_retries = 10; // 최대 10번까지 재시도

    for attempt in 1..=max_retries {
        let status = Command::new("scp")
            .arg("-i")
            .arg(key_path)
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg("UserKnownHostsFile=/dev/null")
            // ✨ [추가] 전송 중 끊김 방지를 위한 연결 유지 옵션
            .arg("-o").arg("ServerAliveInterval=15")
            .arg("-o").arg("ServerAliveCountMax=60")
            .arg("-o").arg("TCPKeepAlive=yes")
            .arg(local)
            .arg(format!("{}@{}:{}", ssh_user, host, remote))
            .status();

        match status {
            Ok(s) if s.success() => return Ok(()), // 성공하면 바로 종료
            Ok(s) => {
                eprintln!("[WARN] SCP 전송 실패 (시도 {}/{}): 종료 코드 {:?}", attempt, max_retries, s.code());
            }
            Err(e) => {
                eprintln!("[WARN] SCP 명령 실행 오류 (시도 {}/{}): {}", attempt, max_retries, e);
            }
        }

        if attempt < max_retries {
            // 실패 시 대기 (점진적으로 늘어남: 5초, 10초, 15초...)
            let wait_secs = 5 * attempt as u64;
            eprintln!("[RETRY] 네트워크 안정화를 위해 {}초 후 재시도합니다...", wait_secs);
            std::thread::sleep(Duration::from_secs(wait_secs));
        }
    }

    Err(eyre!("SCP 전송이 {}회 시도 끝에 최종 실패했습니다.", max_retries))
}

fn ssh_exec(
    ssh_user: &str,
    key_path: &PathBuf,
    host: &str,
    remote_cmd: &str,
) -> Result<()> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::thread;

    // host DNS의 앞부분만 따서 로그 접두사로 사용 (예: "ec2-18-118-11-186")
    let host_prefix = host.split('.').next().unwrap_or(host).to_uppercase();

    let mut child = Command::new("ssh")
        .arg("-i")
        .arg(key_path)
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o").arg("UserKnownHostsFile=/dev/null")
        .arg("-o").arg("ServerAliveInterval=15") // 15초마다 생존 신호
        .arg("-o").arg("ServerAliveCountMax=20") // 20번 실패할 때까지 대기 (총 5분 버팀)
        .arg("-o").arg("TCPKeepAlive=yes")
        .arg(format!("{ssh_user}@{host}"))
        .arg(remote_cmd)
        .stdout(Stdio::piped()) // 1. stdout을 파이프로 연결
        .stderr(Stdio::piped()) // 2. stderr를 파이프로 연결
        .spawn() // 3. .status() 대신 .spawn()으로 변경
        .wrap_err("ssh spawn 실패")?;

    // stdout/stderr 핸들 획득
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre!("stdout 파이프 연결 실패"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| eyre!("stderr 파이프 연결 실패"))?;

    // --- stdout 처리 스레드 ---
    let host_prefix_stdout = host_prefix.clone();
    let stdout_thread = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) => println!("[{}-STDOUT] {}", host_prefix_stdout, line),
                Err(e) => println!("[{}-STDOUT] stdout 읽기 에러: {}", host_prefix_stdout, e),
            }
        }
    });

    // --- stderr 처리 스레드 ---
    let stderr_thread = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(line) => println!("[{}-STDERR] {}", host_prefix, line), // stderr 로그
                Err(e) => println!("[{}-STDERR] stderr 읽기 에러: {}", host_prefix, e),
            }
        }
    });

    // --- 스레드와 자식 프로세스 종료 대기 ---
    stdout_thread.join().unwrap();
    stderr_thread.join().unwrap();

    let status = child.wait().wrap_err("ssh 자식 프로세스 wait 실패")?;

    if !status.success() {
        return Err(eyre!(
            "ssh 명령 실패 (exit code: {:?})",
            status.code()
        ));
    }
    Ok(())
}

// --- 압축 도우미 함수들 ---

/// 파일을 복사한 뒤 strip하고 gzip 압축 (바이너리용)
fn prepare_compressed_binary(src: &PathBuf) -> Result<PathBuf> {
    // 1. 임시 파일로 복사 (stripped_bin)
    let file_stem = src.file_name().unwrap_or_default();
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(file_stem);

    // 이미 있으면 삭제
    if temp_path.exists() {
        let _ = remove_file(&temp_path);
    }

    // 파일이 존재하는지 먼저 확인
    if !src.exists() {
        return Err(eyre!("바이너리 파일을 찾을 수 없습니다: {:?}", src));
    }

    copy(src, &temp_path).wrap_err(format!("바이너리 임시 복사 실패: {:?} -> {:?}", src, temp_path))?;

    // 2. strip 실행 (실패해도 무시하고 진행하도록 수정함)
    println!("[COORD] strip 시도 중... {:?}", temp_path);
    let status = Command::new("strip")
        .arg(&temp_path)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("[COORD] 바이너리 strip 성공 (크기 감소됨).");
        }
        _ => {
            // ✨ 핵심 수정: 실패하면 경고만 출력하고 계속 진행
            println!("[WARN] strip 실패 (아키텍처 불일치 등). 원본 그대로 압축합니다.");
        }
    }

    // 3. gzip 압축 (temp_path -> temp_path.gz)
    // -f: 덮어쓰기
    let status = Command::new("gzip")
        .arg("-f")
        .arg(&temp_path)
        .status()
        .wrap_err("gzip 명령 실행 실패")?;

    if !status.success() {
        return Err(eyre!("gzip 실패: {:?}", status));
    }

    // gzip은 원본 파일명 뒤에 .gz를 붙입니다.
    let gzipped_path_str = format!("{}.gz", temp_path.to_string_lossy());
    let gzipped_path = PathBuf::from(gzipped_path_str);

    println!("[COORD] 바이너리 압축 완료: {:?}", gzipped_path);
    Ok(gzipped_path)
}
/// 파일을 gzip 압축 (데이터 파일용)
fn gzip_compress(src: &PathBuf) -> Result<PathBuf> {
    // -k: 원본 유지, -f: 덮어쓰기
    let status = Command::new("gzip")
        .arg("-k")
        .arg("-f")
        .arg(src)
        .status()
        .wrap_err(format!("gzip 실행 실패: {:?}", src))?;

    if !status.success() {
        return Err(eyre!("gzip 실패: {:?}", status));
    }

    let mut dest = src.clone().into_os_string();
    dest.push(".gz");
    Ok(PathBuf::from(dest))
}

// 함수 시그니처 변경: compressed_worker_bin, compressed_pk 인자 추가
fn upload_worker_files_for_range(
    args: &Args,
    host: &str,
    output_dir: &PathBuf,
    validator_start: usize,
    validator_end: usize,
    compressed_worker_bin: &PathBuf, // 추가됨
    compressed_pk: &PathBuf,         // 추가됨
) -> Result<()> {
    println!(
        "[COORD] {} 에 파일 업로드 및 압축해제 중... (validators {}..={})",
        host, validator_start, validator_end
    );

    // 1. Worker 바이너리 (.gz) 전송
    // (이미 압축된 파일을 받아서 전송만 함)
    scp_upload(
        &args.ssh_user,
        &args.ssh_key_path,
        host,
        compressed_worker_bin,
        "zk_worker.gz",
    )?;

    // 원격: 압축 해제 및 실행 권한 부여
    ssh_exec(
        &args.ssh_user,
        &args.ssh_key_path,
        host,
        "gzip -d -f zk_worker.gz && chmod +x zk_worker",
    )?;

    // 2. 공통 파일 (proving_key.bin.gz) 전송
    scp_upload(
        &args.ssh_user,
        &args.ssh_key_path,
        host,
        compressed_pk,
        "proving_key.bin.gz",
    )?;

    ssh_exec(
        &args.ssh_user,
        &args.ssh_key_path,
        host,
        "gzip -d -f proving_key.bin.gz",
    )?;

    // 3. 작은 공통 파일들은 그냥 전송 (master_pk, config)
    scp_upload(
        &args.ssh_user,
        &args.ssh_key_path,
        host,
        &output_dir.join("master_pk.bin"),
        "master_pk.bin",
    )?;
    scp_upload(
        &args.ssh_user,
        &args.ssh_key_path,
        host,
        &output_dir.join("crypto-config.yaml"),
        "crypto-config.yaml",
    )?;

    // 4. Validator별 Input 파일 압축 전송 (이건 각자 파일이 다르므로 여기서 압축해도 안전)
    for i in validator_start..=validator_end {
        let local = output_dir.join(format!("validator_{}_input.bin", i));

        // 압축
        let local_gz = gzip_compress(&local)?;
        let remote_gz = format!("validator_{}_input.bin.gz", i);

        scp_upload(
            &args.ssh_user,
            &args.ssh_key_path,
            host,
            &local_gz,
            &remote_gz,
        )?;

        // 원격 압축 해제
        ssh_exec(
            &args.ssh_user,
            &args.ssh_key_path,
            host,
            &format!("gzip -d -f {}", remote_gz),
        )?;
    }

    Ok(())
}

fn run_remote_worker(
    args: &Args,
    host: &str,
    validator_start: usize,
    validator_end: usize,
) -> Result<()> {
    println!(
        "[COORD] {} 에서 worker 실행 (validators {}..={})",
        host, validator_start, validator_end
    );

    // 원격에서 사용할 output 디렉토리 이름
    let remote_output_dir = "worker_out";

    // 디렉토리 생성
    ssh_exec(
        &args.ssh_user,
        &args.ssh_key_path,
        host,
        &format!("mkdir -p {}", remote_output_dir),
    )?;

    // worker 실행 명령
    let cmd = format!(
        "./zk_worker \
         --mode worker \
         --committee-size {} \
         --threshold {} \
         --num-voters {} \
         --num-candidates {} \
         --election-id {} \
         --input-dir . \
         --worker-output-dir {} \
         --validator-start {} \
         --validator-end {}",
        args.committee_size,
        args.threshold,
        args.num_voters,
        args.num_candidates,
        args.election_id,
        remote_output_dir,
        validator_start,
        validator_end
    );

    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, &cmd)?;

    Ok(())
}

fn download_results(
    args: &Args,
    host: &str,
    local_output_dir: &PathBuf,
    validator_start: usize,
    validator_end: usize,
) -> Result<()> {
    println!(
        "[COORD] {} 로부터 validator_{}_txs.bin ~ validator_{}_txs.bin 다운로드",
        host, validator_start, validator_end
    );

    for i in validator_start..=validator_end {
        let remote_file = format!("worker_out/validator_{}_txs.bin", i);
        let local_file = local_output_dir.join(format!("validator_{}_txs.bin", i));

        let status = Command::new("scp")
            .arg("-i")
            .arg(&args.ssh_key_path)
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!(
                "{}@{}:{}",
                args.ssh_user, host, remote_file
            ))
            .arg(&local_file)
            .status()
            .wrap_err("scp 다운로드 실행 실패")?;

        if !status.success() {
            return Err(eyre!(
                "scp 다운로드 실패 (validator {}): {:?}",
                i,
                status
            ));
        }
    }

    Ok(())
}
