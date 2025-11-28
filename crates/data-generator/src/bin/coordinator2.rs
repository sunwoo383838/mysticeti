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
use aws_sdk_ec2::types::{BlockDeviceMapping, EbsBlockDevice, VolumeType};
use crypto::dkg::run_dkg_simulation_for_data_generator;
use crypto::elgamal::{elgamal_encrypt, encode_vote};
use crypto::types::{VoteTransaction, ZKElgamalCiphertext};
use crypto::zkp::{prove, setup, setup_poseidon_params, MerkleTreePoseidonConfig};

const GLOBAL_DKG_SEED: u64 = 1234567890;

// ✨ [변경] AGA(Global Accelerator) 관련 import 제거

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
    generation_timestamp: String,
    parameters: &'a Args,
    dkg_seed: u64,
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

    #[clap(long, default_value_t = 50)]
    committee_size: usize,

    /// 임계값 (t)
    #[clap(long, default_value_t = 33)]
    threshold: usize,

    /// 생성할 총 유권자(트랜잭션) 수
    #[clap(long, default_value_t = 7000000)]
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
    #[clap(long, default_value = ".")]
    input_dir: PathBuf,

    #[clap(long, default_value = ".")]
    worker_output_dir: PathBuf,

    #[clap(long, default_value_t = 0)]
    validator_start: usize,

    #[clap(long, default_value_t = 4)]
    validator_end: usize,

    // --- Coordinator 모드용 AWS/SSH 옵션 (한국 리전 전용) ---

    /// 한국(ap-northeast-2) AMI ID (Ubuntu 22.04/24.04 LTS arm64)
    /// ※ 주의: 리전이 바뀌었으므로 한국 리전의 유효한 ARM64 AMI ID를 넣어야 합니다.
    #[clap(long, default_value = "ami-09cd382520f248e66")] // 예시: Ubuntu 22.04 ARM64 in Seoul (확인 필요)
    aws_ami_korea: String,

    /// 한국 리전 Security Group ID (SSH 22번 포트 열려있어야 함)
    #[clap(long, default_value = "sg-0c8ca453fe66cc47d")]
    aws_sg_korea: String,

    /// AWS EC2 키페어 이름 (한국 리전에 등록된 키페어여야 함)
    #[clap(long, default_value = "prover-key-global")]
    aws_key_name: String,

    /// SSH 접속에 사용할 private key 경로 (~/.ssh/xxx.pem)
    #[clap(long, default_value = "~/.ssh/aws-prover-key")]
    ssh_key_path: PathBuf,

    /// SSH 접속 시 유저명 (Ubuntu 공식 AMI면 ubuntu)
    #[clap(long, default_value = "ubuntu")]
    ssh_user: String,

    /// 원격 인스턴스에 업로드할 arm64 실행 파일 경로
    #[clap(long, default_value = "./target/aarch64-unknown-linux-gnu/release/coordinator2")]
    worker_binary_path: PathBuf,

    // ✨ [변경] AGA 관련 옵션 제거됨
}

// ✨ [변경] register_to_aga 함수 제거됨

// main 함수 바깥이나 별도 모듈에 추가
struct InstanceTerminator {
    client: Ec2Client,
    instance_id: String,
    node_name: String, // 로그 출력을 위해 추가
}

impl InstanceTerminator {
    fn new(client: Ec2Client, instance_id: String, node_name: String) -> Self {
        Self { client, instance_id, node_name }
    }
}

impl Drop for InstanceTerminator {
    fn drop(&mut self) {
        println!("[COORD] {} ({}) 인스턴스 자동 정리 시작...", self.node_name, self.instance_id);

        let client = self.client.clone();
        let instance_id = self.instance_id.clone();

        tokio::spawn(async move {
            match terminate_instance(&client, &instance_id).await {
                Ok(_) => println!("[COORD] ({}) 인스턴스 자동 종료 요청 성공.", instance_id),
                Err(e) => eprintln!("[COORD] ({}) 인스턴스 자동 종료 실패: {}", instance_id, e),
            }
        });
    }
}

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

// ==================== WORKER (변경 없음) ====================

fn run_worker(args: &Args) -> Result<()> {
    // ... (기존 코드와 동일, 내용 생략) ...
    // 실제 구현에서는 기존 run_worker 코드를 그대로 사용하세요.
    // 문맥상 기존 코드와 100% 동일합니다.
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

    // 1-1. proving_key.bin
    let pk_path = input_dir.join("proving_key.bin");
    let mut pk_bytes = Vec::new();
    File::open(&pk_path).wrap_err("proving_key.bin 파일 열기 실패")?.read_to_end(&mut pk_bytes)?;
    let mut pk_cursor = &pk_bytes[..];
    let pk: ProvingKey<Bls12_381> = CanonicalDeserialize::deserialize_uncompressed(&mut pk_cursor)?;
    let pk = Arc::new(pk);

    // 1-2. master_pk.bin
    let mpk_path = input_dir.join("master_pk.bin");
    let mut mpk_bytes = Vec::new();
    File::open(&mpk_path).wrap_err("master_pk.bin 파일 열기 실패")?.read_to_end(&mut mpk_bytes)?;
    let mut mpk_cursor = &mpk_bytes[..];
    let master_pk: EdwardsAffine = CanonicalDeserialize::deserialize_uncompressed(&mut mpk_cursor)?;
    let master_pk = Arc::new(master_pk);

    // 1-3. crypto-config
    let crypto_conf_path = input_dir.join("crypto-config.yaml");
    let crypto_yaml = std::fs::read_to_string(&crypto_conf_path)?;
    let crypto_cfg: CryptoConfig = serde_yaml::from_str(&crypto_yaml)?;
    let merkle_root = Fr::from_str(&crypto_cfg.merkle_root).map_err(|_| eyre!("Fr 파싱 실패"))?;
    let g = JubJubAffine::generator();

    for validator_idx in args.validator_start..=args.validator_end {
        let input_file = input_dir.join(format!("validator_{}_input.bin", validator_idx));
        let mut input_bytes = Vec::new();
        File::open(&input_file)?.read_to_end(&mut input_bytes)?;
        let mut input_cursor = &input_bytes[..];

        let cred_path_vec: Vec<(Fr, Path<MerkleTreePoseidonConfig>)> =
            CanonicalDeserialize::deserialize_uncompressed(&mut input_cursor)?;

        let chunk_len = cred_path_vec.len();
        let pk_clone = Arc::clone(&pk);
        let master_pk_clone = Arc::clone(&master_pk);
        let election_id_clone = election_id.clone();
        let progress_counter = Arc::new(AtomicUsize::new(0));
        let log_interval = (chunk_len / 10).max(1);

        // (Prove 로직 동일)
        let transactions: Vec<VoteTransaction> = cred_path_vec
            .into_par_iter()
            .enumerate()
            .map(|(local_index, (cred, merkle_path))| -> Result<VoteTransaction> {
                let mut vote_rng = StdRng::from_entropy();
                let mut vote_bits = vec![false; num_candidates];
                let mut vote_u8 = vec![0u8; num_candidates];
                let vote_idx = vote_rng.gen_range(0..num_candidates);
                vote_bits[vote_idx] = true;
                vote_u8[vote_idx] = 1;

                let r = JubJubFr::rand(&mut vote_rng);
                let mut enc_vote_vec_projective = Vec::with_capacity(num_candidates);
                let mut env_vote_vec_affine = Vec::with_capacity(num_candidates);

                for &bit in vote_bits.iter() {
                    let vote_point = encode_vote(if bit { 1 } else { 0 }, &g);
                    let (c1, c2) = elgamal_encrypt(&vote_point, &master_pk_clone, &g, r);
                    env_vote_vec_affine.push((c1.into_group().into_affine(), c2.into_group().into_affine()));
                    enc_vote_vec_projective.push(ZKElgamalCiphertext { c1, c2 });
                }

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
                )?;

                let nullifier = public_inputs.last().cloned().ok_or_else(|| eyre!("Empty public inputs"))?;

                let current_count = progress_counter.fetch_add(1, Ordering::Relaxed) + 1;
                if current_count % log_interval == 0 && current_count < chunk_len {
                    println!("[WORKER] validator {}: {}/{} 완료", validator_idx, current_count, chunk_len);
                }

                Ok(VoteTransaction { proof, nullifier, enc_vote_vec: enc_vote_vec_projective })
            })
            .collect::<Result<Vec<VoteTransaction>>>()?;

        let out_file = output_dir.join(format!("validator_{}_txs.bin", validator_idx));
        let serialized_data = bincode::serialize(&transactions)?;
        let mut f = File::create(&out_file)?;
        f.write_all(&serialized_data)?;
    }
    println!("[WORKER] 완료.");
    Ok(())
}

// ==================== COORDINATOR - COMMON INPUT GEN (변경 없음) ====================

fn prepare_common_inputs(args: &Args) -> Result<PathBuf> {
    // 기존 prepare_common_inputs 함수 내용 그대로 사용 (N, T, K 등에 따른 데이터 생성)
    // 코드가 너무 길어지므로 생략합니다. 기존 로직과 완전히 동일합니다.
    // ...
    // (기존 코드의 내용이 여기에 들어갑니다)

    // 편의를 위해 짧게 구현 내용 요약 대신 원본 코드 유지 권장
    let n = args.committee_size;
    let t = args.threshold;
    let k_max = args.num_voters;
    let num_candidates = args.num_candidates;
    let g = JubJubAffine::generator();
    let new_dir_name = format!("n{}_t{}_k{}", n, t, k_max);
    let output_dir = args.output_dir.join(new_dir_name);
    create_dir_all(&output_dir)?;

    // 1. DKG
    let master_pk = run_dkg_simulation_for_data_generator(n, t, GLOBAL_DKG_SEED);
    let merkle_height = if k_max <= 1 { 1 } else { (k_max as u64 - 1).ilog2() as usize + 1 };
    let election_id_fr = Fr::from_le_bytes_mod_order(args.election_id.as_bytes());

    // 2. Setup
    let (pk, vk) = setup(num_candidates, merkle_height, master_pk.clone(), g, election_id_fr).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes)?;
    let vk_base64 = STANDARD.encode(vk_bytes);

    // 3. Merkle Tree
    let (params_leaf, params_merkle, _) = setup_poseidon_params();
    let params_leaf_arc = Arc::new(params_leaf);

    let (voter_data, mut leaves): (Vec<Fr>, Vec<Fr>) = (0..k_max).into_par_iter().map(|_| {
        let mut rng = StdRng::from_entropy();
        let cred = Fr::rand(&mut rng);
        let leaf = CRH::evaluate(&params_leaf_arc, [cred, election_id_fr]).unwrap();
        (cred, leaf)
    }).unzip();

    let num_leaves = 2_usize.pow(merkle_height as u32);
    if leaves.len() < num_leaves { leaves.resize(num_leaves, Fr::zero()); }
    let tree = MerkleTree::<MerkleTreePoseidonConfig>::new_with_leaf_digest(&params_leaf_arc, &params_merkle, leaves).unwrap();
    let merkle_root = tree.root();
    let tree_arc = Arc::new(tree);

    // 4. Inputs
    let voter_data_with_index: Vec<(usize, Fr)> = voter_data.iter().cloned().enumerate().collect();
    let chunk_size = (k_max + n - 1) / n;

    for (auth_idx, chunk) in voter_data_with_index.chunks(chunk_size).enumerate() {
        if auth_idx >= n { break; }
        let mut cred_path_vec = Vec::with_capacity(chunk.len());
        for (g_idx, cred) in chunk.iter() {
            let path = tree_arc.generate_proof(*g_idx).unwrap();
            cred_path_vec.push((*cred, path));
        }
        let fname = output_dir.join(format!("validator_{}_input.bin", auth_idx));
        let mut buf = Vec::new();
        cred_path_vec.serialize_uncompressed(&mut buf)?;
        std::fs::write(&fname, buf)?;
    }

    // 5, 6, 7. PK, MPK, Config 저장
    let mut pk_bytes = Vec::new(); pk.serialize_uncompressed(&mut pk_bytes)?;
    std::fs::write(output_dir.join("proving_key.bin"), pk_bytes)?;

    let mut mpk_bytes = Vec::new(); master_pk.serialize_uncompressed(&mut mpk_bytes)?;
    std::fs::write(output_dir.join("master_pk.bin"), mpk_bytes)?;

    let crypto_config = CryptoConfig {
        num_candidates,
        merkle_root: merkle_root.to_string(),
        verifying_key: vk_base64,
        global_seed: GLOBAL_DKG_SEED,
    };
    let yaml = serde_yaml::to_string(&crypto_config)?;
    std::fs::write(output_dir.join("crypto-config.yaml"), yaml)?;

    Ok(output_dir)
}

// ==================== COORDINATOR - AWS CONTROL (수정됨) ====================

async fn run_coordinator(args: &Args) -> Result<()> {
    // 1. 공통 입력 생성 (로컬)
    println!("[COORD] 공통 입력 생성 시작... (시간 소요)");
    let args_clone = args.clone();
    let output_dir = tokio::task::spawn_blocking(move || {
        prepare_common_inputs(&args_clone)
    }).await??;
    println!("[COORD] 공통 입력 생성 완료: {}", output_dir.display());

    // 2. AWS 클라이언트 생성 (한국 리전)
    // ✨ [변경] Global Accelerator 없이, ap-northeast-2 리전만 사용
    let region_name = "ap-northeast-2";
    let conf_korea = aws_config::from_env()
        .region(aws_sdk_ec2::config::Region::new(region_name))
        .load()
        .await;
    let ec2_korea = Ec2Client::new(&conf_korea);

    // 3. 인스턴스 생성 (Node 1, Node 2) - 둘 다 한국 리전
    // ✨ [변경] 같은 리전, 같은 AMI, 같은 KeyName 사용
    println!("[COORD] 한국 리전({})에 2개의 인스턴스 생성 요청 중...", region_name);

    // 병렬 생성을 위해 클라이언트 복제
    let ec2_korea_1 = ec2_korea.clone();
    let ec2_korea_2 = ec2_korea.clone();

    // args는 unwrap하지 않고 clone하여 사용
    let ami = args.aws_ami_korea.clone();
    let key = args.aws_key_name.clone();
    let sg = args.aws_sg_korea.clone();

    let ami_2 = ami.clone();
    let key_2 = key.clone();
    let sg_2 = sg.clone();

    let (inst_node1, inst_node2) = tokio::join!(
        launch_instance(&ec2_korea_1, &ami, &key, "c8g.48xlarge", &sg),
        launch_instance(&ec2_korea_2, &ami_2, &key_2, "c8g.48xlarge", &sg_2)
    );

    let inst_node1 = inst_node1?;
    let inst_node2 = inst_node2?;

    println!("[COORD] Node 1 ID: {}, Node 2 ID: {}", inst_node1.instance_id, inst_node2.instance_id);

    // 자동 종료 가드 설정
    let _node1_guard = InstanceTerminator::new(
        ec2_korea.clone(),
        inst_node1.instance_id.clone(),
        "Node1(Korea)".to_string()
    );
    let _node2_guard = InstanceTerminator::new(
        ec2_korea.clone(),
        inst_node2.instance_id.clone(),
        "Node2(Korea)".to_string()
    );

    // 4. Public DNS 대기 (IP 직접 사용)
    let (info_node1, info_node2) = tokio::join!(
        wait_for_instance_ready(&ec2_korea, &inst_node1.instance_id),
        wait_for_instance_ready(&ec2_korea, &inst_node2.instance_id)
    );
    let info_node1 = info_node1?;
    let info_node2 = info_node2?;

    // ✨ [변경] AGA DNS 대신 EC2 Public DNS 직접 사용
    let host_node1 = info_node1.public_dns;
    let host_node2 = info_node2.public_dns;

    println!("[COORD] Node 1 Address: {}", host_node1);
    println!("[COORD] Node 2 Address: {}", host_node2);

    // 5. SSH 접속 대기
    let h1 = host_node1.clone();
    let h2 = host_node2.clone();
    let ssh_check_1 = tokio::task::spawn_blocking(move || wait_for_ssh(&h1));
    let ssh_check_2 = tokio::task::spawn_blocking(move || wait_for_ssh(&h2));

    let (res1, res2) = tokio::join!(ssh_check_1, ssh_check_2);
    res1??; res2??;
    println!("[COORD] SSH 접속 확인 완료.");

    // 6. 파일 압축
    println!("[COORD] 전송 최적화를 위해 파일 압축 중...");
    let compressed_worker_bin = prepare_compressed_binary(&args.worker_binary_path)?;
    let pk_path = output_dir.join("proving_key.bin");
    let compressed_pk = gzip_compress(&pk_path)?;
    println!("[COORD] 압축 완료.");

    // 7. 파일 업로드 및 실행 (Node 1: 앞부분 절반, Node 2: 뒷부분 절반)
    let half = args.committee_size / 2;
    let n = args.committee_size;

    // 범위 설정
    let node1_start = 0;
    let node1_end = half - 1;
    let node2_start = half;
    let node2_end = n - 1;

    let args_clone_1 = args.clone();
    let args_clone_2 = args.clone();

    let out_dir_1 = output_dir.clone();
    let out_dir_2 = output_dir.clone();

    let bin_1 = compressed_worker_bin.clone();
    let pk_1 = compressed_pk.clone();
    let bin_2 = compressed_worker_bin.clone();
    let pk_2 = compressed_pk.clone();

    let host_upload_1 = host_node1.clone();
    let host_upload_2 = host_node2.clone();

    // 업로드 병렬 실행
    let upload_fut_1 = tokio::task::spawn_blocking(move || {
        upload_worker_files_for_range(
            &args_clone_1, &host_upload_1, &out_dir_1, node1_start, node1_end, &bin_1, &pk_1
        )
    });
    let upload_fut_2 = tokio::task::spawn_blocking(move || {
        upload_worker_files_for_range(
            &args_clone_2, &host_upload_2, &out_dir_2, node2_start, node2_end, &bin_2, &pk_2
        )
    });
    upload_fut_1.await??;
    upload_fut_2.await??;
    println!("[COORD] 파일 업로드 완료.");

    // 8. 원격 실행 및 결과 다운로드
    let args_run_1 = args.clone();
    let args_run_2 = args.clone();
    let out_dir_run_1 = output_dir.clone();
    let out_dir_run_2 = output_dir.clone();
    let host_run_1 = host_node1.clone();
    let host_run_2 = host_node2.clone();

    let run_fut_1 = tokio::task::spawn_blocking(move || {
        println!("[COORD] (Node 1) validators {}..={} 작업 시작", node1_start, node1_end);
        run_remote_worker(&args_run_1, &host_run_1, node1_start, node1_end)?;
        download_results(&args_run_1, &host_run_1, &out_dir_run_1, node1_start, node1_end)?;
        println!("[COORD] (Node 1) 작업 완료");
        Ok::<(), eyre::Report>(())
    });

    let run_fut_2 = tokio::task::spawn_blocking(move || {
        println!("[COORD] (Node 2) validators {}..={} 작업 시작", node2_start, node2_end);
        run_remote_worker(&args_run_2, &host_run_2, node2_start, node2_end)?;
        download_results(&args_run_2, &host_run_2, &out_dir_run_2, node2_start, node2_end)?;
        println!("[COORD] (Node 2) 작업 완료");
        Ok::<(), eyre::Report>(())
    });

    let (res_run_1, res_run_2) = tokio::join!(run_fut_1, run_fut_2);
    res_run_1??;
    res_run_2??;

    // 9. 인스턴스 명시적 종료
    terminate_instance(&ec2_korea, &inst_node1.instance_id).await?;
    terminate_instance(&ec2_korea, &inst_node2.instance_id).await?;

    println!("[COORD] 모든 작업이 성공적으로 완료되었습니다.");
    Ok(())
}

// ==================== AWS UTILS ====================

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
    use aws_sdk_ec2::types::{
        InstanceMarketOptionsRequest, InstanceInterruptionBehavior, MarketType,
        SpotInstanceType, SpotMarketOptions,
    };

    let instance_type = match instance_type_str {
        "c8g.48xlarge" => InstanceType::C8g48xlarge,
        _ => InstanceType::C8g48xlarge,
    };

    let spot_options = SpotMarketOptions::builder()
        .spot_instance_type(SpotInstanceType::OneTime)
        .instance_interruption_behavior(InstanceInterruptionBehavior::Terminate)
        .build();

    let market_options = InstanceMarketOptionsRequest::builder()
        .market_type(MarketType::Spot)
        .spot_options(spot_options)
        .build();

    let block_device_mapping = BlockDeviceMapping::builder()
        .device_name("/dev/sda1")
        .ebs(
            EbsBlockDevice::builder()
                .volume_size(100)             // 8GB -> 500GB로 증설
                .volume_type(VolumeType::Gp3) // 최신 gp3 타입 사용 (성능/비용 유리)
                .delete_on_termination(true)  // 인스턴스 종료 시 디스크도 자동 삭제
                .build(),
        )
        .build();

    // ✨ [확인] Security Group ID가 args로 전달됨
    let out = ec2
        .run_instances()
        .image_id(ami)
        .instance_type(instance_type)
        .key_name(key_name)
        .security_group_ids(security_group_id)
        .min_count(1)
        .max_count(1)
        .instance_market_options(market_options)
        .block_device_mappings(block_device_mapping)
        .send()
        .await
        .wrap_err("run_instances 실패")?;

    let instances = out.instances();
    let inst = instances.first().ok_or_else(|| eyre!("인스턴스 생성 결과가 비어있음"))?;
    let instance_id = inst.instance_id().ok_or_else(|| eyre!("instance_id 없음"))?.to_string();

    Ok(InstanceHandle { instance_id })
}

async fn wait_for_instance_ready(
    ec2: &Ec2Client,
    instance_id: &str,
) -> Result<InstanceInfo> {
    loop {
        let out = ec2.describe_instances().instance_ids(instance_id).send().await
            .wrap_err("describe_instances 실패")?;

        let reservations = out.reservations();
        let inst_opt = reservations.iter().flat_map(|r| r.instances()).find(|i| i.instance_id() == Some(instance_id));

        if let Some(inst) = inst_opt {
            let state = inst.state().and_then(|s| s.name()).map(|s| format!("{:?}", s)).unwrap_or_else(|| "UNKNOWN".to_string());
            let public_dns = inst.public_dns_name().unwrap_or_default().to_string();

            // 일부 경우 public_dns 대신 public_ip가 먼저 할당될 수 있으므로 둘 다 체크하면 좋으나, 여기선 DNS 기준
            println!("[COORD] {} 상태: {}, DNS: {}", instance_id, state, public_dns);

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
    ec2.terminate_instances().instance_ids(instance_id).send().await
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

// ==================== SCP / SSH / COMPRESS UTILS (기존과 동일) ====================

// scp_upload, ssh_exec, prepare_compressed_binary, gzip_compress 등
// 아래 함수들은 기존 코드의 구현을 그대로 사용하면 됩니다.

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

fn ssh_exec(ssh_user: &str, key_path: &PathBuf, host: &str, remote_cmd: &str) -> Result<()> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let host_prefix = host.split('.').next().unwrap_or(host).to_uppercase();
    let mut child = Command::new("ssh")
        .arg("-i").arg(key_path)
        .arg("-o").arg("StrictHostKeyChecking=no")
        .arg("-o").arg("UserKnownHostsFile=/dev/null")
        .arg("-o").arg("ServerAliveInterval=15")
        .arg("-o").arg("ServerAliveCountMax=20")
        .arg("-o").arg("TCPKeepAlive=yes")
        .arg(format!("{ssh_user}@{host}"))
        .arg(remote_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .wrap_err("ssh spawn 실패")?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let h1 = host_prefix.clone();
    let t1 = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() { if let Ok(l) = line { println!("[{}-OUT] {}", h1, l); } }
    });
    let h2 = host_prefix.clone();
    let t2 = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() { if let Ok(l) = line { println!("[{}-ERR] {}", h2, l); } }
    });

    t1.join().unwrap(); t2.join().unwrap();
    let status = child.wait()?;
    if !status.success() { return Err(eyre!("ssh failed: {:?}", status.code())); }
    Ok(())
}

fn prepare_compressed_binary(src: &PathBuf) -> Result<PathBuf> {
    let file_stem = src.file_name().unwrap_or_default();
    let temp_path = std::env::temp_dir().join(file_stem);
    if temp_path.exists() { let _ = remove_file(&temp_path); }
    if !src.exists() { return Err(eyre!("바이너리 없음: {:?}", src)); }

    copy(src, &temp_path)?;
    let _ = Command::new("strip").arg(&temp_path).status(); // strip 시도 (실패해도 무시)

    let status = Command::new("gzip").arg("-f").arg(&temp_path).status()?;
    if !status.success() { return Err(eyre!("gzip failed")); }

    Ok(PathBuf::from(format!("{}.gz", temp_path.to_string_lossy())))
}

fn gzip_compress(src: &PathBuf) -> Result<PathBuf> {
    let status = Command::new("gzip").arg("-k").arg("-f").arg(src).status()?;
    if !status.success() { return Err(eyre!("gzip failed")); }
    let mut dest = src.clone().into_os_string();
    dest.push(".gz");
    Ok(PathBuf::from(dest))
}

fn upload_worker_files_for_range(
    args: &Args,
    host: &str,
    output_dir: &PathBuf,
    validator_start: usize,
    validator_end: usize,
    compressed_worker_bin: &PathBuf,
    compressed_pk: &PathBuf,
) -> Result<()> {
    println!("[COORD] {} 파일 업로드 시작 ({}-{})", host, validator_start, validator_end);

    scp_upload(&args.ssh_user, &args.ssh_key_path, host, compressed_worker_bin, "zk_worker.gz")?;
    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, "gzip -d -f zk_worker.gz && chmod +x zk_worker")?;

    scp_upload(&args.ssh_user, &args.ssh_key_path, host, compressed_pk, "proving_key.bin.gz")?;
    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, "gzip -d -f proving_key.bin.gz")?;

    scp_upload(&args.ssh_user, &args.ssh_key_path, host, &output_dir.join("master_pk.bin"), "master_pk.bin")?;
    scp_upload(&args.ssh_user, &args.ssh_key_path, host, &output_dir.join("crypto-config.yaml"), "crypto-config.yaml")?;

    for i in validator_start..=validator_end {
        let local = output_dir.join(format!("validator_{}_input.bin", i));
        let local_gz = gzip_compress(&local)?;
        let remote_gz = format!("validator_{}_input.bin.gz", i);

        scp_upload(&args.ssh_user, &args.ssh_key_path, host, &local_gz, &remote_gz)?;
        ssh_exec(&args.ssh_user, &args.ssh_key_path, host, &format!("gzip -d -f {}", remote_gz))?;
    }
    Ok(())
}

fn run_remote_worker(args: &Args, host: &str, start: usize, end: usize) -> Result<()> {
    let remote_dir = "worker_out";
    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, &format!("mkdir -p {}", remote_dir))?;

    let cmd = format!(
        "./zk_worker --mode worker --committee-size {} --threshold {} --num-voters {} --num-candidates {} --election-id {} --input-dir . --worker-output-dir {} --validator-start {} --validator-end {}",
        args.committee_size, args.threshold, args.num_voters, args.num_candidates, args.election_id, remote_dir, start, end
    );
    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, &cmd)?;
    Ok(())
}

fn download_results(args: &Args, host: &str, local_dir: &PathBuf, start: usize, end: usize) -> Result<()> {
    for i in start..=end {
        let remote = format!("worker_out/validator_{}_txs.bin", i);
        let local = local_dir.join(format!("validator_{}_txs.bin", i));

        let status = Command::new("scp")
            .arg("-i").arg(&args.ssh_key_path)
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg(format!("{}@{}:{}", args.ssh_user, host, remote))
            .arg(&local)
            .status()?;

        if !status.success() { return Err(eyre!("Download failed: {}", i)); }
    }
    Ok(())
}