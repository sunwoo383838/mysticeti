
use std::fs::{copy, create_dir_all, remove_file, File};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};
use std::str::FromStr;

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

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use eyre::{eyre, Context, Result};

// --- AWS Imports ---
use aws_sdk_ec2::types::InstanceStateName;
// --- Crypto & Arkworks (Placeholder for imports) ---
// 실제 프로젝트에 있는 import들을 유지하세요.
// use ark_bls12_381::Fr; ...

const GLOBAL_DKG_SEED: u64 = 1234567890;

// ==================== CLI & Config ====================

#[derive(Copy, Clone, Debug, Serialize, ValueEnum)]
enum RunMode {
    Coordinator,
    Worker,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Debug)]
struct BenchmarkMetadata<'a> {
    generation_timestamp: String,
    parameters: &'a Args,
    dkg_seed: u64,
    derived_data: DerivedData,
}


#[derive(Parser, Debug, Serialize, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 실행 모드
    #[clap(long, value_enum, default_value_t = RunMode::Coordinator)]
    mode: RunMode,

    // --- Benchmark Parameters ---
    #[clap(long, default_value_t =10)]
    committee_size: usize,
    #[clap(long, default_value_t = 7)]
    threshold: usize,
    #[clap(long, default_value_t = 7000000)]
    num_voters: usize,
    #[clap(long, default_value_t = 3)]
    num_candidates: usize,
    #[clap(long, default_value = "election-2025")]
    election_id: String,
    #[clap(long, default_value = "benchmark_batches")]
    output_dir: PathBuf,

    // --- Worker Options ---
    #[clap(long, default_value = ".")]
    input_dir: PathBuf,
    #[clap(long, default_value = ".")]
    worker_output_dir: PathBuf,
    #[clap(long, default_value_t = 0)]
    validator_start: usize,
    #[clap(long, default_value_t = 4)]
    validator_end: usize,

    // --- Coordinator AWS Options (Sydney Custom Routing) ---

    #[clap(long, default_value = "ap-southeast-2")]
    aws_region: String,

    /// Sydney AMI ID (Ubuntu 22.04 ARM64)
    #[clap(long, default_value = "ami-001d15f74cae057d8")]
    aws_ami: String,

    #[clap(long, default_value = "prover-key-global")]
    aws_key_name: String,

    #[clap(long, default_value = "~/.ssh/aws-prover-key")]
    ssh_key_path: PathBuf,

    #[clap(long, default_value = "ubuntu")]
    ssh_user: String,

    /// 업로드할 Worker 바이너리 경로
    #[clap(long, default_value = "./target/aarch64-unknown-linux-gnu/release/coordinator3")]
    worker_binary_path: PathBuf,

    // ✨ [수정됨] AGA Custom Routing 단순화 설정

    /// AGA Endpoint Group에 등록된 Subnet ID (인스턴스 생성 위치)
    #[clap(long, default_value = "subnet-05f55942aa6a1760b")]
    aws_subnet_id: String,

    /// AGA DNS 주소 (예: a-xxxx.awsglobalaccelerator.com)
    #[clap(long, default_value = "a835be745af9ec0d6.awsglobalaccelerator.com")]
    aga_dns: String,

    /// 첫 번째 워커 인스턴스에 할당된 AGA 외부 포트 (Static Mapping)
    #[clap(long, default_value_t = 10000)]
    worker1_port: u16,

    /// 두 번째 워커 인스턴스에 할당된 AGA 외부 포트 (Static Mapping)
    #[clap(long, default_value_t = 10001)]
    worker2_port: u16,
}

// ==================== Instance Utils ====================

#[derive(Debug, Clone)]
struct InstanceInfo {
    instance_id: String,
    private_ip: String,
}

struct InstanceHandle {
    instance_id: String,
}

struct InstanceTerminator {
    client: Ec2Client,
    instance_id: String,
}

impl InstanceTerminator {
    fn new(client: Ec2Client, instance_id: String) -> Self {
        Self { client, instance_id }
    }
}

impl Drop for InstanceTerminator {
    fn drop(&mut self) {
        let client = self.client.clone();
        let id = self.instance_id.clone();
        tokio::spawn(async move {
            println!("[COORD] 인스턴스 종료 요청(Drop): {}", id);
            let _ = client.terminate_instances().instance_ids(&id).send().await;
        });
    }
}

// ==================== SSH / SCP Helper ====================

fn wait_for_ssh(host: &str, port: u16) -> Result<()> {
    println!("[COORD] SSH 접속 대기: {}:{}", host, port);
    for _ in 0..60 {
        if TcpStream::connect((host, port)).is_ok() {
            println!("[COORD] SSH 연결 성공: {}:{}", host, port);
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    Err(eyre!("SSH 연결 실패: {}:{}", host, port))
}

fn ssh_exec(
    ssh_user: &str,
    key_path: &PathBuf,
    host: &str,
    port: u16,
    remote_cmd: &str,
) -> Result<()> {
    let status = Command::new("ssh")
        .arg("-p").arg(port.to_string())
        .arg("-i").arg(key_path)
        .arg("-o").arg("StrictHostKeyChecking=no")
        .arg("-o").arg("UserKnownHostsFile=/dev/null")
        // 👇 [수정] 15초마다 신호를 보내되, 100번 실패할 때까지(약 25분) 기다려줌
        .arg("-o").arg("ServerAliveInterval=15")
        .arg("-o").arg("ServerAliveCountMax=100")
        .arg("-o").arg("TCPKeepAlive=yes")
        .arg(format!("{}@{}", ssh_user, host))
        .arg(remote_cmd)
        .status() // spawn() 대신 status()를 쓰면 stdout이 현재 터미널에 나옵니다 (권장)
        .wrap_err("ssh 실행 실패")?;
    if !status.success() {
        return Err(eyre!("원격 명령 실패: {}", remote_cmd));
    }
    Ok(())
}

fn scp_upload(
    ssh_user: &str,
    key_path: &PathBuf,
    host: &str,
    port: u16,
    local: &PathBuf,
    remote: &str,
) -> Result<()> {
    let max_retries = 10; // 최대 10번까지 재시도

    for attempt in 1..=max_retries {
        let status = Command::new("scp")
            .arg("-i")
            .arg(key_path)
            .arg("-P").arg(port.to_string())
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

// ==================== Coordinator Functions ====================

async fn launch_instance_in_subnet(
    ec2: &Ec2Client,
    ami: &str,
    key_name: &str,
    subnet_id: &str,
    private_ip: &str,
) -> Result<InstanceHandle> {
    use aws_sdk_ec2::types::{
        InstanceType, InstanceMarketOptionsRequest, InstanceInterruptionBehavior,
        MarketType, SpotInstanceType, SpotMarketOptions, InstanceNetworkInterfaceSpecification
    };

    let spot_options = SpotMarketOptions::builder()
        .spot_instance_type(SpotInstanceType::OneTime)
        .instance_interruption_behavior(InstanceInterruptionBehavior::Terminate)
        .build();

    let market_options = InstanceMarketOptionsRequest::builder()
        .market_type(MarketType::Spot)
        .spot_options(spot_options)
        .build();

    let out = ec2
        .run_instances()
        .image_id(ami)
        .instance_type(InstanceType::C8g48xlarge)
        .key_name(key_name)
        .subnet_id(subnet_id)
        .private_ip_address(private_ip) // 🔥 여기 중요: 고정 IP
        .min_count(1)
        .max_count(1)
        .instance_market_options(market_options)
        .send()
        .await
        .wrap_err("run_instances 실패")?;

    let inst = out.instances().first().ok_or_else(|| eyre!("인스턴스 생성 실패"))?;
    let instance_id = inst.instance_id().ok_or_else(|| eyre!("ID 없음"))?.to_string();

    Ok(InstanceHandle { instance_id })
}

async fn wait_for_instance_ready(ec2: &Ec2Client, instance_id: &str) -> Result<InstanceInfo> {
    loop {
        let out = ec2.describe_instances().instance_ids(instance_id).send().await?;
        if let Some(res) = out.reservations().first() {
            if let Some(inst) = res.instances().first() {
                let state_opt = inst.state().and_then(|s| s.name());
                let private_ip = inst.private_ip_address().unwrap_or_default().to_string();

                if let Some(state) = state_opt {
                    if *state == InstanceStateName::Running && !private_ip.is_empty() {
                        return Ok(InstanceInfo {
                            instance_id: instance_id.to_string(),
                            private_ip,
                        });
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn upload_worker_files_for_range(
    args: &Args,
    host: &str,
    port: u16,
    output_dir: &PathBuf,
    validator_start: usize,
    validator_end: usize,
    compressed_worker_bin: &PathBuf,
    compressed_pk: &PathBuf,
) -> Result<()> {
    println!("[COORD] 파일 업로드 -> {}:{} (Validators {}~{})", host, port, validator_start, validator_end);

    // 1. Worker Binary & PK
    scp_upload(&args.ssh_user, &args.ssh_key_path, host, port, compressed_worker_bin, "zk_worker.gz")?;
    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, port, "gzip -d -f zk_worker.gz && chmod +x zk_worker")?;

    scp_upload(&args.ssh_user, &args.ssh_key_path, host, port, compressed_pk, "proving_key.bin.gz")?;
    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, port, "gzip -d -f proving_key.bin.gz")?;

    // 2. Configs
    scp_upload(&args.ssh_user, &args.ssh_key_path, host, port, &output_dir.join("master_pk.bin"), "master_pk.bin")?;
    scp_upload(&args.ssh_user, &args.ssh_key_path, host, port, &output_dir.join("crypto-config.yaml"), "crypto-config.yaml")?;

    // 3. Inputs
    for i in validator_start..=validator_end {
        let local = output_dir.join(format!("validator_{}_input.bin", i));
        // Gzip compression logic should be here or handled before
        let status = Command::new("gzip").arg("-k").arg("-f").arg(&local).status()?;
        if !status.success() { return Err(eyre!("로컬 gzip 실패")); }

        let local_gz = output_dir.join(format!("validator_{}_input.bin.gz", i));
        let remote_gz = format!("validator_{}_input.bin.gz", i);

        scp_upload(&args.ssh_user, &args.ssh_key_path, host, port, &local_gz, &remote_gz)?;
        ssh_exec(&args.ssh_user, &args.ssh_key_path, host, port, &format!("gzip -d -f {}", remote_gz))?;
    }
    Ok(())
}

fn run_remote_worker(
    args: &Args,
    host: &str,
    port: u16,
    validator_start: usize,
    validator_end: usize,
) -> Result<()> {
    println!("[COORD] Worker 실행 요청 -> {}:{}", host, port);
    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, port, "mkdir -p worker_out")?;

    let cmd = format!(
        "./zk_worker --mode worker --committee-size {} --threshold {} \
         --num-voters {} --num-candidates {} --election-id {} \
         --input-dir . --worker-output-dir worker_out \
         --validator-start {} --validator-end {}",
        args.committee_size, args.threshold,
        args.num_voters, args.num_candidates, args.election_id,
        validator_start, validator_end
    );

    ssh_exec(&args.ssh_user, &args.ssh_key_path, host, port, &cmd)?;
    Ok(())
}

fn download_results(
    args: &Args,
    host: &str,
    port: u16,
    local_output_dir: &PathBuf,
    validator_start: usize,
    validator_end: usize,
) -> Result<()> {
    println!("[COORD] 결과 다운로드 -> {}:{}", host, port);
    for i in validator_start..=validator_end {
        let remote_file = format!("worker_out/validator_{}_txs.bin", i);
        let local_file = local_output_dir.join(format!("validator_{}_txs.bin", i));

        let status = Command::new("scp")
            .arg("-P").arg(port.to_string())
            .arg("-i").arg(&args.ssh_key_path)
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg("UserKnownHostsFile=/dev/null")
            .arg(format!("{}@{}:{}", args.ssh_user, host, remote_file))
            .arg(&local_file)
            .status()?;

        if !status.success() {
            return Err(eyre!("다운로드 실패: validator {}", i));
        }
    }
    Ok(())
}

fn prepare_compressed_binary(src: &PathBuf) -> Result<PathBuf> {
    let file_stem = src.file_name().unwrap();
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(file_stem);
    copy(src, &temp_path)?;
    Command::new("strip").arg(&temp_path).status().ok();
    let status = Command::new("gzip").arg("-f").arg(&temp_path).status()?;
    if !status.success() { return Err(eyre!("gzip fail")); }
    Ok(PathBuf::from(format!("{}.gz", temp_path.display())))
}

fn gzip_compress(src: &PathBuf) -> Result<PathBuf> {
    let status = Command::new("gzip").arg("-k").arg("-f").arg(src).status()?;
    if !status.success() { return Err(eyre!("gzip fail")); }
    Ok(PathBuf::from(format!("{}.gz", src.display())))
}

async fn terminate_instance(ec2: &Ec2Client, instance_id: &str) -> Result<()> {
    println!("[COORD] 인스턴스 종료 요청: {}", instance_id);
    ec2.terminate_instances().instance_ids(instance_id).send().await.unwrap();
    Ok(())
}

// ==================== Main Flow ====================

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    match args.mode {
        RunMode::Coordinator => run_coordinator(&args).await,
        RunMode::Worker => run_worker(&args),
    }
}

async fn run_coordinator(args: &Args) -> Result<()> {
    println!("==================================================");
    println!("   ZK Prover Coordinator (Sydney Custom Routing)  ");
    println!("==================================================");

    // 1. 공통 데이터 생성
    println!("[COORD] 공통 데이터 생성 중...");
    let args_clone = args.clone();
    let output_dir = tokio::task::spawn_blocking(move || prepare_common_inputs(&args_clone)).await??;

    // 2. EC2 클라이언트
    let conf_sydney = aws_config::from_env()
        .region(aws_sdk_ec2::config::Region::new(args.aws_region.clone()))
        .load().await;
    let ec2_sydney = Ec2Client::new(&conf_sydney);

    // 3. 인스턴스 2대 생성
    println!("[COORD] 인스턴스 2대 시작 요청 (Subnet: {})...", args.aws_subnet_id);
    let (inst_1, inst_2) = tokio::try_join!(
        launch_instance_in_subnet(&ec2_sydney, &args.aws_ami, &args.aws_key_name, &args.aws_subnet_id, "172.31.50.4"),
        launch_instance_in_subnet(&ec2_sydney, &args.aws_ami, &args.aws_key_name, &args.aws_subnet_id, "172.31.50.5")
    )?;
    println!("[COORD] 생성된 인스턴스: {}, {}", inst_1.instance_id, inst_2.instance_id);

    // 안전 종료 가드
    let _guard_1 = InstanceTerminator::new(ec2_sydney.clone(), inst_1.instance_id.clone());
    let _guard_2 = InstanceTerminator::new(ec2_sydney.clone(), inst_2.instance_id.clone());

    // 4. 부팅 대기 (IP 로그만 찍음)
    let (info_1, info_2) = tokio::try_join!(
        wait_for_instance_ready(&ec2_sydney, &inst_1.instance_id),
        wait_for_instance_ready(&ec2_sydney, &inst_2.instance_id)
    )?;
    println!("[COORD] Inst 1 Private IP: {}", info_1.private_ip);
    println!("[COORD] Inst 2 Private IP: {}", info_2.private_ip);

    // 5. 포트 할당 (하드코딩된 값 사용)
    // 주의: Custom Routing 매핑 특성상, 어떤 IP가 어떤 포트와 매핑될지 보장하려면
    //       AWS 콘솔에서 (IP range -> Port range) 매핑을 확인하거나,
    //       혹은 "서브넷 내 첫 IP = 첫 포트" 규칙을 가정하고 진행합니다.
    let port_1 = args.worker1_port;
    let port_2 = args.worker2_port;

    println!("--------------------------------------------------");
    println!("[접속 정보] AGA DNS: {}", args.aga_dns);
    println!("[Worker 1] Port: {}", port_1);
    println!("[Worker 2] Port: {}", port_2);
    println!("--------------------------------------------------");

    // 6. SSH 접속 체크
    let aga_dns = args.aga_dns.clone();
    let host_1 = aga_dns.clone();
    let host_2 = aga_dns.clone();

    // 두 포트 모두 접속 가능한지 확인
    let ssh_check_1 = tokio::task::spawn_blocking(move || wait_for_ssh(&host_1, port_1));
    let ssh_check_2 = tokio::task::spawn_blocking(move || wait_for_ssh(&host_2, port_2));
    let (res_1, res_2) = tokio::join!(ssh_check_1, ssh_check_2);

    // 만약 여기서 실패한다면, AGA 매핑과 현재 인스턴스 IP가 일치하지 않는 경우일 수 있습니다.
    res_1??;
    res_2??;

    // 🔥🔥🔥 [여기에 추가하세요] 🔥🔥🔥
    println!("--------------------------------------------------");
    println!("[COORD] SSHD 초기화 안정화 대기 (20초)...");
    println!("(이 대기 시간이 없으면 kex_exchange 에러가 발생합니다)");
    println!("--------------------------------------------------");
    tokio::time::sleep(Duration::from_secs(20)).await;

    // 7. 작업 수행
    let compressed_bin = prepare_compressed_binary(&args.worker_binary_path)?;
    let compressed_pk = gzip_compress(&output_dir.join("proving_key.bin"))?;

    let n = args.committee_size;
    let half = n / 2;

    let args_c1 = args.clone(); let args_c2 = args.clone();
    let out_c1 = output_dir.clone(); let out_c2 = output_dir.clone();
    let bin_c1 = compressed_bin.clone(); let bin_c2 = compressed_bin.clone();
    let pk_c1 = compressed_pk.clone(); let pk_c2 = compressed_pk.clone();
    let h1 = aga_dns.clone(); let h2 = aga_dns.clone();

    let task_1 = tokio::task::spawn_blocking(move || {
        println!("[Task 1] Start");
        upload_worker_files_for_range(&args_c1, &h1, port_1, &out_c1, 0, half - 1, &bin_c1, &pk_c1)?;
        run_remote_worker(&args_c1, &h1, port_1, 0, half - 1)?;
        download_results(&args_c1, &h1, port_1, &out_c1, 0, half - 1)?;
        Ok::<(), eyre::Report>(())
    });

    let task_2 = tokio::task::spawn_blocking(move || {
        println!("[Task 2] Start");
        upload_worker_files_for_range(&args_c2, &h2, port_2, &out_c2, half, n - 1, &bin_c2, &pk_c2)?;
        run_remote_worker(&args_c2, &h2, port_2, half, n - 1)?;
        download_results(&args_c2, &h2, port_2, &out_c2, half, n - 1)?;
        Ok::<(), eyre::Report>(())
    });

    let (out_1, out_2) = tokio::join!(task_1, task_2);
    out_1??; out_2??;

    // 8. 종료
    terminate_instance(&ec2_sydney, &inst_1.instance_id).await?;
    terminate_instance(&ec2_sydney, &inst_2.instance_id).await?;

    println!("[COORD] Done.");
    Ok(())
}

// ==================== [PLACEHOLDER] Worker & Crypto ====================

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
