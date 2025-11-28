// crates/data-generator/src/bin/check_file_format.rs

use clap::Parser;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

// 코디네이터가 저장할 때 사용한 원본 타입
use crypto::types::VoteTransaction;
use bincode::Options;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 검증할 파일 경로
    file_path: PathBuf,
}

fn main() {
    let args = Args::parse();
    println!("Checking file: {:?}", args.file_path);

    let file = File::open(&args.file_path).expect("파일 열기 실패");
    let mut reader = BufReader::new(file);

    // bincode 설정 (기본 설정 사용)
    let config = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes();

    // 1. 벡터의 길이(u64)를 먼저 읽습니다.
    // bincode에서 Vec<T>는 [len: u64][item1][item2]... 형태로 저장됩니다.
    let len: u64 = match bincode::deserialize_from(&mut reader) {
        Ok(l) => l,
        Err(e) => {
            println!("❌ 파일 헤더(길이)를 읽을 수 없습니다: {}", e);
            return;
        }
    };

    println!(">> 파일 헤더에 명시된 트랜잭션 수: {} 개", len);
    println!(">> 하나씩 읽으며 검증을 시작합니다... (메모리 절약 모드)");

    let mut success_count = 0;

    for i in 0..len {
        // VoteTransaction 하나씩 역직렬화
        match bincode::deserialize_from::<_, VoteTransaction>(&mut reader) {
            Ok(_) => {
                success_count += 1;
                if i % 100_000 == 0 {
                    println!("   ... {} 개 확인 완료", i);
                }
            }
            Err(e) => {
                println!("❌ {} 번째 트랜잭션 읽기 실패!", i);
                println!("   에러 내용: {}", e);
                return;
            }
        }
    }

    println!("\n✅ SUCCESS: 파일 포맷 검증 완료!");
    println!("   -> 총 {} / {} 개의 VoteTransaction을 정상적으로 읽었습니다.", success_count, len);
}