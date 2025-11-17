use std::sync::Arc;
use ark_bls12_381::Fr;
use ark_serialize::{serialize_to_vec, CanonicalSerialize};
use dirs_next::data_dir;
use rocksdb::{BlockBasedOptions, Options, TransactionDB, TransactionDBOptions, WriteBatch, WriteBatchWithTransaction, WriteOptions};
use crate::metrics::Metrics;
use eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
enum NullifierState {
    Locked,
    Commit
}

const CF_NULLIFIER: &str = "nullifiers";

#[derive(Clone)]
pub struct NullifierDB {
    db: Arc<TransactionDB>,
    metrics: Arc<Metrics>
}

impl NullifierDB {
    pub fn new(metrics: Arc<Metrics>) -> Result<Self> {

        let data_dir = data_dir()
            .ok_or_else(|| eyre::eyre!("Failed to find standard data directory"))?;
        let db_path = data_dir.join("mysticeti-vote/nullifier_db");
        if !db_path.exists() {
            std::fs::create_dir_all(&db_path)
                .wrap_err(format!("Failed to create DB directory at {}", db_path.display()))?;
        }

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_bloom_filter(10.0, false);
        opts.set_block_based_table_factory(&block_opts);

        opts.increase_parallelism(num_cpus::get().max(2) as i32);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);

        let txn_db_opts = TransactionDBOptions::default();
        let db = TransactionDB::open_cf(
            &opts,
            &txn_db_opts,
            db_path.clone(),
            vec![CF_NULLIFIER],
        ).wrap_err(format!("Failed to open NullifierDB at {}", db_path.display()))?;

        Ok(Self {
            db: Arc::new(db),
            metrics,
        })
    }

    pub fn verify(
        &self,
        nullifier: Fr,
    ) -> Result<bool> {

        let key = serialize_to_vec![nullifier]?;
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER)
            .ok_or_else(|| eyre!("CF_NULLIFIER not found"))?;

        let txn = self.db.transaction();
        // 2. 널리파이어 상태 확인 (Get-for-Update: 이 키에 쓰기 락을 설정)
        //    블룸 필터 덕분에 키가 없으면(Unused) 이 단계는 매우 빠릅니다.
        match txn.get_for_update_cf(cf, &key, true)? {
            // 3a. 키가 존재함 (Locked 또는 Spent)
            Some(_) => {
                Ok(false)
            }
            None => {
                let new_state = NullifierState::Locked;
                txn.put_cf(&cf, &key, &bincode::serialize(&new_state)?)?;
                txn.commit()?;
                self.metrics.nullifier_db_size.inc();
                Ok(true)
            }
        }
    }


    pub fn commit(
        &self,
        nullifier: Fr
    ) -> Result<()> {

        let cf = self
            .db
            .cf_handle(CF_NULLIFIER)
            .ok_or_else(|| eyre!("CF_NULLIFIER not found"))?;

        let key = serialize_to_vec![nullifier]?;
        let txn = self.db.transaction();
        match txn.get_for_update_cf(cf, &key, true)? {
            Some(_) => {
                Err(eyre!("nullifier already exists (duplicate vote)"))
            }
            None => {
                let new_state = NullifierState::Commit;
                txn.put_cf(&cf, &key, &bincode::serialize(&new_state)?)?;
                txn.commit()?;
                Ok(())
            }
        }
    }

    pub fn commit_batch(
        &self,
        nullifiers: Vec<Fr>
    ) -> Result<()> {

        let cf = self
            .db
            .cf_handle(CF_NULLIFIER)
            .ok_or_else(|| eyre!("CF_NULLIFIER not found"))?;

        let mut batch = WriteBatchWithTransaction::<true>::default();
        for nullifier in nullifiers {
            let key = serialize_to_vec![nullifier]?;
            let new_state = NullifierState::Commit;
            let value = bincode::serialize(&new_state)?;
            batch.put_cf(&cf, &key, &value);
        }

        self.db.write(batch)?;
        Ok(())
    }

    pub fn unlock_batch(&self, nullifiers: Vec<Fr>) -> Result<()> {

        let cf = self
            .db
            .cf_handle(CF_NULLIFIER)
            .ok_or_else(|| eyre!("CF_NULLIFIER not found"))?;

        let mut batch = WriteBatchWithTransaction::<true>::default();
        for nullifier in nullifiers {
            let key = serialize_to_vec![nullifier]?;
            batch.delete_cf(&cf, &key);
        }

        self.db.write(batch)?;
        Ok(())
    }
}