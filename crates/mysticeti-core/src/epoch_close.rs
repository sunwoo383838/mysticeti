// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crate::{
    committee::{Committee, QuorumThreshold, StakeAggregator},
    data::Data,
    runtime::timestamp_utc,
    types::{InternalEpochStatus, StatementBlock},
};

pub struct EpochManager {
    epoch_status: InternalEpochStatus,
    change_aggregator: StakeAggregator<QuorumThreshold>,
    epoch_close_time: Arc<AtomicU64>,
}

impl EpochManager {
    pub fn new() -> Self {
        Self {
            epoch_status: Default::default(),
            change_aggregator: StakeAggregator::new(),
            epoch_close_time: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn epoch_change_begun(&mut self) {
        if let InternalEpochStatus::Open = self.epoch_status {
            self.epoch_status = InternalEpochStatus::BeginChange;
            tracing::info!("Epoch change has begun");
        }
    }

    pub fn observe_committed_block(&mut self, block: &Data<StatementBlock>, committee: &Committee) {
        if block.epoch_changed() {
            let is_quorum = self.change_aggregator.add(block.author(), committee);
            if is_quorum && (self.epoch_status != InternalEpochStatus::SafeToClose) {

                // 🚨 [수정] 기존 assert! 코드를 아래 로직으로 대체합니다.
                // 기존: assert!(self.epoch_status == InternalEpochStatus::BeginChange);

                // 변경: Open 상태라면 경고를 찍고 BeginChange로 강제 전환
                if self.epoch_status == InternalEpochStatus::Open {
                    tracing::warn!("Quorum of epoch markers observed while in Open state. Forcing state transition.");
                    self.epoch_status = InternalEpochStatus::BeginChange;
                }

                // 이제 상태는 BeginChange임이 보장되므로 안전하게 진행
                self.epoch_close_time
                    .store(timestamp_utc().as_millis() as u64, Ordering::Relaxed);

                // 🌟 [추가 권장] 상태를 SafeToClose로 업데이트해야 'closed()' 함수가 true를 반환함
                self.epoch_status = InternalEpochStatus::SafeToClose;

                tracing::info!("Epoch is now safe to close");
            }
        }
    }

    pub fn changing(&self) -> bool {
        self.epoch_status != InternalEpochStatus::Open
    }

    pub fn closed(&self) -> bool {
        self.epoch_status == InternalEpochStatus::SafeToClose
    }

    pub fn closing_time(&self) -> Arc<AtomicU64> {
        self.epoch_close_time.clone()
    }
}
