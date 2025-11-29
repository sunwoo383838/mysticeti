// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fmt::Debug,
    fs,
    io::BufRead,
    path::{Path, PathBuf},
    time::Duration,
};

use prettytable::{row, Table};
use prometheus_parse::Scrape;
use serde::{Deserialize, Serialize};

use crate::{benchmark::BenchmarkParameters, display, protocol::ProtocolMetrics};

/// The identifier of prometheus latency buckets.
type BucketId = String;
/// The identifier of a measurement type (e.g., "shared", "owned").
type Label = String;
/// The identifier of a breakdown stage (e.g., "1_queue", "5_committed_c").
type StageId = String;

// Constants for steady state window calculation
const WARM_UP: Duration = Duration::from_secs(240);
const COOLDOWN: Duration = Duration::from_secs(3);

/// Holds standard statistics for a histogram metric.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct HistogramSummary {
    /// Latency buckets.
    pub buckets: HashMap<BucketId, usize>,
    /// Sum of the latencies.
    pub sum: Duration,
    /// Total count.
    pub count: usize,
    /// Sum of squares (for stdev).
    pub squared_sum: f64,
}

impl HistogramSummary {
    /// Compute the average latency.
    pub fn average(&self) -> Duration {
        if self.count == 0 {
            return Duration::default();
        }
        self.sum.checked_div(self.count as u32).unwrap_or_default()
    }

    /// Compute the standard deviation.
    pub fn stdev(&self) -> Duration {
        if self.count == 0 {
            return Duration::default();
        }
        let count = self.count as f64;
        let first_term = self.squared_sum / count;
        let squared_avg = self.average().as_secs_f64().powi(2);

        let variance = if squared_avg > first_term {
            0.0
        } else {
            first_term - squared_avg
        };
        Duration::from_secs_f64(variance.sqrt())
    }
}

/// A snapshot measurement at a given time.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Measurement {
    /// Duration since the beginning of the benchmark.
    pub timestamp: Duration,

    /// 1. Legacy End-to-End Latency (latency_s)
    pub latency_e2e: HistogramSummary,

    /// 2. Detailed Latency Breakdown by Stage
    /// Key: Stage ID (e.g., "1_queue", "5_committed_fpc")
    pub breakdown: HashMap<StageId, HistogramSummary>,

    /// 3. System Metrics
    #[serde(default)]
    pub cpu_accumulated_seconds: f64,
    #[serde(default)]
    pub system_network_in_bytes: f64,
    #[serde(default)]
    pub system_network_out_bytes: f64,
}

impl Measurement {
    /// Make new measurements from the text exposed by prometheus.
    pub fn from_prometheus<M: ProtocolMetrics>(text: &str) -> HashMap<Label, Self> {
        let br = std::io::BufReader::new(text.as_bytes());
        let parsed = Scrape::parse(br.lines()).unwrap();

        let mut measurements: HashMap<Label, Measurement> = HashMap::new();

        for sample in &parsed.samples {
            // 1. Label 결정 (Workload)
            // System Metric인 경우 "system", 그 외에는 workload 라벨 사용
            let label = if sample.metric == "node_cpu_seconds_total"
                || sample.metric.starts_with("node_network")
            {
                "system".to_string()
            } else if let Some(workload) = sample.labels.get("workload") {
                workload.to_string()
            } else {
                // workload 라벨이 없는 경우 (예: global counter 등) 처리
                // 필요하다면 default 키 사용
                "global".to_string()
            };

            let measurement = measurements.entry(label).or_default();

            // 2. Metric Parsing
            match sample.metric.as_str() {
                // --- A. Legacy End-to-End Latency (latency_s) ---
                x if x == M::LATENCY_BUCKETS => {
                    if let prometheus_parse::Value::Histogram(values) = &sample.value {
                        for value in values {
                            measurement.latency_e2e.buckets.insert(
                                value.less_than.to_string(),
                                value.count as usize,
                            );
                        }
                    }
                }
                x if x == M::LATENCY_SUM => {
                    if let prometheus_parse::Value::Untyped(val) = sample.value {
                        measurement.latency_e2e.sum = Duration::from_secs_f64(val);
                    }
                }
                x if x == M::TOTAL_TRANSACTIONS => { // latency_s_count
                    if let prometheus_parse::Value::Untyped(val) = sample.value {
                        measurement.latency_e2e.count = val as usize;
                    }
                }
                x if x == M::LATENCY_SQUARED_SUM => {
                    if let prometheus_parse::Value::Counter(val) = sample.value {
                        measurement.latency_e2e.squared_sum = val;
                    }
                }

                // --- B. Latency Breakdown (latency_breakdown) ---
                "latency_breakdown_bucket" => {
                    if let Some(stage) = sample.labels.get("stage") {
                        let summary = measurement.breakdown.entry(stage.clone().parse().unwrap()).or_default();
                        if let prometheus_parse::Value::Histogram(values) = &sample.value {
                            for value in values {
                                summary.buckets.insert(
                                    value.less_than.to_string(),
                                    value.count as usize,
                                );
                            }
                        }
                    }
                }
                "latency_breakdown_sum" => {
                    if let Some(stage) = sample.labels.get("stage") {
                        let summary = measurement.breakdown.entry(stage.clone().parse().unwrap()).or_default();
                        if let prometheus_parse::Value::Untyped(val) = sample.value {
                            summary.sum = Duration::from_secs_f64(val);
                        }
                    }
                }
                "latency_breakdown_count" => {
                    if let Some(stage) = sample.labels.get("stage") {
                        let summary = measurement.breakdown.entry(stage.clone().parse().unwrap()).or_default();
                        if let prometheus_parse::Value::Untyped(val) = sample.value {
                            summary.count = val as usize;
                        }
                    }
                }
                "latency_breakdown_squared_s" => {
                    if let Some(stage) = sample.labels.get("stage") {
                        let summary = measurement.breakdown.entry(stage.clone().parse().unwrap()).or_default();
                        if let prometheus_parse::Value::Counter(val) = sample.value {
                            summary.squared_sum = val;
                        }
                    }
                }

                // --- C. System Metrics ---
                "node_cpu_seconds_total" => {
                    if let prometheus_parse::Value::Counter(val) = sample.value {
                        let is_idle = sample.labels.get("mode").map(|s| s == "idle").unwrap_or(false);
                        if !is_idle {
                            measurement.cpu_accumulated_seconds += val;
                        }
                    }
                }
                "node_network_receive_bytes_total" => {
                    if let Some(device) = sample.labels.get("device") {
                        if device != "lo" {
                            if let prometheus_parse::Value::Counter(val) = sample.value {
                                measurement.system_network_in_bytes += val;
                            }
                        }
                    }
                }
                "node_network_transmit_bytes_total" => {
                    if let Some(device) = sample.labels.get("device") {
                        if device != "lo" {
                            if let prometheus_parse::Value::Counter(val) = sample.value {
                                measurement.system_network_out_bytes += val;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Benchmark Duration 타임스탬프 적용
        let timestamp = parsed
            .samples
            .iter()
            .find(|x| x.metric == M::BENCHMARK_DURATION)
            .map(|x| match x.value {
                prometheus_parse::Value::Counter(value) => Duration::from_secs(value as u64),
                _ => Duration::default(),
            })
            .unwrap_or_default();

        for sample in measurements.values_mut() {
            sample.timestamp = timestamp;
        }

        measurements
    }
}

/// The identifier of the scrapers collecting the prometheus metrics.
type ScraperId = usize;

#[derive(Serialize, Deserialize, Clone)]
pub struct MeasurementsCollection {
    pub parameters: BenchmarkParameters,
    pub data: HashMap<Label, HashMap<ScraperId, Vec<Measurement>>>,
}

impl MeasurementsCollection {
    pub fn new(mut parameters: BenchmarkParameters) -> Self {
        parameters.settings.repository.remove_access_token();
        Self {
            parameters,
            data: HashMap::new(),
        }
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let data = fs::read(path)?;
        let measurements: Self = serde_json::from_slice(data.as_slice())?;
        Ok(measurements)
    }

    pub fn add(&mut self, scraper_id: ScraperId, label: String, measurement: Measurement) {
        self.data
            .entry(label)
            .or_default()
            .entry(scraper_id)
            .or_default()
            .push(measurement);
    }

    pub fn all_measurements(&self, label: &Label) -> Vec<Vec<Measurement>> {
        self.data
            .get(label)
            .map(|data| data.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn labels(&self) -> impl Iterator<Item = &Label> {
        self.data.keys()
    }

    pub fn benchmark_duration(&self) -> Duration {
        self.labels()
            .map(|label| {
                self.all_measurements(label)
                    .iter()
                    .filter_map(|x| x.last())
                    .map(|x| x.timestamp)
                    .max()
                    .unwrap_or_default()
            })
            .max()
            .unwrap_or_default()
    }

    fn get_steady_state_window<'a>(
        measurements: &'a [Measurement],
    ) -> Option<(&'a Measurement, &'a Measurement)> {
        if measurements.is_empty() {
            return None;
        }
        let total_duration = measurements.last().unwrap().timestamp;
        let cutoff = total_duration.saturating_sub(COOLDOWN);
        let start = measurements.iter().find(|m| m.timestamp > WARM_UP);
        let end = measurements.iter().rev().find(|m| m.timestamp <= cutoff);
        match (start, end) {
            (Some(s), Some(e)) if s.timestamp < e.timestamp => Some((s, e)),
            _ => None,
        }
    }

    // --- TPS Calculation (Based on latency_e2e count) ---
    pub fn aggregate_tps(&self, label: &Label) -> u64 {
        self.all_measurements(label)
            .iter()
            .map(|scraper_data| {
                if let Some((start, end)) = Self::get_steady_state_window(scraper_data) {
                    let duration = end.timestamp.as_secs_f64() - start.timestamp.as_secs_f64();
                    // Use latency_e2e count for global TPS
                    let count = end.latency_e2e.count.saturating_sub(start.latency_e2e.count) as f64;
                    if duration > 0.0 {
                        (count / duration) as u64
                    } else {
                        0
                    }
                } else {
                    0
                }
            })
            .max()
            .unwrap_or_default()
    }

    // --- Average Latency (Legacy) ---
    pub fn aggregate_average_latency(&self, label: &Label) -> Duration {
        let all_measurements = self.all_measurements(label);
        let mut latencies = Vec::new();
        for scraper_data in all_measurements {
            if let Some((start, end)) = Self::get_steady_state_window(&scraper_data) {
                let count = (end.latency_e2e.count.saturating_sub(start.latency_e2e.count)) as u32;
                if count > 0 {
                    let total_time = end.latency_e2e.sum.saturating_sub(start.latency_e2e.sum);
                    latencies.push(total_time / count);
                }
            }
        }
        if latencies.is_empty() {
            return Duration::default();
        }
        let sum: Duration = latencies.iter().sum();
        sum / latencies.len() as u32
    }

    // --- Stdev Latency (Legacy) ---
    pub fn max_stdev_latency(&self, label: &Label) -> Duration {
        self.all_measurements(label)
            .iter()
            .map(|scraper_data| {
                if let Some((start, end)) = Self::get_steady_state_window(scraper_data) {
                    let count = (end.latency_e2e.count.saturating_sub(start.latency_e2e.count)) as f64;
                    if count > 0.0 {
                        let latency_sum = (end.latency_e2e.sum.saturating_sub(start.latency_e2e.sum)).as_secs_f64();
                        let latency_sq_sum = end.latency_e2e.squared_sum - start.latency_e2e.squared_sum;

                        let first = latency_sq_sum / count;
                        let second = (latency_sum / count).powi(2);
                        let variance = first - second;
                        if variance > 0.0 {
                            Duration::from_secs_f64(variance.sqrt())
                        } else {
                            Duration::default()
                        }
                    } else {
                        Duration::default()
                    }
                } else {
                    Duration::default()
                }
            })
            .max()
            .unwrap_or_default()
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) {
        let json = serde_json::to_string_pretty(self).expect("Cannot serialize metrics");
        let mut file = PathBuf::from(path.as_ref());
        file.push(format!("measurements-{:?}.json", self.parameters));
        fs::write(file, json).unwrap();
    }

    pub fn display_summary(&self) {
        let mut table = Table::new();
        table.set_format(display::default_table_format());

        let duration = self.benchmark_duration();

        table.set_titles(row![bH2->"Benchmark Summary"]);
        table.add_row(row![b->"Benchmark type:", self.parameters.node_parameters]);
        table.add_row(row![bH2->""]);
        table.add_row(row![b->"Nodes:", self.parameters.nodes]);
        table.add_row(row![b->"Faults:", self.parameters.settings.faults]);
        table.add_row(row![b->"Load:", format!("{} tx/s", self.parameters.load)]);
        table.add_row(row![b->"Duration:", format!("{} s", duration.as_secs())]);

        let mut labels: Vec<_> = self.labels().collect();
        labels.sort();
        for label in labels {
            if label == "system" { continue; } // system label은 요약에서 제외 가능

            let total_tps = self.aggregate_tps(label);
            let average_latency = self.aggregate_average_latency(label);
            let stdev_latency = self.max_stdev_latency(label);

            table.add_row(row![bH2->""]);
            table.add_row(row![b->"Workload:", label]);
            table.add_row(row![b->"TPS:", format!("{total_tps} tx/s")]);
            table.add_row(row![b->"Latency (avg):", format!("{} ms", average_latency.as_millis())]);
            table.add_row(row![b->"Latency (stdev):", format!("{} ms", stdev_latency.as_millis())]);

            // (선택) 여기서 Breakdown 정보를 출력할 수도 있습니다.
            // 구현 편의상 생략하였으나, self.data[label] 내부의 breakdown 맵을 순회하며 출력 가능합니다.
        }

        display::newline();
        table.printstd();
        display::newline();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::test_protocol_metrics::TestProtocolMetrics;

    #[test]
    fn prometheus_parse_breakdown() {
        let report = r#"
            # HELP benchmark_duration Duration of the benchmark
            # TYPE benchmark_duration counter
            benchmark_duration 30

            # HELP latency_breakdown_sum Cumulative latency breakdown
            # TYPE latency_breakdown_sum histogram
            latency_breakdown_sum{stage="1_queue",workload="shared"} 10.0
            latency_breakdown_count{stage="1_queue",workload="shared"} 100
            latency_breakdown_bucket{stage="1_queue",workload="shared",le="0.1"} 100

            latency_breakdown_sum{stage="5_committed_c",workload="shared"} 50.0
            latency_breakdown_count{stage="5_committed_c",workload="shared"} 100
            latency_breakdown_squared_s{stage="5_committed_c",workload="shared"} 2500.0
        "#;

        let measurements = Measurement::from_prometheus::<TestProtocolMetrics>(report);
        let measurement = measurements.get("shared").unwrap();

        // 1. Check Breakdown (Queue)
        let queue = measurement.breakdown.get("1_queue").unwrap();
        assert_eq!(queue.sum, Duration::from_secs(10));
        assert_eq!(queue.count, 100);
        assert_eq!(queue.buckets.get("0.1"), Some(&100));

        // 2. Check Breakdown (Commit)
        let commit = measurement.breakdown.get("5_committed_c").unwrap();
        assert_eq!(commit.sum, Duration::from_secs(50));
        assert_eq!(commit.count, 100);
        assert_eq!(commit.squared_sum, 2500.0);
    }
}