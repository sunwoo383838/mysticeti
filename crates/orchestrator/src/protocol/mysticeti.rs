// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{Debug, Display},
    net::IpAddr,
    ops::Deref,
    path::PathBuf,
};

use mysticeti_core::{
    config::{self, ClientParameters, NodeParameters},
    types::AuthorityIndex,
};
use serde::{Deserialize, Serialize};

use super::{ProtocolCommands, ProtocolMetrics, ProtocolParameters, BINARY_PATH};
use crate::{benchmark::BenchmarkParameters, client::Instance, settings::Settings};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct MysticetiNodeParameters(NodeParameters);

impl Deref for MysticetiNodeParameters {
    type Target = NodeParameters;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for MysticetiNodeParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.consensus_only {
            write!(f, "c")
        } else {
            write!(f, "fpc")
        }
    }
}

impl Display for MysticetiNodeParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.consensus_only {
            write!(f, "Consensus-only mode")
        } else {
            write!(f, "FPC mode")
        }
    }
}

impl ProtocolParameters for MysticetiNodeParameters {}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(transparent)]
pub struct MysticetiClientParameters(ClientParameters);

impl Deref for MysticetiClientParameters {
    type Target = ClientParameters;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for MysticetiClientParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.transaction_size)
    }
}

impl Display for MysticetiClientParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}B tx", self.transaction_size)
    }
}

impl ProtocolParameters for MysticetiClientParameters {}

pub struct MysticetiProtocol {
    working_dir: PathBuf,
}

impl ProtocolCommands for MysticetiProtocol {
    fn protocol_dependencies(&self) -> Vec<&'static str> {
        vec!["sudo apt -y install libfontconfig1-dev"]
    }

    fn db_directories(&self) -> Vec<std::path::PathBuf> {
        vec![self.working_dir.join("storage-*")]
    }

    async fn genesis_command<'a, I>(&self, instances: I, parameters: &BenchmarkParameters) -> String
    where
        I: Iterator<Item = &'a Instance>,
    {
        let ips = instances
            .map(|x| x.main_ip.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        let node_parameters = parameters.node_parameters.clone();
        let node_parameters_string = serde_yaml::to_string(&node_parameters).unwrap();
        let node_parameters_path = self.working_dir.join("node-parameters.yaml");
        let upload_node_parameters = format!(
            "echo -e '{node_parameters_string}' > {}",
            node_parameters_path.display()
        );

        let mut fault_config_commands = Vec::new();
        for (node_idx, fault_config) in &parameters.fault_assignments {
            let f_str = serde_yaml::to_string(fault_config).unwrap();
            let f_path = self.working_dir.join(format!("fault-config-{}.yaml", node_idx));
            fault_config_commands.push(format!("echo -e '{f_str}' > {}", f_path.display()));
        }

        let mut client_parameters = parameters.client_parameters.clone();
        client_parameters.0.load = parameters.load / parameters.nodes;
        let client_parameters_string = serde_yaml::to_string(&client_parameters).unwrap();
        let client_parameters_path = self.working_dir.join("client-parameters.yaml");
        let upload_client_parameters = format!(
            "echo -e '{client_parameters_string}' > {}",
            client_parameters_path.display()
        );

        let genesis = [
            &format!("./{BINARY_PATH}/mysticeti"),
            "benchmark-genesis",
            &format!(
                "--ips {ips} --working-directory {} --node-parameters-path {}",
                self.working_dir.display(),
                node_parameters_path.display(),
            ),
        ]
            .join(" ");

        let mut commands = vec![
            "source $HOME/.cargo/env".to_string(),
            upload_node_parameters,
        ];
        // 🌟 장애 설정 파일 생성 명령 추가
        commands.extend(fault_config_commands);
        commands.push(upload_client_parameters);
        commands.push(genesis);

        commands.join(" && ")
    }

    fn node_command<I>(
        &self,
        instances: I,
        parameters  : &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        instances
            .into_iter()
            .enumerate()
            .map(|(i, instance)| {
                let authority = i as AuthorityIndex;
                let committee_path = self.working_dir.join("committee.yaml");
                let public_config_path = self.working_dir.join("public-config.yaml");
                let private_config_path = self
                    .working_dir
                    .join(format!("private-config-{authority}.yaml"));
                let client_parameters_path = self.working_dir.join("client-parameters.yaml");
                let crypto_config_path = self.working_dir.join("crypto-config.yaml");
                // 🌟 [신규] 장애 설정 파일 경로 옵션 생성
                let fault_arg = if parameters.fault_assignments.contains_key(&i) {
                    let path = self.working_dir.join(format!("fault-config-{}.yaml", i));
                    format!("--fault-config-path {}", path.display())
                } else {
                    String::new()
                };

                let run = [
                    "RUST_LOG=info RUST_BACKTRACE=1",
                    &format!("./{BINARY_PATH}/mysticeti"),
                    "run",
                    &format!("--authority {authority}"),
                    &format!("--committee-path {}", committee_path.display()),
                    &format!("--public-config-path {}", public_config_path.display()),
                    &format!("--private-config-path {}", private_config_path.display()),
                    &format!(
                        "--client-parameters-path {}",
                        client_parameters_path.display()
                    ),
                    &format!(
                        "--crypto-config-path {}",
                        crypto_config_path.display()
                    ),
                    &fault_arg,
                ]
                    .join(" ");

                let command = ["source $HOME/.cargo/env", &run].join(" && ");
                (instance, command)
            })
            .collect()
    }

    fn client_command<I>(
        &self,
        _instances: I,
        _parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // TODO: Isolate clients from the node (#9).
        vec![]
    }
}

impl ProtocolMetrics for MysticetiProtocol {
    const BENCHMARK_DURATION: &'static str = mysticeti_core::metrics::BENCHMARK_DURATION;
    const TOTAL_TRANSACTIONS: &'static str = "latency_s_count";
    const LATENCY_BUCKETS: &'static str = "latency_s";
    const LATENCY_SUM: &'static str = "latency_s_sum";
    const LATENCY_SQUARED_SUM: &'static str = mysticeti_core::metrics::LATENCY_SQUARED_S;

    fn nodes_metrics_path<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        let (ips, instances): (_, Vec<_>) = instances
            .into_iter()
            .map(|x| (IpAddr::V4(x.main_ip), x))
            .unzip();

        let node_parameters = Some(parameters.node_parameters.deref().clone());
        let node_config = config::NodePublicConfig::new_for_benchmarks(ips, node_parameters);
        let metrics_paths = node_config
            .all_metric_addresses()
            .map(|x| format!("{x}{}", mysticeti_core::prometheus::METRICS_ROUTE));

        instances.into_iter().zip(metrics_paths).collect()
    }

    // [Modified] Override default implementation to scrape Node Exporter as well
    fn nodes_metrics_command<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        self.nodes_metrics_path(instances, parameters)
            .into_iter()
            .map(|(instance, path)| {
                let port_and_route = path.rsplit_once(':').map(|(_, suffix)| suffix).unwrap_or(&path);
                // Scrape both the node metrics (via localhost) and the node exporter metrics (port 9200)
                (
                    instance,
                    format!("curl -s http://127.0.0.1:{port_and_route} && curl -s http://localhost:9200/metrics")
                )
            })
            .collect()
    }

    fn clients_metrics_path<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // NOTE: Hack to avoid clients metrics.
        self.nodes_metrics_path(instances, parameters)
    }
}

impl MysticetiProtocol {
    /// Make a new instance of the Mysticeti protocol commands generator.
    pub fn new(settings: &Settings) -> Self {
        Self {
            working_dir: settings.working_dir.clone(),
        }
    }
}