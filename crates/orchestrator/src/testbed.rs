// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use futures::future::try_join_all;
use prettytable::{row, Table};
use tokio::time::{self, Instant};

use super::client::Instance;
use crate::{
    client::ServerProviderClient,
    display,
    error::{TestbedError, TestbedResult},
    settings::Settings,
    ssh::SshConnection,
};

/// Represents a testbed running on a cloud provider.
pub struct Testbed<C> {
    /// The testbed's settings.
    settings: Settings,
    /// The client interfacing with the cloud provider.
    client: C,
    /// The state of the testbed (reflecting accurately the state of the machines).
    instances: Vec<Instance>,
}

impl<C: ServerProviderClient> Testbed<C> {
    /// Create a new testbed instance with the specified settings and client.
    pub async fn new(settings: Settings, client: C) -> TestbedResult<Self> {
        let public_key = settings.load_ssh_public_key()?;
        client.register_ssh_public_key(public_key).await?;
        let instances = client.list_instances().await?;

        Ok(Self {
            settings,
            client,
            instances,
        })
    }

    /// Return the username to connect to the instances through ssh.
    pub fn username(&self) -> &'static str {
        C::USERNAME
    }

    /// Return the list of instances of the testbed.
    pub fn instances(&self) -> Vec<Instance> {
        self.instances
            .iter()
            .filter(|x| self.settings.filter_instances(x))
            .cloned()
            .collect()
    }

    /// Return the list of provider-specific instance setup commands.
    pub async fn setup_commands(&self) -> TestbedResult<Vec<String>> {
        self.client
            .instance_setup_commands()
            .await
            .map_err(TestbedError::from)
    }

    /// Print the current status of the testbed.
    pub fn status(&self) {
        let filtered = self
            .instances
            .iter()
            .filter(|instance| self.settings.filter_instances(instance));

        // (수정) `region`은 이제 `&RegionConfig`입니다. `region.name` (String)을 비교합니다.
        let sorted: Vec<(_, Vec<_>)> = self
            .settings
            .regions // Vec<RegionConfig>
            .iter()
            .map(|region_config| { // region_config는 &RegionConfig
                (
                    &region_config.name, // 튜플의 첫 번째 요소로 &String (이름)을 사용
                    filtered
                        .clone()
                        .filter(|instance| instance.region == region_config.name) // String == String 비교
                        .collect(),
                )
            })
            .collect();

        let mut table = Table::new();
        table.set_format(display::default_table_format());

        let active = filtered.filter(|x| x.is_active()).count();

        // (수정) 테이블 타이틀 변경 (SSH 접속 정보와 IP 분리)
        table.set_titles(row![bH2->format!("Instances ({active})"), "SSH Command (Control Plane)", "Instance IP (Data Plane / Metrics)"]);

        for (i, (region_name, instances)) in sorted.iter().enumerate() {
            // (수정) 3열로 확장
            table.add_row(row![bH2->region_name.to_uppercase(), "", ""]);
            let mut j = 0;
            for instance in instances {
                if j % 5 == 0 {
                    table.add_row(row![]);
                }
                let private_key_file = self.settings.ssh_private_key_file.display();
                let username = C::USERNAME;

                // (수정) SSH 접속은 ssh_host와 ssh_port 사용
                let connect = format!(
                    "ssh -i {private_key_file} {username}@{} -p {}",
                    instance.ssh_host, instance.ssh_port
                );
                // (수정) 실제 IP(main_ip)는 별도 열에 표시
                let metrics_ip = instance.main_ip;

                if !instance.is_terminated() {
                    if instance.is_active() {
                        // (수정) 3열로 확장
                        table.add_row(row![bFg->format!("{j}"), connect, metrics_ip]);
                    } else {
                        table.add_row(row![bFr->format!("{j}"), connect, metrics_ip]);
                    }
                    j += 1;
                }
            }
            if i != sorted.len() - 1 {
                table.add_row(row![]);
            }
        }

        display::newline();
        display::config("Client", &self.client);
        let repo = &self.settings.repository;
        display::config("Repo", format!("{} ({})", repo.url, repo.commit));
        display::newline();
        table.printstd();
        display::newline();
    }

    /// Populate the testbed by creating the specified amount of instances per region. The total
    /// number of instances created is thus the specified amount x the number of regions.
    pub async fn deploy(&mut self, quantity: usize, region: Option<String>) -> TestbedResult<()> {
        display::action(format!("Deploying instances ({quantity} per region)"));

        let instances = match region {
            Some(x) => {
                try_join_all((0..quantity).map(|_| self.client.create_instance(x.clone()))).await?
            }
            None => {
                // (수정) `settings.regions`를 순회하며 `region.name`을 사용
                try_join_all(self.settings.regions.iter().flat_map(|region_config| {
                    (0..quantity).map(|_| self.client.create_instance(region_config.name.clone()))
                }))
                    .await?
            }
        };

        // Wait until the instances are booted.
        if cfg!(not(test)) {
            self.wait_until_reachable(instances.iter()).await?;
        }
        self.instances = self.client.list_instances().await?;

        display::done();
        Ok(())
    }

    /// Destroy all instances of the testbed.
    pub async fn destroy(&mut self) -> TestbedResult<()> {
        display::action("Destroying testbed");

        try_join_all(
            self.instances
                .drain(..)
                .map(|instance| self.client.delete_instance(instance)),
        )
        .await?;

        display::done();
        Ok(())
    }

    /// Start the specified number of instances in each region. Returns an error if there are not
    /// enough available instances.
    pub async fn start(&mut self, quantity: usize) -> TestbedResult<()> {
        display::action("Booting instances");

        // Gather available instances.
        let mut available = Vec::new();
        for region_config in &self.settings.regions {
            available.extend(
                self.instances
                    .iter()
                    .filter(|x| {
                        x.is_inactive() && &x.region == &region_config.name && self.settings.filter_instances(x)
                    })
                    .take(quantity)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
        }

        // Start instances.
        self.client.start_instances(available.iter()).await?;

        // Wait until the instances are started.
        if cfg!(not(test)) {
            self.wait_until_reachable(available.iter()).await?;
        }
        self.instances = self.client.list_instances().await?;

        display::done();
        Ok(())
    }

    /// Stop all instances of the testbed.
    pub async fn stop(&mut self) -> TestbedResult<()> {
        display::action("Stopping instances");

        // Stop all instances.
        self.client
            .stop_instances(self.instances.iter().filter(|i| i.is_active()))
            .await?;

        // Wait until the instances are stopped.
        loop {
            let instances = self.client.list_instances().await?;
            if instances.iter().all(|x| x.is_inactive()) {
                self.instances = instances;
                break;
            }
        }

        display::done();
        Ok(())
    }

    /// Wait until all specified instances are ready to accept ssh connections.
    async fn wait_until_reachable<'a, I>(&self, instances: I) -> TestbedResult<()>
    where
        I: Iterator<Item = &'a Instance> + Clone,
    {
        let instances_ids: Vec<_> = instances.clone().map(|x| x.id.clone()).collect();

        let mut interval = time::interval(Duration::from_secs(5));
        interval.tick().await; // The first tick returns immediately.

        let start = Instant::now();
        loop {
            let now = interval.tick().await;
            let elapsed = now.duration_since(start).as_secs_f64().ceil() as u64;
            display::status(format!("{elapsed}s"));

            // (수정) list_instances는 EC2와 NLB/AGA를 모두 확인하여 완전한 Instance 객체를 반환
            let instances = self.client.list_instances().await?;
            let futures = instances
                .iter()
                .filter(|x| instances_ids.contains(&x.id))
                .map(|instance| {
                    let private_key_file = self.settings.ssh_private_key_file.clone();
                    // (수정) SshConnection::new는 instance.ssh_address()를 통해
                    // (AGA_DNS, Port)로 접속을 시도
                    SshConnection::new(instance.ssh_address(), C::USERNAME, private_key_file)
                });

            // (수정) 모든 인스턴스가 SSH 접속 가능하고 'Active' 상태인지 확인
            let all_reachable = try_join_all(futures).await.is_ok();
            let all_active = instances
                .iter()
                .filter(|x| instances_ids.contains(&x.id))
                .all(|x| x.is_active());

            if all_reachable && all_active {
                break;
            }
        }
        Ok(())
    }
}


#[cfg(test)]
mod test {
    use crate::{client::test_client::TestClient, settings::Settings, testbed::Testbed};

    #[tokio::test]
    async fn deploy() {
        let settings = Settings::new_for_test();
        let client = TestClient::new(settings.clone());
        let mut testbed = Testbed::new(settings, client).await.unwrap();

        testbed.deploy(5, None).await.unwrap();

        assert_eq!(
            testbed.instances.len(),
            5 * testbed.settings.number_of_regions()
        );
        for (i, instance) in testbed.instances.iter().enumerate() {
            assert_eq!(i.to_string(), instance.id);
        }
    }

    #[tokio::test]
    async fn destroy() {
        let settings = Settings::new_for_test();
        let client = TestClient::new(settings.clone());
        let mut testbed = Testbed::new(settings, client).await.unwrap();

        testbed.destroy().await.unwrap();

        assert_eq!(testbed.instances.len(), 0);
    }

    #[tokio::test]
    async fn start() {
        let settings = Settings::new_for_test();
        let client = TestClient::new(settings.clone());
        let mut testbed = Testbed::new(settings, client).await.unwrap();
        testbed.deploy(5, None).await.unwrap();
        testbed.stop().await.unwrap();

        let result = testbed.start(2).await;

        assert!(result.is_ok());
        for region_config in &testbed.settings.regions {
            let active = testbed
                .instances
                .iter()
                .filter(|x| x.is_active() && &x.region == &region_config.name)
                .count();
            assert_eq!(active, 2);

            let inactive = testbed
                .instances
                .iter()
                .filter(|x| x.is_inactive() && &x.region == &region_config.name)
                .count();
            assert_eq!(inactive, 3);
        }
    }

    #[tokio::test]
    async fn stop() {
        let settings = Settings::new_for_test();
        let client = TestClient::new(settings.clone());
        let mut testbed = Testbed::new(settings, client).await.unwrap();
        testbed.deploy(5, None).await.unwrap();
        testbed.start(2).await.unwrap();

        testbed.stop().await.unwrap();

        assert!(testbed.instances.iter().all(|x| x.is_inactive()))
    }
}
