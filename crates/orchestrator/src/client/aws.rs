// crates/orchestrator/src/client/aws.rs

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    sync::{Arc, Mutex}, // Mutex/Arc 추가
    time::Duration,      // Duration 추가
};

use aws_config::{BehaviorVersion, Region};
use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
use aws_sdk_ec2::{
    error::SdkError,
    meta::PKG_VERSION,
    primitives::Blob,
    types::{
        BlockDeviceMapping,
        EbsBlockDevice,
        Filter,
        IamInstanceProfileSpecification, // IAM 역할 지정을 위해 추가
        Instance as AwsInstance,
        InstanceStateName, // 인스턴스 상태 확인을 위해 추가
        ResourceType,
        Tag,
        TagSpecification,
        VolumeType,
        EphemeralNvmeSupport,
        // --- ⬇️ 스팟 인스턴스를 위해 추가 ⬇️ ---
        InstanceMarketOptionsRequest,
        InstanceInterruptionBehavior,
        MarketType,
        SpotInstanceType,
        SpotMarketOptions,
    },
};
// (신규) ELBv2(NLB) SDK 임포트
use aws_sdk_elasticloadbalancingv2 as elbv2;
// [ 🌟 수정 ] 헬스 체크 관련 Enum 및 타입을 모두 임포트합니다.
use elbv2::types::{Action, ActionTypeEnum, ProtocolEnum, TargetDescription, TargetTypeEnum, TargetHealthStateEnum, TargetHealthDescription};
use log::info;
use serde::Serialize;
use tokio::time::sleep; // (신규) 대기 시간을 위해 추가

use super::{Instance, InstanceStatus, ServerProviderClient};
use crate::{display, error::{CloudProviderError, CloudProviderResult}, settings::Settings};


// Make a request error from an AWS error message.
impl<T> From<SdkError<T>> for CloudProviderError
where
    T: Debug + std::error::Error + Send + Sync + 'static,
{
    fn from(e: SdkError<T>) -> Self {
        Self::RequestError(format!("{:?}", e.into_source()))
    }
}

type PortAllocator = Arc<Mutex<HashMap<String, u16>>>;

/// An AWS client.
pub struct AwsClient {
    /// The settings of the testbed.
    settings: Settings,
    /// A list of clients, one per AWS region.
    clients: HashMap<String, aws_sdk_ec2::Client>,
    elbv2_clients: HashMap<String, elbv2::Client>,
    // (신규) 리전별 다음 할당 포트
    next_port: PortAllocator,
}

impl Display for AwsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AWS EC2 client v{}", PKG_VERSION)
    }
}

impl AwsClient {
    // [ 🌟 수정 ] arm64 AMI를 사용하도록 변경
    const OS_IMAGE: &'static str =
        "Canonical, Ubuntu, 24.04 LTS, arm64 noble image build on 2024-04-23";
    const DEFAULT_EBS_SIZE_GB: i32 = 500; // Default size of the EBS volume in GB.

    /// Make a new AWS client.
    pub async fn new(settings: Settings) -> Self {
        let profile_files = EnvConfigFiles::builder()
            .with_file(EnvConfigFileKind::Credentials, &settings.token_file)
            .with_contents(EnvConfigFileKind::Config, "[default]\noutput=json")
            .build();

        let mut clients = HashMap::new();
        let mut elbv2_clients = HashMap::new();
        let mut port_map = HashMap::new();

        // (수정) settings.regions가 이제 Vec<RegionConfig>임
        for region_config in settings.regions.clone() {
            let region_name = region_config.name.clone();
            let sdk_config = aws_config::defaults(BehaviorVersion::v2024_03_28())
                .region(Region::new(region_name.clone()))
                .profile_files(profile_files.clone())
                .load()
                .await;

            let client = aws_sdk_ec2::Client::new(&sdk_config);
            clients.insert(region_name.clone(), client);

            // (신규) ELBv2 클라이언트 생성
            let elbv2_client = elbv2::Client::new(&sdk_config);
            elbv2_clients.insert(region_name.clone(), elbv2_client);

            // (신규) 포트 할당기 초기화
            port_map.insert(region_name, settings.ssh_start_port);
        }

        Self {
            settings,
            clients,
            elbv2_clients,
            next_port: Arc::new(Mutex::new(port_map)),
        }
    }

    /// Parse an AWS response and ignore errors if they mean a request is a duplicate.
    fn check_but_ignore_duplicates<T, E>(
        response: Result<T, SdkError<E>>,
    ) -> CloudProviderResult<()>
    where
        E: Debug + std::error::Error + Send + Sync + 'static,
    {
        if let Err(e) = response {
            let error_message = format!("{e:?}");
            if !error_message.to_lowercase().contains("duplicate") {
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Convert an AWS instance into an orchestrator instance (used in the rest of the codebase).
    fn make_instance(
        &self,
        region: String,
        aws_instance: &AwsInstance,
        assigned_port: u16,
        target_group_arn: String,
        listener_arn: String,
    ) -> Instance {
        let region_config = self
            .settings
            .get_region_config(&region)
            .expect("Region config not found in make_instance");

        Instance {
            id: aws_instance.instance_id().unwrap().into(),
            region,
            // (수정) IP 대신 AGA DNS와 할당된 포트 사용
            ssh_host: region_config.aga_dns_name.clone(),
            ssh_port: assigned_port,
            main_ip: aws_instance
                .public_ip_address()
                .unwrap_or("0.0.0.0") // 중지된 인스턴스
                .parse()
                .expect("AWS instance should have a valid public ip"),
            tags: vec![self.settings.testbed_id.clone()],
            specs: format!(
                "{:?}",
                aws_instance
                    .instance_type()
                    .expect("AWS instance should have a type")
            ),
            status: format!(
                "{:?}",
                aws_instance
                    .state()
                    .expect("AWS instance should have a state")
                    .name()
                    .expect("AWS status should have a name")
            )
                .as_str()
                .into(),
            // (신규) 생성된 리소스 ARN 저장 (삭제 시 필요)
            nlb_target_group_arn: target_group_arn,
            nlb_listener_arn: listener_arn,
        }
    }

    async fn find_image_id(&self, client: &aws_sdk_ec2::Client) -> CloudProviderResult<String> {
        let request = client.describe_images().filters(
            Filter::builder() // v1.x SDK는 `Filter::builder()`를 사용
                .name("description")
                .values(Self::OS_IMAGE)
                .build(),
        );
        let response = request.send().await?;

        response
            .images
            .unwrap_or_default()
            .first()
            .ok_or_else(|| CloudProviderError::RequestError("Cannot find image id".into()))?
            .image_id
            .clone()
            .ok_or_else(|| {
                CloudProviderError::UnexpectedResponse(
                    "Received image description without id".into(),
                )
            })
    }

    /// Create a new security group for the instance (if it doesn't already exist).
    async fn create_security_group(&self, client: &aws_sdk_ec2::Client) -> CloudProviderResult<()> {
        let request = client
            .create_security_group()
            .group_name(&self.settings.testbed_id)
            .description("Allow all traffic (used for benchmarks).");

        let response = request.send().await;
        Self::check_but_ignore_duplicates(response)?;

        for protocol in ["tcp", "udp", "icmp", "icmpv6"] {
            let mut request = client
                .authorize_security_group_ingress()
                .group_name(&self.settings.testbed_id)
                .ip_protocol(protocol)
                .cidr_ip("0.0.0.0/0");
            if protocol == "icmp" || protocol == "icmpv6" {
                request = request.from_port(-1).to_port(-1);
            } else {
                request = request.from_port(0).to_port(65535);
            }

            let response = request.send().await;
            Self::check_but_ignore_duplicates(response)?;
        }
        Ok(())
    }

    /// Return the command to mount the first (standard) NVMe drive.
    fn nvme_mount_command(&self) -> Vec<String> {
        const DRIVE: &str = "nvme1n1";
        let directory = self.settings.working_dir.display();
        vec![
            format!("(sudo mkfs.ext4 -E nodiscard /dev/{DRIVE} || true)"),
            format!("(sudo mount /dev/{DRIVE} {directory} || true)"),
            format!("sudo chmod 777 -R {directory}"),
        ]
    }

    fn nvme_unmount_command(&self) -> Vec<String> {
        let directory = self.settings.working_dir.display();
        vec![format!("(sudo umount {directory} || true)")]
    }

    /// Check whether the instance type specified in the settings supports NVMe drives.
    async fn check_nvme_support(&self) -> CloudProviderResult<bool> {
        // Get the client for the first region. A given instance type should either have NVMe
        // support in all regions or in none.
        let client = match self
            .settings
            .regions
            .first()
            .and_then(|x| self.clients.get(&x.name))
        {
            Some(client) => client,
            None => return Ok(false),
        };

        // Request storage details for the instance type specified in the settings.
        let request = client
            .describe_instance_types()
            .instance_types(self.settings.specs.as_str().into());

        // Send the request.
        let response = request.send().await?;

        // Return true if the response contains references to NVMe drives.
        if let Some(info) = response.instance_types().first() {
            if let Some(info) = info.instance_storage_info() {
                if info.nvme_support() == Some(&EphemeralNvmeSupport::Required) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    async fn wait_for_instance_running(
        &self,
        client: &aws_sdk_ec2::Client,
        instance_id: &str,
    ) -> CloudProviderResult<String> {
        loop {
            let response = client
                .describe_instances()
                .instance_ids(instance_id)
                .send()
                .await?;

            let reservations = response.reservations.unwrap_or_default();

            let instance = reservations
                .first() // &Vec<Reservation> -> Option<&Reservation>
                .and_then(|r| r.instances.as_ref()) // Option<&Reservation> -> Option<&Vec<AwsInstance>>
                .and_then(|i| i.first()) // Option<&Vec<AwsInstance>> -> Option<&AwsInstance>
                .ok_or_else(|| {
                    CloudProviderError::UnexpectedResponse(format!(
                        "Instance {instance_id} not found after creation"
                    ))
                })?;

            let state = instance
                .state
                .as_ref()
                .and_then(|s| s.name.as_ref())
                .ok_or_else(|| {
                    CloudProviderError::UnexpectedResponse(format!(
                        "Instance {instance_id} has no state"
                    ))
                })?;

            match *state {
                InstanceStateName::Running => {
                    return Ok(instance
                        .vpc_id
                        .as_ref()
                        .expect("Running instance must have VPC ID")
                        .to_string());
                }
                InstanceStateName::Pending => {
                    sleep(Duration::from_secs(5)).await;
                }
                _ => {
                    return Err(CloudProviderError::UnexpectedResponse(format!(
                        "Instance {instance_id} entered unexpected state: {:?}",
                        state
                    )));
                }
            }
        }
    }

    // [ 🌟 추가: NLB 헬스 체크 대기 함수 (오류 수정됨) ]
    async fn wait_for_target_healthy(
        &self,
        elbv2_client: &elbv2::Client,
        target_group_arn: &str,
        instance_id: &str,
    ) -> CloudProviderResult<()> {
        info!("(AWS) [ID: {instance_id}] Waiting for NLB Target Group {target_group_arn} to become 'healthy'...");

        loop {
            // [ 🌟 수정 ] wrap_err를 제거하고 `?`를 사용하여 SdkError가 CloudProviderError로 변환되도록 함
            let response = elbv2_client
                .describe_target_health()
                .target_group_arn(target_group_arn)
                .targets(
                    TargetDescription::builder()
                        .id(instance_id)
                        .build()
                )
                .send()
                .await?; // 👈 [수정됨]

            if let Some(desc) = response.target_health_descriptions.and_then(|mut v| v.pop()) {
                if let Some(state) = desc.target_health.clone().and_then(|th| th.state) {
                    match state {
                        TargetHealthStateEnum::Healthy => {
                            info!("(AWS) [ID: {instance_id}] Target is 'Healthy'.");
                            return Ok(());
                        }
                        TargetHealthStateEnum::Unhealthy => {
                            // [ 🌟 수정된 부분 🌟 ]
                            // .and_then(|th| th.reason) 대신 .as_ref()를 두 번 사용하여
                            // String의 소유권을 이동시키지 않고 참조(&String)를 가져옵니다.
                            let reason = desc.target_health.as_ref() // Option<TargetHealth> -> Option<&TargetHealth>
                                .and_then(|th| th.reason.as_ref()) // Option<&TargetHealth> -> Option<&String>
                                .map_or("No reason provided", |s| s.as_str()); // |s|는 &String 타입

                            info!("(AWS) [ID: {instance_id}] Target state is 'Unhealthy'. Reason: [{reason}]. Waiting 5s...");
                        }
                        TargetHealthStateEnum::Initial | TargetHealthStateEnum::Draining | TargetHealthStateEnum::Unavailable | TargetHealthStateEnum::Unused => {
                            info!("(AWS) [ID: {instance_id}] Target state is '{:?}'. Waiting 5s...", state);
                        }
                        _ => {
                            info!("(AWS) [ID: {instance_id}] Target state is '{:?}'. Waiting 5s...", state);
                        }
                    }
                } else {
                    info!("(AWS) [ID: {instance_id}] Target health description not yet available. Waiting 5s...");
                }

                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

impl ServerProviderClient for AwsClient {
    const USERNAME: &'static str = "ubuntu";

    async fn list_instances(&self) -> CloudProviderResult<Vec<Instance>> {
        let filter = Filter::builder()
            .name("tag:Name")
            .values(self.settings.testbed_id.clone())
            .build();

        let mut instances = Vec::new();

        for region_config in &self.settings.regions {
            let region = &region_config.name;
            let client = self.clients.get(region).unwrap();
            let elbv2_client = self.elbv2_clients.get(region).unwrap();
            let nlb_arn = &region_config.nlb_arn;

            // 1. 이 NLB의 모든 리스너를 가져옵니다.
            let listeners = match elbv2_client
                .describe_listeners()
                .load_balancer_arn(nlb_arn)
                .send()
                .await
            {
                Ok(resp) => resp.listeners.unwrap_or_default(),
                Err(e) => return Err(e.into()),
            };

            // 2. 리스너 포트, 리스너 ARN, 대상 그룹 ARN을 매핑합니다.
            let mut tg_to_port_listener = HashMap::new();
            for listener in listeners {
                if let (Some(port), Some(actions), Some(listener_arn)) =
                    (listener.port, listener.default_actions, listener.listener_arn)
                {
                    if let Some(tg_arn) = actions.first().and_then(|a| a.target_group_arn.as_ref())
                    {
                        // 사용자가 요청한 포트 범위(9000+)인지 확인
                        if port >= self.settings.ssh_start_port as i32 {
                            tg_to_port_listener.insert(
                                tg_arn.to_string(),
                                (port as u16, listener_arn.to_string()),
                            );
                        }
                    }
                }
            }

            // 3. 이 대상 그룹들의 타겟(EC2 인스턴스 ID)을 가져옵니다.
            let mut instance_id_to_mapping = HashMap::new();
            for (tg_arn, (port, listener_arn)) in tg_to_port_listener {
                let health = match elbv2_client
                    .describe_target_health()
                    .target_group_arn(&tg_arn)
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        display::warn(format!("Failed to describe target health for {}: {:?}", tg_arn, e));
                        continue;
                    }
                };

                if let Some(target) =
                    health.target_health_descriptions.unwrap_or_default().first()
                {
                    if let Some(id) = target.target.as_ref().and_then(|t| t.id.as_ref()) {
                        instance_id_to_mapping.insert(
                            id.to_string(),
                            (port, tg_arn.clone(), listener_arn.clone()),
                        );
                    }
                }
            }

            // 4. 태그가 일치하는 EC2 인스턴스를 가져옵니다.
            let request = client.describe_instances().filters(filter.clone());
            for reservation in request.send().await?.reservations.unwrap_or_default() {
                for instance in reservation.instances.unwrap_or_default() {
                    let instance_id = instance.instance_id().unwrap();

                    // 5. EC2 인스턴스 정보와 NLB/AGA 매핑 정보를 결합합니다.
                    if let Some((port, tg_arn, listener_arn)) =
                        instance_id_to_mapping.get(instance_id)
                    {
                        instances.push(self.make_instance(
                            region.clone(),
                            &instance,
                            *port,
                            tg_arn.clone(),
                            listener_arn.clone(),
                        ));
                    } else {
                        // NLB 매핑이 없는 (아직 생성 중이거나, 오류가 발생한) 인스턴스
                        // 또는 모니터링 인스턴스 등 다른 용도의 인스턴스일 수 있습니다.
                        // 여기서는 SSH 접속이 불가능한 '불완전한' 상태로 추가합니다.
                        let status_str = format!(
                            "{:?}",
                            instance.state().unwrap().name().unwrap()
                        )
                            .as_str()
                            .into();

                        // 'terminated' 상태가 아닌 경우에만 추가 (이미 종료된 인스턴스 제외)
                        if status_str != InstanceStatus::Terminated {
                            instances.push(Instance {
                                id: instance_id.to_string(),
                                region: region.clone(),
                                main_ip: instance
                                    .public_ip_address()
                                    .unwrap_or("0.0.0.0") // 중지된 인스턴스
                                    .parse()
                                    .expect("AWS instance should have a valid public ip"),
                                ssh_host: "unknown.aga.com".to_string(), // 접속 불가
                                ssh_port: 0,
                                tags: vec![self.settings.testbed_id.clone()],
                                specs: format!("{:?}", instance.instance_type().unwrap()),
                                status: status_str,
                                nlb_target_group_arn: "unknown".to_string(),
                                nlb_listener_arn: "unknown".to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(instances)
    }

    async fn start_instances<'a, I>(&self, instances: I) -> CloudProviderResult<()>
    where
        I: Iterator<Item = &'a Instance> + Send,
    {
        let mut instance_ids = HashMap::new();
        for instance in instances {
            instance_ids
                .entry(&instance.region)
                .or_insert_with(Vec::new)
                .push(instance.id.clone());
        }

        for (region, client) in &self.clients {
            let ids = instance_ids.remove(&region.to_string());
            if ids.is_some() {
                client
                    .start_instances()
                    .set_instance_ids(ids)
                    .send()
                    .await?;
            }
        }
        Ok(())
    }

    async fn stop_instances<'a, I>(&self, instances: I) -> CloudProviderResult<()>
    where
        I: Iterator<Item = &'a Instance> + Send,
    {
        let mut instance_ids = HashMap::new();
        for instance in instances {
            instance_ids
                .entry(&instance.region)
                .or_insert_with(Vec::new)
                .push(instance.id.clone());
        }

        for (region, client) in &self.clients {
            let ids = instance_ids.remove(&region.to_string());
            if ids.is_some() {
                client.stop_instances().set_instance_ids(ids).send().await?;
            }
        }
        Ok(())
    }

    async fn create_instance<S>(&self, region: S) -> CloudProviderResult<Instance>
    where
        S: Into<String> + Serialize + Send,
    {
        let region = region.into();
        let testbed_id = &self.settings.testbed_id;

        let client = self.clients.get(&region).ok_or_else(|| {
            CloudProviderError::RequestError(format!("Undefined region {region:?}"))
        })?;
        let elbv2_client = self.elbv2_clients.get(&region).ok_or_else(|| {
            CloudProviderError::RequestError(format!("Undefined ELBv2 client for region {region:?}"))
        })?;
        let region_config = self.settings.get_region_config(&region).ok_or_else(|| {
            CloudProviderError::RequestError(format!("Undefined RegionConfig for region {region:?}"))
        })?;

        // 1. (신규) 이 인스턴스에 대한 고유 포트 할당
        let assigned_port = {
            let mut ports = self.next_port.lock().unwrap();
            let port = ports
                .entry(region.clone())
                .or_insert(self.settings.ssh_start_port);
            let assigned_port = *port;
            *port += 1; // 다음 포트를 위해 1 증가
            assigned_port
        };
        info!("(AWS) [Region: {region}] Requesting instance with SSH port {assigned_port}");

        // 2. 보안 그룹 생성 (기존 로직)
        self.create_security_group(client).await?;

        // 3. 이미지 ID 찾기 (기존 로직)
        let image_id = self.find_image_id(client).await?;

        // 4. 태그 정의 (v1.x SDK 문법 수정)
        let tags = TagSpecification::builder()
            .resource_type(ResourceType::Instance)
            .tags(Tag::builder().key("Name").value(testbed_id).build())
            .build();

        // 5. 스토리지 정의 (v1.x SDK 문법 수정)
        let storage = BlockDeviceMapping::builder()
            .device_name("/dev/sda1")
            .ebs(
                EbsBlockDevice::builder()
                    .delete_on_termination(true)
                    .volume_size(Self::DEFAULT_EBS_SIZE_GB)
                    .volume_type(VolumeType::Gp2)
                    .build(),
            )
            .build();

        // [ 🌟 추가 ] 스팟 인스턴스 옵션
        let spot_options = SpotMarketOptions::builder()
            .spot_instance_type(SpotInstanceType::OneTime) // 1회성 요청
            .instance_interruption_behavior(InstanceInterruptionBehavior::Terminate) // 중단 시 종료
            .build();

        let market_options = InstanceMarketOptionsRequest::builder()
            .market_type(MarketType::Spot) // 마켓 타입을 'spot'으로 지정
            .spot_options(spot_options)
            .build();

        // 6. EC2 인스턴스 생성 요청
        let request = client
            .run_instances()
            .image_id(image_id)
            .instance_type(self.settings.specs.as_str().into())
            .key_name(testbed_id)
            .min_count(1)
            .max_count(1)
            .security_groups(&self.settings.testbed_id)
            .block_device_mappings(storage)
            .tag_specifications(tags)
            .instance_market_options(market_options); // [ 🌟 추가 ] 스팟 옵션 적용


        let response = request.send().await?;
        let aws_instance_slim = &response
            .instances
            .as_ref()
            .expect("AWS instances list should contain instances")
            .first()
            .unwrap();
        let instance_id = aws_instance_slim.instance_id().unwrap();

        info!("(AWS) [Region: {region}, Port: {assigned_port}] EC2 instance created: {instance_id}");

        info!("(AWS) [Region: {region}, ID: {instance_id}] Waiting for instance to enter 'running' state...");
        // 7. (신규) EC2가 'running' 상태가 될 때까지 대기
        let vpc_id = self
            .wait_for_instance_running(client, instance_id)
            .await?;
        info!("(AWS) [Region: {region}, ID: {instance_id}] Instance is 'running' in VPC {vpc_id}.");

        // 8. (신규) NLB 대상 그룹(Target Group) 생성
        let tg_name = format!("mysticeti-tg-{}-{}", region, assigned_port);
        info!("(AWS) [Region: {region}, ID: {instance_id}] Creating NLB Target Group: {tg_name}"); // 👈 [로그 추가]
        let tg_response = elbv2_client
            .create_target_group()
            .name(tg_name)
            .protocol(ProtocolEnum::Tcp)
            .port(22) // 대상은 EC2의 SSH 포트(22)
            .vpc_id(vpc_id)
            .target_type(TargetTypeEnum::Instance)
            // --- ⬇️ 헬스 체크 설정을 명시적으로 추가 ⬇️ ---
            .health_check_protocol(ProtocolEnum::Tcp) // [ 🌟 수정 ]
            .health_check_port("22") // 헬스 체크도 22번 포트(SSH)로 수행
            .health_check_interval_seconds(10) // 10초마다 헬스 체크
            .healthy_threshold_count(2) // 2번 성공 시 'Healthy'
            // --- ⬆️ 헬스 체크 설정 추가 끝 ⬆️ ---
            .send()
            .await?;

        let target_group_arn = tg_response
            .target_groups
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .target_group_arn
            .as_ref()
            .unwrap();

        info!("(AWS) [Region: {region}, ID: {instance_id}] Registering instance to Target Group {target_group_arn}");
        // 9. (신규) 대상 그룹에 EC2 인스턴스 등록
        elbv2_client
            .register_targets()
            .target_group_arn(target_group_arn)
            .targets(
                TargetDescription::builder()
                    .id(instance_id)
                    .build(),
            )
            .send()
            .await?;

        // [ 🌟 수정: 10번(리스너 생성)을 9.5번(헬스 체크 대기) 앞으로 이동 ]
        // 10. (신규) NLB에 리스너 생성 (AGA 포트 -> 대상 그룹)
        info!("(AWS) [Region: {region}, ID: {instance_id}] Creating NLB Listener: Port {assigned_port} -> {target_group_arn}");
        let listener_response = elbv2_client
            .create_listener()
            .load_balancer_arn(&region_config.nlb_arn)
            .protocol(ProtocolEnum::Tcp)
            .port(assigned_port as i32) // 예: 9000
            .default_actions(
                Action::builder()
                    .r#type(ActionTypeEnum::Forward)
                    .target_group_arn(target_group_arn)
                    .build()
            )
            .send()
            .await?;

        let listener_arn = listener_response
            .listeners
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .listener_arn
            .as_ref()
            .unwrap();

        // [ 🌟 수정: 9.5번(헬스 체크 대기)을 10번 뒤로 이동 ]
        // 9.5. NLB가 이 대상을 'Healthy'로 인식할 때까지 대기
        self.wait_for_target_healthy(elbv2_client, target_group_arn, instance_id).await?;


        // 11. (수정) make_instance 호출
        // describe_instances를 다시 호출하여 전체 AwsInstance 정보를 가져옵니다.
        let full_aws_instance = client
            .describe_instances()
            .instance_ids(instance_id)
            .send()
            .await?
            .reservations
            .unwrap()
            .first()
            .unwrap()
            .instances
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .clone();

        info!("(AWS) [Region: {region}, ID: {instance_id}] Successfully provisioned all resources.");

        Ok(self.make_instance(
            region,
            &full_aws_instance,
            assigned_port,
            target_group_arn.to_string(),
            listener_arn.to_string(),
        ))
    }

    /// (수정) EC2 종료 시 NLB 리스너 및 대상 그룹 동적 삭제
    async fn delete_instance(&self, instance: Instance) -> CloudProviderResult<()> {
        let client = self.clients.get(&instance.region).ok_or_else(|| {
            CloudProviderError::RequestError(format!("Undefined region {:?}", instance.region))
        })?;
        let elbv2_client = self.elbv2_clients.get(&instance.region).ok_or_else(|| {
            CloudProviderError::RequestError(format!(
                "Undefined ELBv2 client for region {:?}",
                instance.region
            ))
        })?;

        // (신규) 1. NLB 리스너 삭제
        // 오류가 발생해도 무시하고 다음 단계 진행 (정리 작업이므로)
        info!("(AWS) [Region: {}] Deleting Listener: {}", instance.region, instance.nlb_listener_arn); // 👈 [로그 추가]
        if let Err(e) = elbv2_client
            .delete_listener()
            .listener_arn(&instance.nlb_listener_arn)
            .send()
            .await
        {
            display::warn(format!("Failed to delete listener {}: {:?}",
                                  instance.nlb_listener_arn,
                                  e)
            );
        } else {
            // 리스너 삭제가 성공하면 대상 그룹 삭제 전에 잠시 대기
            info!("(AWS) [Region: {}] Waiting 5s for listener deletion...", instance.region); // 👈 [로그 추가]
            sleep(Duration::from_secs(5)).await;
        }

        // (신규) 2. NLB 대상 그룹 삭제
        info!("(AWS) [Region: {}] Deleting Target Group: {}", instance.region, instance.nlb_target_group_arn); // 👈 [로그 추가]
        if let Err(e) = elbv2_client
            .delete_target_group()
            .target_group_arn(&instance.nlb_target_group_arn)
            .send()
            .await
        {
            display::warn(
                format!("Failed to delete target group {}: {:?}",
                        instance.nlb_target_group_arn,
                        e)
            );
        }

        // (기존) 3. EC2 인스턴스 종료
        info!("(AWS) [Region: {}] Terminating Instance: {}", instance.region, instance.id); // 👈 [로그 추가]
        client
            .terminate_instances()
            .set_instance_ids(Some(vec![instance.id.clone()]))
            .send()
            .await?;

        Ok(())
    }

    async fn register_ssh_public_key(&self, public_key: String) -> CloudProviderResult<()> {
        for client in self.clients.values() {
            let request = client
                .import_key_pair()
                .key_name(&self.settings.testbed_id)
                .public_key_material(Blob::new::<String>(public_key.clone()));

            let response = request.send().await;
            Self::check_but_ignore_duplicates(response)?;
        }
        Ok(())
    }

    async fn instance_setup_commands(&self) -> CloudProviderResult<Vec<String>> {
        if self.settings.nvme && self.check_nvme_support().await? {
            Ok(self.nvme_mount_command())
        } else {
            Ok(self.nvme_unmount_command())
        }
    }
}
