// crates/orchestrator/src/ssh.rs

use std::{fs, io::Read, net::SocketAddr, path::{Path, PathBuf}, time::Duration};

use futures::future::try_join_all;
use log::info;
use ssh2::{Channel, Session};
use tokio::{net::TcpStream, runtime::Handle, task::JoinHandle, time::sleep};

use crate::{
    client::Instance,
    ensure,
    error::{SshError, SshResult},
};

#[derive(PartialEq, Eq)]
/// The status of a ssh command running in the background.
pub enum CommandStatus {
    Running,
    Terminated,
}

impl CommandStatus {
    /// Return whether a background command is still running. Returns `Terminated` if the
    /// command is not running in the background.
    pub fn status(command_id: &str, text: &str) -> Self {
        if text.contains(command_id) {
            Self::Running
        } else {
            Self::Terminated
        }
    }
}

/// The command to execute on all specified remote machines.
#[derive(Clone, Default)]
pub struct CommandContext {
    /// Whether to run the command in the background (and return immediately). Commands
    /// running in the background are identified by a unique id.
    pub background: Option<String>,
    /// The path from where to execute the command.
    pub path: Option<PathBuf>,
    /// The log file to redirect all stdout and stderr.
    pub log_file: Option<PathBuf>,
}

impl CommandContext {
    /// Create a new ssh command.
    pub fn new() -> Self {
        Self {
            background: None,
            path: None,
            log_file: None,
        }
    }

    /// Set id of the command and indicate that it should run in the background.
    pub fn run_background(mut self, id: String) -> Self {
        self.background = Some(id);
        self
    }

    /// Set the path from where to execute the command.
    pub fn with_execute_from_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Set the log file where to redirect stdout and stderr.
    pub fn with_log_file(mut self, path: PathBuf) -> Self {
        self.log_file = Some(path);
        self
    }

    /// Apply the context to a base command.
    pub fn apply<S: Into<String>>(&self, base_command: S) -> String {
        let mut str = base_command.into();
        if let Some(log_file) = &self.log_file {
            str = format!("{str} |& tee {}", log_file.as_path().display());
        }
        if let Some(id) = &self.background {
            str = format!("tmux new -d -s \"{id}\" \"{str}\"");
        }
        if let Some(exec_path) = &self.path {
            str = format!("(cd {} && {str})", exec_path.as_path().display());
        }
        str
    }
}

#[derive(Clone)]
pub struct SshConnectionManager {
    /// The ssh username.
    username: String,
    /// The ssh primate key to connect to the instances.
    private_key_file: PathBuf,
    /// The timeout value of the connection.
    timeout: Option<Duration>,
    /// The number of retries before giving up to execute the command.
    retries: usize,
}

impl SshConnectionManager {
    /// Delay before re-attempting an ssh execution.
    const RETRY_DELAY: Duration = Duration::from_secs(5);

    /// Create a new ssh manager from the instances username and private keys.
    pub fn new(username: String, private_key_file: PathBuf) -> Self {
        Self {
            username,
            private_key_file,
            timeout: None,
            retries: 0,
        }
    }

    /// Set a timeout duration for the connections.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the maximum number of times to retries to establish a connection and execute commands.
    pub fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    /// Create a new ssh connection with the provided host.
    pub async fn connect(&self, address: SocketAddr) -> SshResult<SshConnection> {
        let mut error = None;
        for _ in 0..self.retries + 1 {
            match SshConnection::new(address, &self.username, self.private_key_file.clone()).await {
                Ok(x) => return Ok(x.with_timeout(&self.timeout).with_retries(self.retries)),
                Err(e) => error = Some(e),
            }
            sleep(Self::RETRY_DELAY).await;
        }
        Err(error.unwrap())
    }

    // [ 🌟 수정: spawn_blocking을 scp_upload에도 적용 🌟 ]
    pub async fn upload<I, P1, P2>(
        &self,
        instances: I,
        local_path: P1,
        remote_path: P2,
    ) -> SshResult<Vec<()>>
    where
        I: IntoIterator<Item = Instance>,
        P1: AsRef<Path> + Send + 'static + Clone,
        P2: AsRef<Path> + Send + 'static + Clone,
    {
        let handles = instances
            .into_iter()
            .map(|instance| {
                let ssh_manager = self.clone();
                let local_path = local_path.clone();
                let remote_path = remote_path.clone();

                tokio::spawn(async move {
                    let connection = ssh_manager.connect(instance.ssh_address()).await?;

                    let local_file_size = fs::metadata(local_path.as_ref())
                        .map_err(|e| SshError::ConnectionError {
                            address: instance.ssh_address(),
                            error: e
                        })?.len();

                    // 3. 블로킹 I/O인 SCP 전송을 블로킹 풀에서 실행합니다.
                    tokio::task::spawn_blocking(move || {
                        connection.upload(
                            local_path.as_ref(),
                            remote_path.as_ref(),
                            local_file_size,
                        )
                    })
                        .await
                        .unwrap_or_else(|e| { // JoinError 처리
                            let error_string = format!("Blocking task failed: {e}");
                            let static_message = Box::leak(error_string.into_boxed_str());
                            Err(SshError::SessionError {
                                address: instance.ssh_address(),
                                error: ssh2::Error::new(ssh2::ErrorCode::Session(-1),
                                                        static_message,
                                ),
                            })
                        })
                })
            })
            .collect::<Vec<_>>();

        try_join_all(handles)
            .await
            .unwrap() // JoinError 처리 (여기서는 패닉)
            .into_iter()
            .collect::<SshResult<_>>() // SshResult 처리
    }

    /// Execute the specified ssh command on all provided instances.
    pub async fn execute<I, S>(
        &self,
        instances: I,
        command: S,
        context: CommandContext,
    ) -> SshResult<Vec<(String, String)>>
    where
        I: IntoIterator<Item = Instance>,
        S: Into<String> + Clone + Send + 'static,
    {
        let targets = instances
            .into_iter()
            .map(|instance| (instance, command.clone()));
        self.execute_per_instance(targets, context).await
    }

    /// Execute the ssh command associated with each instance.
    pub async fn execute_per_instance<I, S>(
        &self,
        instances: I,
        context: CommandContext,
    ) -> SshResult<Vec<(String, String)>>
    where
        I: IntoIterator<Item = (Instance, S)>,
        S: Into<String> + Send + 'static,
    {
        let handles = self.run_per_instance(instances, context);

        try_join_all(handles)
            .await
            .unwrap()
            .into_iter()
            .collect::<SshResult<_>>()
    }

    pub fn run_per_instance<I, S>(
        &self,
        instances: I,
        context: CommandContext,
    ) -> Vec<JoinHandle<SshResult<(String, String)>>>
    where
        I: IntoIterator<Item = (Instance, S)>,
        S: Into<String> + Send + 'static,
    {
        instances
            .into_iter()
            .map(|(instance, command)| {
                let ssh_manager = self.clone();
                let context = context.clone();

                tokio::spawn(async move {
                    let connection = ssh_manager.connect(instance.ssh_address()).await?;
                    let command_str = context.apply(command); // [ 🌟 수정 ]

                    // [ 🌟 수정: SshConnection::execute는 블로킹이므로 spawn_blocking 사용 ]
                    Handle::current()
                        .spawn_blocking(move || connection.execute(command_str))
                        .await
                        .unwrap() // JoinError 처리 (패닉)
                })
            })
            .collect::<Vec<_>>()
    }

    /// Wait until a command running in the background returns or started.
    pub async fn wait_for_command<I>(
        &self,
        instances: I,
        command_id: &str,
        status: CommandStatus,
    ) -> SshResult<()>
    where
        I: IntoIterator<Item = Instance> + Clone,
    {
        loop {
            sleep(Self::RETRY_DELAY).await;

            let result = self
                .execute(
                    instances.clone(),
                    "(tmux ls || true)",
                    CommandContext::default(),
                )
                .await?;
            if result
                .iter()
                .all(|(stdout, _)| CommandStatus::status(command_id, stdout) == status)
            {
                break;
            }
        }
        Ok(())
    }

    pub async fn wait_for_success<I, S>(&self, instances: I)
    where
        I: IntoIterator<Item = (Instance, S)> + Clone,
        S: Into<String> + Send + 'static + Clone,
    {
        loop {
            sleep(Self::RETRY_DELAY).await;

            if self
                .execute_per_instance(instances.clone(), CommandContext::default())
                .await
                .is_ok()
            {
                break;
            }
        }
    }

    /// Kill a command running in the background of the specified instances.
    pub async fn kill<I>(&self, instances: I, command_id: &str) -> SshResult<()>
    where
        I: IntoIterator<Item = Instance>,
    {
        let ssh_command = format!("(tmux kill-session -t {command_id} || true)");
        let targets = instances.into_iter().map(|x| (x, ssh_command.clone()));
        self.execute_per_instance(targets, CommandContext::default())
            .await?;
        Ok(())
    }
}

/// Representation of an ssh connection.
pub struct SshConnection {
    /// The ssh session.
    session: Session,
    /// The host address.
    address: SocketAddr,
    /// The number of retries before giving up to execute the command.
    retries: usize,
}

impl SshConnection {
    /// Default duration before timing out the ssh connection.
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

    /// Create a new ssh connection with a specific host.
    pub async fn new<P: AsRef<Path>>(
        address: SocketAddr,
        username: &str,
        private_key_file: P,
    ) -> SshResult<Self> {
        info!("[SSH] Attempting TCP connection to {username}@{address}...");

        let tcp = TcpStream::connect(address)
            .await
            .map_err(|error| {
                info!("[SSH] FAILED TCP connect to {address}: {error}");
                SshError::ConnectionError { address, error }
            })?;

        // [ 🌟 수정: spawn_blocking으로 전체 블로킹 로직 감싸기 🌟 ]
        let username = username.to_string();
        let private_key_path = private_key_file.as_ref().to_path_buf();
        let session = tokio::task::spawn_blocking(move || {
            let mut session =
                Session::new().map_err(|error| SshError::SessionError { address, error })?;
            session.set_timeout(Self::DEFAULT_TIMEOUT.as_millis() as u32);
            session.set_tcp_stream(tcp);

            info!("[SSH] TCP connected. Performing handshake with {address}...");
            session
                .handshake()
                .map_err(|error| {
                    info!("[SSH] FAILED handshake with {address}: {error}");
                    SshError::SessionError { address, error }
                })?;

            info!("[SSH] Handshake complete. Authenticating with key {path} for {username}...", path = private_key_path.display());
            session
                .userauth_pubkey_file(&username, None, &private_key_path, None)
                .map_err(|error| {
                    info!("[SSH] FAILED authentication for {username}@{address}: {error}");
                    SshError::SessionError { address, error }
                })?;

            info!("[SSH] Authentication successful for {username}@{address}");
            Ok::<Session, SshError>(session)
        }).await.unwrap()?; // .unwrap()는 spawn_blocking의 JoinError 처리, `?`는 SshResult 처리

        Ok(Self {
            session,
            address,
            retries: 0,
        })
    }

    // [ 🌟 수정: 이 함수는 spawn_blocking 내부에서 호출되므로 동기식으로 유지 🌟 ]
    pub fn upload(
        &self,
        local_path: &Path,
        remote_path: &Path,
        file_size: u64,
    ) -> SshResult<()> {
        let mut error = None;
        for _ in 0..self.retries + 1 {
            // 0o644는 파일 권한 (rw-r--r--)
            let mut remote_file = match self.session.scp_send(remote_path, 0o644, file_size, None) {
                Ok(x) => x,
                Err(e) => {
                    error = Some(self.make_session_error(e));
                    continue;
                }
            };

            let mut local_file = fs::File::open(local_path)
                .map_err(|e| self.make_connection_error(e))?;

            // 파일을 청크 단위로 복사
            match std::io::copy(&mut local_file, &mut remote_file) {
                Ok(_) => {
                    // SCP 세션 종료
                    remote_file.send_eof().map_err(|e| self.make_session_error(e))?;
                    remote_file.wait_eof().map_err(|e| self.make_session_error(e))?;
                    remote_file.close().map_err(|e| self.make_session_error(e))?;
                    remote_file.wait_close().map_err(|e| self.make_session_error(e))?;
                    return Ok(());
                }
                Err(e) => {
                    error = Some(self.make_connection_error(e));
                }
            }
        }
        Err(error.unwrap())
    }

    /// Set a timeout for the ssh connection. If no timeouts are specified, reset it to the
    /// default value.
    pub fn with_timeout(self, timeout: &Option<Duration>) -> Self {
        let duration = match timeout {
            Some(value) => value,
            None => &Self::DEFAULT_TIMEOUT,
        };
        self.session.set_timeout(duration.as_millis() as u32);
        self
    }

    /// Set the maximum number of times to retries to establish a connection and execute commands.
    pub fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    /// Make a useful session error from the lower level error message.
    fn make_session_error(&self, error: ssh2::Error) -> SshError {
        SshError::SessionError {
            address: self.address,
            error,
        }
    }

    /// Make a useful connection error from the lower level error message.
    fn make_connection_error(&self, error: std::io::Error) -> SshError {
        SshError::ConnectionError {
            address: self.address,
            error,
        }
    }

    /// Execute a ssh command on the remote machine.
    // [ 🌟 수정: 이 함수는 spawn_blocking 내부에서 호출되므로 동기식으로 유지 🌟 ]
    pub fn execute(&self, command: String) -> SshResult<(String, String)> {
        let mut error = None;
        for _ in 0..self.retries + 1 {
            let channel = match self.session.channel_session() {
                Ok(x) => x,
                Err(e) => {
                    error = Some(self.make_session_error(e));
                    continue;
                }
            };
            match self.execute_impl(channel, command.clone()) {
                r @ Ok(..) => return r,
                Err(e) => error = Some(e),
            }
        }
        Err(error.unwrap())
    }

    /// Execute an ssh command on the remote machine and return both stdout and stderr.
    fn execute_impl(&self, mut channel: Channel, command: String) -> SshResult<(String, String)> {
        info!("[SSH] Executing command on {}: {}", self.address, command); // 👈 [로그 추가]
        channel
            .exec(&command)
            .map_err(|e| self.make_session_error(e))?;

        let mut stdout = String::new();
        channel
            .read_to_string(&mut stdout)
            .map_err(|e| self.make_connection_error(e))?;

        let mut stderr = String::new();
        channel
            .stderr()
            .read_to_string(&mut stderr)
            .map_err(|e| self.make_connection_error(e))?;

        channel.close().map_err(|e| self.make_session_error(e))?;
        channel
            .wait_close()
            .map_err(|e| self.make_session_error(e))?;

        let exit_status = channel
            .exit_status()
            .map_err(|e| self.make_session_error(e))?;

        info!("[SSH] Command on {} exited with status {}", self.address, exit_status); // 👈 [로그 추가]

        ensure!(
            exit_status == 0,
            SshError::NonZeroExitCode {
                address: self.address,
                code: exit_status,
                message: stderr.clone()
            }
        );

        Ok((stdout, stderr))
    }

    /// Download a file from the remote machines through scp.
    // [ 🌟 수정: 이 함수도 블로킹이므로 spawn_blocking으로 감싸야 함 (SshConnectionManager에서) 🌟 ]
    // (하지만 지금 당장 사용되지는 않으므로, new와 execute만 수정해도 deploy는 통과됩니다)
    pub fn download<P: AsRef<Path>>(&self, path: P) -> SshResult<String> {
        let mut error = None;
        for _ in 0..self.retries + 1 {
            let (mut channel, _stats) = match self.session.scp_recv(path.as_ref()) {
                Ok(x) => x,
                Err(e) => {
                    error = Some(self.make_session_error(e));
                    continue;
                }
            };

            let mut content = String::new();
            match channel
                .read_to_string(&mut content)
                .map_err(|e| self.make_connection_error(e))
            {
                Ok(..) => return Ok(content),
                Err(e) => error = Some(e),
            }
        }
        Err(error.unwrap())
    }
}

