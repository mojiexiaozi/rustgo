#![forbid(unsafe_code)]

mod protocol;

pub use protocol::{
    AuthenticationChallenge, ScriptedProtocolClient, ScriptedProtocolError, authenticate,
    authentication_message, begin_authentication, begin_authentication_with_fingerprint,
    finish_authentication, wire_fingerprint,
};

use std::{
    error::Error,
    ffi::OsStr,
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustgo_crypto::{DeviceKeypair, generate_key_file};
use tempfile::TempDir;

pub type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const SERVER_NAME: &str = "tunnel.example.test";
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
static BINARIES: OnceLock<Result<Binaries, String>> = OnceLock::new();

#[derive(Clone)]
struct Binaries {
    server: PathBuf,
    client: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryProfile {
    Debug,
    Release,
}

impl BinaryProfile {
    const fn directory(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }
}

fn select_binary_profile(value: Option<&OsStr>) -> Result<BinaryProfile, String> {
    match value {
        None => Ok(BinaryProfile::Debug),
        Some(value) if value == "release" => Ok(BinaryProfile::Release),
        Some(value) => Err(format!(
            "RUSTGO_E2E_BIN_PROFILE must be `release` when set, got `{}`",
            value.to_string_lossy()
        )),
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("e2e crate lives below the workspace root")
        .to_owned()
}

fn ensure_binaries() -> TestResult<Binaries> {
    let result = BINARIES.get_or_init(|| {
        let root = workspace_root();
        let profile = select_binary_profile(std::env::var_os("RUSTGO_E2E_BIN_PROFILE").as_deref())?;
        let mut build_arguments = vec![
            "build", "--quiet", "-p", "rustgos", "-p", "rustgoc", "--bins",
        ];
        if profile == BinaryProfile::Release {
            build_arguments.push("--release");
        }
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut last_status = None;
        for attempt in 1..=3 {
            let status = Command::new(&cargo)
                .current_dir(&root)
                .args(&build_arguments)
                .status()
                .map_err(|error| format!("could not launch cargo build: {error}"))?;
            if status.success() {
                last_status = None;
                break;
            }
            last_status = Some(status);
            if attempt < 3 {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        if let Some(status) = last_status {
            return Err(format!(
                "cargo build for process fixtures failed with {status}"
            ));
        }

        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    root.join(path)
                }
            })
            .unwrap_or_else(|| root.join("target"));
        let executable_suffix = std::env::consts::EXE_SUFFIX;
        Ok(Binaries {
            server: target
                .join(profile.directory())
                .join(format!("rustgos{executable_suffix}")),
            client: target
                .join(profile.directory())
                .join(format!("rustgoc{executable_suffix}")),
        })
    });

    result
        .as_ref()
        .cloned()
        .map_err(|message| message.clone().into())
}

pub fn server_binary_path() -> TestResult<PathBuf> {
    Ok(ensure_binaries()?.server)
}

pub fn client_binary_path() -> TestResult<PathBuf> {
    Ok(ensure_binaries()?.client)
}

struct PortReservation {
    listener: Option<TcpListener>,
    address: SocketAddr,
}

struct UdpPortReservation {
    socket: Option<UdpSocket>,
    address: SocketAddr,
}

impl UdpPortReservation {
    fn acquire() -> TestResult<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0))?;
        let address = socket.local_addr()?;
        Ok(Self {
            socket: Some(socket),
            address,
        })
    }

    fn release(&mut self) {
        self.socket.take();
    }
}

enum EndpointReservation {
    Tcp(PortReservation),
    Udp(UdpPortReservation),
}

impl EndpointReservation {
    fn release(&mut self) {
        match self {
            Self::Tcp(reservation) => reservation.release(),
            Self::Udp(reservation) => reservation.release(),
        }
    }
}

impl PortReservation {
    fn acquire() -> TestResult<Self> {
        let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0))?;
        let address = listener.local_addr()?;
        Ok(Self {
            listener: Some(listener),
            address,
        })
    }

    fn release(&mut self) {
        self.listener.take();
    }
}

pub struct ProcessFixture {
    _directory: TempDir,
    server_config: PathBuf,
    client_config: PathBuf,
    ca_file: PathBuf,
    control_port: PortReservation,
    public_ports: Vec<RemoteEndpoint>,
    server_environment: Vec<(String, String)>,
    client_environment: Vec<(String, String)>,
}

struct RemoteEndpoint {
    address: SocketAddr,
    reservation: Option<EndpointReservation>,
}

#[derive(Debug, Clone)]
pub struct UdpTunnelSpec {
    name: String,
    local_address: SocketAddr,
    remote_port: Option<u16>,
}

impl UdpTunnelSpec {
    pub fn available(name: impl Into<String>, local_address: SocketAddr) -> Self {
        Self {
            name: name.into(),
            local_address,
            remote_port: None,
        }
    }

    pub fn on_port(name: impl Into<String>, local_address: SocketAddr, remote_port: u16) -> Self {
        Self {
            name: name.into(),
            local_address,
            remote_port: Some(remote_port),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpTunnelSpec {
    name: String,
    local_address: SocketAddr,
    remote_port: Option<u16>,
}

impl TcpTunnelSpec {
    pub fn available(name: impl Into<String>, local_address: SocketAddr) -> Self {
        Self {
            name: name.into(),
            local_address,
            remote_port: None,
        }
    }

    pub fn on_port(name: impl Into<String>, local_address: SocketAddr, remote_port: u16) -> Self {
        Self {
            name: name.into(),
            local_address,
            remote_port: Some(remote_port),
        }
    }
}

impl ProcessFixture {
    pub fn single_tcp(local_address: SocketAddr) -> TestResult<Self> {
        Self::tcp_tunnels(vec![TcpTunnelSpec::available("echo", local_address)], 8)
    }

    pub fn tcp_tunnels(
        tunnels: Vec<TcpTunnelSpec>,
        max_tcp_connections_per_tunnel: u32,
    ) -> TestResult<Self> {
        if tunnels.is_empty() {
            return Err("process fixture requires at least one TCP tunnel".into());
        }
        let directory = tempfile::tempdir()?;
        let pki = generate_ephemeral_pki(directory.path(), SERVER_NAME)?;
        let ca_file = pki.certificate_authority_file;
        let certificate_file = pki.certificate_file;
        let private_key_file = pki.private_key_file;

        let key_directory = directory.path().join("device");
        generate_key_file(&key_directory)?;
        let device_key_file = key_directory.join("device.key");
        let device_key = DeviceKeypair::load_private_file(&device_key_file)?;

        let control_port = PortReservation::acquire()?;
        let mut public_ports = Vec::with_capacity(tunnels.len());
        for tunnel in &tunnels {
            if let Some(port) = tunnel.remote_port {
                public_ports.push(RemoteEndpoint {
                    address: SocketAddr::new(LOOPBACK, port),
                    reservation: None,
                });
            } else {
                let reservation = PortReservation::acquire()?;
                public_ports.push(RemoteEndpoint {
                    address: reservation.address,
                    reservation: Some(EndpointReservation::Tcp(reservation)),
                });
            }
        }
        let server_config = directory.path().join("server.toml");
        let client_config = directory.path().join("client.toml");
        fs::write(
            &server_config,
            format!(
                "[server]\nbind_addr = \"{}\"\ncertificate_file = {}\nprivate_key_file = {}\nheartbeat_timeout_secs = 5\n\n[limits]\nmax_clients = 8\nmax_tunnels_per_client = {}\nmax_tcp_connections_per_tunnel = {max_tcp_connections_per_tunnel}\nmax_udp_sessions_per_tunnel = 1\nmax_udp_payload_bytes = 65507\n\n[[clients]]\nname = \"home-pc\"\npublic_key = \"{}\"\nenabled = true\n",
                control_port.address,
                toml_path(&certificate_file)?,
                toml_path(&private_key_file)?,
                tunnels.len(),
                device_key.public_key(),
            ),
        )?;
        let mut client_toml = format!(
            "[client]\nname = \"home-pc\"\nserver_addr = \"{}\"\nserver_name = \"{SERVER_NAME}\"\ncertificate_authority_file = {}\nprivate_key_file = {}\nheartbeat_interval_secs = 1\n",
            control_port.address,
            toml_path(&ca_file)?,
            toml_path(&device_key_file)?,
        );
        for (tunnel, public) in tunnels.iter().zip(&public_ports) {
            client_toml.push_str(&format!(
                "\n[[tunnels]]\nname = {}\nprotocol = \"tcp\"\nlocal_addr = \"{}\"\nremote_port = {}\n",
                toml_basic_string(&tunnel.name),
                tunnel.local_address,
                public.address.port(),
            ));
        }
        fs::write(&client_config, client_toml)?;

        Ok(Self {
            _directory: directory,
            server_config,
            client_config,
            ca_file,
            control_port,
            public_ports,
            server_environment: Vec::new(),
            client_environment: Vec::new(),
        })
    }

    pub fn single_udp(
        local_address: SocketAddr,
        max_udp_sessions_per_tunnel: u32,
        max_udp_payload_bytes: u32,
    ) -> TestResult<Self> {
        Self::udp_tunnels(
            vec![UdpTunnelSpec::available("echo", local_address)],
            max_udp_sessions_per_tunnel,
            max_udp_payload_bytes,
        )
    }

    pub fn udp_tunnels(
        tunnels: Vec<UdpTunnelSpec>,
        max_udp_sessions_per_tunnel: u32,
        max_udp_payload_bytes: u32,
    ) -> TestResult<Self> {
        if tunnels.is_empty() {
            return Err("process fixture requires at least one UDP tunnel".into());
        }
        let directory = tempfile::tempdir()?;
        let pki = generate_ephemeral_pki(directory.path(), SERVER_NAME)?;
        let ca_file = pki.certificate_authority_file;
        let certificate_file = pki.certificate_file;
        let private_key_file = pki.private_key_file;

        let key_directory = directory.path().join("device");
        generate_key_file(&key_directory)?;
        let device_key_file = key_directory.join("device.key");
        let device_key = DeviceKeypair::load_private_file(&device_key_file)?;

        let control_port = PortReservation::acquire()?;
        let mut public_ports = Vec::with_capacity(tunnels.len());
        for tunnel in &tunnels {
            if let Some(port) = tunnel.remote_port {
                public_ports.push(RemoteEndpoint {
                    address: SocketAddr::new(LOOPBACK, port),
                    reservation: None,
                });
            } else {
                let reservation = UdpPortReservation::acquire()?;
                public_ports.push(RemoteEndpoint {
                    address: reservation.address,
                    reservation: Some(EndpointReservation::Udp(reservation)),
                });
            }
        }
        let server_config = directory.path().join("server.toml");
        let client_config = directory.path().join("client.toml");
        fs::write(
            &server_config,
            format!(
                "[server]\nbind_addr = \"{}\"\ncertificate_file = {}\nprivate_key_file = {}\nheartbeat_timeout_secs = 5\n\n[limits]\nmax_clients = 8\nmax_tunnels_per_client = {}\nmax_tcp_connections_per_tunnel = 1\nmax_udp_sessions_per_tunnel = {max_udp_sessions_per_tunnel}\nmax_udp_payload_bytes = {max_udp_payload_bytes}\n\n[[clients]]\nname = \"home-pc\"\npublic_key = \"{}\"\nenabled = true\n",
                control_port.address,
                toml_path(&certificate_file)?,
                toml_path(&private_key_file)?,
                tunnels.len(),
                device_key.public_key(),
            ),
        )?;
        let mut client_toml = format!(
            "[client]\nname = \"home-pc\"\nserver_addr = \"{}\"\nserver_name = \"{SERVER_NAME}\"\ncertificate_authority_file = {}\nprivate_key_file = {}\nheartbeat_interval_secs = 1\n",
            control_port.address,
            toml_path(&ca_file)?,
            toml_path(&device_key_file)?,
        );
        for (tunnel, public) in tunnels.iter().zip(&public_ports) {
            client_toml.push_str(&format!(
                "\n[[tunnels]]\nname = {}\nprotocol = \"udp\"\nlocal_addr = \"{}\"\nremote_port = {}\n",
                toml_basic_string(&tunnel.name),
                tunnel.local_address,
                public.address.port(),
            ));
        }
        fs::write(&client_config, client_toml)?;

        Ok(Self {
            _directory: directory,
            server_config,
            client_config,
            ca_file,
            control_port,
            public_ports,
            server_environment: Vec::new(),
            client_environment: Vec::new(),
        })
    }

    pub fn with_server_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.server_environment.push((name.into(), value.into()));
        self
    }

    pub fn with_client_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.client_environment.push((name.into(), value.into()));
        self
    }

    pub fn client_config_path(&self) -> &Path {
        &self.client_config
    }

    pub fn server_config_path(&self) -> &Path {
        &self.server_config
    }

    pub fn certificate_authority_path(&self) -> &Path {
        &self.ca_file
    }

    pub fn public_address(&self) -> SocketAddr {
        self.public_address_at(0)
    }

    pub fn public_address_at(&self, index: usize) -> SocketAddr {
        self.public_ports[index].address
    }

    pub fn control_address(&self) -> SocketAddr {
        self.control_port.address
    }

    pub fn start_server(&mut self) -> TestResult<ManagedChild> {
        self.control_port.release();
        let binaries = ensure_binaries()?;
        ManagedChild::spawn(
            "rustgos",
            &binaries.server,
            &self.server_config,
            &self.server_environment,
        )
    }

    pub fn start_client(&mut self) -> TestResult<ManagedChild> {
        for public in &mut self.public_ports {
            if let Some(mut reservation) = public.reservation.take() {
                reservation.release();
            }
        }
        let binaries = ensure_binaries()?;
        ManagedChild::spawn(
            "rustgoc",
            &binaries.client,
            &self.client_config,
            &self.client_environment,
        )
    }
}

pub struct ReservedPort {
    reservation: Option<PortReservation>,
    address: SocketAddr,
}

impl ReservedPort {
    pub fn acquire() -> TestResult<Self> {
        let reservation = PortReservation::acquire()?;
        Ok(Self {
            address: reservation.address,
            reservation: Some(reservation),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn release(&mut self) {
        if let Some(mut reservation) = self.reservation.take() {
            reservation.release();
        }
    }
}

fn toml_path(path: &Path) -> TestResult<String> {
    let value = path.to_str().ok_or("test path is not valid UTF-8")?;
    if value.contains('\'') {
        return Err("test path contains an unsupported apostrophe".into());
    }
    Ok(format!("'{value}'"))
}

fn toml_basic_string(value: &str) -> String {
    use std::fmt::Write as _;

    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for character in value.chars() {
        match character {
            '\u{0008}' => rendered.push_str("\\b"),
            '\t' => rendered.push_str("\\t"),
            '\n' => rendered.push_str("\\n"),
            '\u{000c}' => rendered.push_str("\\f"),
            '\r' => rendered.push_str("\\r"),
            '"' => rendered.push_str("\\\""),
            '\\' => rendered.push_str("\\\\"),
            character if character.is_control() && u32::from(character) <= 0xffff => {
                write!(&mut rendered, "\\u{:04X}", u32::from(character))
                    .expect("writing to a String cannot fail");
            }
            character if character.is_control() => {
                write!(&mut rendered, "\\U{:08X}", u32::from(character))
                    .expect("writing to a String cannot fail");
            }
            character => rendered.push(character),
        }
    }
    rendered.push('"');
    rendered
}

/// Files generated for script and process E2E only.
pub struct EphemeralPki {
    pub certificate_authority_file: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}

/// Generates an isolated CA plus a server leaf/key pair. The server file
/// contains the leaf followed by its CA so the production loader checks every
/// certificate in a non-empty chain.
pub fn generate_ephemeral_pki(directory: &Path, server_name: &str) -> TestResult<EphemeralPki> {
    fs::create_dir_all(directory)?;
    let certificate_authority_file = directory.join("ca.crt");
    let certificate_file = directory.join("server.crt");
    let private_key_file = directory.join("server.key");
    let (ca_pem, issuer) = certificate_authority()?;
    let (server_pem, server_key_pem) = server_certificate(server_name, &issuer)?;
    write_new(&certificate_authority_file, ca_pem.as_bytes())?;
    write_new(
        &certificate_file,
        format!("{server_pem}{ca_pem}").as_bytes(),
    )?;
    write_new(&private_key_file, server_key_pem.as_bytes())?;
    Ok(EphemeralPki {
        certificate_authority_file,
        certificate_file,
        private_key_file,
    })
}

fn write_new(path: &Path, contents: &[u8]) -> TestResult {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn certificate_authority() -> TestResult<(String, Issuer<'static, KeyPair>)> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Rustgo process e2e CA");
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate()?;
    let certificate = parameters.self_signed(&key)?;
    Ok((certificate.pem(), Issuer::new(parameters, key)))
}

fn server_certificate(
    server_name: &str,
    issuer: &Issuer<'static, KeyPair>,
) -> TestResult<(String, String)> {
    let mut parameters = CertificateParams::new(vec![server_name.to_owned()])?;
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, server_name);
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let certificate = parameters.signed_by(&key, issuer)?;
    Ok((certificate.pem(), key.serialize_pem()))
}

pub struct ManagedChild {
    name: &'static str,
    child: Child,
    lines: mpsc::Receiver<String>,
    captured: Arc<Mutex<Vec<u8>>>,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    readers: Vec<thread::JoinHandle<()>>,
}

impl ManagedChild {
    fn spawn(
        name: &'static str,
        binary: &Path,
        config: &Path,
        environment: &[(String, String)],
    ) -> TestResult<Self> {
        let mut child = Command::new(binary)
            .arg("-c")
            .arg(config)
            .env("RUST_LOG", "rustgos=debug,rustgoc=debug")
            .envs(environment.iter().map(|(name, value)| (name, value)))
            .current_dir(config.parent().expect("config has a parent"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("child stdout was not piped")?;
        let stderr = child.stderr.take().ok_or("child stderr was not piped")?;
        let (sender, lines) = mpsc::channel();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let stdout_captured = Arc::new(Mutex::new(Vec::new()));
        let stderr_captured = Arc::new(Mutex::new(Vec::new()));
        let readers = vec![
            spawn_log_reader(
                stdout,
                sender.clone(),
                captured.clone(),
                stdout_captured.clone(),
            ),
            spawn_log_reader(stderr, sender, captured.clone(), stderr_captured.clone()),
        ];
        Ok(Self {
            name,
            child,
            lines,
            captured,
            stdout: stdout_captured,
            stderr: stderr_captured,
            readers,
        })
    }

    pub fn wait_for_line(&mut self, needle: &str, timeout: Duration) -> TestResult<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Err(format!(
                    "{} exited with {status} before `{needle}`; output:\n{}",
                    self.name,
                    self.output()
                )
                .into());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "timed out waiting for `{needle}` from {}; output:\n{}",
                    self.name,
                    self.output()
                )
                .into());
            }
            match self
                .lines
                .recv_timeout((deadline - now).min(Duration::from_millis(100)))
            {
                Ok(line) if line.contains(needle) => return Ok(line),
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "{} closed its logs before `{needle}`; output:\n{}",
                        self.name,
                        self.output()
                    )
                    .into());
                }
            }
        }
    }

    pub fn output(&self) -> String {
        captured_output(&self.captured)
    }

    pub fn output_bytes(&self) -> Vec<u8> {
        captured_bytes(&self.captured)
    }

    pub fn stdout_output(&self) -> String {
        captured_output(&self.stdout)
    }

    pub fn stdout_bytes(&self) -> Vec<u8> {
        captured_bytes(&self.stdout)
    }

    pub fn stderr_output(&self) -> String {
        captured_output(&self.stderr)
    }

    pub fn stderr_bytes(&self) -> Vec<u8> {
        captured_bytes(&self.stderr)
    }

    pub fn wait_for_stderr_line(&mut self, needle: &str, timeout: Duration) -> TestResult<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(line) = self.stderr.lock().ok().and_then(|bytes| {
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .find(|line| line.contains(needle))
                    .map(str::to_owned)
            }) {
                return Ok(line);
            }
            if let Some(status) = self.child.try_wait()? {
                return Err(format!(
                    "{} exited with {status} before stderr contained `{needle}`; stderr:\n{}",
                    self.name,
                    self.stderr_output()
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for `{needle}` on {} stderr; stderr:\n{}",
                    self.name,
                    self.stderr_output()
                )
                .into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn terminate(&mut self) -> TestResult {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        let _ = self.child.wait()?;
        while let Some(reader) = self.readers.pop() {
            let _ = reader.join();
        }
        Ok(())
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        while let Some(reader) = self.readers.pop() {
            let _ = reader.join();
        }
    }
}

fn spawn_log_reader<R>(
    stream: R,
    sender: mpsc::Sender<String>,
    captured: Arc<Mutex<Vec<u8>>>,
    stream_captured: Arc<Mutex<Vec<u8>>>,
) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut stream = stream;
        let mut buffer = [0_u8; 4096];
        let mut pending_line = Vec::new();
        loop {
            let read = match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let bytes = &buffer[..read];
            if let Ok(mut output) = captured.lock() {
                output.extend_from_slice(bytes);
            }
            if let Ok(mut output) = stream_captured.lock() {
                output.extend_from_slice(bytes);
            }
            pending_line.extend_from_slice(bytes);
            while let Some(newline) = pending_line.iter().position(|byte| *byte == b'\n') {
                let mut raw_line: Vec<u8> = pending_line.drain(..=newline).collect();
                raw_line.pop();
                if raw_line.last() == Some(&b'\r') {
                    raw_line.pop();
                }
                let _ = sender.send(String::from_utf8_lossy(&raw_line).into_owned());
            }
        }
        if !pending_line.is_empty() {
            let _ = sender.send(String::from_utf8_lossy(&pending_line).into_owned());
        }
    })
}

fn captured_output(captured: &Arc<Mutex<Vec<u8>>>) -> String {
    captured
        .lock()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|_| "<poisoned log capture>".to_owned())
}

fn captured_bytes(captured: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    captured
        .lock()
        .map(|bytes| bytes.clone())
        .unwrap_or_default()
}

pub struct EchoServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

pub struct UdpEchoServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl UdpEchoServer {
    pub fn start() -> TestResult<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0))?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            let mut buffer = vec![0_u8; u16::MAX as usize];
            while !thread_shutdown.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((received, peer)) => {
                        let _ = socket.send_to(&buffer[..received], peer);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            shutdown,
            thread: Some(thread),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for UdpEchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Ok(wakeup) = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)) {
            let _ = wakeup.send_to(&[], self.address);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl EchoServer {
    pub fn start() -> TestResult<Self> {
        Self::start_with_delay(Duration::ZERO, 16 * 1024)
    }

    pub fn start_with_delay(delay: Duration, chunk_size: usize) -> TestResult<Self> {
        if chunk_size == 0 || chunk_size > 16 * 1024 {
            return Err("echo chunk size must be between 1 and 16384".into());
        }
        let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            let mut connections = Vec::new();
            while !thread_shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => connections.push(thread::spawn(move || {
                        if stream.set_nonblocking(false).is_err() {
                            return;
                        }
                        let mut buffer = vec![0_u8; chunk_size];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(read) => {
                                    if !delay.is_zero() {
                                        thread::sleep(delay);
                                    }
                                    if stream.write_all(&buffer[..read]).is_err() {
                                        break;
                                    }
                                }
                                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                                Err(_) => break,
                            }
                        }
                    })),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            drop(listener);
            for connection in connections {
                let _ = connection.join();
            }
        });
        Ok(Self {
            address,
            shutdown,
            thread: Some(thread),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

pub struct HalfCloseServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl HalfCloseServer {
    pub fn start(response: &'static [u8]) -> TestResult<Self> {
        let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            let mut connections = Vec::new();
            while !thread_shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => connections.push(thread::spawn(move || {
                        if stream.set_nonblocking(false).is_err() {
                            return;
                        }
                        let mut request = Vec::new();
                        if stream.read_to_end(&mut request).is_ok() && !request.is_empty() {
                            let _ = stream.write_all(response);
                            let _ = stream.shutdown(std::net::Shutdown::Write);
                        }
                    })),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            drop(listener);
            for connection in connections {
                let _ = connection.join();
            }
        });
        Ok(Self {
            address,
            shutdown,
            thread: Some(thread),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for HalfCloseServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsStr,
        io::Cursor,
        sync::{Arc, Mutex, mpsc},
    };

    use super::{BinaryProfile, captured_bytes, select_binary_profile, spawn_log_reader};

    #[test]
    fn release_entrypoint_selects_release_build_and_rejects_unknown_profiles() {
        assert_eq!(select_binary_profile(None).unwrap(), BinaryProfile::Debug);
        assert_eq!(
            select_binary_profile(Some(OsStr::new("release"))).unwrap(),
            BinaryProfile::Release
        );
        assert!(select_binary_profile(Some(OsStr::new("fast"))).is_err());
    }

    #[test]
    fn byte_capture_keeps_invalid_utf8_and_every_following_byte() {
        let expected = b"before\n\xffraw\nafter\n".to_vec();
        let (sender, receiver) = mpsc::channel();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let stream_captured = Arc::new(Mutex::new(Vec::new()));
        let reader = spawn_log_reader(
            Cursor::new(expected.clone()),
            sender,
            captured.clone(),
            stream_captured.clone(),
        );
        reader.join().expect("log reader must finish");

        assert_eq!(captured_bytes(&captured), expected);
        assert_eq!(captured_bytes(&stream_captured), expected);
        let lines: Vec<_> = receiver.into_iter().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "before");
        assert!(lines[1].ends_with("raw"));
        assert_eq!(lines[2], "after");
    }
}
