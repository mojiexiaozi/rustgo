#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
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
        let status = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(&root)
            .args([
                "build", "--quiet", "-p", "rustgos", "-p", "rustgoc", "--bins",
            ])
            .status()
            .map_err(|error| format!("could not launch cargo build: {error}"))?;
        if !status.success() {
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
                .join("debug")
                .join(format!("rustgos{executable_suffix}")),
            client: target
                .join("debug")
                .join(format!("rustgoc{executable_suffix}")),
        })
    });

    result
        .as_ref()
        .cloned()
        .map_err(|message| message.clone().into())
}

struct PortReservation {
    listener: Option<TcpListener>,
    address: SocketAddr,
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
    control_port: PortReservation,
    public_ports: Vec<RemoteEndpoint>,
}

struct RemoteEndpoint {
    address: SocketAddr,
    reservation: Option<PortReservation>,
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
        let ca_file = directory.path().join("ca.pem");
        let certificate_file = directory.path().join("server.pem");
        let private_key_file = directory.path().join("server.key");
        let (ca_pem, issuer) = certificate_authority()?;
        let (server_pem, server_key_pem) = server_certificate(&issuer)?;
        fs::write(&ca_file, ca_pem)?;
        fs::write(&certificate_file, server_pem)?;
        fs::write(&private_key_file, server_key_pem)?;

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
                    reservation: Some(reservation),
                });
            }
        }
        let server_config = directory.path().join("server.toml");
        let client_config = directory.path().join("client.toml");
        fs::write(
            &server_config,
            format!(
                "[server]\nbind_addr = \"{}\"\ncertificate_file = {}\nprivate_key_file = {}\nheartbeat_timeout_secs = 5\n\n[limits]\nmax_clients = 8\nmax_tunnels_per_client = 8\nmax_tcp_connections_per_tunnel = {max_tcp_connections_per_tunnel}\nmax_udp_sessions_per_tunnel = 8\nmax_udp_payload_bytes = 65507\n\n[[clients]]\nname = \"home-pc\"\npublic_key = \"{}\"\nenabled = true\n",
                control_port.address,
                toml_path(&certificate_file)?,
                toml_path(&private_key_file)?,
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
                "\n[[tunnels]]\nname = \"{}\"\nprotocol = \"tcp\"\nlocal_addr = \"{}\"\nremote_port = {}\n",
                tunnel.name,
                tunnel.local_address,
                public.address.port(),
            ));
        }
        fs::write(&client_config, client_toml)?;

        Ok(Self {
            _directory: directory,
            server_config,
            client_config,
            control_port,
            public_ports,
        })
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
        ManagedChild::spawn("rustgos", &binaries.server, &self.server_config)
    }

    pub fn start_client(&mut self) -> TestResult<ManagedChild> {
        for public in &mut self.public_ports {
            if let Some(mut reservation) = public.reservation.take() {
                reservation.release();
            }
        }
        let binaries = ensure_binaries()?;
        ManagedChild::spawn("rustgoc", &binaries.client, &self.client_config)
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

fn server_certificate(issuer: &Issuer<'static, KeyPair>) -> TestResult<(String, String)> {
    let mut parameters = CertificateParams::new(vec![SERVER_NAME.to_owned()])?;
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, SERVER_NAME);
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
    captured: Arc<Mutex<Vec<String>>>,
    readers: Vec<thread::JoinHandle<()>>,
}

impl ManagedChild {
    fn spawn(name: &'static str, binary: &Path, config: &Path) -> TestResult<Self> {
        let mut child = Command::new(binary)
            .arg("-c")
            .arg(config)
            .env("RUST_LOG", "rustgos=debug,rustgoc=debug")
            .current_dir(config.parent().expect("config has a parent"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("child stdout was not piped")?;
        let stderr = child.stderr.take().ok_or("child stderr was not piped")?;
        let (sender, lines) = mpsc::channel();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let readers = vec![
            spawn_log_reader(stdout, sender.clone(), captured.clone()),
            spawn_log_reader(stderr, sender, captured.clone()),
        ];
        Ok(Self {
            name,
            child,
            lines,
            captured,
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
        self.captured
            .lock()
            .map(|lines| lines.join("\n"))
            .unwrap_or_else(|_| "<poisoned log capture>".to_owned())
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
    captured: Arc<Mutex<Vec<String>>>,
) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            if let Ok(mut output) = captured.lock() {
                output.push(line.clone());
            }
            let _ = sender.send(line);
        }
    })
}

pub struct EchoServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
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
