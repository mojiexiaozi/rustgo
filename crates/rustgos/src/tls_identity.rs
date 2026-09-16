use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use rcgen::{CertificateParams, KeyPair};
use rustgo_config::ServerConfig;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProvisioning {
    Existing,
    Generated,
}

#[derive(Debug, Error)]
pub enum ServerIdentityError {
    #[error("TLS certificate and private key must either both exist or both be absent")]
    IncompleteIdentity,
    #[error("cannot prepare TLS identity path {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot generate TLS identity: {0}")]
    Generate(#[from] rcgen::Error),
}

pub fn ensure_server_identity(
    config: &ServerConfig,
) -> Result<IdentityProvisioning, ServerIdentityError> {
    let lock_directory = config
        .server
        .private_key_file
        .parent()
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(lock_directory).map_err(|source| io_error(lock_directory, source))?;
    let lock_path = lock_directory.join(".rustgo-server-identity.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| io_error(&lock_path, source))?;
    lock.lock().map_err(|source| io_error(&lock_path, source))?;

    let pending_path = lock_directory.join(".rustgo-server-identity.pending");
    if recover_pending(
        &pending_path,
        &config.server.certificate_file,
        &config.server.private_key_file,
    )? {
        return Ok(IdentityProvisioning::Generated);
    }

    match (
        path_exists(&config.server.certificate_file)?,
        path_exists(&config.server.private_key_file)?,
    ) {
        (true, true) => return Ok(IdentityProvisioning::Existing),
        (true, false) | (false, true) => return Err(ServerIdentityError::IncompleteIdentity),
        (false, false) => {}
    }

    let key = KeyPair::generate()?;
    let certificate = CertificateParams::new(certificate_names(config))?.self_signed(&key)?;
    let private_key = key.serialize_pem();
    let certificate = certificate.pem();
    let pending = format!(
        "{}\n{}\n",
        digest(private_key.as_bytes()),
        digest(certificate.as_bytes())
    );
    persist_new(&pending_path, pending.as_bytes(), false)?;
    persist_new(
        &config.server.private_key_file,
        private_key.as_bytes(),
        true,
    )?;
    persist_new(
        &config.server.certificate_file,
        certificate.as_bytes(),
        false,
    )?;
    fs::remove_file(&pending_path).map_err(|source| io_error(&pending_path, source))?;
    sync_directory(lock_directory)?;
    Ok(IdentityProvisioning::Generated)
}

fn recover_pending(
    pending_path: &Path,
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<bool, ServerIdentityError> {
    let pending = match fs::read_to_string(pending_path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error(pending_path, source)),
    };
    let mut hashes = pending.lines();
    let Some(private_hash) = hashes.next() else {
        return Err(ServerIdentityError::IncompleteIdentity);
    };
    let Some(certificate_hash) = hashes.next() else {
        return Err(ServerIdentityError::IncompleteIdentity);
    };
    if hashes.next().is_some() {
        return Err(ServerIdentityError::IncompleteIdentity);
    }
    let private_exists = generated_file_matches(private_key_path, private_hash)?;
    let certificate_exists = generated_file_matches(certificate_path, certificate_hash)?;
    if private_exists && certificate_exists {
        fs::remove_file(pending_path).map_err(|source| io_error(pending_path, source))?;
        sync_directory(pending_path.parent().unwrap_or_else(|| Path::new(".")))?;
        return Ok(true);
    }
    if private_exists {
        fs::remove_file(private_key_path).map_err(|source| io_error(private_key_path, source))?;
    }
    if certificate_exists {
        fs::remove_file(certificate_path).map_err(|source| io_error(certificate_path, source))?;
    }
    fs::remove_file(pending_path).map_err(|source| io_error(pending_path, source))?;
    sync_directory(pending_path.parent().unwrap_or_else(|| Path::new(".")))?;
    Ok(false)
}

fn generated_file_matches(path: &Path, expected_hash: &str) -> Result<bool, ServerIdentityError> {
    match fs::read(path) {
        Ok(contents) if digest(&contents) == expected_hash => Ok(true),
        Ok(_) => Err(ServerIdentityError::IncompleteIdentity),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn digest(contents: &[u8]) -> String {
    Sha256::digest(contents)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn path_exists(path: &Path) -> Result<bool, ServerIdentityError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn persist_new(path: &Path, contents: &[u8], private: bool) -> Result<(), ServerIdentityError> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory).map_err(|source| io_error(directory, source))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".rustgo-tls-")
        .suffix(".tmp")
        .tempfile_in(directory)
        .map_err(|source| io_error(path, source))?;
    if private {
        set_private_permissions(temporary.as_file(), temporary.path(), path)?;
    }
    temporary
        .write_all(contents)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| io_error(path, source))?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| io_error(path, error.error))?;
    sync_directory(directory)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(
    file: &File,
    _temporary: &Path,
    path: &Path,
) -> Result<(), ServerIdentityError> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error(path, source))
}

#[cfg(windows)]
fn set_private_permissions(
    _file: &File,
    temporary: &Path,
    path: &Path,
) -> Result<(), ServerIdentityError> {
    use std::process::Command;

    let system32 = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("System32"))
        .ok_or_else(|| io_error(path, io::Error::other("SystemRoot is unavailable")))?;
    let output = Command::new(system32.join("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|source| io_error(path, source))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let sid = text
        .split(',')
        .nth(1)
        .map(|value| value.trim().trim_matches('"'))
        .filter(|value| value.starts_with("S-1-"))
        .ok_or_else(|| {
            io_error(
                path,
                io::Error::other("cannot determine current Windows SID"),
            )
        })?;
    let grant = format!("*{sid}:(F)");
    let output = Command::new(system32.join("icacls.exe"))
        .arg(temporary)
        .args(["/inheritance:r", "/grant:r", &grant])
        .output()
        .map_err(|source| io_error(path, source))?;
    if !output.status.success() {
        return Err(io_error(
            path,
            io::Error::other("cannot restrict private key ACL"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), ServerIdentityError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|source| io_error(directory, source))
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), ServerIdentityError> {
    Ok(())
}

fn certificate_names(config: &ServerConfig) -> Vec<String> {
    let mut names = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ];
    if let Some(name) = &config.server.tls_server_name {
        names.push(name.clone());
    }
    if let Ok(address) = config.server.bind_addr.parse::<SocketAddr>()
        && !address.ip().is_unspecified()
    {
        names.push(address.ip().to_string());
    }
    if let Some(enrollment) = config.enrollment.as_ref().filter(|value| value.enabled)
        && let Some(host) = address_host(&enrollment.public_addr)
    {
        names.push(host);
    }
    names.sort();
    names.dedup();
    names
}

fn address_host(address: &str) -> Option<String> {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return Some(socket.ip().to_string());
    }
    address
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']).to_owned())
        .filter(|host| !host.is_empty())
}

fn io_error(path: &Path, source: io::Error) -> ServerIdentityError {
    ServerIdentityError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustgo_config::{Limits, ServerSection};

    fn config(directory: &Path) -> ServerConfig {
        ServerConfig {
            server: ServerSection {
                bind_addr: "127.0.0.1:7443".into(),
                tls_server_name: Some("relay.example.test".into()),
                udp_bind_ip: None,
                p2p_observation_bind: None,
                p2p_observation_alternate_bind: None,
                certificate_file: directory.join("server.crt"),
                private_key_file: directory.join("server.key"),
                heartbeat_timeout_secs: 60,
            },
            limits: Limits {
                max_clients: 8,
                max_tunnels_per_client: 8,
                max_tcp_connections_per_tunnel: 8,
                max_udp_sessions_per_tunnel: 8,
                max_udp_payload_bytes: 65_507,
            },
            clients: Vec::new(),
            web: None,
            enrollment: None,
            managed_tunnels: None,
        }
    }

    #[test]
    fn missing_pair_is_generated_and_reused() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        assert_eq!(
            ensure_server_identity(&config).unwrap(),
            IdentityProvisioning::Generated
        );
        rustgo_transport::TlsServer::validate_identity(
            &config.server.certificate_file,
            &config.server.private_key_file,
        )
        .unwrap();
        let certificate = fs::read(&config.server.certificate_file).unwrap();
        let private_key = fs::read(&config.server.private_key_file).unwrap();
        assert_eq!(
            ensure_server_identity(&config).unwrap(),
            IdentityProvisioning::Existing
        );
        assert_eq!(
            certificate,
            fs::read(&config.server.certificate_file).unwrap()
        );
        assert_eq!(
            private_key,
            fs::read(&config.server.private_key_file).unwrap()
        );
    }

    #[test]
    fn half_existing_identity_is_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        fs::write(&config.server.private_key_file, b"existing-secret").unwrap();
        assert!(matches!(
            ensure_server_identity(&config),
            Err(ServerIdentityError::IncompleteIdentity)
        ));
        assert_eq!(
            fs::read(&config.server.private_key_file).unwrap(),
            b"existing-secret"
        );
        assert!(!config.server.certificate_file.exists());
    }

    #[test]
    fn interrupted_generation_recovers_only_its_matching_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let private_key = b"generated-partial-key";
        let certificate = b"generated-partial-certificate";
        fs::write(&config.server.private_key_file, private_key).unwrap();
        fs::write(
            directory.path().join(".rustgo-server-identity.pending"),
            format!("{}\n{}\n", digest(private_key), digest(certificate)),
        )
        .unwrap();

        assert_eq!(
            ensure_server_identity(&config).unwrap(),
            IdentityProvisioning::Generated
        );
        rustgo_transport::TlsServer::validate_identity(
            &config.server.certificate_file,
            &config.server.private_key_file,
        )
        .unwrap();
        assert!(
            !directory
                .path()
                .join(".rustgo-server-identity.pending")
                .exists()
        );
    }

    #[test]
    fn completed_pending_generation_is_preserved_and_reported_as_generated() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        assert_eq!(
            ensure_server_identity(&config).unwrap(),
            IdentityProvisioning::Generated
        );
        let private_key = fs::read(&config.server.private_key_file).unwrap();
        let certificate = fs::read(&config.server.certificate_file).unwrap();
        fs::write(
            directory.path().join(".rustgo-server-identity.pending"),
            format!("{}\n{}\n", digest(&private_key), digest(&certificate)),
        )
        .unwrap();

        assert_eq!(
            ensure_server_identity(&config).unwrap(),
            IdentityProvisioning::Generated
        );
        assert_eq!(
            private_key,
            fs::read(&config.server.private_key_file).unwrap()
        );
        assert_eq!(
            certificate,
            fs::read(&config.server.certificate_file).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_private_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        ensure_server_identity(&config).unwrap();
        assert_eq!(
            fs::metadata(&config.server.private_key_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn configured_tls_name_passes_standard_ca_verification() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        ensure_server_identity(&config).unwrap();
        let server = std::sync::Arc::new(
            rustgo_transport::TlsServer::bind(
                "127.0.0.1:0",
                &config.server.certificate_file,
                &config.server.private_key_file,
            )
            .await
            .unwrap(),
        );
        let address = server.local_addr().unwrap();
        let acceptor = server.clone();
        let accepted = tokio::spawn(async move {
            let (socket, _) = acceptor.accept_tcp().await.unwrap();
            acceptor.handshake(socket).await.unwrap()
        });
        let client = rustgo_transport::TlsClient::from_ca_file(
            &config.server.certificate_file,
            "relay.example.test",
        )
        .unwrap();
        let connection = client.connect(address).await.unwrap();
        drop(connection);
        accepted.await.unwrap();
    }

    #[test]
    fn concurrent_generation_has_one_writer_and_one_reuser() {
        let directory = tempfile::tempdir().unwrap();
        let config = std::sync::Arc::new(config(directory.path()));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let config = config.clone();
                std::thread::spawn(move || ensure_server_identity(&config).unwrap())
            })
            .collect();
        let outcomes: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|&&value| value == IdentityProvisioning::Generated)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|&&value| value == IdentityProvisioning::Existing)
                .count(),
            1
        );
    }
}
