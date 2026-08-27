use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

use assert_cmd::Command;
use rustgo_crypto::{AuthTranscript, DeviceKeypair, DevicePublicKey, sign_auth, verify_auth};

static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustgoc-keygen-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn command() -> Command {
    Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap()
}

fn run_keygen(output_dir: &Path) -> std::process::Output {
    command()
        .args(["keygen", "-o", output_dir.to_str().unwrap()])
        .output()
        .unwrap()
}

#[test]
fn keygen_creates_a_loadable_private_key_and_matching_public_key() {
    let temp = TempDir::new();
    let output_dir = temp.path.join("new-keys");

    let output = run_keygen(&output_dir);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let private_path = output_dir.join("device.key");
    let public_path = output_dir.join("device.pub");
    let private_encoding = fs::read_to_string(&private_path).unwrap();
    let public_key =
        DevicePublicKey::from_str(fs::read_to_string(public_path).unwrap().trim()).unwrap();
    let keypair = DeviceKeypair::load_private_file(&private_path).unwrap();
    let transcript = AuthTranscript::new(vec![1, 2, 3], vec![4, 5], 1, "generated".into());
    let signature = sign_auth(&keypair, &transcript);

    assert!(private_encoding.starts_with("rustgo-ed25519-private-v1:"));
    assert_eq!(keypair.public_key(), public_key);
    assert!(verify_auth(&public_key, &transcript, &signature).is_ok());

    let process_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!process_text.contains(private_encoding.trim()));
    assert!(
        !process_text.contains(
            private_encoding
                .trim_start_matches("rustgo-ed25519-private-v1:")
                .trim()
        )
    );
}

#[test]
fn keygen_refuses_to_overwrite_either_destination() {
    for existing_name in ["device.key", "device.pub"] {
        let temp = TempDir::new();
        let output_dir = temp.path.join(existing_name.replace('.', "-"));
        fs::create_dir_all(&output_dir).unwrap();
        let existing_path = output_dir.join(existing_name);
        fs::write(&existing_path, b"owned-by-user").unwrap();

        let output = run_keygen(&output_dir);

        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("Use -c"));
        assert_eq!(fs::read(&existing_path).unwrap(), b"owned-by-user");
        let other_name = if existing_name == "device.key" {
            "device.pub"
        } else {
            "device.key"
        };
        assert!(!output_dir.join(other_name).exists());
    }
}

#[test]
fn repeated_keygen_preserves_the_original_pair() {
    let temp = TempDir::new();
    let output_dir = temp.path.join("keys");
    assert!(run_keygen(&output_dir).status.success());
    let private_path = output_dir.join("device.key");
    let public_path = output_dir.join("device.pub");
    let original_private = fs::read(&private_path).unwrap();
    let original_public = fs::read(&public_path).unwrap();

    let second = run_keygen(&output_dir);

    assert!(!second.status.success());
    assert_eq!(fs::read(private_path).unwrap(), original_private);
    assert_eq!(fs::read(public_path).unwrap(), original_public);
}

#[cfg(unix)]
#[test]
fn generated_private_key_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let output_dir = temp.path.join("keys");
    assert!(run_keygen(&output_dir).status.success());

    let mode = fs::metadata(output_dir.join("device.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
