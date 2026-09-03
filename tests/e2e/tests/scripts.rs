#![cfg(unix)]

use std::{path::PathBuf, process::Command};

#[test]
fn bash_cleanup_self_test_protects_reaped_pid_reuse_and_delete_failures() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap()
        .to_path_buf();
    let script = workspace.join("scripts/e2e.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("--self-test")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "cleanup self-test failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "e2e bash cleanup self-test passed"
    );
}
