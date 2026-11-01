//! Process-level startup for the `conductor::server::run` entry point.
//!
//! These tests execute the real binary with a cleared environment, so a
//! regression that turns startup into a silent success (or loses the
//! fail-closed configuration gate) is visible to the test suite rather than
//! only in deployment.

use std::process::Command;

fn conductor() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_conductor"));
    // No inherited CONDUCTOR_* configuration can make these cases pass by
    // accident; the binary path is absolute, so PATH is unnecessary.
    command.env_clear();
    command
}

#[test]
fn missing_configuration_exits_non_zero() {
    let output = conductor().output().expect("binary must launch");
    assert!(
        !output.status.success(),
        "startup without a token or trusted key must fail, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing required configuration: api_token"),
        "startup must report the missing token: {stderr}"
    );
}

#[test]
fn unreadable_config_file_exits_non_zero() {
    let missing =
        std::env::temp_dir().join(format!("conductor-cli-missing-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&missing);

    let output = conductor()
        .arg("--config")
        .arg(&missing)
        .output()
        .expect("binary must launch");
    assert!(
        !output.status.success(),
        "an unreadable config file must abort startup, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("config file"),
        "startup must name the unreadable configuration: {stderr}"
    );
}
