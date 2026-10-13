//! Worker execution end to end through the public API: a signed, validated
//! package is staged, resolved into a target, spawned as a child process,
//! driven over the stdin/stdout protocol, and terminated.
//!
//! Unix-gated: the fixtures are `#!/bin/sh` entrypoints, and timeout,
//! cancellation, and descendant termination rely on process groups, which
//! the executor only controls on Unix.

#![cfg(unix)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use conductor::control_plane::validate_package::{PackageValidationBuilder, PackageValidator};
use conductor::executions::executor::{
    ExecutionError, ExecutionLimits, ExecutionOutcome, TargetError, WorkerExecutor, WorkerTarget,
};
use conductor::executions::protocol::{ExecutionRequest, Invocation};
use conductor::packages::archive::QuarantinedFile;
use conductor::packages::digest::Sha256DigestProvider;
use conductor::packages::policy::PackageValidationPolicy;
use conductor::packages::signature::{
    canonical_payload, ConfiguredTrustedKeys, PackageSignature, SignatureAlgorithm,
    TrustedSigningKey, SUPPORTED_SIGNATURE_FORMAT_VERSION,
};
use conductor::storage::staging::{extract_verified, StagedPackage};

/// Test-only signing key. Precedent: unit tests sign with fixed keys; this
/// private key must never sign anything outside these tests.
const TEST_SIGNING_KEY: [u8; 32] = [42u8; 32];

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Process-unique scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let count = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "conductor-execution-{}-{tag}-{count}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir must be creatable");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn validator() -> (PackageValidator, ed25519_dalek::SigningKey) {
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
    let keys = ConfiguredTrustedKeys::new(vec![TrustedSigningKey::new(
        "k1",
        SignatureAlgorithm::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )])
    .expect("distinct test keys must build");
    let validator = PackageValidationBuilder::new(PackageValidationPolicy::production())
        .trusted_keys(keys)
        .build()
        .expect("test validator must build");
    (validator, signing)
}

/// Builds, signs, validates, and extracts a package whose entrypoint is
/// `script`.
fn staged_script(scratch: &Scratch, script: &str) -> StagedPackage {
    use ed25519_dalek::Signer as _;

    let (validator, signing) = validator();
    let manifest = serde_json::json!({
        "manifest_version": 1,
        "module_id": "worker-fixture",
        "version": "1.0.0",
        "runtime": "rust",
        "entrypoint": "payload/worker",
        "files": ["payload/worker"],
    });
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("manifest.json", options)
        .expect("manifest entry must be writable");
    writer
        .write_all(&serde_json::to_vec(&manifest).expect("manifest must serialize"))
        .expect("manifest bytes must be writable");
    writer
        .start_file("payload/worker", options)
        .expect("payload entry must be writable");
    writer
        .write_all(script.as_bytes())
        .expect("payload bytes must be writable");
    writer.finish().expect("zip must finalize");
    let bytes = cursor.into_inner();

    let digest: [u8; 32] = Sha256DigestProvider
        .digest(&bytes)
        .expect("hashing must succeed");
    let envelope = PackageSignature {
        format_version: SUPPORTED_SIGNATURE_FORMAT_VERSION,
        key_id: "k1".to_owned(),
        signature: signing
            .sign(&canonical_payload(&digest))
            .to_bytes()
            .to_vec(),
    };
    let archive = scratch.file("pkg.zip");
    std::fs::write(&archive, &bytes).expect("package must be writable");
    let mut handle = QuarantinedFile::open(&archive).expect("quarantine must open");
    let validated = validator
        .validate(&mut handle, &envelope)
        .expect("package must validate");
    extract_verified(
        scratch.path(),
        &archive,
        &validated,
        &PackageValidationPolicy::production(),
    )
    .expect("extraction must succeed")
}

fn resolved_target(scratch: &Scratch, script: &str) -> WorkerTarget {
    WorkerTarget::resolve(staged_script(scratch, script), "payload/worker").expect("resolve")
}

fn request(deadline: Duration) -> ExecutionRequest {
    ExecutionRequest::new(
        Invocation {
            execution_id: "exec-1".to_owned(),
            module_id: "worker-fixture".to_owned(),
            version: "1.0.0".to_owned(),
            digest_hex: "ab".repeat(32),
            function: "run".to_owned(),
        },
        serde_json::json!({"batch": 7}),
        deadline,
    )
}

fn tick_count(path: &Path) -> usize {
    std::fs::read(path)
        .map(|bytes| bytes.iter().filter(|byte| **byte == b'\n').count())
        .unwrap_or(0)
}

/// Host process identity as reported by `id <flag>`.
fn host_id(flag: &str) -> String {
    let output = std::process::Command::new("id")
        .arg(flag)
        .output()
        .expect("host `id` must run");
    assert!(output.status.success(), "host `id {flag}` must succeed");
    String::from_utf8(output.stdout)
        .expect("`id` output must be UTF-8")
        .trim()
        .to_owned()
}

fn parse_groups(line: &str) -> Vec<u32> {
    let mut groups: Vec<u32> = line
        .split_whitespace()
        .map(|group| group.parse().expect("group id must be numeric"))
        .collect();
    groups.sort_unstable();
    groups.dedup();
    groups
}

const SCRIPT_ROUND_TRIP: &str = r#"#!/bin/sh
read -r line
printf '%s' "$line" > "$CAPTURE_FILE"
printf '{"protocol_version":1,"status":"ok","result":{"rows":3}}\n'
"#;

#[tokio::test]
async fn validated_artifact_runs_and_the_request_reaches_the_worker() {
    let scratch = Scratch::new("round-trip");
    let capture = scratch.file("request.jsonl");
    let target = resolved_target(&scratch, SCRIPT_ROUND_TRIP).with_env(vec![(
        "CAPTURE_FILE".to_owned(),
        capture.display().to_string(),
    )]);
    let sent = request(Duration::from_secs(10));
    let report = WorkerExecutor::new(ExecutionLimits::default())
        .execute(&target, sent.clone())
        .await
        .expect("host side must succeed");
    assert_eq!(
        report.outcome,
        ExecutionOutcome::Succeeded {
            result: serde_json::json!({"rows": 3}),
        }
    );
    assert_eq!(report.execution_id, "exec-1");
    assert!(report.duration > Duration::ZERO);
    let captured = std::fs::read_to_string(&capture).expect("request must be captured");
    let received: ExecutionRequest =
        serde_json::from_str(&captured).expect("captured line must decode");
    assert_eq!(received, sent, "worker must receive the exact request line");
}

const SCRIPT_PROBE: &str = r#"#!/bin/sh
read -r line
env | sort > "$ENV_FILE"
printf 'diagnostic: start\n' >&2
printf '{"protocol_version":1,"status":"ok","result":null}\n'
"#;

#[tokio::test]
async fn secrets_stay_on_stdin_and_the_environment_is_restricted() {
    let scratch = Scratch::new("environment");
    let env_file = scratch.file("env.txt");
    let target = resolved_target(&scratch, SCRIPT_PROBE).with_env(vec![(
        "ENV_FILE".to_owned(),
        env_file.display().to_string(),
    )]);
    let sent = request(Duration::from_secs(10)).with_secrets(std::collections::BTreeMap::from([(
        "db_password".to_owned(),
        "hunter2".to_owned(),
    )]));
    let report = WorkerExecutor::new(ExecutionLimits::default())
        .execute(&target, sent)
        .await
        .expect("host side must succeed");
    assert!(matches!(report.outcome, ExecutionOutcome::Succeeded { .. }));
    assert!(report.stderr.text_lossy().contains("diagnostic: start"));

    let env_dump = std::fs::read_to_string(&env_file).expect("environment must be captured");
    assert!(env_dump.contains(&format!("ENV_FILE={}", env_file.display())));
    for leaked in ["PATH=", "HOME=", "hunter2"] {
        assert!(
            !env_dump.contains(leaked),
            "environment must not carry {leaked}: {env_dump}"
        );
    }
}

const SCRIPT_IDENTITY: &str = r#"#!/bin/sh
read -r line
{
  id -u
  id -g
  id -G
} > "$IDENTITY_FILE"
printf '{"protocol_version":1,"status":"ok","result":null}\n'
"#;

/// Workers run as the host: the executor must never change `uid`, `gid`, or
/// supplementary groups.
#[tokio::test]
async fn workers_run_with_the_host_identity() {
    let scratch = Scratch::new("identity");
    let identity_file = scratch.file("identity.txt");
    let target = resolved_target(&scratch, SCRIPT_IDENTITY).with_env(vec![(
        "IDENTITY_FILE".to_owned(),
        identity_file.display().to_string(),
    )]);
    let report = WorkerExecutor::new(ExecutionLimits::default())
        .execute(&target, request(Duration::from_secs(10)))
        .await
        .expect("host side must succeed");
    assert!(matches!(report.outcome, ExecutionOutcome::Succeeded { .. }));

    let captured = std::fs::read_to_string(&identity_file).expect("identity must be captured");
    let mut lines = captured.lines();
    let worker_uid = lines.next().expect("uid line");
    let worker_gid = lines.next().expect("gid line");
    let worker_groups = lines.next().expect("groups line");
    assert_eq!(worker_uid, host_id("-u"), "worker uid must match the host");
    assert_eq!(worker_gid, host_id("-g"), "worker gid must match the host");
    assert_eq!(
        parse_groups(worker_groups),
        parse_groups(&host_id("-G")),
        "worker supplementary groups must match the host"
    );
}

const SCRIPT_FAILED: &str = r#"#!/bin/sh
read -r line
printf '{"protocol_version":1,"status":"failed","message":"bad input"}\n'
"#;

#[tokio::test]
async fn worker_failure_is_reported_with_its_message() {
    let scratch = Scratch::new("failed");
    let target = resolved_target(&scratch, SCRIPT_FAILED);
    let report = WorkerExecutor::new(ExecutionLimits::default())
        .execute(&target, request(Duration::from_secs(10)))
        .await
        .expect("host side must succeed");
    assert_eq!(
        report.outcome,
        ExecutionOutcome::Failed {
            message: "bad input".to_owned(),
        }
    );
}

const SCRIPT_TICKS: &str = r#"#!/bin/sh
( while :; do echo tick >> "$TICKS"; sleep 0.2; done ) &
sleep 60
"#;

#[tokio::test]
async fn deadline_terminates_the_worker_group_including_descendants() {
    let scratch = Scratch::new("deadline");
    let ticks = scratch.file("ticks");
    let target = resolved_target(&scratch, SCRIPT_TICKS)
        .with_env(vec![("TICKS".to_owned(), ticks.display().to_string())]);
    let limits = ExecutionLimits {
        terminate_grace: Duration::from_millis(200),
        ..ExecutionLimits::default()
    };
    let started = Instant::now();
    let report = WorkerExecutor::new(limits)
        .execute(&target, request(Duration::from_millis(300)))
        .await
        .expect("host side must succeed");
    assert!(matches!(report.outcome, ExecutionOutcome::TimedOut { .. }));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "timeout teardown must be prompt"
    );

    // The ticker is a descendant in the worker's process group: if the
    // group was terminated, it writes nothing more.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = tick_count(&ticks);
    assert!(before > 0, "the ticker must have run before termination");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let after = tick_count(&ticks);
    assert_eq!(
        before, after,
        "descendants must be terminated with the worker"
    );
}

#[tokio::test]
async fn cancellation_terminates_the_worker() {
    let scratch = Scratch::new("cancel");
    let target = resolved_target(&scratch, "#!/bin/sh\nsleep 60\n");
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = sender.send("operator requested stop".to_owned());
    });
    let limits = ExecutionLimits {
        terminate_grace: Duration::from_millis(200),
        ..ExecutionLimits::default()
    };
    let started = Instant::now();
    let report = WorkerExecutor::new(limits)
        .execute_cancellable(&target, request(Duration::from_secs(60)), Some(receiver))
        .await
        .expect("host side must succeed");
    match report.outcome {
        ExecutionOutcome::Cancelled { reason } => {
            assert!(reason.contains("operator requested stop"));
        }
        other => panic!("expected cancellation, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn early_exit_is_a_worker_error_with_the_exit_status() {
    let scratch = Scratch::new("early-exit");
    let target = resolved_target(&scratch, "#!/bin/sh\nexit 7\n");
    let report = WorkerExecutor::new(ExecutionLimits::default())
        .execute(&target, request(Duration::from_secs(10)))
        .await
        .expect("host side must succeed");
    match report.outcome {
        ExecutionOutcome::WorkerError { detail } => {
            assert!(detail.contains("exit code 7"), "detail: {detail}");
        }
        other => panic!("expected worker error, got {other:?}"),
    }
}

const SCRIPT_OVERSIZE: &str = r#"#!/bin/sh
read -r line
i=0
while [ "$i" -lt 2000 ]; do
  printf 'aaaaaaaa'
  i=$((i + 1))
done
printf '\n'
"#;

#[tokio::test]
async fn oversized_response_is_a_protocol_violation() {
    let scratch = Scratch::new("oversize");
    let target = resolved_target(&scratch, SCRIPT_OVERSIZE);
    let limits = ExecutionLimits {
        max_message_bytes: 1024,
        terminate_grace: Duration::from_millis(200),
        ..ExecutionLimits::default()
    };
    let report = WorkerExecutor::new(limits)
        .execute(&target, request(Duration::from_secs(10)))
        .await
        .expect("host side must succeed");
    assert!(matches!(
        report.outcome,
        ExecutionOutcome::ProtocolViolation { .. }
    ));
}

#[tokio::test]
async fn malformed_response_is_a_protocol_violation() {
    let scratch = Scratch::new("malformed");
    let target = resolved_target(&scratch, "#!/bin/sh\nread -r line\nprintf 'not-json\\n'\n");
    let report = WorkerExecutor::new(ExecutionLimits::default())
        .execute(&target, request(Duration::from_secs(10)))
        .await
        .expect("host side must succeed");
    match report.outcome {
        ExecutionOutcome::ProtocolViolation { detail } => {
            assert!(detail.contains("malformed response"), "detail: {detail}");
        }
        other => panic!("expected protocol violation, got {other:?}"),
    }
}

const SCRIPT_NOISY: &str = r#"#!/bin/sh
read -r line
i=0
while [ "$i" -lt 4000 ]; do
  printf 'e' >&2
  i=$((i + 1))
done
printf '{"protocol_version":1,"status":"ok","result":null}\n'
"#;

#[tokio::test]
async fn stderr_is_captured_bounded_and_separate_from_the_protocol() {
    let scratch = Scratch::new("noisy");
    let target = resolved_target(&scratch, SCRIPT_NOISY);
    let limits = ExecutionLimits {
        max_stderr_bytes: 100,
        ..ExecutionLimits::default()
    };
    let report = WorkerExecutor::new(limits)
        .execute(&target, request(Duration::from_secs(10)))
        .await
        .expect("host side must succeed");
    assert!(matches!(report.outcome, ExecutionOutcome::Succeeded { .. }));
    assert!(report.stderr.truncated());
    assert_eq!(report.stderr.bytes().len(), 100);
    assert_eq!(report.stderr.total_bytes(), 4000);
}

#[tokio::test]
async fn oversized_request_is_rejected_before_spawn() {
    let scratch = Scratch::new("request-bound");
    let target = resolved_target(&scratch, "#!/bin/sh\nexit 0\n");
    let limits = ExecutionLimits {
        max_message_bytes: 64,
        ..ExecutionLimits::default()
    };
    let err = WorkerExecutor::new(limits)
        .execute(&target, request(Duration::from_secs(10)))
        .await
        .expect_err("oversized request must not spawn");
    assert!(matches!(err, ExecutionError::InvalidRequest(_)));
}

#[test]
fn tampered_staged_payload_is_refused_at_resolve() {
    let scratch = Scratch::new("tamper");
    let staged = staged_script(&scratch, "#!/bin/sh\nexit 0\n");
    std::fs::write(staged.root().join("payload/worker"), "#!/bin/sh\nexit 1\n")
        .expect("tamper must be writable");
    assert!(matches!(
        WorkerTarget::resolve(staged, "payload/worker"),
        Err(TargetError::StagedFileChanged { .. })
    ));
}

#[test]
fn entrypoint_path_escape_is_refused() {
    let scratch = Scratch::new("escape");
    let staged = staged_script(&scratch, "#!/bin/sh\nexit 0\n");
    assert!(matches!(
        WorkerTarget::resolve(staged, "../../etc/passwd"),
        Err(TargetError::EntrypointRejected(_))
    ));
}

#[test]
fn dropping_the_target_removes_the_staging_directory() {
    let scratch = Scratch::new("cleanup");
    let staged = staged_script(&scratch, "#!/bin/sh\nexit 0\n");
    let stage_root = staged.root().to_owned();
    let target = WorkerTarget::resolve(staged, "payload/worker").expect("resolve");
    drop(target);
    assert!(!stage_root.exists(), "staging must be cleaned up on drop");
}

#[tokio::test]
async fn unread_request_larger_than_the_pipe_does_not_stall_the_deadline() {
    let scratch = Scratch::new("unread-request");
    // `exec` replaces the shell, so nothing ever reads stdin.
    let target = resolved_target(&scratch, "#!/bin/sh\nexec sleep 60\n");
    let mut sent = request(Duration::from_millis(300));
    sent.configuration = serde_json::json!({"blob": "x".repeat(256 * 1024)});
    let limits = ExecutionLimits {
        terminate_grace: Duration::from_millis(200),
        ..ExecutionLimits::default()
    };
    let started = Instant::now();
    let report = tokio::time::timeout(
        Duration::from_secs(5),
        WorkerExecutor::new(limits).execute(&target, sent),
    )
    .await
    .expect("the deadline must fire while the request write is blocked")
    .expect("host side must succeed");
    assert!(matches!(report.outcome, ExecutionOutcome::TimedOut { .. }));
    assert!(started.elapsed() < Duration::from_secs(5));
}

const SCRIPT_STDERR_FLOOD: &str = r#"#!/bin/sh
yes e | head -c 200000 >&2
read -r line
printf '{"protocol_version":1,"status":"ok","result":"drained"}\n'
"#;

#[tokio::test]
async fn stderr_flood_while_the_request_is_written_does_not_deadlock() {
    let scratch = Scratch::new("stderr-flood");
    let target = resolved_target(&scratch, SCRIPT_STDERR_FLOOD);
    let mut sent = request(Duration::from_secs(10));
    sent.configuration = serde_json::json!({"blob": "x".repeat(256 * 1024)});
    let limits = ExecutionLimits {
        max_stderr_bytes: 1024,
        ..ExecutionLimits::default()
    };
    let report = tokio::time::timeout(
        Duration::from_secs(15),
        WorkerExecutor::new(limits).execute(&target, sent),
    )
    .await
    .expect("stderr must drain concurrently with the request write")
    .expect("host side must succeed");
    assert_eq!(
        report.outcome,
        ExecutionOutcome::Succeeded {
            result: serde_json::json!("drained"),
        }
    );
    assert!(report.stderr.truncated());
    assert_eq!(report.stderr.total_bytes(), 200000);
}

const SCRIPT_IGNORE_SIGTERM: &str = r#"#!/bin/sh
trap '' TERM
( trap '' TERM; while :; do echo tick >> "$TICKS"; sleep 0.2; done ) &
sleep 0.15
"#;

#[tokio::test]
async fn sigterm_ignoring_descendants_die_when_the_leader_exits_first() {
    let scratch = Scratch::new("ignore-term");
    let ticks = scratch.file("ticks");
    let target = resolved_target(&scratch, SCRIPT_IGNORE_SIGTERM)
        .with_env(vec![("TICKS".to_owned(), ticks.display().to_string())]);
    let limits = ExecutionLimits {
        terminate_grace: Duration::from_millis(300),
        ..ExecutionLimits::default()
    };
    let report = WorkerExecutor::new(limits)
        .execute(&target, request(Duration::from_millis(100)))
        .await
        .expect("host side must succeed");
    assert!(matches!(report.outcome, ExecutionOutcome::TimedOut { .. }));

    // The leader ignored SIGTERM and exited on its own inside the grace
    // window; the group escalation must still kill its descendant.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = tick_count(&ticks);
    assert!(before > 0, "the descendant ticker must have run");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        before,
        tick_count(&ticks),
        "a SIGTERM-ignoring descendant must not survive the escalation"
    );
}

#[tokio::test]
async fn dropping_the_execution_future_terminates_descendants() {
    let scratch = Scratch::new("future-drop");
    let ticks = scratch.file("ticks");
    let target = resolved_target(&scratch, SCRIPT_TICKS)
        .with_env(vec![("TICKS".to_owned(), ticks.display().to_string())]);
    let executor = WorkerExecutor::new(ExecutionLimits::default());
    let outcome = tokio::time::timeout(
        Duration::from_millis(300),
        executor.execute(&target, request(Duration::from_secs(60))),
    )
    .await;
    assert!(
        outcome.is_err(),
        "the execution must still be running when its future is dropped"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = tick_count(&ticks);
    assert!(before > 0, "the descendant ticker must have run");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        before,
        tick_count(&ticks),
        "dropping the execution future must not leak descendants"
    );
}

const SCRIPT_SLOW_OK: &str = r#"#!/bin/sh
read -r line
sleep 0.3
printf '{"protocol_version":1,"status":"ok","result":"slow"}\n'
"#;

#[tokio::test]
async fn dropped_cancel_sender_does_not_cancel() {
    let scratch = Scratch::new("cancel-dropped");
    let target = resolved_target(&scratch, SCRIPT_SLOW_OK);
    let (sender, receiver) = tokio::sync::oneshot::channel::<String>();
    drop(sender);
    let started = Instant::now();
    let report = WorkerExecutor::new(ExecutionLimits::default())
        .execute_cancellable(&target, request(Duration::from_secs(10)), Some(receiver))
        .await
        .expect("host side must succeed");
    assert_eq!(
        report.outcome,
        ExecutionOutcome::Succeeded {
            result: serde_json::json!("slow"),
        }
    );
    assert!(started.elapsed() >= Duration::from_millis(250));
}
