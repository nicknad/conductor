//! Worker-process executor: resolve a staged artifact to a runnable
//! process, spawn it with a restricted environment, exchange one IPC
//! request/response over stdin/stdout, and terminate its process group on
//! timeout or cancellation.
//!
//! One worker process per execution: startup cost buys trivial lifecycle
//! management and real fault isolation. stdout carries only protocol
//! responses, stderr only diagnostics; both are drained concurrently so a
//! chatty worker cannot deadlock on a full pipe, and both are bounded so it
//! cannot exhaust host memory. A worker that stops cooperating is SIGTERMed
//! and, after a grace period, SIGKILLed together with its descendants
//! (process groups, where the platform supports them).
//!
//! A separate process is fault isolation, not a security sandbox. The
//! executor restricts what it can — explicit environment, no shell
//! interpretation, digest re-verification at resolve time, process-group
//! teardown — while filesystem, network, and credential restriction remain
//! deployment concerns.
//!
//! Workers inherit the host's identity by design: no `uid`, `gid`, or
//! supplementary-group change is ever applied. Same-identity execution
//! means package code is as trusted as the host where files and
//! credentials are concerned (staging directories are owner-reachable, the
//! artifact store is readable); the process boundary exists for faults and
//! resources, not for malice.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::packages::archive::check_entry_path;
use crate::packages::digest::Sha256DigestProvider;
use crate::storage::staging::StagedPackage;

use super::protocol::{self, ExecutionRequest, ExecutionResponse};

/// Default bound on one protocol message: the request line the host sends
/// and the response line it accepts. Large enough for real configuration,
/// small enough that a hostile worker cannot buffer the host out of memory.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1 << 20;

/// Default bound on captured stderr per execution. Excess output is
/// discarded, not buffered; the total byte count is still recorded.
pub const DEFAULT_MAX_STDERR_BYTES: usize = 64 << 10;

/// Default wall-clock window a worker gets to exit after being asked to
/// stop (or after answering) before it is killed, and the window output
/// readers get to drain after termination.
pub const DEFAULT_TERMINATE_GRACE: Duration = Duration::from_secs(2);

/// How often the executor polls for child exit. Polling keeps every wait
/// cancel-safe by construction: no half-consumed `wait` future can be
/// dropped while it owns kernel state.
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Chunk size for draining stderr.
const STDERR_CHUNK_BYTES: usize = 8 * 1024;

/// Resource bounds for one execution. Message and stderr caps are byte
/// bounds; the execution-time bound is the request's `deadline_ms`, and
/// `terminate_grace` bounds how long a stopping worker has to comply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub max_message_bytes: usize,
    pub max_stderr_bytes: usize,
    pub terminate_grace: Duration,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
            terminate_grace: DEFAULT_TERMINATE_GRACE,
        }
    }
}

/// Bounded diagnostic capture (stderr). `total_bytes` counts everything
/// the worker wrote; `bytes` holds at most the configured cap.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
    total_bytes: u64,
}

impl CapturedOutput {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn text_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    /// True when stderr exceeded the cap and the tail was discarded.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// How one execution ended. The upstream execution record maps these onto
/// its status vocabulary (`Succeeded | Failed | Cancelled | TimedOut`,
/// with worker and protocol faults folding into `Failed`).
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionOutcome {
    /// The worker answered `ok`.
    Succeeded { result: serde_json::Value },
    /// The worker answered `failed`; `message` is its sanitized reason.
    Failed { message: String },
    /// The deadline expired and the worker was terminated.
    TimedOut { deadline: Duration },
    /// The host cancelled the execution and the worker was terminated.
    Cancelled { reason: String },
    /// No usable response: the worker crashed, exited early, or its pipes
    /// failed. `detail` is host-side prose, never raw worker output.
    WorkerError { detail: String },
    /// The worker responded outside the protocol: oversized, malformed, or
    /// a foreign version.
    ProtocolViolation { detail: String },
}

/// What one execution produced, for the execution record.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionReport {
    pub execution_id: String,
    pub outcome: ExecutionOutcome,
    /// Bounded stderr diagnostics (truncated at the configured cap).
    pub stderr: CapturedOutput,
    /// Wall time from spawn to report, including termination.
    pub duration: Duration,
}

/// Failures of the host side of an execution, before or at spawn. A worker
/// that spawned is always reported through an [`ExecutionOutcome`], never
/// an `Err`.
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("invalid execution request: {0}")]
    InvalidRequest(String),
    #[error("worker process failed to start: {0}")]
    Spawn(String),
}

/// Why a staged package could not be resolved into a worker target.
#[derive(Debug, Error)]
pub enum TargetError {
    #[error("staged file changed after verification: {path}")]
    StagedFileChanged { path: String },
    #[error("staged file could not be verified: {path}: {detail}")]
    StagedFileUnreadable { path: String, detail: String },
    #[error("entrypoint path rejected: {0}")]
    EntrypointRejected(String),
    #[error("entrypoint is not a regular file in the staged package")]
    EntrypointMissing,
    #[error("entrypoint could not be marked executable: {0}")]
    EntrypointNotExecutable(String),
}

/// A worker resolved from a staged, verified package: the absolute
/// entrypoint path plus the private working directory, owned so the staging
/// directory is removed when the target drops.
///
/// [`resolve`](Self::resolve) re-hashes every staged file against the
/// digests recorded at extraction time before accepting the target: staging
/// and spawning are separate moments, and a path is never trusted across
/// time.
#[derive(Debug)]
pub struct WorkerTarget {
    staged: StagedPackage,
    program: PathBuf,
    env: Vec<(String, String)>,
}

impl WorkerTarget {
    /// Verifies the staged files against their recorded digests, confines
    /// `entrypoint` under the staging root, and marks it executable.
    pub fn resolve(staged: StagedPackage, entrypoint: &str) -> Result<Self, TargetError> {
        verify_staged_files(&staged)?;
        let normalized = check_entry_path(entrypoint, false)
            .map_err(|e| TargetError::EntrypointRejected(e.to_string()))?;
        let program = staged.root().join(&normalized);
        if !program.is_file() {
            return Err(TargetError::EntrypointMissing);
        }
        mark_executable(&program)?;
        Ok(Self {
            staged,
            program,
            env: Vec::new(),
        })
    }

    /// Sets the worker's complete environment. The executor clears the
    /// inherited environment and applies exactly these pairs: operational
    /// variables only, never secrets (they ride the request's stdin line).
    #[must_use]
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    /// Absolute path of the entrypoint the worker executes.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Private staging directory the worker runs in.
    #[must_use]
    pub fn working_dir(&self) -> &Path {
        self.staged.root()
    }

    #[must_use]
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }
}

/// Re-hashes every staged file and compares against the size and SHA-256
/// recorded when extraction hashed the same bytes. Any mismatch (or
/// unreadable file) refuses the target.
fn verify_staged_files(staged: &StagedPackage) -> Result<(), TargetError> {
    for file in staged.files() {
        let path = staged.root().join(&file.path);
        let metadata = std::fs::metadata(&path).map_err(|e| TargetError::StagedFileUnreadable {
            path: file.path.clone(),
            detail: e.to_string(),
        })?;
        if !metadata.is_file() || metadata.len() != file.size {
            return Err(TargetError::StagedFileChanged {
                path: file.path.clone(),
            });
        }
        let mut source =
            std::fs::File::open(&path).map_err(|e| TargetError::StagedFileUnreadable {
                path: file.path.clone(),
                detail: e.to_string(),
            })?;
        let digest = Sha256DigestProvider
            .digest_stream(&mut source)
            .map_err(|e| TargetError::StagedFileUnreadable {
                path: file.path.clone(),
                detail: e.to_string(),
            })?;
        if digest != file.sha256 {
            return Err(TargetError::StagedFileChanged {
                path: file.path.clone(),
            });
        }
    }
    Ok(())
}

/// Extraction writes payload files without executable bits (they are only
/// ever hashed before this point), so the declared entrypoint is marked
/// owner-executable here — inside the owner-only staging directory.
fn mark_executable(program: &Path) -> Result<(), TargetError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(program)
            .map_err(|e| TargetError::StagedFileUnreadable {
                path: program.display().to_string(),
                detail: e.to_string(),
            })?
            .permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        std::fs::set_permissions(program, permissions)
            .map_err(|e| TargetError::EntrypointNotExecutable(e.to_string()))?;
    }
    #[cfg(not(unix))]
    let _ = program;
    Ok(())
}

/// Executes worker processes for resolved targets.
#[derive(Debug, Clone)]
pub struct WorkerExecutor {
    limits: ExecutionLimits,
}

impl WorkerExecutor {
    #[must_use]
    pub fn new(limits: ExecutionLimits) -> Self {
        Self { limits }
    }

    #[must_use]
    pub fn limits(&self) -> &ExecutionLimits {
        &self.limits
    }

    /// Runs one execution to completion: spawn, invoke, collect, terminate.
    pub async fn execute(
        &self,
        target: &WorkerTarget,
        request: ExecutionRequest,
    ) -> Result<ExecutionReport, ExecutionError> {
        self.execute_cancellable(target, request, None).await
    }

    /// Like [`execute`](Self::execute), with a cancellation channel: a
    /// value sent on `cancel` (the string is the recorded reason) terminates
    /// the worker and reports [`ExecutionOutcome::Cancelled`]. Cancellation
    /// is only ever an explicit send — dropping the sender without sending
    /// cancels nothing, and the execution runs to its deadline. The
    /// deadline and cancellation cover the entire exchange, including the
    /// request write.
    pub async fn execute_cancellable(
        &self,
        target: &WorkerTarget,
        request: ExecutionRequest,
        mut cancel: Option<oneshot::Receiver<String>>,
    ) -> Result<ExecutionReport, ExecutionError> {
        request
            .validate()
            .map_err(|e| ExecutionError::InvalidRequest(e.to_string()))?;
        let line = request
            .to_line()
            .map_err(|e| ExecutionError::InvalidRequest(e.to_string()))?;
        if line.len() > self.limits.max_message_bytes {
            return Err(ExecutionError::InvalidRequest(format!(
                "execution request is {} bytes, over the {} byte message bound",
                line.len(),
                self.limits.max_message_bytes
            )));
        }
        let execution_id = request.execution_id.clone();
        let deadline = Duration::from_millis(request.deadline_ms);

        let mut command = Command::new(target.program());
        command
            .current_dir(target.working_dir())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command.envs(
            target
                .env()
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        // Identity: deliberately inherited — the worker runs as the host
        // (`uid`, `gid`, and supplementary groups unchanged). Do not add
        // privilege changes here; see the module docs for the contract.
        //
        // One process group per execution, so timeout and cancellation can
        // take descendants along "where supported" (Unix).
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .spawn()
            .map_err(|e| ExecutionError::Spawn(e.to_string()))?;
        let pid = child.id();
        let started = Instant::now();
        // Teardown backstop for callers that drop this future mid-run
        // (host-side timeouts, runtime shutdown): `kill_on_drop` on the
        // child only reaches the direct child, so the guard kills the whole
        // process group and aborts the I/O tasks unless the run finishes
        // normally.
        let mut guard = ExecutionGuard::new(pid);

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecutionError::Spawn("worker stdout pipe is missing".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ExecutionError::Spawn("worker stderr pipe is missing".to_owned()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ExecutionError::Spawn("worker stdin pipe is missing".to_owned()))?;

        // Start draining both output pipes before the request write: a
        // worker that floods stderr or stdout before reading stdin must not
        // be able to deadlock the exchange.
        let mut response_task =
            tokio::spawn(read_response_line(stdout, self.limits.max_message_bytes));
        guard.track(&response_task);
        let stderr_sink = Arc::new(Mutex::new(CapturedOutput::default()));
        let mut stderr_task = tokio::spawn(drain_stderr(
            stderr,
            self.limits.max_stderr_bytes,
            Arc::clone(&stderr_sink),
        ));
        guard.track(&stderr_task);

        // Invoke: exactly one request line, then EOF, on its own task so a
        // worker that never reads stdin cannot block the deadline or
        // cancellation race below. Write failures are not fatal: a broken
        // pipe means the worker closed stdin or died, and the outcome
        // branches surface that.
        let mut write_task = tokio::spawn(write_request(stdin, line));
        guard.track(&write_task);

        enum First {
            Response(ResponseRead),
            Exit(io::Result<ExitStatus>),
            Timeout,
            Cancelled(String),
        }
        let deadline_at = tokio::time::Instant::now() + deadline;
        let mut write_finished = false;
        // The loop only re-enters when the request write finishes first;
        // the deadline is an absolute instant, so it never restarts.
        let first = loop {
            tokio::select! {
                read = &mut response_task => break First::Response(match read {
                    Ok(read) => read,
                    Err(_) => ResponseRead::Io("stdout reader task failed".to_owned()),
                }),
                status = wait_for_exit(&mut child) => break First::Exit(status),
                () = tokio::time::sleep_until(deadline_at) => break First::Timeout,
                reason = CancelWait::new(&mut cancel) => break First::Cancelled(reason),
                _ = &mut write_task, if !write_finished => {
                    write_finished = true;
                }
            }
        };
        // Whatever ended the race, the request is no longer in flight:
        // aborting drops the writer's stdin, closing the pipe (a no-op when
        // the write already finished).
        write_task.abort();

        let outcome = match first {
            First::Response(read) => {
                // The worker answered (or closed stdout). Let it exit on its
                // own for the grace window; one that answers and then hangs
                // is stopped like a timed-out one. The exit status backs up
                // an EOF response ("exited without a protocol response").
                let status = match wait_until(
                    &mut child,
                    Instant::now() + self.limits.terminate_grace,
                )
                .await
                {
                    Ok(Some(status)) => Some(status),
                    Ok(None) | Err(_) => {
                        stop_process_group(&mut child, pid, self.limits.terminate_grace)
                            .await
                            .ok()
                            .flatten()
                    }
                };
                // Whatever the leader did, descendants are not part of the
                // one-process contract; clean up the group best-effort.
                kill_group_best_effort(pid);
                match read {
                    ResponseRead::Eof => worker_error_for_exit(status),
                    read => outcome_from_response(read, self.limits.max_message_bytes),
                }
            }
            First::Exit(status) => {
                // The worker may have written its response just before
                // exiting; give the reader a bounded window to collect it.
                let read = match timeout(self.limits.terminate_grace, &mut response_task).await {
                    Ok(Ok(read)) => Some(read),
                    _ => {
                        response_task.abort();
                        None
                    }
                };
                kill_group_best_effort(pid);
                match read {
                    Some(ResponseRead::Eof) | None => match status {
                        Ok(status) => worker_error_for_exit(Some(status)),
                        Err(e) => ExecutionOutcome::WorkerError {
                            detail: format!("waiting for the worker failed: {e}"),
                        },
                    },
                    Some(read) => outcome_from_response(read, self.limits.max_message_bytes),
                }
            }
            First::Timeout => {
                let _ = stop_process_group(&mut child, pid, self.limits.terminate_grace).await;
                response_task.abort();
                ExecutionOutcome::TimedOut { deadline }
            }
            First::Cancelled(reason) => {
                let _ = stop_process_group(&mut child, pid, self.limits.terminate_grace).await;
                response_task.abort();
                ExecutionOutcome::Cancelled { reason }
            }
        };

        // Collect diagnostics: the readers should hit EOF once the group is
        // dead; the bounded wait protects against pipes held open by a
        // process that escaped the group.
        if timeout(self.limits.terminate_grace, &mut stderr_task)
            .await
            .is_err()
        {
            stderr_task.abort();
        }
        let stderr = stderr_sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        guard.disarm();

        Ok(ExecutionReport {
            execution_id,
            outcome,
            stderr,
            duration: started.elapsed(),
        })
    }
}

/// What the stdout reader collected.
enum ResponseRead {
    /// One line, without its terminator.
    Line(Vec<u8>),
    /// stdout closed without a single byte.
    Eof,
    /// The line exceeded the message bound before terminating.
    TooLarge,
    /// Reading stdout failed; the worker's fault surface, not the host's.
    Io(String),
}

/// Reads at most one bounded line from stdout. The read is capped at the
/// bound (plus terminator) so a hostile worker streaming forever can never
/// make the host buffer more than that.
async fn read_response_line(stdout: tokio::process::ChildStdout, max_bytes: usize) -> ResponseRead {
    let cap = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(2);
    let mut reader = BufReader::new(stdout).take(cap);
    let mut buf = Vec::new();
    match reader.read_until(b'\n', &mut buf).await {
        Err(e) => ResponseRead::Io(e.to_string()),
        Ok(_) => {
            if buf.is_empty() {
                return ResponseRead::Eof;
            }
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            // Tolerate a CRLF worker; the JSON payload ignores it anyway.
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            if buf.len() > max_bytes {
                return ResponseRead::TooLarge;
            }
            ResponseRead::Line(buf)
        }
    }
}

/// Drains stderr to EOF, keeping at most `cap` bytes in the shared sink and
/// counting (but discarding) everything beyond it. Never fails the
/// execution: diagnostics are best-effort by definition.
async fn drain_stderr(
    mut stderr: tokio::process::ChildStderr,
    cap: usize,
    sink: Arc<Mutex<CapturedOutput>>,
) {
    let mut buf = [0u8; STDERR_CHUNK_BYTES];
    loop {
        match stderr.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                let mut sink = sink.lock().unwrap_or_else(|e| e.into_inner());
                sink.total_bytes = sink.total_bytes.saturating_add(read as u64);
                let room = cap.saturating_sub(sink.bytes.len());
                let keep = read.min(room);
                sink.bytes.extend_from_slice(&buf[..keep]);
                if keep < read {
                    sink.truncated = true;
                }
            }
        }
    }
}

/// Writes the request line and then closes stdin (EOF), on its own task so
/// a worker that never reads stdin cannot block the deadline race.
/// Failures are ignored on purpose: a broken pipe means the worker closed
/// stdin or died, and the outcome branches surface that.
async fn write_request(mut stdin: tokio::process::ChildStdin, line: Vec<u8>) {
    let _ = stdin.write_all(&line).await;
    let _ = stdin.flush().await;
}

/// Polls the optional cancellation channel without consuming it, so a
/// `select!` iteration that loses the race keeps the receiver for the next
/// one. A dropped sender resolves nothing: cancellation is only ever an
/// explicit send, matching the documented contract.
struct CancelWait<'a> {
    cancel: &'a mut Option<oneshot::Receiver<String>>,
}

impl<'a> CancelWait<'a> {
    fn new(cancel: &'a mut Option<oneshot::Receiver<String>>) -> Self {
        Self { cancel }
    }
}

impl std::future::Future for CancelWait<'_> {
    type Output = String;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<String> {
        use std::task::Poll;

        let this = self.get_mut();
        let Some(receiver) = this.cancel.as_mut() else {
            return Poll::Pending;
        };
        let polled = std::pin::Pin::new(receiver).poll(cx);
        match polled {
            Poll::Ready(Ok(reason)) => {
                this.cancel.take();
                Poll::Ready(reason)
            }
            // Sender dropped without sending: the channel can never fire.
            Poll::Ready(Err(_)) => {
                this.cancel.take();
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Aborts the worker's I/O tasks and kills its process group when dropped
/// unless disarmed by a normal finish, covering callers that drop the
/// execution future mid-run. `kill_on_drop` on the child only reaches the
/// direct child; descendants are the group's problem.
struct ExecutionGuard {
    pid: Option<u32>,
    tasks: Vec<tokio::task::AbortHandle>,
    armed: bool,
}

impl ExecutionGuard {
    fn new(pid: Option<u32>) -> Self {
        Self {
            pid,
            tasks: Vec::new(),
            armed: true,
        }
    }

    fn track<T>(&mut self, task: &tokio::task::JoinHandle<T>) {
        self.tasks.push(task.abort_handle());
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        kill_group_best_effort(self.pid);
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Polls for child exit until it happens. Polling keeps this future
/// cancel-safe for `select!` by construction.
async fn wait_for_exit(child: &mut Child) -> io::Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        tokio::time::sleep(EXIT_POLL_INTERVAL).await;
    }
}

/// Polls for child exit until `deadline`; `Ok(None)` means still running.
async fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(EXIT_POLL_INTERVAL).await;
    }
}

/// Stops the whole process group: SIGTERM first (workers get a chance to
/// exit cleanly), then SIGKILL regardless of how the grace period ended,
/// then reap the leader. The unconditional escalation matters when the
/// leader exits inside the grace period while a descendant ignored SIGTERM:
/// returning as soon as the leader is reaped would strand that descendant.
async fn stop_process_group(
    child: &mut Child,
    pid: Option<u32>,
    grace: Duration,
) -> io::Result<Option<ExitStatus>> {
    #[cfg(unix)]
    signal_group(pid, libc::SIGTERM);
    #[cfg(not(unix))]
    {
        let _ = pid;
        let _ = child.start_kill();
    }

    let status = wait_until(child, Instant::now() + grace).await;

    #[cfg(unix)]
    signal_group(pid, libc::SIGKILL);
    #[cfg(not(unix))]
    {
        let _ = child.start_kill();
    }

    match status {
        Ok(Some(status)) => Ok(Some(status)),
        Ok(None) | Err(_) => {
            let _ = child.start_kill();
            child.wait().await.map(Some)
        }
    }
}

/// Best-effort SIGKILL of whatever remains in the worker's process group
/// after the leader is gone (daemonized descendants, stragglers).
fn kill_group_best_effort(pid: Option<u32>) {
    #[cfg(unix)]
    signal_group(pid, libc::SIGKILL);
    #[cfg(not(unix))]
    let _ = pid;
}

/// Sends `signal` to the process group led by `pid`. The group exists
/// because the executor spawns every worker with `process_group(0)`; if it
/// is already gone the call is ignored.
#[cfg(unix)]
#[allow(unsafe_code)]
fn signal_group(pid: Option<u32>, signal: i32) {
    let Some(pid) = pid else {
        return;
    };
    // SAFETY: `pid` is the direct child this executor spawned with
    // `process_group(0)`, so its process-group id equals its pid and the
    // signal can only reach that worker and its descendants — until the
    // child is reaped and the pid becomes recyclable. Signaling after the
    // leader is reaped (the best-effort descendant cleanup) accepts that
    // narrow reuse window deliberately: descendants still holding the group
    // open are the more immediate leak.
    let _ = unsafe { libc::killpg(pid as libc::pid_t, signal) };
}

fn outcome_from_response(read: ResponseRead, max_message_bytes: usize) -> ExecutionOutcome {
    match read {
        ResponseRead::Line(bytes) => match protocol::decode_response(&bytes) {
            Ok(ExecutionResponse::Ok { result }) => ExecutionOutcome::Succeeded { result },
            Ok(ExecutionResponse::Failed { message }) => ExecutionOutcome::Failed { message },
            Err(e) => ExecutionOutcome::ProtocolViolation {
                detail: e.to_string(),
            },
        },
        ResponseRead::TooLarge => ExecutionOutcome::ProtocolViolation {
            detail: format!("worker response exceeds the {max_message_bytes} byte message bound"),
        },
        ResponseRead::Eof => worker_error_for_exit(None),
        ResponseRead::Io(detail) => ExecutionOutcome::WorkerError { detail },
    }
}

/// A worker that exited (or closed stdout) without a usable response. The
/// exit status is host-observed metadata, safe to record.
fn worker_error_for_exit(status: Option<ExitStatus>) -> ExecutionOutcome {
    ExecutionOutcome::WorkerError {
        detail: match status {
            Some(status) => format!(
                "worker exited without a protocol response ({})",
                describe_exit(&status)
            ),
            None => "worker exited without a protocol response".to_owned(),
        },
    }
}

fn describe_exit(status: &ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => "terminated by signal".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_nonzero_and_bounded() {
        let limits = ExecutionLimits::default();
        assert!(limits.max_message_bytes > 0);
        assert!(limits.max_stderr_bytes > 0);
        assert!(limits.terminate_grace > Duration::ZERO);
    }

    #[test]
    fn response_shapes_map_to_outcomes() {
        assert_eq!(
            outcome_from_response(
                ResponseRead::Line(br#"{"protocol_version":1,"status":"ok"}"#.to_vec()),
                4096
            ),
            ExecutionOutcome::Succeeded {
                result: serde_json::Value::Null,
            }
        );
        assert_eq!(
            outcome_from_response(
                ResponseRead::Line(
                    br#"{"protocol_version":1,"status":"failed","message":"boom"}"#.to_vec()
                ),
                4096
            ),
            ExecutionOutcome::Failed {
                message: "boom".to_owned(),
            }
        );
        assert!(matches!(
            outcome_from_response(ResponseRead::TooLarge, 4096),
            ExecutionOutcome::ProtocolViolation { .. }
        ));
        assert!(matches!(
            outcome_from_response(ResponseRead::Io("read failed".to_owned()), 4096),
            ExecutionOutcome::WorkerError { .. }
        ));
    }
}
