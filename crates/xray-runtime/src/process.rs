use std::{
    fmt, io,
    path::Path,
    process::{ExitStatus, Stdio},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    time::{sleep, timeout},
};

use crate::{
    BinaryValidationError, ConfigValidationError, RenderedXrayConfig, VerifiedXrayBinary,
    VerifiedXrayConfig,
};

const MAX_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_OUTPUT_BYTES_PER_STREAM: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(1);
const MANAGED_CHILD_OPERATION: &str = "managed child";
const MANAGED_REAP_OPERATION: &str = "managed child reap";

/// Explicit process limits used by both runtime probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionLimits {
    timeout: Duration,
    max_output_bytes_per_stream: usize,
}

impl ExecutionLimits {
    /// Creates bounded execution limits.
    ///
    /// Each of stdout and stderr is independently capped by
    /// `max_output_bytes_per_stream`.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidLimits`] for zero or excessive values.
    pub fn new(
        timeout: Duration,
        max_output_bytes_per_stream: usize,
    ) -> Result<Self, RuntimeError> {
        if timeout.is_zero()
            || timeout > MAX_TIMEOUT
            || max_output_bytes_per_stream == 0
            || max_output_bytes_per_stream > MAX_OUTPUT_BYTES_PER_STREAM
        {
            return Err(RuntimeError::InvalidLimits);
        }
        Ok(Self {
            timeout,
            max_output_bytes_per_stream,
        })
    }

    /// Returns the wall-clock process timeout.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Returns the independent stdout and stderr byte cap.
    #[must_use]
    pub const fn max_output_bytes_per_stream(self) -> usize {
        self.max_output_bytes_per_stream
    }
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_output_bytes_per_stream: 64 * 1024,
        }
    }
}

/// Successful, bounded output from `xray version`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionProbe {
    stdout: String,
    stderr_bytes: usize,
}

impl VersionProbe {
    /// Returns trimmed UTF-8 version output from stdout.
    #[must_use]
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    /// Returns the number of bounded stderr bytes discarded from the report.
    #[must_use]
    pub const fn stderr_bytes(&self) -> usize {
        self.stderr_bytes
    }
}

/// Successful result of `xray run -test -config <tempfile>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigTestReport {
    stdout_bytes: usize,
    stderr_bytes: usize,
}

impl ConfigTestReport {
    /// Returns the number of bounded stdout bytes produced.
    #[must_use]
    pub const fn stdout_bytes(self) -> usize {
        self.stdout_bytes
    }

    /// Returns the number of bounded stderr bytes produced.
    #[must_use]
    pub const fn stderr_bytes(self) -> usize {
        self.stderr_bytes
    }
}

/// Runs `xray version` against a previously verified explicit binary.
///
/// The binary checksum is revalidated immediately before the child is spawned.
/// The command does not use a shell or `PATH` lookup.
///
/// # Errors
///
/// Returns a stable, redacted [`RuntimeError`] for validation, spawn, timeout,
/// output-bound, encoding, or exit-status failures.
pub async fn probe_version(
    binary: &VerifiedXrayBinary,
    limits: ExecutionLimits,
) -> Result<VersionProbe, RuntimeError> {
    revalidate_binary(binary).await?;

    let mut command = Command::new(binary.path());
    command.arg("version");
    configure_command(&mut command, binary.path().parent());
    let output = run_bounded(command, "version probe", limits).await?;
    if !output.status.success() {
        return Err(non_zero_error("version probe", &output));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| RuntimeError::InvalidVersionOutput)?
        .trim()
        .to_owned();
    if stdout.is_empty() {
        return Err(RuntimeError::EmptyVersionOutput);
    }
    Ok(VersionProbe {
        stdout,
        stderr_bytes: output.stderr.len(),
    })
}

/// Writes a private temporary config and runs Xray's built-in config test.
///
/// The temporary file is mode `0600` on Unix and is removed when this function
/// returns. The complete configuration is never included in an error message or
/// command-line argument.
///
/// # Errors
///
/// Returns a stable, redacted [`RuntimeError`] for oversized config, binary
/// validation, temporary-file, spawn, timeout, output-bound, or exit failures.
pub async fn test_config(
    binary: &VerifiedXrayBinary,
    config: &RenderedXrayConfig,
    limits: ExecutionLimits,
) -> Result<ConfigTestReport, RuntimeError> {
    if config.len() > MAX_CONFIG_BYTES {
        return Err(RuntimeError::ConfigTooLarge);
    }
    revalidate_binary(binary).await?;
    let config_file = write_private_config(config)?;

    let mut command = Command::new(binary.path());
    command
        .arg("run")
        .arg("-test")
        .arg("-config")
        .arg(config_file.path());
    configure_command(&mut command, config_file.path().parent());
    let output = run_bounded(command, "config test", limits).await?;
    if !output.status.success() {
        return Err(non_zero_error("config test", &output));
    }
    Ok(ConfigTestReport {
        stdout_bytes: output.stdout.len(),
        stderr_bytes: output.stderr.len(),
    })
}

/// Starts `xray run -config <path>` as a constrained long-running child.
///
/// Binary and configuration checksums are revalidated concurrently on blocking
/// workers immediately before the spawn. The command uses the explicit absolute
/// binary path directly, clears the environment, nulls all standard streams, and
/// is configured to be killed if its handle is dropped.
///
/// # Errors
///
/// Returns a stable, redacted [`RuntimeError`] when revalidation or process
/// startup fails.
pub async fn start_managed(
    binary: &VerifiedXrayBinary,
    verified_config: &VerifiedXrayConfig,
) -> Result<ManagedXrayChild, RuntimeError> {
    tokio::try_join!(
        revalidate_binary(binary),
        revalidate_config(verified_config)
    )?;

    let mut command = Command::new(binary.path());
    command
        .arg("run")
        .arg("-config")
        .arg(verified_config.path())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(directory) = verified_config.path().parent() {
        command.current_dir(directory);
    }

    let child = command
        .spawn()
        .map_err(|source| RuntimeError::SpawnFailed {
            operation: MANAGED_CHILD_OPERATION,
            source,
        })?;
    let pid = child.id().ok_or(RuntimeError::MissingProcessId)?;
    Ok(ManagedXrayChild { child, pid })
}

/// A constrained long-running Xray child owned by the caller.
///
/// Dropping this value requests forceful termination through Tokio's
/// `kill_on_drop` behavior. Call [`Self::kill_and_wait`] when deterministic
/// bounded reaping is required.
pub struct ManagedXrayChild {
    child: Child,
    pid: u32,
}

impl ManagedXrayChild {
    /// Returns the process identifier assigned at spawn time.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the exit status without blocking, if the child has exited.
    ///
    /// # Errors
    ///
    /// Returns a stable, redacted [`RuntimeError`] if the operating-system status
    /// check fails.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, RuntimeError> {
        self.child
            .try_wait()
            .map_err(|source| RuntimeError::ProcessIoFailed {
                operation: MANAGED_CHILD_OPERATION,
                source,
            })
    }

    /// Forcefully kills the child and waits at most one second to reap it.
    ///
    /// This is deliberately not a graceful `SIGTERM` protocol. If the child has
    /// already exited, its status is returned without sending a signal.
    ///
    /// # Errors
    ///
    /// Returns a stable, redacted [`RuntimeError`] if kill, wait, or the bounded
    /// reap fails.
    pub async fn kill_and_wait(&mut self) -> Result<ExitStatus, RuntimeError> {
        if let Some(status) = self.try_wait()? {
            return Ok(status);
        }

        if let Err(source) = self.child.start_kill() {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            return Err(RuntimeError::ProcessIoFailed {
                operation: MANAGED_CHILD_OPERATION,
                source,
            });
        }

        timeout(CHILD_REAP_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| RuntimeError::TimedOut {
                operation: MANAGED_REAP_OPERATION,
                timeout_ms: CHILD_REAP_TIMEOUT.as_millis(),
            })?
            .map_err(|source| RuntimeError::ProcessIoFailed {
                operation: MANAGED_REAP_OPERATION,
                source,
            })
    }
}

impl fmt::Debug for ManagedXrayChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedXrayChild")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

/// Stable, redacted failures from bounded Xray subprocess operations.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Process limits were zero or exceeded library safety bounds.
    #[error("Xray execution limits are invalid")]
    InvalidLimits,
    /// The rendered config exceeded the private tempfile bound.
    #[error("Xray configuration exceeds the runtime size limit")]
    ConfigTooLarge,
    /// Explicit binary validation failed.
    #[error(transparent)]
    BinaryValidation(#[from] BinaryValidationError),
    /// Explicit configuration-file validation failed.
    #[error(transparent)]
    ConfigValidation(#[from] ConfigValidationError),
    /// The blocking checksum task could not be completed.
    #[error("Xray binary verification task failed")]
    VerificationTaskFailed,
    /// The blocking configuration checksum task could not be completed.
    #[error("Xray configuration verification task failed")]
    ConfigVerificationTaskFailed,
    /// A private temporary config could not be prepared.
    #[error("private Xray configuration file could not be prepared")]
    TempConfigFailed {
        /// Underlying filesystem failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// The explicit process could not be spawned.
    #[error("Xray {operation} process could not be started")]
    SpawnFailed {
        /// Static operation label.
        operation: &'static str,
        /// Underlying process failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// A spawned child did not expose its process identifier.
    #[error("Xray managed child process identifier was unavailable")]
    MissingProcessId,
    /// A pipe disappeared unexpectedly after spawn.
    #[error("Xray {operation} output pipe was unavailable")]
    MissingPipe {
        /// Static operation label.
        operation: &'static str,
    },
    /// Reading or waiting for the child failed.
    #[error("Xray {operation} process I/O failed")]
    ProcessIoFailed {
        /// Static operation label.
        operation: &'static str,
        /// Underlying process failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// The internal process state was incomplete after the bounded wait loop.
    #[error("Xray {operation} process result was incomplete")]
    IncompleteProcessResult {
        /// Static operation label.
        operation: &'static str,
    },
    /// The wall-clock timeout expired and the child was terminated.
    #[error("Xray {operation} timed out after {timeout_ms} ms")]
    TimedOut {
        /// Static operation label.
        operation: &'static str,
        /// Configured timeout in milliseconds.
        timeout_ms: u128,
    },
    /// Stdout or stderr exceeded its explicit byte cap.
    #[error("Xray {operation} {stream} exceeded the {limit}-byte output limit")]
    OutputLimitExceeded {
        /// Static operation label.
        operation: &'static str,
        /// Static stream label.
        stream: &'static str,
        /// Configured per-stream cap.
        limit: usize,
    },
    /// The child returned an unsuccessful status; output contents are omitted.
    #[error(
        "Xray {operation} failed with exit code {exit_code:?} (stdout {stdout_bytes} bytes, stderr {stderr_bytes} bytes)"
    )]
    NonZeroExit {
        /// Static operation label.
        operation: &'static str,
        /// Numeric exit code, or `None` when terminated by signal.
        exit_code: Option<i32>,
        /// Captured stdout length only.
        stdout_bytes: usize,
        /// Captured stderr length only.
        stderr_bytes: usize,
    },
    /// Version stdout was not valid UTF-8.
    #[error("Xray version output was not valid UTF-8")]
    InvalidVersionOutput,
    /// Version stdout was empty.
    #[error("Xray version output was empty")]
    EmptyVersionOutput,
}

pub(crate) struct CapturedOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

enum ReadFailure {
    LimitExceeded,
    Io(io::Error),
}

pub(crate) async fn revalidate_binary(binary: &VerifiedXrayBinary) -> Result<(), RuntimeError> {
    let binary = binary.clone();
    tokio::task::spawn_blocking(move || binary.revalidate())
        .await
        .map_err(|_| RuntimeError::VerificationTaskFailed)?
        .map_err(RuntimeError::BinaryValidation)
}

async fn revalidate_config(config: &VerifiedXrayConfig) -> Result<(), RuntimeError> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || config.revalidate())
        .await
        .map_err(|_| RuntimeError::ConfigVerificationTaskFailed)?
        .map_err(RuntimeError::ConfigValidation)
}

fn write_private_config(config: &RenderedXrayConfig) -> Result<NamedTempFile, RuntimeError> {
    let mut file = TempFileBuilder::new()
        .prefix("xray-config-")
        .suffix(".json")
        .tempfile()
        .map_err(|source| RuntimeError::TempConfigFailed { source })?;
    #[cfg(unix)]
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|source| RuntimeError::TempConfigFailed { source })?;
    io::Write::write_all(&mut file, config.expose_json().as_bytes())
        .and_then(|()| io::Write::flush(&mut file))
        .map_err(|source| RuntimeError::TempConfigFailed { source })?;
    Ok(file)
}

pub(crate) fn configure_command(command: &mut Command, current_directory: Option<&Path>) {
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(directory) = current_directory {
        command.current_dir(directory);
    }
}

pub(crate) async fn run_bounded(
    mut command: Command,
    operation: &'static str,
    limits: ExecutionLimits,
) -> Result<CapturedOutput, RuntimeError> {
    let mut child = command
        .spawn()
        .map_err(|source| RuntimeError::SpawnFailed { operation, source })?;
    let stdout = child
        .stdout
        .take()
        .ok_or(RuntimeError::MissingPipe { operation })?;
    let stderr = child
        .stderr
        .take()
        .ok_or(RuntimeError::MissingPipe { operation })?;

    let mut stdout_read = Box::pin(read_bounded_stream(
        stdout,
        limits.max_output_bytes_per_stream,
    ));
    let mut stderr_read = Box::pin(read_bounded_stream(
        stderr,
        limits.max_output_bytes_per_stream,
    ));
    let deadline = sleep(limits.timeout);
    tokio::pin!(deadline);

    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;

    while status.is_none() || stdout.is_none() || stderr.is_none() {
        tokio::select! {
            biased;
            result = child.wait(), if status.is_none() => {
                status = Some(result.map_err(|source| RuntimeError::ProcessIoFailed {
                    operation,
                    source,
                })?);
            }
            result = &mut stdout_read, if stdout.is_none() => {
                match result {
                    Ok(bytes) => stdout = Some(bytes),
                    Err(ReadFailure::LimitExceeded) => {
                        terminate_child(&mut child, status.is_some()).await;
                        return Err(RuntimeError::OutputLimitExceeded {
                            operation,
                            stream: "stdout",
                            limit: limits.max_output_bytes_per_stream,
                        });
                    }
                    Err(ReadFailure::Io(source)) => {
                        terminate_child(&mut child, status.is_some()).await;
                        return Err(RuntimeError::ProcessIoFailed { operation, source });
                    }
                }
            }
            result = &mut stderr_read, if stderr.is_none() => {
                match result {
                    Ok(bytes) => stderr = Some(bytes),
                    Err(ReadFailure::LimitExceeded) => {
                        terminate_child(&mut child, status.is_some()).await;
                        return Err(RuntimeError::OutputLimitExceeded {
                            operation,
                            stream: "stderr",
                            limit: limits.max_output_bytes_per_stream,
                        });
                    }
                    Err(ReadFailure::Io(source)) => {
                        terminate_child(&mut child, status.is_some()).await;
                        return Err(RuntimeError::ProcessIoFailed { operation, source });
                    }
                }
            }
            () = &mut deadline => {
                terminate_child(&mut child, status.is_some()).await;
                return Err(RuntimeError::TimedOut {
                    operation,
                    timeout_ms: limits.timeout.as_millis(),
                });
            }
        }
    }

    match (status, stdout, stderr) {
        (Some(status), Some(stdout), Some(stderr)) => Ok(CapturedOutput {
            status,
            stdout,
            stderr,
        }),
        _ => Err(RuntimeError::IncompleteProcessResult { operation }),
    }
}

async fn read_bounded_stream<R>(mut reader: R, limit: usize) -> Result<Vec<u8>, ReadFailure>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(limit.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer).await.map_err(ReadFailure::Io)?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > limit {
            return Err(ReadFailure::LimitExceeded);
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

async fn terminate_child(child: &mut Child, already_exited: bool) {
    if already_exited {
        return;
    }
    let _ = child.start_kill();
    let _ = timeout(CHILD_REAP_TIMEOUT, child.wait()).await;
}

pub(crate) fn non_zero_error(operation: &'static str, output: &CapturedOutput) -> RuntimeError {
    RuntimeError::NonZeroExit {
        operation,
        exit_code: output.status.code(),
        stdout_bytes: output.stdout.len(),
        stderr_bytes: output.stderr.len(),
    }
}
