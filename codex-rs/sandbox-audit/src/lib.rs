use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::BufRead;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

mod transaction;

pub use transaction::WritableRootMapping;
pub use transaction::WritableRootTransaction;

pub const FS_RECORD_SCHEMA_VERSION: u32 = 1;
pub const SESSION_SYSCALL_RECORD_SCHEMA_VERSION: u32 = 1;
pub const EVENT_METADATA_FILE: &str = "event.json";
pub const STRACE_RAW_FILE: &str = "strace.raw";
pub const FS_RECORDS_FILE: &str = "fs.jsonl";
const SESSION_SYSCALL_ARTIFACT_EXTENSION: &str = "syscalls.jsonl";
const SESSION_SYSCALL_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxAuditConfig {
    pub enabled: bool,
    pub records_dir: PathBuf,
    pub checker_config_dir: Option<PathBuf>,
}

impl SandboxAuditConfig {
    pub fn disabled(records_dir: PathBuf) -> Self {
        Self {
            enabled: false,
            records_dir,
            checker_config_dir: None,
        }
    }

    pub fn for_event(
        &self,
        tool_name: impl AsRef<str>,
        call_id: impl AsRef<str>,
        attempt: AuditAttempt,
    ) -> Option<SandboxAuditExecConfig> {
        if !self.enabled {
            return None;
        }
        let event_id = build_event_id(tool_name.as_ref(), call_id.as_ref(), attempt);
        Some(SandboxAuditExecConfig {
            event_id,
            tool_name: tool_name.as_ref().to_string(),
            call_id: call_id.as_ref().to_string(),
            records_dir: self.records_dir.clone(),
            checker_config_dir: self.checker_config_dir.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAttempt {
    Initial,
    Retry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxAuditExecConfig {
    pub event_id: String,
    pub tool_name: String,
    pub call_id: String,
    pub records_dir: PathBuf,
    pub checker_config_dir: Option<PathBuf>,
}

impl SandboxAuditExecConfig {
    pub fn event_dir(&self) -> PathBuf {
        self.records_dir.join(&self.event_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxAuditEventMetadata {
    pub schema_version: u32,
    pub event_id: String,
    pub tool_name: String,
    pub call_id: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub sandbox: String,
    pub started_at_unix_ms: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsSyscallRecord {
    pub schema_version: u32,
    pub seq: u64,
    pub event_id: String,
    pub source: FsRecordSource,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub syscall: String,
    pub paths: Vec<String>,
    pub access: FsAccessKind,
    pub args: BTreeMap<String, String>,
    pub result: Option<String>,
    pub errno: Option<String>,
    pub raw: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSyscallRecord {
    pub schema_version: u32,
    pub session_id: String,
    pub thread_id: String,
    pub turn_id: String,
    pub call_id: String,
    pub tool_name: String,
    pub event_id: String,
    pub attempt: AuditAttempt,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub seq: u64,
    pub source: FsRecordSource,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub syscall: String,
    pub paths: Vec<String>,
    pub access: FsAccessKind,
    pub args: BTreeMap<String, String>,
    pub result: Option<String>,
    pub errno: Option<String>,
    pub raw: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct SessionSyscallExport<'a> {
    pub rollout_path: &'a Path,
    pub event_dir: &'a Path,
    pub session_id: &'a str,
    pub thread_id: &'a str,
    pub turn_id: &'a str,
    pub attempt: AuditAttempt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsRecordSource {
    Strace,
    Synthetic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccessKind {
    Read,
    Write,
    Metadata,
    Delete,
    Rename,
    Link,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckerInput {
    pub event_id: String,
    pub event_dir: PathBuf,
    pub records_path: PathBuf,
    pub checker_config_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckerDecision {
    Allow,
    Deny { reason: String },
}

/// Checks whether a completed sandbox event may commit its staged filesystem
/// changes to the host. Implementations should treat `CheckerInput.records_path`
/// as an ordered JSONL stream of `FsSyscallRecord` values and return a denial
/// when the event violates their policy.
pub trait SandboxAuditChecker {
    fn check(&self, input: &CheckerInput) -> Result<CheckerDecision, SandboxAuditError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopChecker;

impl SandboxAuditChecker for NoopChecker {
    fn check(&self, _input: &CheckerInput) -> Result<CheckerDecision, SandboxAuditError> {
        Ok(CheckerDecision::Allow)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultChecker;

impl SandboxAuditChecker for DefaultChecker {
    fn check(&self, input: &CheckerInput) -> Result<CheckerDecision, SandboxAuditError> {
        let event_metadata = read_event_metadata(&input.event_dir)?;
        let file = match fs::File::open(&input.records_path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(CheckerDecision::Allow);
            }
            Err(err) => return Err(err.into()),
        };
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: FsSyscallRecord = serde_json::from_str(&line)?;
            if !matches!(record.access, FsAccessKind::Delete | FsAccessKind::Rename) {
                continue;
            }
            if record
                .paths
                .iter()
                .any(|path| requested_path_targets_output(path, &event_metadata.cwd))
            {
                return Ok(CheckerDecision::Deny {
                    reason: format!(
                        "filesystem syscall {} attempted to delete or move a path under output",
                        record.syscall
                    ),
                });
            }
        }
        Ok(CheckerDecision::Allow)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxAuditError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct FinalizedRecords {
    pub records_path: PathBuf,
    pub record_count: usize,
}

pub fn strace_available() -> bool {
    Command::new(strace_program()).arg("-V").output().is_ok()
}

pub fn wrap_command_with_strace(command: Vec<String>, raw_log_path: &Path) -> Vec<String> {
    let mut wrapped = vec![
        strace_program(),
        "-f".to_string(),
        "-qq".to_string(),
        "-s".to_string(),
        "4096".to_string(),
        "-e".to_string(),
        "trace=%file".to_string(),
        "-o".to_string(),
        raw_log_path.to_string_lossy().to_string(),
        "--".to_string(),
    ];
    wrapped.extend(command);
    wrapped
}

pub fn prepare_event_dir(config: &SandboxAuditExecConfig) -> Result<PathBuf, SandboxAuditError> {
    let event_dir = config.event_dir();
    fs::create_dir_all(&event_dir)?;
    Ok(event_dir)
}

pub fn write_event_metadata(
    event_dir: &Path,
    metadata: &SandboxAuditEventMetadata,
) -> Result<(), SandboxAuditError> {
    let path = event_dir.join(EVENT_METADATA_FILE);
    let file = fs::File::create(path)?;
    serde_json::to_writer_pretty(file, metadata)?;
    Ok(())
}

pub fn finalize_strace_log(
    event_id: &str,
    event_dir: &Path,
) -> Result<FinalizedRecords, SandboxAuditError> {
    let raw_path = event_dir.join(STRACE_RAW_FILE);
    let records_path = event_dir.join(FS_RECORDS_FILE);
    let input = match fs::File::open(&raw_path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::File::create(&records_path)?;
            return Ok(FinalizedRecords {
                records_path,
                record_count: 0,
            });
        }
        Err(err) => return Err(err.into()),
    };
    let reader = io::BufReader::new(input);
    let mut output = fs::File::create(&records_path)?;
    let mut record_count = 0;
    for line in reader.lines() {
        let line = line?;
        let Some(record) = parse_strace_line(event_id, record_count as u64, &line) else {
            continue;
        };
        serde_json::to_writer(&mut output, &record)?;
        output.write_all(b"\n")?;
        record_count += 1;
    }
    Ok(FinalizedRecords {
        records_path,
        record_count,
    })
}

pub fn session_syscall_artifact_path(rollout_path: &Path) -> PathBuf {
    rollout_path.with_extension(SESSION_SYSCALL_ARTIFACT_EXTENSION)
}

pub fn append_session_syscall_records(
    export: SessionSyscallExport<'_>,
) -> Result<usize, SandboxAuditError> {
    let event_metadata = read_event_metadata(export.event_dir)?;
    let records = read_session_syscall_records(export, &event_metadata)?;
    let artifact_path = session_syscall_artifact_path(export.rollout_path);
    if let Some(parent) = artifact_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let _lock = AppendLock::acquire(&artifact_path)?;
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&artifact_path)?;
    for record in &records {
        serde_json::to_writer(&mut output, record)?;
        output.write_all(b"\n")?;
    }
    output.flush()?;

    Ok(records.len())
}

pub fn run_default_checker(input: CheckerInput) -> Result<CheckerDecision, SandboxAuditError> {
    DefaultChecker.check(&input)
}

pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn build_event_id(tool_name: &str, call_id: &str, attempt: AuditAttempt) -> String {
    let attempt = match attempt {
        AuditAttempt::Initial => "initial",
        AuditAttempt::Retry => "retry",
    };
    let tool_name = sanitize_event_id_component(tool_name);
    let call_id = sanitize_event_id_component(call_id);
    format!("{tool_name}-{call_id}-{attempt}-{}", uuid::Uuid::new_v4())
}

fn sanitize_event_id_component(value: &str) -> String {
    let mut out = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    out.truncate(80);
    if out.is_empty() {
        "event".to_string()
    } else {
        out
    }
}

fn strace_program() -> String {
    std::env::var("CODEX_SANDBOX_AUDIT_STRACE").unwrap_or_else(|_| "strace".to_string())
}

fn read_event_metadata(event_dir: &Path) -> Result<SandboxAuditEventMetadata, SandboxAuditError> {
    let file = fs::File::open(event_dir.join(EVENT_METADATA_FILE))?;
    Ok(serde_json::from_reader(file)?)
}

fn read_session_syscall_records(
    export: SessionSyscallExport<'_>,
    event_metadata: &SandboxAuditEventMetadata,
) -> Result<Vec<SessionSyscallRecord>, SandboxAuditError> {
    let records_path = export.event_dir.join(FS_RECORDS_FILE);
    let file = match fs::File::open(records_path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let reader = io::BufReader::new(file);
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let fs_record: FsSyscallRecord = serde_json::from_str(&line)?;
        records.push(SessionSyscallRecord {
            schema_version: SESSION_SYSCALL_RECORD_SCHEMA_VERSION,
            session_id: export.session_id.to_string(),
            thread_id: export.thread_id.to_string(),
            turn_id: export.turn_id.to_string(),
            call_id: event_metadata.call_id.clone(),
            tool_name: event_metadata.tool_name.clone(),
            event_id: event_metadata.event_id.clone(),
            attempt: export.attempt,
            command: event_metadata.command.clone(),
            cwd: event_metadata.cwd.clone(),
            seq: fs_record.seq,
            source: fs_record.source,
            pid: fs_record.pid,
            tid: fs_record.tid,
            syscall: fs_record.syscall,
            paths: fs_record.paths,
            access: fs_record.access,
            args: fs_record.args,
            result: fs_record.result,
            errno: fs_record.errno,
            raw: fs_record.raw,
        });
    }
    Ok(records)
}

struct AppendLock {
    path: PathBuf,
}

impl AppendLock {
    fn acquire(artifact_path: &Path) -> io::Result<Self> {
        let path = append_lock_path(artifact_path);
        let started = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id()).ok();
                    return Ok(Self { path });
                }
                Err(err)
                    if err.kind() == io::ErrorKind::AlreadyExists
                        && started.elapsed() < SESSION_SYSCALL_LOCK_TIMEOUT =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "timed out waiting for sandbox audit syscall artifact lock {}",
                            path.display()
                        ),
                    ));
                }
                Err(err) => return Err(err),
            }
        }
    }
}

impl Drop for AppendLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn append_lock_path(artifact_path: &Path) -> PathBuf {
    let mut path = artifact_path.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

fn parse_strace_line(event_id: &str, seq: u64, line: &str) -> Option<FsSyscallRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("+++ ") || trimmed.starts_with("--- ") {
        return None;
    }
    let (pid, body) = split_optional_pid(trimmed);
    let syscall_end = body.find('(')?;
    let syscall = body[..syscall_end].trim();
    if syscall.is_empty() {
        return None;
    }
    let paths = extract_quoted_paths(body);
    if paths.is_empty() && !filesystem_syscall_without_path(syscall) {
        return None;
    }
    let (result, errno) = parse_result(body);
    Some(FsSyscallRecord {
        schema_version: FS_RECORD_SCHEMA_VERSION,
        seq,
        event_id: event_id.to_string(),
        source: FsRecordSource::Strace,
        pid,
        tid: pid,
        syscall: syscall.to_string(),
        paths,
        access: classify_syscall(syscall),
        args: BTreeMap::new(),
        result,
        errno,
        raw: Some(trimmed.to_string()),
    })
}

fn split_optional_pid(line: &str) -> (Option<u32>, &str) {
    let Some((first, rest)) = line.split_once(char::is_whitespace) else {
        return (None, line);
    };
    match first.parse::<u32>() {
        Ok(pid) => (Some(pid), rest.trim_start()),
        Err(_) => (None, line),
    }
}

fn extract_quoted_paths(body: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut chars = body.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for (_, inner) in chars.by_ref() {
            if escaped {
                value.push(match inner {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '\\' => '\\',
                    '"' => '"',
                    other => other,
                });
                escaped = false;
                continue;
            }
            if inner == '\\' {
                escaped = true;
                continue;
            }
            if inner == '"' {
                break;
            }
            value.push(inner);
        }
        if looks_like_path(&value) {
            paths.push(value);
        }
    }
    paths
}

fn looks_like_path(value: &str) -> bool {
    !value.is_empty()
}

pub fn requested_path_targets_output(path: impl AsRef<Path>, cwd: &Path) -> bool {
    let path = path.as_ref();
    if path.is_absolute() {
        return path_has_output_component(path);
    }
    path_has_output_component(&cwd.join(path))
}

pub fn path_has_output_component(path: &Path) -> bool {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                components.clear();
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::Normal(component) => components.push(component.to_os_string()),
        }
    }
    components
        .iter()
        .any(|component| component == std::ffi::OsStr::new("output"))
}

fn parse_result(body: &str) -> (Option<String>, Option<String>) {
    let Some((_, result)) = body.rsplit_once(" = ") else {
        return (None, None);
    };
    let result = result.trim();
    let errno = result
        .strip_prefix("-1 ")
        .and_then(|tail| tail.split_whitespace().next())
        .filter(|value| value.chars().all(|ch| ch.is_ascii_uppercase()))
        .map(str::to_string);
    (Some(result.to_string()), errno)
}

fn classify_syscall(syscall: &str) -> FsAccessKind {
    match syscall {
        "open" | "openat" | "openat2" | "creat" | "mkdir" | "mkdirat" | "mknod" | "mknodat"
        | "truncate" | "ftruncate" | "chmod" | "fchmodat" | "fchmodat2" | "chown" | "fchownat"
        | "utime" | "utimes" | "utimensat" | "setxattr" | "lsetxattr" | "fsetxattr" => {
            FsAccessKind::Write
        }
        "unlink" | "unlinkat" | "rmdir" | "removexattr" | "lremovexattr" | "fremovexattr" => {
            FsAccessKind::Delete
        }
        "rename" | "renameat" | "renameat2" => FsAccessKind::Rename,
        "link" | "linkat" | "symlink" | "symlinkat" => FsAccessKind::Link,
        "stat" | "lstat" | "newfstatat" | "statx" | "access" | "faccessat" | "faccessat2"
        | "readlink" | "readlinkat" | "getxattr" | "lgetxattr" | "listxattr" | "llistxattr" => {
            FsAccessKind::Metadata
        }
        _ => FsAccessKind::Unknown,
    }
}

fn filesystem_syscall_without_path(syscall: &str) -> bool {
    matches!(syscall, "getcwd" | "chdir" | "fchdir")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    #[test]
    fn parses_strace_file_syscall_line() {
        let line =
            r#"1234 openat(AT_FDCWD, "/tmp/example.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3"#;
        let record = parse_strace_line("event-1", 0, line).expect("record");

        assert_eq!(
            record,
            FsSyscallRecord {
                schema_version: FS_RECORD_SCHEMA_VERSION,
                seq: 0,
                event_id: "event-1".to_string(),
                source: FsRecordSource::Strace,
                pid: Some(1234),
                tid: Some(1234),
                syscall: "openat".to_string(),
                paths: vec!["/tmp/example.txt".to_string()],
                access: FsAccessKind::Write,
                args: BTreeMap::new(),
                result: Some("3".to_string()),
                errno: None,
                raw: Some(line.to_string()),
            }
        );
    }

    #[test]
    fn finalizes_raw_strace_to_jsonl_records() {
        let temp = tempdir().expect("temp dir");
        fs::write(
            temp.path().join(STRACE_RAW_FILE),
            "123 statx(AT_FDCWD, \"/tmp/a\", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1) = 0\n",
        )
        .expect("write raw");

        let finalized = finalize_strace_log("event-2", temp.path()).expect("finalize");

        assert_eq!(finalized.record_count, 1);
        let contents = fs::read_to_string(finalized.records_path).expect("read records");
        let record: FsSyscallRecord = serde_json::from_str(contents.trim()).expect("parse record");
        assert_eq!(record.event_id, "event-2");
        assert_eq!(record.access, FsAccessKind::Metadata);
    }

    #[test]
    fn parses_denied_eperm_strace_line() {
        let line =
            r#"123 unlinkat(AT_FDCWD, "output/file.txt", 0) = -1 EPERM (Operation not permitted)"#;
        let record = parse_strace_line("event-1", 0, line).expect("record");

        assert_eq!(record.errno, Some("EPERM".to_string()));
        assert_eq!(
            record.result,
            Some("-1 EPERM (Operation not permitted)".to_string())
        );
        assert_eq!(record.paths, vec!["output/file.txt".to_string()]);
        assert_eq!(record.access, FsAccessKind::Delete);
    }

    #[test]
    fn output_component_predicate_is_exact_and_normalized() {
        assert!(path_has_output_component(Path::new("/tmp/work/output")));
        assert!(path_has_output_component(Path::new(
            "/tmp/work/nested/../output/file"
        )));
        assert!(!path_has_output_component(Path::new(
            "/tmp/work/outputs/file"
        )));
        assert!(!path_has_output_component(Path::new(
            "/tmp/work/Output/file"
        )));
    }

    #[test]
    fn default_checker_denies_output_deletes() {
        let temp = tempdir().expect("temp dir");
        let event_dir = temp.path().join("event-1");
        fs::create_dir_all(&event_dir).expect("create event dir");
        write_test_event_metadata(&event_dir, "event-1");
        let mut record = test_fs_record("event-1", 0, "output/file.txt");
        record.syscall = "unlinkat".to_string();
        record.access = FsAccessKind::Delete;
        write_test_fs_records(&event_dir, &[record]);
        let input = CheckerInput {
            event_id: "event-1".to_string(),
            event_dir: event_dir.clone(),
            records_path: event_dir.join(FS_RECORDS_FILE),
            checker_config_dir: None,
        };

        let decision = run_default_checker(input).expect("checker");

        assert!(matches!(decision, CheckerDecision::Deny { .. }));
    }

    #[test]
    fn default_checker_allows_non_output_deletes() {
        let temp = tempdir().expect("temp dir");
        let event_dir = temp.path().join("event-1");
        fs::create_dir_all(&event_dir).expect("create event dir");
        write_test_event_metadata(&event_dir, "event-1");
        let mut record = test_fs_record("event-1", 0, "scratch/file.txt");
        record.syscall = "unlinkat".to_string();
        record.access = FsAccessKind::Delete;
        write_test_fs_records(&event_dir, &[record]);
        let input = CheckerInput {
            event_id: "event-1".to_string(),
            event_dir: event_dir.clone(),
            records_path: event_dir.join(FS_RECORDS_FILE),
            checker_config_dir: None,
        };

        let decision = run_default_checker(input).expect("checker");

        assert_eq!(decision, CheckerDecision::Allow);
    }

    #[test]
    fn derives_session_syscall_artifact_path_from_rollout_path() {
        let rollout_path =
            Path::new("/tmp/codex/sessions/2026/05/21/rollout-2026-05-21T21-55-31-id.jsonl");

        assert_eq!(
            session_syscall_artifact_path(rollout_path),
            PathBuf::from(
                "/tmp/codex/sessions/2026/05/21/rollout-2026-05-21T21-55-31-id.syscalls.jsonl"
            )
        );
    }

    #[test]
    fn appends_session_syscall_records_with_session_metadata() {
        let temp = tempdir().expect("temp dir");
        let event_dir = temp.path().join("event-1");
        fs::create_dir_all(&event_dir).expect("create event dir");
        write_test_event_metadata(&event_dir, "event-1");
        write_test_fs_records(
            &event_dir,
            &[test_fs_record("event-1", 0, "/tmp/example.txt")],
        );
        let rollout_path = temp.path().join("rollout-2026-05-21T21-55-31-id.jsonl");

        let count = append_session_syscall_records(SessionSyscallExport {
            rollout_path: &rollout_path,
            event_dir: &event_dir,
            session_id: "session-1",
            thread_id: "thread-1",
            turn_id: "turn-1",
            attempt: AuditAttempt::Initial,
        })
        .expect("append session records");

        assert_eq!(count, 1);
        let artifact_path = session_syscall_artifact_path(&rollout_path);
        let records = read_session_syscall_records_from_artifact(&artifact_path);
        assert_eq!(
            records,
            vec![SessionSyscallRecord {
                schema_version: SESSION_SYSCALL_RECORD_SCHEMA_VERSION,
                session_id: "session-1".to_string(),
                thread_id: "thread-1".to_string(),
                turn_id: "turn-1".to_string(),
                call_id: "call-1".to_string(),
                tool_name: "shell".to_string(),
                event_id: "event-1".to_string(),
                attempt: AuditAttempt::Initial,
                command: vec!["bash".to_string(), "-lc".to_string(), "touch x".to_string()],
                cwd: PathBuf::from("/tmp/work"),
                seq: 0,
                source: FsRecordSource::Strace,
                pid: Some(123),
                tid: Some(123),
                syscall: "openat".to_string(),
                paths: vec!["/tmp/example.txt".to_string()],
                access: FsAccessKind::Write,
                args: BTreeMap::new(),
                result: Some("3".to_string()),
                errno: None,
                raw: Some("123 openat(...) = 3".to_string()),
            }]
        );
    }

    #[test]
    fn appends_multiple_events_to_same_session_artifact() {
        let temp = tempdir().expect("temp dir");
        let rollout_path = temp.path().join("rollout.jsonl");
        let event_dir_1 = temp.path().join("event-1");
        let event_dir_2 = temp.path().join("event-2");
        fs::create_dir_all(&event_dir_1).expect("create first event dir");
        fs::create_dir_all(&event_dir_2).expect("create second event dir");
        write_test_event_metadata(&event_dir_1, "event-1");
        write_test_event_metadata(&event_dir_2, "event-2");
        write_test_fs_records(&event_dir_1, &[test_fs_record("event-1", 0, "/tmp/a")]);
        write_test_fs_records(&event_dir_2, &[test_fs_record("event-2", 0, "/tmp/b")]);

        for (event_dir, attempt) in [
            (event_dir_1.as_path(), AuditAttempt::Initial),
            (event_dir_2.as_path(), AuditAttempt::Retry),
        ] {
            append_session_syscall_records(SessionSyscallExport {
                rollout_path: &rollout_path,
                event_dir,
                session_id: "session-1",
                thread_id: "thread-1",
                turn_id: "turn-1",
                attempt,
            })
            .expect("append session records");
        }

        let artifact_path = session_syscall_artifact_path(&rollout_path);
        let records = read_session_syscall_records_from_artifact(&artifact_path);
        let event_ids = records
            .iter()
            .map(|record| record.event_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(event_ids, vec!["event-1", "event-2"]);
        assert_eq!(records[0].attempt, AuditAttempt::Initial);
        assert_eq!(records[1].attempt, AuditAttempt::Retry);
    }

    #[test]
    fn empty_fs_records_create_empty_session_artifact() {
        let temp = tempdir().expect("temp dir");
        let event_dir = temp.path().join("event-1");
        fs::create_dir_all(&event_dir).expect("create event dir");
        write_test_event_metadata(&event_dir, "event-1");
        fs::File::create(event_dir.join(FS_RECORDS_FILE)).expect("create fs records");
        let rollout_path = temp.path().join("rollout.jsonl");

        let count = append_session_syscall_records(SessionSyscallExport {
            rollout_path: &rollout_path,
            event_dir: &event_dir,
            session_id: "session-1",
            thread_id: "thread-1",
            turn_id: "turn-1",
            attempt: AuditAttempt::Initial,
        })
        .expect("append session records");

        assert_eq!(count, 0);
        let artifact_path = session_syscall_artifact_path(&rollout_path);
        assert_eq!(
            fs::read_to_string(artifact_path).expect("read artifact"),
            ""
        );
    }

    #[test]
    fn missing_fs_records_create_empty_session_artifact() {
        let temp = tempdir().expect("temp dir");
        let event_dir = temp.path().join("event-1");
        fs::create_dir_all(&event_dir).expect("create event dir");
        write_test_event_metadata(&event_dir, "event-1");
        let rollout_path = temp.path().join("rollout.jsonl");

        let count = append_session_syscall_records(SessionSyscallExport {
            rollout_path: &rollout_path,
            event_dir: &event_dir,
            session_id: "session-1",
            thread_id: "thread-1",
            turn_id: "turn-1",
            attempt: AuditAttempt::Initial,
        })
        .expect("append session records");

        assert_eq!(count, 0);
        let artifact_path = session_syscall_artifact_path(&rollout_path);
        assert_eq!(
            fs::read_to_string(artifact_path).expect("read artifact"),
            ""
        );
    }

    #[test]
    fn writable_root_transaction_commits_changes_and_deletions() {
        let host = tempdir().expect("host");
        let event = tempdir().expect("event");
        fs::write(host.path().join("keep.txt"), "old").expect("write keep");
        fs::write(host.path().join("delete.txt"), "delete").expect("write delete");

        let transaction = WritableRootTransaction::start(event.path(), [host.path().to_path_buf()])
            .expect("start");
        let staged = &transaction.mappings()[0].staged_root;
        fs::write(staged.join("keep.txt"), "new").expect("update staged");
        fs::write(staged.join("add.txt"), "add").expect("add staged");
        fs::remove_file(staged.join("delete.txt")).expect("delete staged");

        transaction.commit().expect("commit");

        assert_eq!(
            fs::read_to_string(host.path().join("keep.txt")).unwrap(),
            "new"
        );
        assert_eq!(
            fs::read_to_string(host.path().join("add.txt")).unwrap(),
            "add"
        );
        assert!(!host.path().join("delete.txt").exists());
    }

    #[test]
    fn writable_root_transaction_rejects_stage_inside_writable_root() {
        let host = tempdir().expect("host");
        let event = host.path().join(".codex").join("audit-event");

        let result = WritableRootTransaction::start(&event, [host.path().to_path_buf()]);

        assert!(result.is_err());
        assert!(!event.exists());
    }

    fn write_test_event_metadata(event_dir: &Path, event_id: &str) {
        write_event_metadata(
            event_dir,
            &SandboxAuditEventMetadata {
                schema_version: FS_RECORD_SCHEMA_VERSION,
                event_id: event_id.to_string(),
                tool_name: "shell".to_string(),
                call_id: "call-1".to_string(),
                command: vec!["bash".to_string(), "-lc".to_string(), "touch x".to_string()],
                cwd: PathBuf::from("/tmp/work"),
                sandbox: "linux-seccomp-bwrap".to_string(),
                started_at_unix_ms: 123,
            },
        )
        .expect("write event metadata");
    }

    fn write_test_fs_records(event_dir: &Path, records: &[FsSyscallRecord]) {
        let mut output =
            fs::File::create(event_dir.join(FS_RECORDS_FILE)).expect("create fs records");
        for record in records {
            serde_json::to_writer(&mut output, record).expect("write record");
            output.write_all(b"\n").expect("write newline");
        }
    }

    fn test_fs_record(event_id: &str, seq: u64, path: &str) -> FsSyscallRecord {
        FsSyscallRecord {
            schema_version: FS_RECORD_SCHEMA_VERSION,
            seq,
            event_id: event_id.to_string(),
            source: FsRecordSource::Strace,
            pid: Some(123),
            tid: Some(123),
            syscall: "openat".to_string(),
            paths: vec![path.to_string()],
            access: FsAccessKind::Write,
            args: BTreeMap::new(),
            result: Some("3".to_string()),
            errno: None,
            raw: Some("123 openat(...) = 3".to_string()),
        }
    }

    fn read_session_syscall_records_from_artifact(path: &Path) -> Vec<SessionSyscallRecord> {
        fs::read_to_string(path)
            .expect("read artifact")
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse session syscall record"))
            .collect()
    }
}
