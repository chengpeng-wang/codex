use codex_protocol::protocol::FileSystemSandboxPolicy;
use codex_sandbox_audit::CheckerDecision;
use codex_sandbox_audit::CheckerInput;
use codex_sandbox_audit::FS_RECORD_SCHEMA_VERSION;
use codex_sandbox_audit::STRACE_RAW_FILE;
use codex_sandbox_audit::SandboxAuditEventMetadata;
use codex_sandbox_audit::SandboxAuditExecConfig;
use codex_sandbox_audit::WritableRootTransaction;
use codex_sandbox_audit::finalize_strace_log;
use codex_sandbox_audit::now_unix_ms;
use codex_sandbox_audit::prepare_event_dir;
use codex_sandbox_audit::run_default_checker;
use codex_sandbox_audit::wrap_command_with_strace;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

const SANDBOX_AUDIT_MOUNT_ROOT: &str = "/tmp/codex-sandbox-audit";

#[derive(Debug)]
pub(crate) struct SandboxAuditRun {
    config: SandboxAuditExecConfig,
    event_dir: PathBuf,
    sandbox_event_dir: PathBuf,
    transaction: WritableRootTransaction,
    inner_command: Vec<String>,
}

impl SandboxAuditRun {
    pub(crate) fn prepare(
        config: SandboxAuditExecConfig,
        file_system_sandbox_policy: &FileSystemSandboxPolicy,
        sandbox_policy_cwd: &Path,
        inner_command: Vec<String>,
        command_cwd: &Path,
        audit_command: Vec<String>,
    ) -> std::result::Result<Self, codex_sandbox_audit::SandboxAuditError> {
        let event_dir = prepare_event_dir(&config)?;
        let writable_roots = file_system_sandbox_policy
            .get_writable_roots_with_cwd(sandbox_policy_cwd)
            .into_iter()
            .map(|root| root.root.into_path_buf());
        let transaction = WritableRootTransaction::start(&event_dir, writable_roots)?;
        let sandbox_event_dir = Path::new(SANDBOX_AUDIT_MOUNT_ROOT).join(&config.event_id);

        codex_sandbox_audit::write_event_metadata(
            &event_dir,
            &SandboxAuditEventMetadata {
                schema_version: FS_RECORD_SCHEMA_VERSION,
                event_id: config.event_id.clone(),
                tool_name: config.tool_name.clone(),
                call_id: config.call_id.clone(),
                command: audit_command,
                cwd: command_cwd.to_path_buf(),
                sandbox: "linux-seccomp-bwrap".to_string(),
                started_at_unix_ms: now_unix_ms(),
            },
        )?;

        Ok(Self {
            config,
            event_dir,
            sandbox_event_dir,
            transaction,
            inner_command,
        })
    }

    pub(crate) fn writable_root_overrides(&self) -> BTreeMap<PathBuf, PathBuf> {
        self.transaction
            .mappings()
            .iter()
            .map(|mapping| (mapping.host_root.clone(), mapping.staged_root.clone()))
            .collect()
    }

    pub(crate) fn wrapped_inner_command(&self) -> Vec<String> {
        wrap_command_with_strace(
            self.inner_command.clone(),
            &self.sandbox_event_dir.join(STRACE_RAW_FILE),
        )
    }

    pub(crate) fn append_event_bind(&self, argv: &mut Vec<String>) {
        let command_separator_index = argv
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or_else(|| panic!("bubblewrap argv is missing command separator '--'"));
        let sandbox_parent = Path::new(SANDBOX_AUDIT_MOUNT_ROOT);
        argv.splice(
            command_separator_index..command_separator_index,
            [
                "--dir".to_string(),
                sandbox_parent.to_string_lossy().to_string(),
                "--dir".to_string(),
                self.sandbox_event_dir.to_string_lossy().to_string(),
                "--bind".to_string(),
                self.event_dir.to_string_lossy().to_string(),
                self.sandbox_event_dir.to_string_lossy().to_string(),
            ],
        );
    }

    pub(crate) fn finalize(&self) -> bool {
        let finalized = match finalize_strace_log(&self.config.event_id, &self.event_dir) {
            Ok(finalized) => finalized,
            Err(err) => {
                eprintln!("sandbox audit failed to finalize syscall records: {err}");
                return true;
            }
        };
        let decision = run_default_checker(CheckerInput {
            event_id: self.config.event_id.clone(),
            event_dir: self.event_dir.clone(),
            records_path: finalized.records_path,
            checker_config_dir: self.config.checker_config_dir.clone(),
        });
        match decision {
            Ok(CheckerDecision::Allow) => match self.transaction.commit() {
                Ok(()) => false,
                Err(err) => {
                    eprintln!("sandbox audit failed to commit staged writes: {err}");
                    true
                }
            },
            Ok(CheckerDecision::Deny { reason }) => {
                eprintln!("audit denied filesystem writes: {reason}");
                true
            }
            Err(err) => {
                eprintln!("sandbox audit checker failed: {err}");
                true
            }
        }
    }
}
