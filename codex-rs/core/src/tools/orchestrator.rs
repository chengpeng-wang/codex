/*
Module: orchestrator

Central place for approvals + sandbox selection + retry semantics. Drives a
simple sequence for any ToolRuntime: approval → select sandbox → attempt →
retry with an escalated sandbox strategy on denial (no re‑approval thanks to
caching).
*/
use crate::guardian::guardian_rejection_message;
use crate::guardian::guardian_timeout_message;
use crate::guardian::new_guardian_review_id;
use crate::guardian::routes_approval_to_guardian;
use crate::hook_runtime::run_permission_request_hooks;
use crate::network_policy_decision::network_approval_context_from_payload;
use crate::tools::flat_tool_name;
use crate::tools::network_approval::ActiveNetworkApproval;
use crate::tools::network_approval::DeferredNetworkApproval;
use crate::tools::network_approval::NetworkApprovalMode;
use crate::tools::network_approval::begin_network_approval;
use crate::tools::network_approval::finish_deferred_network_approval;
use crate::tools::network_approval::finish_immediate_network_approval;
use crate::tools::sandboxing::ApprovalCtx;
use crate::tools::sandboxing::ExecApprovalRequirement;
use crate::tools::sandboxing::SandboxAttempt;
use crate::tools::sandboxing::SandboxOverride;
use crate::tools::sandboxing::ToolCtx;
use crate::tools::sandboxing::ToolError;
use crate::tools::sandboxing::ToolRuntime;
use crate::tools::sandboxing::default_exec_approval_requirement;
use crate::tools::sandboxing::sandbox_override_for_first_attempt;
use codex_hooks::PermissionRequestDecision;
use codex_otel::ToolDecisionSource;
use codex_protocol::error::CodexErr;
use codex_protocol::error::SandboxErr;
use codex_protocol::exec_output::ExecToolCallOutput;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::NetworkPolicyRuleAction;
use codex_protocol::protocol::ReviewDecision;
use codex_sandbox_audit::AuditAttempt;
use codex_sandbox_audit::SandboxAuditExecConfig;
use codex_sandbox_audit::SessionSyscallExport;
use codex_sandbox_audit::append_session_syscall_records;
use codex_sandboxing::SandboxManager;
use codex_sandboxing::SandboxType;
use std::path::Path;

pub(crate) struct ToolOrchestrator {
    sandbox: SandboxManager,
}

pub(crate) struct OrchestratorRunResult<Out> {
    pub output: Out,
    pub deferred_network_approval: Option<DeferredNetworkApproval>,
}

impl ToolOrchestrator {
    pub fn new() -> Self {
        Self {
            sandbox: SandboxManager::new(),
        }
    }

    async fn run_attempt<Rq, Out, T>(
        tool: &mut T,
        req: &Rq,
        tool_ctx: &ToolCtx,
        attempt: &SandboxAttempt<'_>,
        managed_network_active: bool,
    ) -> (Result<Out, ToolError>, Option<DeferredNetworkApproval>)
    where
        T: ToolRuntime<Rq, Out>,
    {
        let network_approval = begin_network_approval(
            &tool_ctx.session,
            &tool_ctx.turn.sub_id,
            managed_network_active,
            tool.network_approval_spec(req, tool_ctx),
        )
        .await;

        let attempt_tool_ctx = ToolCtx {
            session: tool_ctx.session.clone(),
            turn: tool_ctx.turn.clone(),
            call_id: tool_ctx.call_id.clone(),
            tool_name: tool_ctx.tool_name.clone(),
        };
        let attempt_with_network_approval = SandboxAttempt {
            sandbox: attempt.sandbox,
            permissions: attempt.permissions,
            enforce_managed_network: attempt.enforce_managed_network,
            manager: attempt.manager,
            sandbox_cwd: attempt.sandbox_cwd,
            codex_linux_sandbox_exe: attempt.codex_linux_sandbox_exe,
            use_legacy_landlock: attempt.use_legacy_landlock,
            windows_sandbox_level: attempt.windows_sandbox_level,
            windows_sandbox_private_desktop: attempt.windows_sandbox_private_desktop,
            network_denial_cancellation_token: network_approval
                .as_ref()
                .map(ActiveNetworkApproval::cancellation_token),
            sandbox_audit: attempt.sandbox_audit.clone(),
        };
        let run_result = tool
            .run(req, &attempt_with_network_approval, &attempt_tool_ctx)
            .await;

        let Some(network_approval) = network_approval else {
            return (run_result, None);
        };

        match network_approval.mode() {
            NetworkApprovalMode::Immediate => {
                let finalize_result =
                    finish_immediate_network_approval(&tool_ctx.session, network_approval).await;
                if let Err(err) = finalize_result {
                    return (Err(err), None);
                }
                (run_result, None)
            }
            NetworkApprovalMode::Deferred => {
                let deferred = network_approval.into_deferred();
                if run_result.is_err() {
                    let finalize_result =
                        finish_deferred_network_approval(&tool_ctx.session, deferred).await;
                    if let Err(err) = finalize_result {
                        return (Err(err), None);
                    }
                    return (run_result, None);
                }
                (run_result, deferred)
            }
        }
    }

    pub async fn run<Rq, Out, T>(
        &mut self,
        tool: &mut T,
        req: &Rq,
        tool_ctx: &ToolCtx,
        turn_ctx: &crate::session::turn_context::TurnContext,
        approval_policy: AskForApproval,
    ) -> Result<OrchestratorRunResult<Out>, ToolError>
    where
        T: ToolRuntime<Rq, Out>,
    {
        let otel = turn_ctx.session_telemetry.clone();
        let otel_tn = flat_tool_name(&tool_ctx.tool_name).into_owned();
        let otel_ci = &tool_ctx.call_id;
        let strict_auto_review = tool_ctx.session.strict_auto_review_enabled_for_turn().await;
        let use_guardian = routes_approval_to_guardian(turn_ctx) || strict_auto_review;

        // 1) Approval
        let mut already_approved = false;

        let file_system_sandbox_policy = turn_ctx.file_system_sandbox_policy();
        let network_sandbox_policy = turn_ctx.network_sandbox_policy();
        let requirement = tool.exec_approval_requirement(req).unwrap_or_else(|| {
            default_exec_approval_requirement(approval_policy, &file_system_sandbox_policy)
        });
        match &requirement {
            ExecApprovalRequirement::Skip { .. } => {
                if strict_auto_review {
                    let guardian_review_id = Some(new_guardian_review_id());
                    let approval_ctx = ApprovalCtx {
                        session: &tool_ctx.session,
                        turn: &tool_ctx.turn,
                        call_id: &tool_ctx.call_id,
                        guardian_review_id: guardian_review_id.clone(),
                        retry_reason: None,
                        network_approval_context: None,
                    };
                    let decision = Self::request_approval(
                        tool,
                        req,
                        tool_ctx.call_id.as_str(),
                        approval_ctx,
                        tool_ctx,
                        /*evaluate_permission_request_hooks*/ false,
                        &otel,
                    )
                    .await?;
                    Self::reject_if_not_approved(tool_ctx, guardian_review_id.as_deref(), decision)
                        .await?;
                    already_approved = true;
                } else {
                    otel.tool_decision(
                        &otel_tn,
                        otel_ci,
                        &ReviewDecision::Approved,
                        ToolDecisionSource::Config,
                    );
                }
            }
            ExecApprovalRequirement::Forbidden { reason } => {
                return Err(ToolError::Rejected(reason.clone()));
            }
            ExecApprovalRequirement::NeedsApproval { reason, .. } => {
                let guardian_review_id = use_guardian.then(new_guardian_review_id);
                let approval_ctx = ApprovalCtx {
                    session: &tool_ctx.session,
                    turn: &tool_ctx.turn,
                    call_id: &tool_ctx.call_id,
                    guardian_review_id: guardian_review_id.clone(),
                    retry_reason: reason.clone(),
                    network_approval_context: None,
                };
                let decision = Self::request_approval(
                    tool,
                    req,
                    tool_ctx.call_id.as_str(),
                    approval_ctx,
                    tool_ctx,
                    /*evaluate_permission_request_hooks*/ !strict_auto_review,
                    &otel,
                )
                .await?;

                Self::reject_if_not_approved(tool_ctx, guardian_review_id.as_deref(), decision)
                    .await?;
                already_approved = true;
            }
        }

        // 2) First attempt under the selected sandbox.
        let sandbox_override = sandbox_override_for_first_attempt(
            tool.sandbox_permissions(req),
            &requirement,
            &file_system_sandbox_policy,
        );
        let managed_network_active = turn_ctx.network.is_some();
        let initial_sandbox = match sandbox_override {
            SandboxOverride::BypassSandboxFirstAttempt => SandboxType::None,
            SandboxOverride::NoOverride => self.sandbox.select_initial(
                &file_system_sandbox_policy,
                network_sandbox_policy,
                tool.sandbox_preference(),
                turn_ctx.windows_sandbox_level,
                managed_network_active,
            ),
        };
        let sandbox_audit = Self::sandbox_audit_for_attempt(
            tool,
            tool_ctx,
            turn_ctx,
            initial_sandbox,
            &file_system_sandbox_policy,
            AuditAttempt::Initial,
        );

        // Platform-specific flag gating is handled by SandboxManager::select_initial.
        let use_legacy_landlock = turn_ctx.features.use_legacy_landlock();
        #[allow(deprecated)]
        let sandbox_cwd = tool.sandbox_cwd(req).unwrap_or(&turn_ctx.cwd);
        let initial_attempt = SandboxAttempt {
            sandbox: initial_sandbox,
            permissions: &turn_ctx.permission_profile,
            enforce_managed_network: managed_network_active,
            manager: &self.sandbox,
            sandbox_cwd,
            codex_linux_sandbox_exe: turn_ctx.codex_linux_sandbox_exe.as_ref(),
            use_legacy_landlock,
            windows_sandbox_level: turn_ctx.windows_sandbox_level,
            windows_sandbox_private_desktop: turn_ctx
                .config
                .permissions
                .windows_sandbox_private_desktop,
            network_denial_cancellation_token: None,
            sandbox_audit,
        };

        let (first_result, first_deferred_network_approval) = Self::run_attempt(
            tool,
            req,
            tool_ctx,
            &initial_attempt,
            managed_network_active,
        )
        .await;
        Self::export_sandbox_audit_records(
            tool_ctx,
            initial_attempt.sandbox_audit.as_ref(),
            AuditAttempt::Initial,
        )
        .await;
        match first_result {
            Ok(out) => {
                // We have a successful initial result
                Ok(OrchestratorRunResult {
                    output: out,
                    deferred_network_approval: first_deferred_network_approval,
                })
            }
            Err(ToolError::Codex(CodexErr::Sandbox(SandboxErr::Denied {
                output,
                network_policy_decision,
            }))) => {
                let network_approval_context = if managed_network_active {
                    network_policy_decision
                        .as_ref()
                        .and_then(network_approval_context_from_payload)
                } else {
                    None
                };
                if network_policy_decision.is_some() && network_approval_context.is_none() {
                    return Err(ToolError::Codex(CodexErr::Sandbox(SandboxErr::Denied {
                        output,
                        network_policy_decision,
                    })));
                }
                if !tool.escalate_on_failure() {
                    return Err(ToolError::Codex(CodexErr::Sandbox(SandboxErr::Denied {
                        output,
                        network_policy_decision,
                    })));
                }
                // Under `Never` or `OnRequest`, do not retry without sandbox;
                // surface a concise sandbox denial that preserves the
                // original output.
                if !tool.wants_no_sandbox_approval(approval_policy) {
                    let allow_on_request_network_prompt =
                        matches!(approval_policy, AskForApproval::OnRequest)
                            && network_approval_context.is_some()
                            && matches!(
                                default_exec_approval_requirement(
                                    approval_policy,
                                    &file_system_sandbox_policy
                                ),
                                ExecApprovalRequirement::NeedsApproval { .. }
                            );
                    if !allow_on_request_network_prompt {
                        return Err(ToolError::Codex(CodexErr::Sandbox(SandboxErr::Denied {
                            output,
                            network_policy_decision,
                        })));
                    }
                }
                let retry_reason =
                    if let Some(network_approval_context) = network_approval_context.as_ref() {
                        format!(
                            "Network access to \"{}\" is blocked by policy.",
                            network_approval_context.host
                        )
                    } else {
                        build_denial_reason_from_output(output.as_ref())
                    };

                // Strict auto-review approval covers the sandboxed attempt only;
                // retrying without the sandbox requires a fresh guardian review.
                let bypass_retry_approval = !strict_auto_review
                    && tool.should_bypass_approval(approval_policy, already_approved)
                    && network_approval_context.is_none();
                if !bypass_retry_approval {
                    let guardian_review_id = use_guardian.then(new_guardian_review_id);
                    let approval_ctx = ApprovalCtx {
                        session: &tool_ctx.session,
                        turn: &tool_ctx.turn,
                        call_id: &tool_ctx.call_id,
                        guardian_review_id: guardian_review_id.clone(),
                        retry_reason: Some(retry_reason),
                        network_approval_context: network_approval_context.clone(),
                    };

                    let permission_request_run_id = format!("{}:retry", tool_ctx.call_id);
                    let decision = Self::request_approval(
                        tool,
                        req,
                        &permission_request_run_id,
                        approval_ctx,
                        tool_ctx,
                        /*evaluate_permission_request_hooks*/ !strict_auto_review,
                        &otel,
                    )
                    .await?;

                    Self::reject_if_not_approved(tool_ctx, guardian_review_id.as_deref(), decision)
                        .await?;
                }

                let retry_sandbox_audit = Self::sandbox_audit_for_attempt(
                    tool,
                    tool_ctx,
                    turn_ctx,
                    SandboxType::None,
                    &file_system_sandbox_policy,
                    AuditAttempt::Retry,
                );
                let retry_linux_sandbox_exe = if retry_sandbox_audit.is_some() {
                    turn_ctx.codex_linux_sandbox_exe.as_ref()
                } else {
                    None
                };
                let escalated_attempt = SandboxAttempt {
                    sandbox: SandboxType::None,
                    permissions: &turn_ctx.permission_profile,
                    enforce_managed_network: managed_network_active,
                    manager: &self.sandbox,
                    sandbox_cwd,
                    codex_linux_sandbox_exe: retry_linux_sandbox_exe,
                    use_legacy_landlock,
                    windows_sandbox_level: turn_ctx.windows_sandbox_level,
                    windows_sandbox_private_desktop: turn_ctx
                        .config
                        .permissions
                        .windows_sandbox_private_desktop,
                    network_denial_cancellation_token: None,
                    sandbox_audit: retry_sandbox_audit,
                };

                // Second attempt.
                let (retry_result, retry_deferred_network_approval) = Self::run_attempt(
                    tool,
                    req,
                    tool_ctx,
                    &escalated_attempt,
                    managed_network_active,
                )
                .await;
                Self::export_sandbox_audit_records(
                    tool_ctx,
                    escalated_attempt.sandbox_audit.as_ref(),
                    AuditAttempt::Retry,
                )
                .await;
                retry_result.map(|output| OrchestratorRunResult {
                    output,
                    deferred_network_approval: retry_deferred_network_approval,
                })
            }
            Err(err) => Err(err),
        }
    }

    fn sandbox_audit_for_attempt<Rq, Out, T>(
        tool: &T,
        tool_ctx: &ToolCtx,
        turn_ctx: &crate::session::turn_context::TurnContext,
        sandbox: SandboxType,
        file_system_sandbox_policy: &codex_protocol::protocol::FileSystemSandboxPolicy,
        attempt: AuditAttempt,
    ) -> Option<SandboxAuditExecConfig>
    where
        T: ToolRuntime<Rq, Out>,
    {
        if !cfg!(target_os = "linux") || !tool.sandbox_audit_support().is_enabled() {
            return None;
        }
        let audit_supported_for_sandbox = match sandbox {
            SandboxType::None => true,
            SandboxType::LinuxSeccomp => !file_system_sandbox_policy.has_full_disk_write_access(),
            SandboxType::MacosSeatbelt | SandboxType::WindowsRestrictedToken => false,
        };
        if !audit_supported_for_sandbox {
            return None;
        }
        turn_ctx.config.sandbox_audit.for_event(
            flat_tool_name(&tool_ctx.tool_name),
            &tool_ctx.call_id,
            attempt,
        )
    }

    async fn export_sandbox_audit_records(
        tool_ctx: &ToolCtx,
        sandbox_audit: Option<&SandboxAuditExecConfig>,
        attempt: AuditAttempt,
    ) {
        let Some(sandbox_audit) = sandbox_audit else {
            return;
        };
        let session_id = tool_ctx.session.session_id().to_string();
        let thread_id = tool_ctx.session.thread_id().to_string();
        let turn_id = tool_ctx.turn.sub_id.clone();
        let rollout_path = match tool_ctx.session.current_rollout_path().await {
            Ok(Some(path)) => path,
            Ok(None) => {
                tracing::warn!(
                    event_id = %sandbox_audit.event_id,
                    call_id = %tool_ctx.call_id,
                    "skipping sandbox audit syscall session artifact: no local rollout path"
                );
                return;
            }
            Err(err) => {
                tracing::warn!(
                    event_id = %sandbox_audit.event_id,
                    call_id = %tool_ctx.call_id,
                    "skipping sandbox audit syscall session artifact: failed to locate rollout path: {err:#}"
                );
                return;
            }
        };

        match append_sandbox_audit_records_to_rollout(
            rollout_path.as_path(),
            session_id.as_str(),
            thread_id.as_str(),
            turn_id.as_str(),
            sandbox_audit,
            attempt,
        ) {
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(
                    event_id = %sandbox_audit.event_id,
                    call_id = %tool_ctx.call_id,
                    "failed to append sandbox audit syscall session artifact: {err}"
                );
            }
        }
    }

    // PermissionRequest hooks take top precedence for answering approval
    // prompts. If no matching hook returns a decision, fall back to the
    // normal guardian or user approval path.
    async fn request_approval<Rq, Out, T>(
        tool: &mut T,
        req: &Rq,
        permission_request_run_id: &str,
        approval_ctx: ApprovalCtx<'_>,
        tool_ctx: &ToolCtx,
        evaluate_permission_request_hooks: bool,
        otel: &codex_otel::SessionTelemetry,
    ) -> Result<ReviewDecision, ToolError>
    where
        T: ToolRuntime<Rq, Out>,
    {
        if evaluate_permission_request_hooks
            && let Some(permission_request) = tool.permission_request_payload(req)
        {
            let tool_name = flat_tool_name(&tool_ctx.tool_name);
            match run_permission_request_hooks(
                approval_ctx.session,
                approval_ctx.turn,
                permission_request_run_id,
                permission_request,
            )
            .await
            {
                Some(PermissionRequestDecision::Allow) => {
                    let decision = ReviewDecision::Approved;
                    otel.tool_decision(
                        tool_name.as_ref(),
                        &tool_ctx.call_id,
                        &decision,
                        ToolDecisionSource::Config,
                    );
                    return Ok(decision);
                }
                Some(PermissionRequestDecision::Deny { message }) => {
                    let decision = ReviewDecision::Denied;
                    otel.tool_decision(
                        tool_name.as_ref(),
                        &tool_ctx.call_id,
                        &decision,
                        ToolDecisionSource::Config,
                    );
                    return Err(ToolError::Rejected(message));
                }
                None => {}
            }
        }

        let otel_source = if approval_ctx.guardian_review_id.is_some() {
            ToolDecisionSource::AutomatedReviewer
        } else {
            ToolDecisionSource::User
        };
        let decision = tool.start_approval_async(req, approval_ctx).await;
        let tool_name = flat_tool_name(&tool_ctx.tool_name);
        otel.tool_decision(
            tool_name.as_ref(),
            &tool_ctx.call_id,
            &decision,
            otel_source,
        );
        Ok(decision)
    }

    async fn reject_if_not_approved(
        tool_ctx: &ToolCtx,
        guardian_review_id: Option<&str>,
        decision: ReviewDecision,
    ) -> Result<(), ToolError> {
        match decision {
            ReviewDecision::Denied | ReviewDecision::Abort => {
                let reason = if let Some(review_id) = guardian_review_id {
                    guardian_rejection_message(tool_ctx.session.as_ref(), review_id).await
                } else {
                    "rejected by user".to_string()
                };
                Err(ToolError::Rejected(reason))
            }
            ReviewDecision::TimedOut => Err(ToolError::Rejected(guardian_timeout_message())),
            ReviewDecision::Approved
            | ReviewDecision::ApprovedExecpolicyAmendment { .. }
            | ReviewDecision::ApprovedForSession => Ok(()),
            ReviewDecision::NetworkPolicyAmendment {
                network_policy_amendment,
            } => match network_policy_amendment.action {
                NetworkPolicyRuleAction::Allow => Ok(()),
                NetworkPolicyRuleAction::Deny => {
                    Err(ToolError::Rejected("rejected by user".to_string()))
                }
            },
        }
    }
}

fn append_sandbox_audit_records_to_rollout(
    rollout_path: &Path,
    session_id: &str,
    thread_id: &str,
    turn_id: &str,
    sandbox_audit: &SandboxAuditExecConfig,
    attempt: AuditAttempt,
) -> Result<usize, codex_sandbox_audit::SandboxAuditError> {
    let event_dir = sandbox_audit.event_dir();
    append_session_syscall_records(SessionSyscallExport {
        rollout_path,
        event_dir: event_dir.as_path(),
        session_id,
        thread_id,
        turn_id,
        attempt,
    })
}

fn build_denial_reason_from_output(_output: &ExecToolCallOutput) -> String {
    // Keep approval reason terse and stable for UX/tests, but accept the
    // output so we can evolve heuristics later without touching call sites.
    "command failed; retry without sandbox?".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_sandbox_audit::FS_RECORD_SCHEMA_VERSION;
    use codex_sandbox_audit::FsAccessKind;
    use codex_sandbox_audit::FsRecordSource;
    use codex_sandbox_audit::FsSyscallRecord;
    use codex_sandbox_audit::SESSION_SYSCALL_RECORD_SCHEMA_VERSION;
    use codex_sandbox_audit::SandboxAuditEventMetadata;
    use codex_sandbox_audit::SessionSyscallRecord;
    use codex_sandbox_audit::session_syscall_artifact_path;
    use codex_sandbox_audit::write_event_metadata;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn appends_sandbox_audit_records_to_current_rollout_artifact() {
        let temp = tempdir().expect("temp dir");
        let records_dir = temp.path().join("events");
        let event_id = "event-1";
        let event_dir = records_dir.join(event_id);
        fs::create_dir_all(&event_dir).expect("create event dir");
        write_event_metadata(
            &event_dir,
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
        let fs_record = FsSyscallRecord {
            schema_version: FS_RECORD_SCHEMA_VERSION,
            seq: 0,
            event_id: event_id.to_string(),
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
        };
        let mut fs_records = fs::File::create(event_dir.join(codex_sandbox_audit::FS_RECORDS_FILE))
            .expect("create fs records");
        serde_json::to_writer(&mut fs_records, &fs_record).expect("write fs record");
        fs_records.write_all(b"\n").expect("write newline");
        let rollout_path = temp.path().join("rollout-2026-05-21T21-55-31-id.jsonl");
        let sandbox_audit = SandboxAuditExecConfig {
            event_id: event_id.to_string(),
            tool_name: "shell".to_string(),
            call_id: "call-1".to_string(),
            records_dir,
            checker_config_dir: None,
        };

        let count = append_sandbox_audit_records_to_rollout(
            &rollout_path,
            "session-1",
            "thread-1",
            "turn-1",
            &sandbox_audit,
            AuditAttempt::Initial,
        )
        .expect("append records");

        assert_eq!(count, 1);
        let contents = fs::read_to_string(session_syscall_artifact_path(&rollout_path))
            .expect("read session artifact");
        let record: SessionSyscallRecord =
            serde_json::from_str(contents.trim()).expect("parse session record");
        assert_eq!(
            record,
            SessionSyscallRecord {
                schema_version: SESSION_SYSCALL_RECORD_SCHEMA_VERSION,
                session_id: "session-1".to_string(),
                thread_id: "thread-1".to_string(),
                turn_id: "turn-1".to_string(),
                call_id: "call-1".to_string(),
                tool_name: "shell".to_string(),
                event_id: event_id.to_string(),
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
            }
        );
    }
}
