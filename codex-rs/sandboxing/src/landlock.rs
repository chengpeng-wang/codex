use codex_protocol::models::PermissionProfile;
use codex_sandbox_audit::SandboxAuditExecConfig;
use std::path::Path;

/// Basename used when the Codex executable self-invokes as the Linux sandbox
/// helper.
pub const CODEX_LINUX_SANDBOX_ARG0: &str = "codex-linux-sandbox";

pub fn allow_network_for_proxy(enforce_managed_network: bool) -> bool {
    // When managed network requirements are active, request proxy-only
    // networking from the Linux sandbox helper. Without managed requirements,
    // preserve existing behavior.
    enforce_managed_network
}

/// Converts the permission profile into the CLI invocation for
/// `codex-linux-sandbox`.
///
/// The helper performs the actual sandboxing (bubblewrap by default + seccomp)
/// after parsing these arguments. The profile JSON flag is emitted before
/// helper feature flags so the argv order matches the helper's CLI shape. See
/// `docs/linux_sandbox.md` for the Linux semantics.
#[allow(clippy::too_many_arguments)]
pub fn create_linux_sandbox_command_args_for_permission_profile(
    command: Vec<String>,
    command_cwd: &Path,
    permission_profile: &PermissionProfile,
    sandbox_policy_cwd: &Path,
    use_legacy_landlock: bool,
    allow_network_for_proxy: bool,
    sandbox_audit: Option<&SandboxAuditExecConfig>,
) -> Vec<String> {
    let permission_profile_json = serde_json::to_string(permission_profile)
        .unwrap_or_else(|err| panic!("failed to serialize permission profile: {err}"));
    let sandbox_policy_cwd = sandbox_policy_cwd
        .to_str()
        .unwrap_or_else(|| panic!("cwd must be valid UTF-8"))
        .to_string();
    let command_cwd = command_cwd
        .to_str()
        .unwrap_or_else(|| panic!("command cwd must be valid UTF-8"))
        .to_string();

    let mut linux_cmd: Vec<String> = vec![
        "--sandbox-policy-cwd".to_string(),
        sandbox_policy_cwd,
        "--command-cwd".to_string(),
        command_cwd,
        "--permission-profile".to_string(),
        permission_profile_json,
    ];
    if use_legacy_landlock {
        linux_cmd.push("--use-legacy-landlock".to_string());
    }
    if allow_network_for_proxy {
        linux_cmd.push("--allow-network-for-proxy".to_string());
    }
    if let Some(sandbox_audit) = sandbox_audit {
        append_sandbox_audit_args(&mut linux_cmd, sandbox_audit);
    }
    linux_cmd.push("--".to_string());
    linux_cmd.extend(command);
    linux_cmd
}

pub fn create_linux_sandbox_direct_audit_command_args(
    command: Vec<String>,
    command_cwd: &Path,
    sandbox_policy_cwd: &Path,
    sandbox_audit: &SandboxAuditExecConfig,
) -> Vec<String> {
    let command_cwd = command_cwd
        .to_str()
        .unwrap_or_else(|| panic!("command cwd must be valid UTF-8"))
        .to_string();
    let sandbox_policy_cwd = sandbox_policy_cwd
        .to_str()
        .unwrap_or_else(|| panic!("cwd must be valid UTF-8"))
        .to_string();

    let mut linux_cmd: Vec<String> = vec![
        "--sandbox-policy-cwd".to_string(),
        sandbox_policy_cwd,
        "--command-cwd".to_string(),
        command_cwd,
        "--sandbox-audit-direct".to_string(),
    ];
    append_sandbox_audit_args(&mut linux_cmd, sandbox_audit);
    linux_cmd.push("--".to_string());
    linux_cmd.extend(command);
    linux_cmd
}

fn append_sandbox_audit_args(args: &mut Vec<String>, sandbox_audit: &SandboxAuditExecConfig) {
    args.push("--sandbox-audit-event-id".to_string());
    args.push(sandbox_audit.event_id.clone());
    args.push("--sandbox-audit-tool-name".to_string());
    args.push(sandbox_audit.tool_name.clone());
    args.push("--sandbox-audit-call-id".to_string());
    args.push(sandbox_audit.call_id.clone());
    args.push("--sandbox-audit-records-dir".to_string());
    args.push(sandbox_audit.records_dir.to_string_lossy().to_string());
    if let Some(checker_config_dir) = &sandbox_audit.checker_config_dir {
        args.push("--sandbox-audit-checker-config-dir".to_string());
        args.push(checker_config_dir.to_string_lossy().to_string());
    }
}

/// Converts the sandbox cwd and execution options into the CLI invocation for
/// `codex-linux-sandbox`.
#[cfg_attr(not(test), allow(dead_code))]
fn create_linux_sandbox_command_args(
    command: Vec<String>,
    command_cwd: &Path,
    sandbox_policy_cwd: &Path,
    use_legacy_landlock: bool,
    allow_network_for_proxy: bool,
) -> Vec<String> {
    let command_cwd = command_cwd
        .to_str()
        .unwrap_or_else(|| panic!("command cwd must be valid UTF-8"))
        .to_string();
    let sandbox_policy_cwd = sandbox_policy_cwd
        .to_str()
        .unwrap_or_else(|| panic!("cwd must be valid UTF-8"))
        .to_string();

    let mut linux_cmd: Vec<String> = vec![
        "--sandbox-policy-cwd".to_string(),
        sandbox_policy_cwd,
        "--command-cwd".to_string(),
        command_cwd,
    ];
    if use_legacy_landlock {
        linux_cmd.push("--use-legacy-landlock".to_string());
    }
    if allow_network_for_proxy {
        linux_cmd.push("--allow-network-for-proxy".to_string());
    }

    // Separator so that command arguments starting with `-` are not parsed as
    // options of the helper itself.
    linux_cmd.push("--".to_string());

    // Append the original tool command.
    linux_cmd.extend(command);

    linux_cmd
}

#[cfg(test)]
#[path = "landlock_tests.rs"]
mod tests;
