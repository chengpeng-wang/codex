use super::*;
use pretty_assertions::assert_eq;

#[test]
fn legacy_landlock_flag_is_included_when_requested() {
    let command = vec!["/bin/true".to_string()];
    let command_cwd = Path::new("/tmp/link");
    let cwd = Path::new("/tmp");

    let default_bwrap = create_linux_sandbox_command_args(
        command.clone(),
        command_cwd,
        cwd,
        /*use_legacy_landlock*/ false,
        /*allow_network_for_proxy*/ false,
    );
    assert_eq!(
        default_bwrap.contains(&"--use-legacy-landlock".to_string()),
        false
    );

    let legacy_landlock = create_linux_sandbox_command_args(
        command,
        command_cwd,
        cwd,
        /*use_legacy_landlock*/ true,
        /*allow_network_for_proxy*/ false,
    );
    assert_eq!(
        legacy_landlock.contains(&"--use-legacy-landlock".to_string()),
        true
    );
}

#[test]
fn proxy_flag_is_included_when_requested() {
    let command = vec!["/bin/true".to_string()];
    let command_cwd = Path::new("/tmp/link");
    let cwd = Path::new("/tmp");

    let args = create_linux_sandbox_command_args(
        command,
        command_cwd,
        cwd,
        /*use_legacy_landlock*/ true,
        /*allow_network_for_proxy*/ true,
    );
    assert_eq!(
        args.contains(&"--allow-network-for-proxy".to_string()),
        true
    );
}

#[test]
fn permission_profile_flag_is_included() {
    let command = vec!["/bin/true".to_string()];
    let command_cwd = Path::new("/tmp/link");
    let cwd = Path::new("/tmp");
    let permission_profile = PermissionProfile::read_only();

    let args = create_linux_sandbox_command_args_for_permission_profile(
        command,
        command_cwd,
        &permission_profile,
        cwd,
        /*use_legacy_landlock*/ true,
        /*allow_network_for_proxy*/ false,
        /*sandbox_audit*/ None,
    );

    assert_eq!(
        args.windows(2)
            .any(|window| { window[0] == "--permission-profile" && !window[1].is_empty() }),
        true
    );
    assert_eq!(
        args.windows(2)
            .any(|window| window[0] == "--command-cwd" && window[1] == "/tmp/link"),
        true
    );
}

#[test]
fn sandbox_audit_flags_are_included_when_requested() {
    let command = vec!["/bin/true".to_string()];
    let command_cwd = Path::new("/tmp/link");
    let cwd = Path::new("/tmp");
    let permission_profile = PermissionProfile::read_only();
    let sandbox_audit = SandboxAuditExecConfig {
        event_id: "event-1".to_string(),
        tool_name: "shell".to_string(),
        call_id: "call-1".to_string(),
        records_dir: std::path::PathBuf::from("/tmp/audit"),
        checker_config_dir: Some(std::path::PathBuf::from("/tmp/checker")),
    };

    let args = create_linux_sandbox_command_args_for_permission_profile(
        command,
        command_cwd,
        &permission_profile,
        cwd,
        /*use_legacy_landlock*/ false,
        /*allow_network_for_proxy*/ false,
        Some(&sandbox_audit),
    );

    assert!(
        args.windows(2)
            .any(|window| { window[0] == "--sandbox-audit-event-id" && window[1] == "event-1" })
    );
    assert!(
        args.windows(2)
            .any(|window| { window[0] == "--sandbox-audit-tool-name" && window[1] == "shell" })
    );
    assert!(
        args.windows(2)
            .any(|window| { window[0] == "--sandbox-audit-call-id" && window[1] == "call-1" })
    );
    assert!(
        args.windows(2).any(|window| {
            window[0] == "--sandbox-audit-records-dir" && window[1] == "/tmp/audit"
        })
    );
    assert!(args.windows(2).any(|window| {
        window[0] == "--sandbox-audit-checker-config-dir" && window[1] == "/tmp/checker"
    }));
}

#[test]
fn proxy_network_requires_managed_requirements() {
    assert_eq!(
        allow_network_for_proxy(/*enforce_managed_network*/ false),
        false
    );
    assert_eq!(
        allow_network_for_proxy(/*enforce_managed_network*/ true),
        true
    );
}
