#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use codex_sandbox_audit::EVENT_METADATA_FILE;
use codex_sandbox_audit::FS_RECORDS_FILE;
use codex_sandbox_audit::STRACE_RAW_FILE;
use std::process::Command;
use tempfile::tempdir;

fn codex_linux_sandbox_exe() -> &'static str {
    env!("CARGO_BIN_EXE_codex-linux-sandbox")
}

fn direct_audit_command(
    event_id: &str,
    records_dir: &std::path::Path,
    cwd: &std::path::Path,
    script: &str,
) -> Command {
    let mut command = Command::new(codex_linux_sandbox_exe());
    command
        .arg("--sandbox-policy-cwd")
        .arg(cwd)
        .arg("--command-cwd")
        .arg(cwd)
        .arg("--sandbox-audit-direct")
        .arg("--sandbox-audit-event-id")
        .arg(event_id)
        .arg("--sandbox-audit-tool-name")
        .arg("shell")
        .arg("--sandbox-audit-call-id")
        .arg("call-1")
        .arg("--sandbox-audit-records-dir")
        .arg(records_dir)
        .arg("--")
        .arg("bash")
        .arg("-lc")
        .arg(script)
        .current_dir(cwd);
    command
}

#[test]
fn direct_audit_creates_event_and_fs_records() {
    let workspace = tempdir().expect("workspace");
    let records = tempdir().expect("records");
    let event_id = "event-direct";

    let output = direct_audit_command(
        event_id,
        records.path(),
        workspace.path(),
        "printf data > touched.txt",
    )
    .output()
    .expect("run direct audit");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let event_dir = records.path().join(event_id);
    assert!(event_dir.join(EVENT_METADATA_FILE).is_file());
    assert!(event_dir.join(STRACE_RAW_FILE).is_file());
    let fs_records = std::fs::read_to_string(event_dir.join(FS_RECORDS_FILE))
        .expect("read finalized fs records");
    assert!(fs_records.contains("touched.txt"));
}

#[test]
fn direct_audit_blocks_output_deletion_but_allows_other_deletes() {
    let workspace = tempdir().expect("workspace");
    let records = tempdir().expect("records");
    let event_id = "event-output-delete";
    let output_dir = workspace.path().join("output");
    std::fs::create_dir(&output_dir).expect("create output");
    std::fs::write(output_dir.join("keep.txt"), "keep").expect("write output file");
    std::fs::write(workspace.path().join("scratch.txt"), "scratch").expect("write scratch");

    let output = direct_audit_command(
        event_id,
        records.path(),
        workspace.path(),
        "rm -f scratch.txt; rm -rf output",
    )
    .output()
    .expect("run direct audit");

    assert!(!output.status.success());
    assert!(output_dir.join("keep.txt").is_file());
    assert!(!workspace.path().join("scratch.txt").exists());
    let event_dir = records.path().join(event_id);
    let raw = std::fs::read_to_string(event_dir.join(STRACE_RAW_FILE)).expect("read raw trace");
    assert!(raw.contains("EPERM"));
    assert!(raw.contains("output"));
}
