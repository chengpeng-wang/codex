# Linux Sandbox Audit And Commit Gate

This document is an internal development plan for a custom Codex fork. It is
not product documentation for upstream Codex.

## Summary

- Scope is Linux only, covering the workspace plus configured writable roots.
- `--sandbox-audit` enables the mode explicitly; the custom fork defaults it on,
  with `--no-sandbox-audit` and config able to disable it.
- Startup preflight fails fast when audit is enabled outside Linux, when Linux
  sandbox prerequisites are unavailable, or when audit/checker directories
  cannot be prepared.
- MCP and remote tools are default-allow in v1 and only get metadata records;
  they are not syscall-enforced.
- Short shell commands run in a transactional shadow root, emit file-system
  syscall JSONL, run a no-op checker, and only commit to host when checker
  allows.
- Likely long-running commands are statically bypassed and default-allowed
  without tracing; missed long-running commands remain in the lifecycle
  transaction until exit.

## Current Implementation Status

This custom fork currently implements the first Linux shell-command slice:

- local `LinuxSeccomp` tool attempts get an audit event when the effective
  filesystem policy is restricted;
- writable roots are copied into per-event staging directories under
  `$CODEX_HOME/sandbox-audit/events/<event>/stage/`;
- bubblewrap binds staged roots back to their original paths, so command writes
  stay isolated until commit;
- the inner command is wrapped with `strace -f -e trace=%file`, producing
  `strace.raw` and normalized `fs.jsonl`;
- `event.json` stores event metadata, command, cwd, tool name, and call id;
- the checker interface is present and defaults to no-op allow;
- allowed checker decisions commit staged writes back to host; deny/error
  decisions leave staged writes uncommitted;
- after each audited Linux sandbox attempt, Codex also appends the normalized
  syscall rows to a session-level artifact next to the rollout JSONL, for
  example `rollout-2026-05-21T21-55-31-<id>.syscalls.jsonl`.

Still future work from the broader plan:

- synthetic records for internal Codex filesystem operations;
- MCP/remote tool metadata records;
- long-running command bypass and lifecycle tracking;
- fd-level write effect reconstruction beyond `strace` file syscall records;
- host conflict detection before commit.

## Key Changes

- Add a small `codex-sandbox-audit` crate for shared audit types, config,
  no-op checker, record writing, touched-path extraction, and transaction
  commit helpers.
- Add config:
  - `[sandbox_audit] enabled = true|false`
  - `checker_config_dir = "/path/to/checker-config"`; defaults to
    `$CODEX_HOME/checker.d`
  - audit records stored under `$CODEX_HOME/audit/<session>/<event>/`
  - configurable long-process bypass patterns, with built-ins for dev servers,
    watchers, and TTY-style commands.
- Add CLI flags to shared interactive and `exec` options:
  - `--sandbox-audit`
  - `--no-sandbox-audit`
  - CLI overrides config; the custom fork default is enabled.
- Add startup preflight when effective audit is enabled:
  - require Linux
  - require usable `codex-linux-sandbox`, bubblewrap, and user namespaces
  - reject `danger-full-access` and sandbox bypass unless audit is explicitly
    disabled
  - create and validate `$CODEX_HOME/audit` and checker config dir.

## Audit And Execution Model

- Shell and unified exec:
  - Before execution, create shadow writable roots under
    `$CODEX_HOME/tmp/sandbox-audit/<event>/`.
  - Seed roots with reflink copy when available, falling back to normal copy.
  - Bubblewrap binds each shadow root back to the original absolute path, so
    commands see normal paths while writes land only in staging.
  - `codex-linux-sandbox` inner stage runs a ptrace-based tracer after bwrap
    setup and before user command exec, so bwrap setup syscalls are not included.
  - Tracer records ordered file-system syscalls and file-descriptor write
    effects.
  - Checker receives the event dir, session audit dir, and `checker_config_dir`;
    current implementation always returns allow.
  - If checker allows, commit touched-path diff from staging to host with
    conflict checks; if denied, discard staging and mark the tool result
    blocked/failed.
- Internal Codex filesystem operations:
  - Use the same JSONL schema, but emit synthetic syscall-shaped records instead
    of kernel ptrace records.
  - `apply_patch`, `view_image`, and workspace file operations routed through
    `ExecutorFileSystem` get an audited wrapper.
  - Direct workspace `tokio::fs` usages in tool handlers are refactored to the
    audited filesystem path.
- Long process handling:
  - Static likely-long commands are bypassed and recorded as `audit_bypassed`
    metadata.
  - If a command was not bypassed but stays alive, keep the transaction open and
    run checker plus commit only when that process exits.
  - `write_stdin` records are linked to the original process audit event.

## Public Record Format

Each event writes the original per-event artifacts under
`$CODEX_HOME/sandbox-audit/events/<event_id>/`:

- `event.json`: event id, call id, tool name, cwd, command metadata, sandbox
  name, and start time.
- `fs.jsonl`: ordered records with one common schema for real and synthetic
  operations:
  - `schema_version`
  - `seq`
  - `event_id`
  - `source`: `strace` or `synthetic`
  - `pid`, `tid` when available
  - `syscall`: for example `openat`, `read`, `write`, `unlinkat`, `renameat2`,
    `mkdirat`, `newfstatat`
  - `paths`: normalized path entries with role such as `source`, `target`, `fd`,
    `cwd`
  - `access`: `read`, `write`, `delete`, `metadata`, `rename`
  - `args`: structured syscall-like arguments
  - `result`, `errno`

The current implementation also writes a session-level export next to the
rollout file:

- `<rollout-stem>.syscalls.jsonl`: one syscall per line, preserving the original
  syscall fields and adding `session_id`, `thread_id`, `turn_id`, `call_id`,
  `tool_name`, `event_id`, `attempt`, `command`, and `cwd`.

This export is additive. The original `event.json`, `strace.raw`, `fs.jsonl`,
and staged filesystem artifacts remain in the per-event audit directory.

Checker interface:

- `CheckerInput { session_audit_dir, event_dir, checker_config_dir }`
- `CheckerDecision::Allow | Deny { reason }`
- v1 checker ignores XML FSM files and always returns `Allow`.

## Test Plan

- Config and CLI tests for `--sandbox-audit`, `--no-sandbox-audit`, config
  precedence, default-on fork behavior, and Linux preflight failures.
- Linux sandbox tests for ptrace syscall ordering, path decoding, fd tracking,
  child process tracing, and no bwrap setup noise.
- Transaction tests for create/modify/delete/rename commit, checker denial
  discarding staging, and host conflict detection.
- Core integration tests for shell command commit, `apply_patch` synthetic
  records, internal audited filesystem reads/writes, MCP default-allow metadata,
  and long-process bypass/lifecycle behavior.
- Run after implementation:
  - `cd codex-rs && just fmt`
  - `cargo test -p codex-linux-sandbox`
  - `cargo test -p codex-sandbox-audit`
  - `cargo test -p codex-core`
  - `just write-config-schema` if `ConfigToml` changes.
