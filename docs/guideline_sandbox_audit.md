# Sandbox Audit Interactive Verification

This guide verifies, through the interactive Codex UI, that sandbox audit blocks
deleting an `output` directory and writes syscall audit records.

The verification uses a temporary workspace outside the repository and does not
require modifying the repository contents.

## Expected Milestones

Both the legacy shell path and the default unified exec path must satisfy:

1. `output/keep.txt` still exists after Codex attempts to delete `output`.
2. The latest sandbox audit event directory contains `event.json`,
   `strace.raw`, and `fs.jsonl`, with a delete syscall that reports `EPERM`.

## Build Debug Binaries

```bash
cd /path/to/codex/codex-rs
cargo build -p codex-cli -p codex-linux-sandbox
```

Confirm that both debug binaries are present:

```bash
ls -l ./target/debug/codex ./target/debug/codex-linux-sandbox
```

## Prepare Workspace

Run this in a terminal outside the Codex UI:

```bash
WORK="$(mktemp -d)"
rm -rf "$WORK"
mkdir -p "$WORK/output"
printf keep > "$WORK/output/keep.txt"
```

## Legacy Shell Path

### Start Codex

In terminal A, start the interactive UI with unified exec disabled:

```bash
./target/debug/codex \
  --disable unified_exec \
  --sandbox danger-full-access \
  --sandbox-audit \
  --ask-for-approval never \
  --cd "$WORK"
```

In the Codex UI, send this prompt:

```text
Run this command exactly once, then stop without diagnosing or retrying: rm -rf output
```

The command should fail with output similar to:

```text
rm: cannot remove 'output/keep.txt': Operation not permitted
```

### Verify Milestones

In terminal B, run:

```bash
WORK=/path/to/the/temp/workspace

test -f "$WORK/output/keep.txt" && echo "M1 OK: output/keep.txt still exists"

LATEST_EVENT=$(find "${CODEX_HOME:-$HOME/.codex}/sandbox-audit/events" \
  -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)

echo "$LATEST_EVENT"
ls "$LATEST_EVENT"
rg -n 'EPERM|unlink|unlinkat|rmdir|rename|output|keep.txt' "$LATEST_EVENT/fs.jsonl"
```

Expected result:

- `M1 OK: output/keep.txt still exists` is printed.
- `ls "$LATEST_EVENT"` includes `event.json`, `strace.raw`, and `fs.jsonl`.
- The event directory name usually starts with `shell_command-`.
- `fs.jsonl` includes a delete syscall with `EPERM`.

## Default Unified Exec Path

Exit the Codex UI from the legacy run, then reset the workspace:

```bash
WORK=/path/to/the/temp/workspace
rm -rf "$WORK"
mkdir -p "$WORK/output"
printf keep > "$WORK/output/keep.txt"
```

### Start Codex

In terminal A, start the interactive UI without disabling unified exec:

```bash
./target/debug/codex \
  --sandbox danger-full-access \
  --sandbox-audit \
  --ask-for-approval never \
  --cd "$WORK"
```

In the Codex UI, send the same prompt:

```text
Run this command exactly once, then stop without diagnosing or retrying: rm -rf output
```

The command should fail with output similar to:

```text
rm: cannot remove 'output/keep.txt': Operation not permitted
```

### Verify Milestones

In terminal B, run:

```bash
WORK=/path/to/the/temp/workspace

test -f "$WORK/output/keep.txt" && echo "M1 OK: output/keep.txt still exists"

LATEST_EVENT=$(find "${CODEX_HOME:-$HOME/.codex}/sandbox-audit/events" \
  -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)

echo "$LATEST_EVENT"
ls "$LATEST_EVENT"
rg -n 'EPERM|unlink|unlinkat|rmdir|rename|output|keep.txt' "$LATEST_EVENT/fs.jsonl"

find "${CODEX_HOME:-$HOME/.codex}/sessions" -name '*.syscalls.jsonl' | sort | tail
```

Expected result:

- `M1 OK: output/keep.txt still exists` is printed.
- `ls "$LATEST_EVENT"` includes `event.json`, `strace.raw`, and `fs.jsonl`.
- The event directory name should start with `exec_command-`.
- `fs.jsonl` includes a denied delete syscall. It may look like
  `unlinkat(... "keep.txt" ...) = -1 EPERM` because `rm` can open the
  `output` directory first, then delete `keep.txt` relative to that directory
  file descriptor.
- A rollout-side `.syscalls.jsonl` file is listed under
  `${CODEX_HOME:-$HOME/.codex}/sessions`.

## Notes

- Keep the prompt narrow. Asking Codex to diagnose or retry can create multiple
  audit events, making the latest event harder to identify.
- If the latest event is not the one you expect, list the recent event
  directories with:

  ```bash
  find "${CODEX_HOME:-$HOME/.codex}/sandbox-audit/events" \
    -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -n | tail -20
  ```

- If the default unified exec path is working, the audited event for that run
  should be an `exec_command-...` event, not only a `shell_command-...` event.
