<p align="center"><code>npm i -g @openai/codex</code><br />or <code>brew install --cask codex</code></p>
<p align="center"><strong>Codex CLI</strong> is a coding agent from OpenAI that runs locally on your computer.
<p align="center">
  <img src="https://github.com/openai/codex/blob/main/.github/codex-cli-splash.png" alt="Codex CLI splash" width="80%" />
</p>
</br>
If you want Codex in your code editor (VS Code, Cursor, Windsurf), <a href="https://developers.openai.com/codex/ide">install in your IDE.</a>
</br>If you want the desktop app experience, run <code>codex app</code> or visit <a href="https://chatgpt.com/codex?app-landing-page=true">the Codex App page</a>.
</br>If you are looking for the <em>cloud-based agent</em> from OpenAI, <strong>Codex Web</strong>, go to <a href="https://chatgpt.com/codex">chatgpt.com/codex</a>.</p>

---

## Quickstart

### Installing and running Codex CLI

Install globally with your preferred package manager:

```shell
# Install using npm
npm install -g @openai/codex
```

```shell
# Install using Homebrew
brew install --cask codex
```

Then simply run `codex` to get started.

<details>
<summary>You can also go to the <a href="https://github.com/openai/codex/releases/latest">latest GitHub Release</a> and download the appropriate binary for your platform.</summary>

Each GitHub Release contains many executables, but in practice, you likely want one of these:

- macOS
  - Apple Silicon/arm64: `codex-aarch64-apple-darwin.tar.gz`
  - x86_64 (older Mac hardware): `codex-x86_64-apple-darwin.tar.gz`
- Linux
  - x86_64: `codex-x86_64-unknown-linux-musl.tar.gz`
  - arm64: `codex-aarch64-unknown-linux-musl.tar.gz`

Each archive contains a single entry with the platform baked into the name (e.g., `codex-x86_64-unknown-linux-musl`), so you likely want to rename it to `codex` after extracting it.

</details>

### Using Codex with your ChatGPT plan

Run `codex` and select **Sign in with ChatGPT**. We recommend signing into your ChatGPT account to use Codex as part of your Plus, Pro, Business, Edu, or Enterprise plan. [Learn more about what's included in your ChatGPT plan](https://help.openai.com/en/articles/11369540-codex-in-chatgpt).

You can also use Codex with an API key, but this requires [additional setup](https://developers.openai.com/codex/auth#sign-in-with-an-api-key).

## Custom fork: sandbox audit mode

This repository includes an experimental fork-only sandbox audit mode for local
Linux command execution. When enabled, Codex records filesystem syscalls for
audited shell tool calls, writes per-call audit artifacts, and applies a built-in
guard that prevents deleting or moving paths under an `output` directory.

The mode currently covers both command execution backends:

- Legacy `shell_command` runs when `unified_exec` is disabled.
- Default `exec_command` runs when `unified_exec` is enabled.

On Linux, the audit artifacts are written under:

```text
$CODEX_HOME/sandbox-audit/events
```

`CODEX_HOME` defaults to `~/.codex`. Each event directory contains:

- `event.json`: command metadata, cwd, tool name, call id, and sandbox type.
- `strace.raw`: raw filesystem syscall trace output.
- `fs.jsonl`: normalized ordered filesystem syscall records.

Codex also appends the normalized syscall records to a rollout-side artifact:

```text
$CODEX_HOME/sessions/**/rollout-*.syscalls.jsonl
```

### Build this fork

From the repository root:

```shell
cd codex-rs
cargo build -p codex-cli -p codex-linux-sandbox
```

The debug binaries are written to the configured Cargo target directory. If you
do not override Cargo's target directory, they are:

```shell
./target/debug/codex
./target/debug/codex-linux-sandbox
```

### Enable sandbox audit

Enable audit for one interactive run:

```shell
./target/debug/codex \
  --sandbox danger-full-access \
  --sandbox-audit \
  --ask-for-approval never \
  --cd /path/to/workspace
```

Or enable it in `$CODEX_HOME/config.toml`:

```toml
[sandbox_audit]
enabled = true
records_dir = "/absolute/path/to/sandbox-audit/events"
# checker_config_dir = "/absolute/path/to/checker.d"
```

If `records_dir` is omitted, Codex uses
`$CODEX_HOME/sandbox-audit/events`.

Disable audit for one run:

```shell
./target/debug/codex --no-sandbox-audit
```

### Interactive verification

Use a temporary workspace so the verification does not touch this repository:

```shell
WORK="$(mktemp -d)"
rm -rf "$WORK"
mkdir -p "$WORK/output"
printf keep > "$WORK/output/keep.txt"
```

Start the legacy shell path by disabling unified exec:

```shell
./target/debug/codex \
  --disable unified_exec \
  --sandbox danger-full-access \
  --sandbox-audit \
  --ask-for-approval never \
  --cd "$WORK"
```

In the interactive UI, send:

```text
Run this command exactly once, then stop without diagnosing or retrying: rm -rf output
```

The command should fail with `Operation not permitted`, and
`$WORK/output/keep.txt` should still exist.

Then reset the workspace and start the default unified exec path:

```shell
rm -rf "$WORK"
mkdir -p "$WORK/output"
printf keep > "$WORK/output/keep.txt"

./target/debug/codex \
  --sandbox danger-full-access \
  --sandbox-audit \
  --ask-for-approval never \
  --cd "$WORK"
```

Send the same prompt in the interactive UI. The default path should also fail
with `Operation not permitted`, keep `output/keep.txt`, and create an
`exec_command-...` audit event.

Verify either run from another terminal:

```shell
test -f "$WORK/output/keep.txt" && echo "M1 OK: output/keep.txt still exists"

LATEST_EVENT=$(find ~/.codex/sandbox-audit/events \
  -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)

echo "$LATEST_EVENT"
ls "$LATEST_EVENT"
rg -n 'EPERM|unlink|unlinkat|rmdir|rename|output|keep.txt' "$LATEST_EVENT/fs.jsonl"
find ~/.codex/sessions -name '*.syscalls.jsonl' | sort | tail
```

Expected result:

- `output/keep.txt` still exists.
- The latest audit event contains `event.json`, `strace.raw`, and `fs.jsonl`.
- `fs.jsonl` contains a delete or rename syscall that reports `EPERM`.
- The default unified exec run creates an `exec_command-...` event.

More detailed step-by-step verification notes are in
[`docs/guideline_sandbox_audit.md`](./docs/guideline_sandbox_audit.md).

## Docs

- [**Codex Documentation**](https://developers.openai.com/codex)
- [**Contributing**](./docs/contributing.md)
- [**Installing & building**](./docs/install.md)
- [**Open source fund**](./docs/open-source-fund.md)

This repository is licensed under the [Apache-2.0 License](LICENSE).
