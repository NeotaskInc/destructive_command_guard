# Codex Integration

Last updated: 2026-04-28

This document is the maintainer reference for dcg's Codex CLI hook path. It
explains how dcg distinguishes Codex from Claude-compatible hook payloads, why
Codex denials use exit code 2 with stderr instead of stdout JSON, and how to
debug a hook run that Codex reports as failed instead of blocked.

## Protocol Detection

Codex CLI 0.125.0+ sends the same basic hook payload shape as Claude Code for
shell commands: `tool_name`, `tool_input.command`, hook event metadata, and a
tool-use identifier. dcg must therefore avoid treating every Bash hook as
Codex. The discriminator is Codex's `turn_id` field.

The rule in `src/hook.rs:detect_protocol` is intentionally narrow:

- A shell tool (`Bash`, `bash`, or `launch-process`) with a non-empty `turn_id`
  is treated as `HookProtocol::Codex`.
- A shell tool with `tool_use_id` but no `turn_id` stays on the
  Claude-compatible JSON path.
- Non-shell tools do not become Codex just because a `turn_id` field is present.
- Copilot and Gemini envelope detection runs before the Codex check so their
  protocol-specific handling still wins.

The important regression is the Claude-shaped payload that includes
`tool_use_id` but not `turn_id`. If that ever flips to the Codex path, Claude
Code would stop receiving the structured JSON denial it expects.

Coverage lives in two layers:

- `src/hook.rs` unit tests cover protocol detection and output dispatch.
- `tests/codex_hook_protocol.rs` runs the compiled dcg binary against
  Codex-shaped hook payloads and verifies process exit codes, stdout, stderr,
  allowlists, allow-once codes, pack enablement, history writes, and heredoc
  behavior.

## Deny Contract

Claude-compatible hooks receive a structured JSON denial on stdout. That JSON
contains fields dcg users and agents rely on, including `hookSpecificOutput`,
`ruleId`, `packId`, `severity`, `confidence`, `allowOnceCode`, and
`remediation`.

Codex's hook output parser is stricter. The Codex deny parser rejects unknown
fields, so sending dcg's Claude-compatible JSON to Codex can turn a policy
decision into a `PreToolUse Failed` event instead of a blocked command. That is
the unsafe failure mode this integration avoids.

For Codex, dcg uses Codex's alternate deny path:

- stdout is empty;
- stderr contains the human-readable deny reason, command, rule, and
  remediation;
- the process exits with code 2.

The implementation points are:

- `src/hook.rs:output_denial_for_protocol` selects the Codex stderr-only output
  shape.
- The deny branch in `src/main.rs` flushes pending history writes before calling
  `std::process::exit(2)` for `HookProtocol::Codex`.
- `src/hook.rs` keeps the Claude-compatible JSON path unchanged for Claude,
  Gemini, Copilot, and other non-Codex hook callers.

The exit-code split is intentional:

| Case | stdout | stderr | exit |
|------|--------|--------|------|
| Allow under any protocol | empty | empty | 0 |
| Claude-compatible deny | JSON denial | warning text | 0 |
| Codex deny | empty | deny reason | 2 |
| Parse/config/runtime error | optional error output | error details | 1 or 2 |

For Codex hook integrations, interpret exit code 2 plus non-empty stderr as a
policy denial. Do not require stdout JSON on the Codex path.

## Manual Protocol Probe

Use a throwaway repository when testing real destructive commands through an
agent. For a cheap protocol-shape probe, you can pipe a Codex-shaped hook
payload directly into a dcg binary without asking Codex to run anything:

```bash
printf '%s\n' \
  '{"session_id":"s","turn_id":"turn-1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"},"tool_use_id":"call-1"}' \
  | ./target/release/dcg >/tmp/dcg-codex-stdout.txt 2>/tmp/dcg-codex-stderr.txt
echo "exit=$?"
wc -c /tmp/dcg-codex-stdout.txt /tmp/dcg-codex-stderr.txt
```

Expected result:

- exit code is 2;
- stdout is empty;
- stderr is non-empty and mentions the blocked command plus the matching rule.

For a Claude-compatible negative control, remove `turn_id` from the same payload.
The denial should return exit code 0 with a JSON object on stdout.

## Troubleshooting

### Codex Reports `PreToolUse Failed`

This usually means Codex could not interpret the hook result as a valid Codex
block. Check these in order:

1. Confirm the hook command in `~/.codex/hooks.json` points to the intended dcg
   binary and that the binary exists.
2. Confirm the binary is executable and runs from the same shell environment
   Codex uses.
3. Confirm `codex --version` reports 0.125.0 or newer.
4. Run the manual protocol probe above. If stdout contains a Claude-style JSON
   denial, dcg did not detect the payload as Codex.
5. If stderr is empty on a destructive command, inspect `src/hook.rs` output
   dispatch and `src/main.rs` deny handling before looking at installer code.

### Codex Runs The Command After A Denial

Look for a failed-hook symptom first. A failed hook is not the same as a blocked
hook. The common causes are an old dcg binary, stale hook configuration, or a
hook output shape that no longer matches Codex's parser.

The real-Codex harness checks the smoking-gun condition directly: after Codex is
asked to run a destructive command, the test verifies the repository state is
unchanged and the Codex log includes `hook: PreToolUse Blocked`.

### Safe Commands Emit dcg Text

Allowed commands must be silent. Under Codex, `git status` and other safe
commands should return exit code 0 with empty stdout and empty stderr from dcg.
If Codex displays dcg text for an allowed command, inspect warning-mode routing
and any environment variables that force diagnostic output.

### Allow-Once Or Allowlists Do Not Apply

Codex uses the same evaluation, allowlist, pack, and allow-once logic as the
Claude-compatible path. Only the final hook output contract changes. Check:

- `DCG_CONFIG`, `DCG_PACKS`, and `DCG_DISABLE` are visible to the hook process;
- the project/user/system allowlist file being edited is the one dcg loads;
- the pending exception store is under the same home/project context that the
  hook process sees;
- `tests/codex_hook_protocol.rs` still passes the allowlist and allow-once
  round-trip tests.

## Installer And CI Surfaces

Installer support is split by platform:

- `install.sh:configure_codex` merges a dcg `PreToolUse` Bash hook into
  `~/.codex/hooks.json` when Codex is detected.
- `uninstall.sh:unconfigure_codex` removes only dcg-owned Codex hooks and
  preserves unrelated user hooks.
- `install.ps1` and `uninstall.ps1` provide the same ownership-preserving
  behavior for `%USERPROFILE%\.codex\hooks.json` on Windows.

CI covers Codex without making every pull request depend on a live Codex account:

- The normal `check` job runs `cargo nextest run`, which includes
  `tests/codex_hook_protocol.rs`.
- The coverage job enforces the project thresholds and keeps `src/hook.rs`
  coverage visible.
- The push-only `codex-e2e` job builds dcg, installs Codex when
  `CODEX_API_KEY` is configured, authenticates, and runs
  `scripts/e2e_codex.sh`.
- The real-Codex job exits cleanly with a clear skip when Codex is unavailable,
  unauthenticated, quota-limited, or temporarily unable to reach the API.

Do not make PR CI require live Codex network access. Subprocess protocol tests
are the PR gate; the real-Codex harness is a push-to-main smoke layer.

## Performance Notes

Codex does not get a separate matching engine. The hot path remains the same:
parse, quick reject, normalize, safe patterns, destructive patterns, then output
formatting. The Codex-specific work happens after the decision, where dcg chooses
stderr-only output and exit code 2 for denials.

Performance-sensitive changes should keep these properties:

- allowed commands stay silent and fast;
- protocol detection stays O(1) over parsed hook metadata;
- stderr formatting for Codex denials does not force JSON serialization;
- history writes are flushed synchronously only before Codex's `process::exit(2)`
  deny path.

The `codex_deny` benchmark exists to catch regressions in the Codex denial path.

## Migration Notes

For existing users upgrading from older dcg versions:

1. Upgrade the dcg binary first.
2. Re-run the installer so `~/.codex/hooks.json` points to the upgraded binary.
3. Confirm Codex is 0.125.0 or newer.
4. Run `codex login status` if you plan to use the real-Codex e2e harness.
5. Run the manual protocol probe above before testing against a real repository.

If Codex has stale hooks that still point to an old binary, the safest fix is to
run dcg's installer or uninstaller. They update only dcg-owned hook entries and
preserve coexisting hooks.

## Verifying It Works

Before closing Codex hook work, collect evidence for the relevant layer:

- `cargo test --test codex_hook_protocol` passes.
- `cargo test --lib hook::` passes when protocol detection or output dispatch
  changes.
- `cargo check --all-targets` passes.
- `cargo clippy --all-targets -- -D warnings` passes.
- The manual protocol probe returns exit code 2, empty stdout, and non-empty
  stderr for a destructive Codex-shaped payload.
- `scripts/e2e_codex.sh --verbose --json --artifacts <dir> --dcg-binary <path>`
  either passes against an authenticated Codex CLI or exits successfully with an
  explicit skip reason.
- README's Codex CLI note links back to this document.
- AGENTS.md states that exit code 2 can mean either a configuration error or a
  Codex hook denial, with non-empty stderr distinguishing the Codex denial case.
