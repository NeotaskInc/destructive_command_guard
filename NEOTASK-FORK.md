# NEOTASK-FORK.md

This is Neotask's vendored fork of
[`Dicklesworthstone/destructive_command_guard`](https://github.com/Dicklesworthstone/destructive_command_guard)
(dcg), a Rust pre-execution hook that blocks destructive shell commands.

## Why this fork exists

Neotask bundles `dcg` as a required core dependency and runs it as stage 0 of
the gateway exec pipeline (a hard block in front of the approval layer), the
same way Neotask vendors `codag-drain`. We build our OWN release binaries from
this fork's pinned source in our OWN CI so the product never downloads upstream
binaries or depends on upstream's release cadence, keys, or availability. The
Electron build downloads these release assets and sha256-verifies each one.

## Pin policy — no auto-update, deliberate upstream intake

- **We pin a specific upstream commit and intake on our schedule. We never
  auto-update.** The product never self-updates the binary: the invocation
  layer forces `DCG_NO_UPDATE_CHECK=1` and never runs `dcg update`. New dcg
  versions reach users only inside a Neotask release.
- **Current pin:** upstream `v0.16.0` = commit
  `665fcd8fc62cb5941e0484ddab012419f146523d` plus the two carried patches
  below. Neotask release tag: **`v0.16.0-neotask.1`**, cut from the
  `release/v0.16.0-neotask.1` branch (dev-igbgn). Previous pin: upstream
  `v0.6.7` (`d847471364adf24d819c34a96058bc136cdc00b1`) as
  `v0.6.7-neotask.3`; `v0.6.7-neotask.2` was never released (its run was
  cancelled because review found hook-mode rebase-recovery signals still
  applied under the switch).
- **Toolchain:** upstream pins `channel = "nightly-2026-08-31"` in
  `rust-toolchain.toml` (bare nightly cannot compile rustix 1.1.4). Our release
  CI installs that exact nightly and keeps the pin.
- **Intake cadence:** review upstream quarterly, or immediately on (a) a
  security fix in dcg itself, (b) a rule-pack addition covering a class Neotask
  ships, or (c) an exit-code / robot-JSON `schema_version` change. Intake steps:
  **diff LICENSE first** (any rider change re-opens the license read + the
  counsel item), review CHANGELOG + pack changes, re-pin the commit, cut a new
  `v<upstream>-neotask.N` tag, bump `DCG_VERSION_FALLBACK` in the Electron
  download script, and re-run the guard closeout matrix.

## Source patches

This fork carries exactly two source patches. Everything else in the Rust
source is byte-identical to upstream, except one upstream test about the
retired `dist.yml` (see the CI plumbing below).

- **`--no-policy-files` / `DCG_NO_POLICY_FILES=1`** (dev-f31aw, recorded
  decision). With the switch, dcg reads no policy from disk: config files
  (system, user, project `.dcg.toml`, `DCG_CONFIG`), allowlist files (project
  `.dcg/allowlist.toml`, user, system), allow-once entries and hook-mode
  rebase-recovery signals are ignored, so only flags, `DCG_*` environment
  settings and compiled defaults decide (an explicit `dcg test --config PATH`
  still applies). The
  gateway passes it on every call. Without it, an agent that can write its
  workspace or home directory could allow its own denied commands, T0
  included, with a file such as `.dcg/allowlist.toml`. The gateway cannot
  avoid that itself: dcg finds those files from its working directory and
  home, and it needs the agent's real working directory to read the scripts a
  command runs. Covered by `tests/no_policy_files.rs`. Re-apply it on every
  upstream intake until upstream offers an equivalent switch (upstream 0.16
  trusts project policy only when `DCG_CONFIG` names it, but still reads the
  user layers, which follow `XDG_CONFIG_HOME`, and allow-once grants).
- **`core.filesystem:neotask-quoted-redirect`** (dev-igbgn, recorded
  decision). Upstream 0.16 reads inline interpreter code in its own language,
  which ends the dev-4fg5k false positives (`node -e "x.match(/<p>/)"` read as
  a redirect), but it cannot see a sink the code builds at run time:
  `__import__('os').system(...)`, `globalThis['req'+'uire']`,
  `Kernel.send(:sys + 'tem', ...)`, Perl's `&$f(...)`, PHP's `$f(...)`, Lua's
  `os['exe'..'cute']`, R's `do.call(paste0('sys','tem'), ...)` and Groovy's
  `[...].execute()` writing `/etc/passwd` were allowed, as were the same with
  the interpreter in a variable (`P=python3; $P -c ...`) or nested in
  `sh -c '...'`, where v0.6.7 denied them all by reading every redirect in the
  raw text (as it did awk's `print > "/etc/passwd"`). Neither run-time names
  nor interpreters can be enumerated, so `src/neotask_quoted_redirect.rs`
  names neither: it judges each segment of a command by its shape. A program
  given code through a code flag (`-c`, `-e`, `-r`, `-E`, a short cluster
  ending in one, `--eval`/`--exec`/`--execute`/`--command`, or an `eval`
  subcommand) followed by a quoted word, or an awk program, whose quoted text
  spells a truncating write to a system, home or variable path, is denied, as
  v0.6.7 denied it; an unlisted program counts, as does a command word in a
  variable. Upstream keeps the decision for what it parses itself: shell and
  remote scripts (`sh`/`bash`/... `-c`, `ssh`, `su`; the evaluator hands their
  nested commands back to this rule one depth down, so `sh -c 'ruby -e ...'`
  is judged at `ruby -e`), the `-c`/`-e` text of SQL clients and search tools,
  quoted data handed to any other program (`echo '...'`, `--note "..."`), and
  heredoc programs except Ruby's (upstream denies the obfuscated sink in a
  python, node, perl, php, lua, awk, R or Groovy heredoc and allows Ruby's).
  Quoted words are kept apart (a `'>'` argument and a `'/etc/hosts'` argument
  are not one write). A real redirect outside quotes stays upstream's decision,
  and so does every other verdict: the hook in `src/evaluator.rs` wraps the
  upstream entry point, applies at every nesting depth and only turns an allow
  into a deny. The quote-aware fix and the old block are
  one mechanism, so taking upstream's fix alone onto v0.6.7 would have
  reopened the same bypass. Re-apply on every intake until upstream denies
  these shapes itself; drop it when the module's own tests pass with the hook
  removed.

The rest of this fork's changes are release/CI plumbing and this doc:

- **Added** `.github/workflows/release.yml` — builds our four ship targets
  (`aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`,
  `x86_64-unknown-linux-musl`) and publishes binaries + `checksums.txt` + the
  unmodified `LICENSE` as release assets. It does not publish to crates.io and
  does not sign with upstream's keys.
- **Added** this `NEOTASK-FORK.md`.
- **Retired** upstream's own release/ACFS CI workflows (`dist.yml`,
  `acfs-checksums-dispatch.yml`) so `release.yml` is the SOLE release path.
  Upstream `dist.yml` also triggers on `v*` tag pushes and would otherwise cut a
  duplicate, differently-named (tar.xz + cosign) release for the same neotask
  tag, and `acfs-checksums-dispatch.yml` phones home to upstream infra on
  release publish. Removing them does not change the compiled binary.
- **Retired** at the v0.16.0 intake: `release-automation.yml` (it pushes a
  `v<Cargo version>` tag and dispatches `dist.yml`, upstream's release path,
  and needs `actions: write` to do it), and upstream's maintainer automation
  that applies patch blobs and publishes commits to upstream `main`
  (`config-load-568.yml`, `credential-compound-verification.yml`,
  `dcg-stdin-owner-materialize.yml`, `flowctl-command-data-verification.yml`,
  `ifs-destination-verification.yml`, `inline-program-570.yml`,
  `tar-helper-verification.yml`; most are gated to the upstream
  repository and would only skip here). Their regression tests stay in the
  tree and run under `ci.yml`. `ci.yml` also drops upstream's
  `published-release-matrix` and published-release installer step: they
  install upstream-shaped release archives this fork does not publish.
  `notify-acfs.yml` is retired too: it dispatches to upstream's
  `agentic_coding_flywheel_setup` repository when the installer changes, and
  its shellcheck job validates an installer this fork does not ship. Upstream's
  `dist_gate_checks_exact_embedded_tag_before_packaging` test in
  `src/perf.rs` reads `dist.yml`, so it goes with that workflow (a test-only
  removal; `release.yml` smoke-tests every artifact it publishes). `ci.yml`
  measures the comparison revision with that revision's own
  `perf_baseline.py`, since a newer harness can require probes an older binary
  does not answer, and builds it in a `git worktree` under `$RUNNER_TEMP` so
  the absolute gate's clean-checkout binding still holds.
  `tests/fixtures/scan/expected_output.json` counts 25 extracted commands, not
  upstream's 22: v0.16 extracts one more command from each scan fixture with
  identical findings, and upstream (which runs no Actions CI on `main`) never
  refreshed the count; plain upstream v0.16.0 fails its own golden the same way.
- **Kept** upstream's source-verification workflows
  (`credential-policy-verification.yml`, `disk-safety.yml`,
  `opencode-security-regression.yml`, `regression-560.yml`,
  `scanner-safety.yml`) with the CI plumbing below.
- **Changed** CI plumbing only in the remaining upstream workflows: Blacksmith
  runners, actions pinned to full commit SHAs, a timeout on every job,
  least-privilege `permissions:` (`release.yml` is read-only except its
  `release` job, and build checkouts do not keep the token), and in `ci.yml`
  a `CI Gate` job, draft-PR skips with a `ready_for_review` trigger, PR-only
  cancellation, `persist-credentials: false` checkouts, no ordering-only
  `needs: check`, and no nightly schedule (the deep fuzz job runs on manual
  dispatch with an explicit `--target`, and fails on a crash). Re-apply these
  when taking upstream workflow changes.

If a behavior change is ever needed, it goes in Neotask's own wrapper /
verdict-mapping layer (gateway `src/infra/dcg.ts`), not here. If that is
impossible, it becomes an upstream PR or an explicit, recorded decision to
carry a patch, listed above — never a silent source edit on this fork.

## License / rider compliance

dcg ships under `MIT License (with OpenAI/Anthropic Rider)`. Neotask's position
is that it uses dcg as a paying **customer** of Anthropic, not as a party acting
on Anthropic's behalf, and complies with the rider's conditions regardless:

- **The full `LICENSE` ships unmodified with every distribution** — it is a
  release asset here, it is written beside the binary in the packaged app
  (`resources/deps/<platform>/dcg/LICENSE.dcg.txt`), and it appears in the
  product's third-party notices / OSS attributions. The rider's requirement to
  include it unmodified is satisfied mechanically on every build.
- **We never provide the software to a Restricted Party** (OpenAI / Anthropic /
  their affiliates or agents): never hand them the binary, this fork, or
  derivatives; never run it on their infrastructure on their behalf; never feed
  its source into any model-training / eval dataset.
- **Self-update / phone-home is disabled downstream** via `DCG_NO_UPDATE_CHECK=1`
  (forced by the wrapper; `dcg update` is never invoked), so the vendored binary
  makes zero network calls in product use. This fork's release assets are the
  only distribution channel.
- Counsel review of the rider is a diligence item on the first packaged Neotask
  release that ships dcg (not a build blocker).
