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

This fork carries the source patches below. Everything else in the Rust
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
  subcommand) followed by a quoted word, a value attached to a code flag
  (`--eval="..."`, `-e'...'`), a here-string, an awk program, or quoted text
  piped into a program that reads its code from stdin (no operand, or `-`;
  text filters such as `cat`, `tee` and `sort` read it as data), whose quoted
  text spells a truncating write to a system, home or variable path, is
  denied, as v0.6.7 denied it; an unlisted program counts, as does a command
  word in a variable. Upstream keeps the decision for what it parses itself:
  shell and remote scripts (`sh`/`bash`/... `-c`, `ssh`, `su`, and GNU
  `parallel`, which runs its input lines as commands; the evaluator hands their
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

- **Temp-root deletes and Perl `unlink`** (dev-igbgn.2, dev-igbgn.4,
  dev-qgoxf1, dev-hs30uj; recorded decisions in the dcg .2 gate reviews).
  Upstream 0.16 judges each segment of a command, so the `/tmp` and `/var/tmp`
  exemptions now decide compound commands that v0.6.7 denied as a whole; and
  it judges Perl's `unlink` only by a catastrophic literal target.
  - **`core.filesystem`** (`src/packs/core/filesystem.rs`): a temp path counts
    as scratch only when it names an entry **below** the root by a literal
    first component. The root itself (however spelled, with redundant `/` or
    `.`), and a first component that starts with a glob, name every child of
    the shared directory, so `find … -delete`, `find … -exec rm`, `rm -rf` and
    the Windows per-user Temp exemption review them. A `find` on the root stays
    exempt when a predicate that selects by name, path, time, size, owner or
    permission comes before the action, as v0.6.7 allowed, unless the name
    pattern matches anything or the expression can undo the selection
    (`-o`, `!`, `,`) or the action is a recursive `rm`.
  - **Perl `unlink`** (`src/ast_pattern_engine.rs`): only calls Perl runs are
    weighed, through a code view that blanks string, quote-like, regex,
    heredoc, POD, `format` and `__END__` bodies and errs toward code wherever
    Perl's reading is ambiguous. Every target is weighed: a catastrophic one is
    Critical; a list of literal temp scratch paths stays warn-only; anything
    else (a glob, a variable, a list, a bare `unlink`, a non-temp name) is
    `heredoc.perl.unlink.non_temp`, High.
  - **Intended differences from v0.6.7:** stricter on the whole temp root
    (the bare root, `-mindepth`/`-type`-only expressions and child globs were
    allowed by v0.6.7 and now review); looser on literal temp scratch (`echo
    done; unlink /tmp/x`, `echo done; find /tmp/x -delete` and a Perl `unlink`
    of a literal `/tmp/<subdir>/…` path, which v0.6.7 denied by matching raw
    text, are allowed, as the same command alone always was). Re-apply on every
    intake until upstream treats a temp root as non-scratch and weighs Perl
    `unlink` targets itself.

- **Database carrier pack order** (dev-igbgn.6, dcg#8). Upstream's
  `database_carrier_first` reorders the enabled packs for heredoc and
  here-string commands, but the keyword index stayed positional over the old
  order, so a database client's own pack could be skipped. The reordered list
  now builds its own index. Intended difference from v0.6.7: with
  `database.sqlite` enabled, a here-string into `sqlite3` (even a literal
  SELECT) is denied by upstream's own `stdin-unverified` rule, which v0.6.7
  allowed (RedPuma N1). Drop when upstream builds the index after reordering.
- **Runtime-expanded heredoc bodies** (dev-qh9n29, dcg#9). A protected
  database client reading an unquoted-delimiter heredoc receives the body
  after shell expansion, so a body with a parameter, command or arithmetic
  expansion is `stdin-unverified` for that client's pack; the cat-pipeline
  producer reads its body by the same heredoc rules. Quoted delimiters and
  literal bodies are unchanged. Intended difference from v0.6.7, which
  allowed these (RedPuma N1). Drop when upstream treats expanding heredoc
  bodies as unverified input.

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

### Upstream tests excluded from CI (MON ruling, dev-igbgn)

These upstream v0.16.0 tests fail on the tag itself, on upstream `main`
(`24562397`, 2026-11-03) and on this fork alike; upstream runs no Actions CI.
`.config/nextest.toml`'s `ci` profile excludes exactly these by full name
(`ci.yml`'s `check` and `coverage` jobs both run that profile). None weakens a
verdict the previous pin (`v0.6.7-neotask.3`) gives. Recheck on every intake
and drop an entry once upstream passes it (bead dev-2gdcxq).

| Binary | Test | Why it fails, and why that is not a weakening |
|---|---|---|
| `repro_277_git_stdin_sink_fallback` | `unquoted_delimiter_with_command_substitution_stays_denied` | The library `evaluate()` path allows `git commit -F - <<EOF\n$(rm -rf ...)\nEOF`; through the CLI the binary denies it (v0.6.7 allowed it). `tests/neotask_heredoc_substitution_cli.rs` keeps the deny enforced through the binary. |
| `repro_393_heredoc_boundary_data_sink` | `executing_receivers_and_expanding_bodies_stay_denied` | The same shape through `evaluate()`; covered the same way. |
| `cross_pack_corpus` | `cross_pack_true_positive_controls_still_deny` | One control, the same #277 shape; covered the same way. |
| `repro_313_powershell_read_only_false_positives` | `escaped_dcg_options_keep_agent_values_and_inspection_arguments_as_data` | Over-blocks `dcg --agent=...` argument data (a false positive, not an allow). |
| `repro_313_powershell_read_only_false_positives` | `escaped_dcg_syntax_cannot_hide_guardrail_changes` | Same family: over-block. |
| `repro_313_powershell_read_only_false_positives` | `global_options_preserve_inspection_and_argument_data` | Same family: over-block. |
| `repro_313_powershell_read_only_false_positives` | `native_agent_argument_boundaries_are_dialect_specific` | Denies `GIT RESET --HARD` under PowerShell with another rule id than the test expects. |
| `repro_558_ifs_destinations` | `literal_command_queries_and_quoted_wrapper_operands_remain_harmless` | Over-blocks an IFS literal query (a false positive). |
| `cli_e2e` | `custom_pack_loading_tests::exact_command_grants_do_not_reappear_after_detection_rewrites` | Denies `GIT RESET --HARD` (PowerShell and unknown dialects, as everywhere) with `core.git:git-alias-semantic-unverified` instead of the `core.git:reset-hard` the test expects: a Git subcommand is case-sensitive while alias names are not, so the alias rule decides. Still a deny (dev-igbgn.7). |

### Upstream tests excluded on Windows only (MON ruling #82548, dev-igbgn)

These 44 upstream v0.16.0 tests fail only on Windows, in upstream's own path and dialect handling; the fork rule produces none of their verdicts. `.config/nextest.toml` excludes them by exact name in a `cfg(windows)` override of the `ci` profile (which keeps the 9 above as well); Linux and macOS still run them. Retire them on intake or upstream (bead dev-32i0o2).

The `cli_e2e` allow-once tests (`allow_once_flow_tests::*_issue_599`) also need their temporary directory outside every Git repository: a grant made inside a repository is scoped to its root (`project`), so with a `.git` above `TMPDIR` (a stray `/tmp/.git`, for example) they report `project` where they expect `cwd`. That is the designed scope, not a loosening; run them with `TMPDIR` outside any repository (dev-igbgn.7).

| Reason | Tests |
|---|---|
| 8.3 short names: `C:\Users\RUNNER~1` against `\\?\C:\Users\runneradmin` canonical paths (13) | `cli_e2e` `allow_once_flow_tests::expired_inline_interpreter_grants_never_authorize_issue_599`<br>`cli_e2e` `allow_once_flow_tests::explicit_inline_policy_denials_preserve_unforced_grants_issue_599`<br>`cli_e2e` `allow_once_flow_tests::forced_nested_policy_grants_skip_retained_ordinary_grants_issue_599`<br>`cli_e2e` `allow_once_flow_tests::incomplete_nested_policy_inspection_preserves_inline_grants_issue_599`<br>`cli_e2e` `allow_once_flow_tests::inline_interpreter_native_grants_match_original_bytes_and_cwd_issue_599`<br>`cli_e2e` `allow_once_flow_tests::nested_inline_policy_denials_require_explicit_force_issue_599`<br>`cli_e2e` `allow_once_flow_tests::nested_inline_requests_cannot_borrow_an_inner_grant_issue_599`<br>`cli_e2e` `allow_once_flow_tests::nested_policy_denials_preserve_outer_inline_grants_issue_599`<br>`cli_e2e` `allow_once_flow_tests::nested_policy_order_preserves_ordinary_inline_grants_issue_599`<br>`cli_e2e` `allow_once_flow_tests::opaque_quoted_python_sources_preserve_nested_policy_issue_599`<br>`cli_e2e` `allow_once_flow_tests::outer_quoted_interpreter_grants_survive_nested_inspection_issue_599`<br>`cli_e2e` `allow_once_flow_tests::unread_python_sources_cannot_clear_policy_with_a_decoy_issue_599`<br>`robot_mode` `test_omp_robot_boundary_persists_history_before_block_exit_and_isolates_agents` |
| Unix fixtures: Unix-absolute paths (`/opt/dcg`, `/iso`) that are not absolute on Windows (3) | `destructive_command_guard` `cli::tests::reasonix_home_override_is_normalized_like_reasonix`<br>`destructive_command_guard` `cli::tests::reasonix_settings_merge_preserves_user_state`<br>`destructive_command_guard` `cli::tests::reasonix_windows_entry_is_quoted_and_recognized` |
| dialect and lib rows: Windows dialect or path handling in upstream rows (3) | `cli_e2e` `custom_pack_loading_tests::command_grants_cannot_be_acquired_from_a_confidence_replay`<br>`destructive_command_guard` `evaluator::tests::database_script_files_are_bounded_and_inspected_by_their_client_pack`<br>`destructive_command_guard` `simulate::tests::simulation_uses_resolved_policy_modes` |
| separators: `\` against `/` in reported paths (4) | `cli_e2e` `config_tests::doctor_audits_project_user_and_system_allowlists_from_nested_cwd`<br>`cli_e2e` `config_tests::doctor_reports_untrusted_project_allowlist_as_inactive`<br>`cli_e2e` `config_tests::doctor_warns_about_global_indefinite_user_rule_issue_545`<br>`repro_541_active_config_edge_cases` `absolute_relative_and_home_paths_share_the_active_install_lifecycle` |
| suggest_allowlist_e2e: `dcg suggest-allowlist` exits non-zero on Windows (21) | `suggest_allowlist_e2e` `apply_flag_out_of_range_index`<br>`suggest_allowlist_e2e` `apply_flag_refuses_require_confirmation_without_accept_risk`<br>`suggest_allowlist_e2e` `apply_flag_writes_require_confirmation_with_accept_risk`<br>`suggest_allowlist_e2e` `apply_flag_writes_to_allowlist`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_ci_forces_non_interactive_mode`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_cli_parsing_confidence_filter`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_cli_parsing_format`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_cli_parsing_risk_filter`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_empty_history`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_interactive_accept_writes_allowlist`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_interactive_quit_early`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_interactive_shows_action_prompts`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_interactive_skip_no_write`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_json_output_non_empty`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_json_output_structure`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_limit_filter`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_min_frequency_filter`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_non_interactive_no_writes`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_output_diagnostics`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_robot_env_forces_json_non_interactive_mode`<br>`suggest_allowlist_e2e` `test_suggest_allowlist_runs_without_crash` |

### Known upstream red outside the test suites

- `bench.yml`'s `benchmark` job (not required, not in the CI Gate): upstream's
  `benches/heredoc_perf.rs` asserts its `commit_message_300` case (a
  destructive substitution as quoted heredoc data inside `git commit -m`) is
  allowed; plain upstream v0.16.0 denies it, as the fork does (the
  conservative direction), so the bench panics before timing. Recheck on
  intake with dev-2gdcxq.
- `ci.yml`'s Windows installer smoke zipped `dcg-<target>/dcg.exe`, a layout
  v0.16's own `install.ps1` refuses; the fork zips one root-level `dcg.exe`,
  the shape the installer accepts.

### PR-diff scan exclusions (MON rulings #81420 and #81517, dev-igbgn)

`dcg scan` reads `.dcg/hooks.toml` from the repository root; its
`[scan.paths] exclude` names exactly 19 upstream files, each an installer,
uninstaller, install test or end-to-end script that contains destructive
commands by design and is not in what Neotask ships (the binary and LICENSE
only): `install.ps1`, `install.sh`, `uninstall.ps1`, `uninstall.sh`,
`scripts/e2e_test.sh`, `scripts/e2e_test.ps1`, `scripts/e2e_fleet_install.sh`,
`scripts/e2e_harness_matrix.sh`, `scripts/e2e_destructive_equivalents.sh`,
`scripts/win_history_concurrency.ps1`, `scripts/scan_regression.sh`,
`tests/install/test_helper.bash`, `tests/e2e/run_install_e2e.sh`,
`tests/e2e/test_doctor_install_uninstall.sh`, and
`tests/installer/{claude_hook,cursor_hook,profile_check,uninstall,checksum}_test.ps1`.
Exact paths, no globs: a new path in a future intake is a new decision.

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
