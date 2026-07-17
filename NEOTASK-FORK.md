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
- **Current pin:** upstream `v0.6.7` = commit
  `d847471364adf24d819c34a96058bc136cdc00b1`. Neotask release tag:
  **`v0.6.7-neotask.1`**.
- **Toolchain:** the repo pins `channel = "nightly-2026-06-06"` in
  `rust-toolchain.toml` (bare nightly cannot compile rustix 1.1.4). Our release
  CI installs that exact nightly and keeps the pin.
- **Intake cadence:** review upstream quarterly, or immediately on (a) a
  security fix in dcg itself, (b) a rule-pack addition covering a class Neotask
  ships, or (c) an exit-code / robot-JSON `schema_version` change. Intake steps:
  **diff LICENSE first** (any rider change re-opens the license read + the
  counsel item), review CHANGELOG + pack changes, re-pin the commit, cut a new
  `v<upstream>-neotask.N` tag, bump `DCG_VERSION_FALLBACK` in the Electron
  download script, and re-run the guard closeout matrix.

## No source patches

This fork stays **byte-identical to upstream source**. The only additions are
release/CI plumbing and this doc:

- `.github/workflows/release.yml` — builds our four ship targets
  (`aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`,
  `x86_64-unknown-linux-musl`) and publishes binaries + `checksums.txt` + the
  unmodified `LICENSE` as release assets. It does not publish to crates.io and
  does not sign with upstream's keys.
- this `NEOTASK-FORK.md`.

If a behavior change is ever needed, it goes in Neotask's own wrapper /
verdict-mapping layer (gateway `src/infra/dcg.ts`), not here. If that is
impossible, it becomes an upstream PR or an explicit, recorded decision to
carry a patch — never a silent source edit on this fork.

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
