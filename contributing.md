# Contributing to AgentSnitch

AgentSnitch is focused on one concrete product promise:

> Give developers local, explainable evidence when AI coding agents cross from sensitive local context into outbound network activity.

The project is visibility-first. Hooks are semantic sensors, NetworkStatistics/`nettop` plus process snapshots are the default OS/network signal, the macOS Network Extension is the optional stronger attribution path, and the daemon produces linked evidence. Runtime product data must come from those real sensors and correlation paths only.

## Current Priorities

1. Keep Claude Code hook emission boring and reliable.
   - Hooks must fail open and return Claude's expected proceed response.
   - The emitter should use short daemon timeouts and local diagnostics.
   - Every semantic event should include session, tool use, cwd, PID/PPID, tool, target, tags, and sanitized summaries.
2. Keep the default NetworkStatistics/process-snapshot path useful.
   - The default user experience is semantic hooks plus unprivileged NetworkStatistics/`nettop` and `ps` process-tree correlation.
   - `lsof` remains the fallback path; hook-triggered burst polling should reduce its polling blind spot without requiring privileged sensors.
   - The signed Network Extension is advanced, experimental, and opt-in. Do not delete it; keep it metadata-only, fail-open, and ready for future ground-truth attribution/enforcement work.
   - When explicitly testing the Network Extension path, disable NetworkStatistics and lsof with `AGENTSNITCH_DISABLE_NETWORK_STATISTICS=1 AGENTSNITCH_DISABLE_LSOF=1` so observer provenance is clear.
   - Extension events should be real flow events, not fabricated probes.
3. Improve process-tree correlation.
   - Seed from hook PID/PPID.
   - Track ancestors/children for known agent roots.
   - Keep Claude Code subagent attribution current across OS-process fanout, hook-inferred `Agent` tool launches, and sidechain transcript `agentId` records.
   - Surface sidechain `tool_use` rows as subagent activity without replaying local transcripts as fabricated product evidence.
   - Expire stale PIDs to reduce PID reuse risk.
   - Keep confidence reasons explicit: `pid_match`, `parent_match`, `ancestor_match`, `common_agent_ancestor`, `same_agent_session`, `known_agent_binary_match`, timing, and sensitive-read context.
   - Keep explicit egress tools such as WebFetch and WebSearch linkable even when Claude emits the semantic event after the network flow has already appeared.
4. Keep the UI evidence-first.
   - Prioritize attention-needed evidence by default while keeping linked evidence cards easy to inspect.
   - Keep raw hooks, raw network rows, and linked semantic-plus-network evidence separate; `Network` is raw flow visibility, `Linked` is derived evidence, and `All` includes both.
   - Avoid showing unrelated OS-wide network noise in the product UI.
   - Treat `destination_intents` as semantic hints for display and categorization only. They should improve cards such as `github.com (140.82.112.4:443)` but must not replace OS network proof.
   - Keep human WHY, raw reasons, severity, destination, byte counts, timing, and process tree available without making the default card noisy.
   - Keep quieting scoped and explainable: known-service presets are global runtime preferences, while per-card pattern quieting follows the current project path.
   - Collapse known low-risk service categories by default, but keep expand, quiet-category, and export paths obvious.
   - Keep the session summary compact and count-based so users can see known Claude/bridge traffic, telemetry, local bridge traffic, package traffic, and new destinations without reading every raw row.
   - Keep subagent-heavy sessions readable: evidence tabs should show compact `Main (N)` context beside per-agent activity, while the `Agents` tab shows the full hierarchy and agent-specific event drill-down.
5. Keep claims precise.
   - Use: linked, correlated, after sensitive access, same process tree, outbound activity.
   - Avoid: exfiltrated, leaked, stolen.

## Development Notes

- Treat hooks as **sensors**, not enforcement points.
- The daemon and UI should not accept demo/prepared runtime data as product evidence.
- Test fixtures are fine for automated tests, but runtime app data must come from real hooks, real OS network observations, optional Network Extension events, and daemon-side correlation.
- macOS System Extension packaging is strict. When changing extension code, bump the extension bundle version so macOS activates the new build.
- Keep generated build products, provisioning profiles, certificates, notary credentials, and local logs out of git.
- Do not print candidate secret values in issue comments, PR comments, logs, or test output.
- Do not add realistic token strings to fixtures. Use placeholders like `<example-token>`, `<example-api-key>`, and `example.invalid` hosts.
- A clean tracked-tree secret scan is expected before commit. Full-history findings must be triaged; do not add broad allowlists to hide real credentials.

## Useful Commands

```sh
go test ./...
make ne-typecheck
cargo test --locked --manifest-path ui/src-tauri/Cargo.toml --lib
AGENTSNITCH_DISABLE_NETWORK_STATISTICS=1 AGENTSNITCH_DISABLE_LSOF=1 ./bin/daemon
./bin/doctor
```

## Supply-chain Security & Local Checks

AgentSnitch keeps its dependency surface small and auditable on purpose. The
local checks below run automatically through [pre-commit](https://pre-commit.com/),
mirror what CI enforces, and are fast at commit time and thorough at push time.
Configuration lives in `.pre-commit-config.yaml`, `ui/src-tauri/deny.toml`,
`.gitleaks.toml`, `.github/dependabot.yml`, and `.github/workflows/supply-chain.yml`.

### Setup

Install `pre-commit` once (`pipx install pre-commit` or `brew install pre-commit`),
then enable both hook stages in your clone:

```sh
pre-commit install
pre-commit install --hook-type pre-push
```

`pre-commit` fetches and pins the hook tooling (gitleaks, shellcheck, hygiene
hooks) at the versions declared in `.pre-commit-config.yaml`. The local Go/Rust
checks use your installed toolchain.

### Required local toolchain

- **Go 1.26.4** (matches `go.mod`). AgentSnitch is intentionally **standard-library
  only**: `go.mod` has no `require` block and there is no `go.sum`. The dependency
  tripwire (`scripts/check-deps.sh`) fails the build if that changes.
- **Rust** (stable) with `clippy` and `rustfmt` for the Tauri UI in `ui/src-tauri`.
- **cargo-deny 0.19.8** (pinned) — `cargo install cargo-deny --version 0.19.8 --locked`.
- **gitleaks** / **shellcheck** — fetched at pinned versions by `pre-commit`.

### What runs where

| Check | commit | push | CI |
| --- | :---: | :---: | :---: |
| gofmt / go vet | ✓ | | ✓ |
| dependency tripwire (`check-deps.sh`) | ✓ | | ✓ |
| cargo fmt --check | ✓ | | ✓ |
| gitleaks (staged) | ✓ | | ✓ (full history) |
| shellcheck (scripts) | ✓ | | ✓ |
| go test ./... | | ✓ | ✓ |
| cargo test --locked --lib | | ✓ | ✓ |
| cargo clippy -D warnings | | ✓ | ✓ |
| cargo build --locked | | ✓ | ✓ |
| cargo deny check | | ✓ | ✓ |
| govulncheck | | | ✓ |

CI re-runs everything on a clean checkout so a skipped local hook cannot bypass
policy. Run the whole gate manually with `pre-commit run --all-files` and
`pre-commit run --hook-stage pre-push --all-files`.

### Policy

- **Dependencies are pinned via lockfiles.** Rust deps are locked through
  `Cargo.lock` (committed; do not gitignore it) and exercised with `--locked` and
  `cargo deny` (advisories, licenses, source allowlist, bans). Go stays
  standard-library only — any new `require`/`go.sum` is a deliberate, reviewed
  decision, and `scripts/check-deps.sh` enforces it.
- **GitHub Actions are pinned by full commit SHA**, not tag. A tag is mutable and
  can be re-pointed at malicious code (e.g. the March 2025 `tj-actions/changed-files`
  compromise, where tags were moved to a commit that leaked CI secrets). A 40-char
  SHA is immutable and content-addressed. Keep the trailing `# vX.Y.Z` comment so
  Dependabot can bump the SHA and version together.
- **No real secrets in the repo.** Use placeholders such as `<example-token>` and
  `example.invalid` hosts. Triage full-history findings; never add broad allowlists
  to hide real credentials.

### Recommended GitHub settings (set in the web UI)

- Branch protection on `main`: require a PR, require the `supply-chain` checks to
  pass, and require branches be up to date before merging.
- Enable Dependabot alerts + security updates and the dependency graph.
- Default `GITHUB_TOKEN` to read-only; grant write scopes per-workflow as needed.

For packaging/signing details, see [docs/getting-started.md](./docs/getting-started.md) and [extension/integration.md](./extension/integration.md).

For secret hygiene, see [docs/getting-started.md#secret-audit](./docs/getting-started.md#secret-audit).

## Good Contributions

- Better Claude Code hook normalization and classification.
- More robust process-tree tracking and PID reuse protection.
- macOS Network Extension attribution and lifecycle improvements.
- Evidence-card UI improvements that make correlations clearer without increasing noise.
- Tests that prove real contracts without adding fake product data paths.
- Documentation that makes signing, activation, and verification repeatable.
