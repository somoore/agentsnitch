# AgentSnitch — security remediation findings

- **Repository:** `/Users/scottmoore/github/agentsnitch` @ `f4e3e98` (working tree modified by this pass; nothing committed).
- **Date:** 2026-11-02.
- **What was scanned:** 162 tracked files — Go (57, stdlib-only), Rust/Tauri (3), Swift Network Extension + host bridge (4), Bash (14), 2 GitHub workflows, dependency and scanner config, HTML/JS UI. Background reports: `/Users/scottmoore/github/.security-scan/agentsnitch/`.
- **Tools:** `gosec`, `semgrep`, `govulncheck`, `gitleaks`, `cargo-audit`/`cargo deny`, `go build|vet|test|-race`, `cargo build|test|clippy|fmt|deny`, `shellcheck`, the repo's dependency tripwire and Network Extension invariant scripts.
- **Team roles:** Role 1 PM, Role 2 AppSec, Role 3 Pentester, Role 4 Devil's Advocate, Role 5 QA.

Severity below follows the Devil's Advocate's corrected severity where it disagreed with the team (the devil wins on verdicts; the pentester wins on reachability).

## Findings

| ID | Severity | Status | Location | Issue | Fix | Verification |
|----|----------|--------|----------|-------|-----|--------------|
| SEC-01 / SEC-A01 / PENT-01 | MEDIUM | **FIXED** | `cmd/daemon/peercred_darwin.go`; callers `cmd/daemon/main.go:585-710` | Darwin peer identity came from `ps -p <pid> -o comm=`, which returns **argv[0]`; `execve("/bin/sleep", ["<installed emitter>", …])` forged emitter/UI/NE trust and then codesigned the genuine installed file. Any same-user process could pause sensing or forge evidence. | Resolve the real image with `/usr/sbin/lsof -a -p <pid> -d txt -Fn` (skip `/usr/lib/dyld`), fail closed when unresolved, and keep the existing path + TeamID signature checks. New regression test execs `/bin/sleep` with a forged `argv[0]`. | `go test ./cmd/daemon -run 'ResolvePeerExePath|ParseLsofTextImage'` PASS; full `-race` suite PASS |
| SEC-A02 / PENT-01 (UI twin) | MEDIUM | **FIXED** | `ui/src-tauri/src/lib.rs:4370-4425` | The UI's `ui.sock` listener had the same darwin `ps -o comm=` (argv[0]) resolver, so a same-user process could impersonate the daemon and inject/evict evidence cards in the webview. | Mirrored the lsof image resolver in Rust, fail-closed, with `arg0` forged-argv and parser unit tests. | `cargo test --locked --lib` → 89 passed; `cargo clippy --locked -- -D warnings` PASS |
| SEC-02 / SEC-A04 / PENT-02 / QA-05 | LOW (robustness P1) | **FIXED** | `internal/inspect/proxy.go:157,256,581` | Inspect proxy buffered entire request and response bodies with `io.ReadAll` in every mode, including `metadata_only` where the body is discarded; repeated redaction passes amplified memory. | Added a 32 MiB per-direction cap (`Proxy.maxBodyBytes`, test override). Oversize is refused with a clean 413/502 **before** any byte is written, so a short body is never replayed under the full `Content-Length`. `metadata_only` now skips `RedactBody` entirely. Removed the dead `limitReader`. | `go test ./internal/inspect -run 'Oversized|Metadata'` PASS; existing MITM/metadata tests PASS under `-race` |
| DEV-03 / SEC-A06 / PENT-03 / QA-03 | LOW | **FIXED** | `internal/inspect/proxy.go:155-181` | `handlePlainHTTP` never called `DestinationInScope` or the active-ToolSpan gate, so `http://` traffic to never-domains/out-of-scope hosts was still captured and previewed, contradicting the documented promise. | Applied scope + ToolSpan checks before buffering; out-of-scope plain HTTP is forwarded transparently (streamed, no hashing/preview/event). Added never-domain, inactive-ToolSpan and in-scope tests. | `go test ./internal/inspect -run 'PlainHTTP|Scope'` PASS |
| SEC-05 / SEC-A10a / QA-08 | LOW | **FIXED** | `.github/workflows/supply-chain.yml:104` | `go install …/govulncheck@latest` was the only unpinned fetched executable in a SHA-pinned pipeline. | Pinned `govulncheck@v1.1.4` with a bump comment. | Install command succeeds locally (`govulncheck -version` → `v1.1.4`); `govulncheck ./...` → no vulnerabilities |
| SEC-06 / S-37 | LOW | **FIXED** | `.github/dependabot.yml` | No Dependabot `cooldown`, so PRs could target releases published minutes earlier. | Added `cooldown: { default-days: 7 }` to cargo, gomod and github-actions blocks. | Ruby YAML parse: all three ecosystems have `default-days: 7` |
| DEV-02 / SEC-A08 / QA-06 | LOW | **FIXED** | `internal/event/event.go:222-241`; `cmd/daemon/main.go:469` | Agent-supplied `agent.name`/`event`/`tool`/`target`/`tags`/`cwd` were concatenated raw into `SEMANTIC:` log lines; ESC/OSC/newlines could forge lines or drive a `tail -f` terminal. `UNRECOGNIZED LINE` echoed up to 2 MiB raw. | `SemanticEvent.String()` now replaces non-printable runes (keeping stored values intact); daemon truncates/sanitises unrecognised lines to 512 runes and sanitises `NETFLOW` remote/SNI. | `go test ./internal/event -run SemanticEventString` PASS; `go test -race ./...` PASS |
| SEC-A11 | LOW | **FIXED** | `scripts/create.sh:232-278`; `internal/runtime/paths.go`; `cmd/daemon/main.go` | `create.sh` made `~/.agentsnitch` 0755 and launchd created `daemon.log` 0644; `MkdirAll` never chmods an existing dir. | `install -d -m 0700` + `chmod 0700`; `Umask 63` (077) in the LaunchAgent; runtime `ensurePrivateDir` tightens existing dirs; daemon chmods `daemon.log` 0600 and sets `umask 077` at startup. | `go test ./internal/runtime -run SocketPath` PASS; generated plist `plutil -lint` OK and shows `Umask => 63` |
| QA-01 | MEDIUM | **FIXED** | `internal/inspect/inspect_test.go` | `go test -race` failed in 8 tests / 22 reports: test-only unsynchronised `seen` slice shared between httptest goroutines and test goroutines. No production race in those reports. | Replaced the shared slice with a mutex-guarded `exchangeSink`; also cloned `upstreamTLSConfig` per round trip (Go's HTTP/2 setup mutates `NextProtos`). | `go test -race -count=1 ./...` → 0 race reports (all 16 packages PASS) |
| QA-02 | MEDIUM | **FIXED** | `.github/workflows/supply-chain.yml:95` | Required Go check never ran the race detector. | Added `go test -race -count=1 ./...` step; job name/required context unchanged. | Same command passes locally |
| QA-04 | LOW | **MITIGATED** | `cmd/daemon/main.go:126-135` | Socket was `net.Listen`ed under the caller's umask and only then `chmod 0600`, exposing 0755/0777 briefly (0755 observed 21–24 times per 1.5 M stats). | Daemon sets `umask 077` before bind; `~/.agentsnitch` is 0700. No subprocess test asserting the bind-window mode was added. | Code review + `umask 077`; existing socket tests PASS. No automated proof of the window. |
| PENT-05 | LOW | **MITIGATED** | `cmd/daemon/main.go:469,526` | Unrecognised socket lines (up to 2 MiB) and accepted events are logged verbatim into an unrotated `daemon.log` (observed 93 MB on this Mac). | Unrecognised lines are now capped at 512 runes; no rotation/rate limit was added (behaviour change would be larger). | `go test -race ./...` PASS; code review |
| SEC-03 / SEC-A03 / PENT-04 | LOW | **DEFERRED** | `internal/inspect/proxy.go:375-385`, `cmd/daemon/main.go:296-301`, `internal/runtime/transcript.go:42-52` | Client-supplied session id is accepted verbatim (sanitised against traversal but unbounded in distinct values), creating unbounded session dirs/JSONL files and letting the agent label its own proxy traffic as another live session. | Not changed in this pass. Needs an LRU cap on live sessions + transcript retention, which touches session/prune semantics and the evidence-store contract. | Existing session/prune tests PASS (unchanged) |
| SEC-04 / SEC-A07 / S-05 | LOW | **DEFERRED** | `cmd/hookctl/main.go:581-609` | Predictable `<settings>.agentsnitch-tmp` and `…backup-<timestamp>` names are written with `os.WriteFile` (no `O_EXCL`/`O_NOFOLLOW`), so a same-user process can pre-plant a symlink. No privilege boundary is crossed and hookctl is user-invoked. | Not changed (user priority list did not include it). Recommended `os.CreateTemp` + `0600` + rename, and `O_CREATE|O_EXCL|O_NOFOLLOW` for the backup. | `go test ./cmd/hookctl` PASS (unchanged) |
| SEC-07 / DEV-01 | MEDIUM | **ACCEPTED RISK** | `cmd/daemon/main.go:485-498,1711-1751`; `internal/correlator/correlator.go:1650-1689` | Ancestor identity still comes from `ps … command=` names. Even after SEC-01, the monitored agent can run the **genuine** emitter with well-formed payloads (its own parent is genuinely `claude`), so it can add fabricated semantic evidence. | Cannot be closed without a secret the agent cannot read; the emitter is spawned by the agent, so any secret it holds is agent-readable. The peer-impersonation half (forged executable) **is** fixed. Documented honestly in `readme.md`. | Disclosure in `readme.md`; peer spoof test PASS |
| SEC-08 | INFO | **ACCEPTED RISK** | `cmd/daemon/pause.go:64-126` | A pause that never resumes (crash/kill) writes no `pause_gap` row; the paused flag is deliberately not persisted. This is a code-comment accuracy issue, not a documented-behaviour break (the phrase only exists in a comment). | Not changed in this pass. Writing an open-interval row needs an explicit `open:true` field and UI handling; the naive `NewPauseGapEvent(from, zero)` would emit a zero-length gap. | Existing pause/resume transcript tests PASS |
| SEC-A05 | LOW | **DEFERRED** | `extension/AgentSnitchNetworkExtension.swift:331-333,441-443,597-601,812-829` | `flows`/`attributionCache` grow for the life of the system extension when `capture_bytes` is false, because completion callbacks never fire. | Not changed. Needs a `FlowCache` seam + Swift test target or an LRU/TTL sweep; no in-tree Swift test target exists. | `make ne-invariants`, `ne-invariants-test`, `ne-typecheck` PASS (unchanged) |
| SEC-A09 | LOW | **DEFERRED** | `scripts/ensure-release-environment-unlocked.sh:18-23` | Script clears the only human gate on signed releases (`release-signing` environment reviewers/wait timer) and writes a fixed `/tmp/release-env.json`. | Not changed — deleting or gating a release-process script is an owner decision (`AGENTSNITCH_ALLOW_UNPROTECTED_RELEASE` opt-in recommended). Requires an admin `gh` token, i.e. the actor the gate protects against. | Script unchanged; `shellcheck` PASS |
| SEC-A12 | INFO | **DEFERRED** | `internal/inspect/trust.go:45-62` | `SystemTrustStatus` treats certificate presence in `System.keychain` as trust, without reading trust settings. | Not changed; needs `security verify-cert`/`dump-trust-settings` and a manual fixture. | Existing trust-status tests PASS (unchanged) |
| QA-07 | LOW | **DEFERRED** | `.github/workflows/supply-chain.yml` | CI never runs `swiftc`; a broken NE can merge to `main`. | Not changed; adding a macOS Swift typecheck step to the required Rust job was outside the chosen scope. | `make ne-typecheck` PASS locally (not in CI) |
| QA-09 | LOW | **DEFERRED** | `Makefile:156-157` | `make lint` is a no-op stub; `golangci-lint` is not wired. | Not changed; enabling it wholesale can flood the build and needs a baseline. | `go vet ./...` PASS |
| QA-10 | INFO | **DEFERRED** | repo-wide | No `Fuzz*` targets for agent-facing parsers. | Not changed; add fuzz targets in a separate change. | n/a |
| QA-11 | INFO | **DEFERRED** | `scripts/uninstall.sh`, `scripts/create.sh` | Install/uninstall has shellcheck only; destructive `rm -rf` guard is a substring match. | Not changed; needs bats or a temp-`HOME` exec test and a path allowlist. | `bash -n` + `shellcheck` PASS |
| QA-12 | INFO | **DEFERRED** | `.github/workflows/supply-chain.yml:169-185` | TruffleHog `--only-verified` is intentionally not reproducible offline. | No change; gitleaks remains the local gate. | `gitleaks detect` → no leaks |

### Scanner rows — adjudication

| IDs (SUMMARY) | Status | Reason |
|---|---|---|
| S-01, S-07, S-10, S-11 | FALSE POSITIVE | Documented `agentsnitchctl inspect run -- <cmd>` / `inspect cert <file>` passthrough: fixed argv, no shell, operator-supplied path. |
| S-02, S-04, S-06, S-16, S-17, S-21, S-22, S-25, S-28, S-31, S-32, S-36 | FALSE POSITIVE | G703/G304 "traversal": every sink is a fixed `Paths` join, a 128-bit random id, `safeSessionID`-sanitised input, an `os.ReadDir` name, or a contained sidechain path. `..` cannot reach a sink. (S-36's volume issue is SEC-03.) |
| S-03, S-08, S-20 | FALSE POSITIVE | `exec.CommandContext($SHELL, "-lc", "command -v claude")`: constant script, separate argv, user's own `$SHELL`. |
| S-05 | FALSE POSITIVE as traversal | `hookctl:608` is a derived backup path, not attacker-chosen. The real defect on that line is the predictable-name symlink write, tracked as SEC-04 (deferred). |
| S-09 (GHSA-wrw7-89jp-8q8g, glib 0.18.5) | FALSE POSITIVE | Linux/GTK-only Tauri transitive; product is macOS/WKWebView, `deny.toml` is `all-features = false`, `cargo deny check` passes. Adding a cargo-deny ignore would use the wrong ID space and hide a future real advisory. |
| S-12, S-15, S-23, S-34 | FALSE POSITIVE | Fixed absolute binaries (`codesign`, `lsof`, `plutil`, `nm`, `strings`, `security`, `osascript`) with a path as one argv element; `trust.go` shell/AppleScript quoting is correct. |
| S-13 (`peercred_darwin.go:20`) | CONFIRMED (not injection) | The `ps` argv is fixed; the defect is that its output was forgeable. Fixed under SEC-01. |
| S-14 | FALSE POSITIVE | `sidechain.go` opens are gated by `EvalSymlinks` + `filepath.Rel` containment and fail closed; the residual TOCTOU is inside a directory the attacker already owns. |
| S-18, S-19, S-26, S-27, S-33, S-35, S-38 | FALSE POSITIVE | SHA-1 is truncated to 48 bits for local ids (collision merges ids) or used as a keychain lookup key because `security find-certificate -Z` reports only SHA-1. User-facing fingerprints/hashes are SHA-256. Not a signature or MAC. |
| S-24, S-29 | FALSE POSITIVE | 0644 on the public CA certificate/process bundle is required for clients; the CA **key** is 0600 in 0700 dirs. G302 flags 0700 (`MkdirAll`) although it is more restrictive than the rule intends. |
| S-30, S-39 | FALSE POSITIVE | The Inspect proxy is deliberately byte-transparent; it replays the origin's own bytes to the requesting client and never parses/renders HTML, so it adds no XSS capability. |
| S-37 | CONFIRMED | Deduplicated three semgrep rows to one config file. Fixed with `cooldown: default-days: 7`. |
| S-40 | FALSE POSITIVE | `l.Close()` during shutdown; the error is unactionable after context cancellation. |
| S-41 | FALSE POSITIVE (misdirected) | `proxy.go:195,205`: `hostOnly` comes from a Go-validated request authority and the output is one `log.Printf` line. The reachable instances of this class were in the daemon, fixed under DEV-02. |

## Verification log (exact commands, run in `/Users/scottmoore/github/agentsnitch`)

| Command | Result |
|---|---|
| `gofmt -l .` | no output |
| `go build ./...` | PASS |
| `go vet ./...` | PASS |
| `go test -count=1 ./...` | PASS, 16 packages |
| `go test -race -count=1 ./...` | **PASS, 0 race reports** (previously 8 tests / 22 reports) |
| `go test ./cmd/daemon -run 'ResolvePeerExePath|ParseLsofTextImage' -v` | PASS (forged `argv[0]` resolves to `/bin/sleep`) |
| `go test ./internal/inspect -run 'Oversized|PlainHTTP|Metadata' -v` | PASS |
| `go test ./internal/event -run SemanticEventString -v` | PASS |
| `go test ./internal/runtime -run SocketPath -v` | PASS (0755 → 0700) |
| `./scripts/check-deps.sh` | PASS (stdlib-only, zero third-party Go deps) |
| `shellcheck --severity=warning --shell=bash scripts/*.sh extension/*.sh` | PASS |
| `./scripts/check-network-extension-invariants.sh` | PASS |
| `./scripts/test-network-extension-invariants.sh` | PASS |
| `gitleaks detect --redact --no-banner` | PASS — 105 commits, no leaks |
| `/tmp/asbin/govulncheck ./...` (pinned v1.1.4) | PASS — "No vulnerabilities found" |
| `cd ui/src-tauri && cargo fmt --check` | PASS |
| `cd ui/src-tauri && cargo test --locked --lib` | PASS — 89 passed (87 before + 2 new peer tests) |
| `cd ui/src-tauri && cargo clippy --locked -- -D warnings` | PASS |
| `cd ui/src-tauri && cargo deny check` | PASS — advisories/bans/licenses/sources ok |
| `make ne-typecheck` | PASS |
| Ruby YAML parse of `.github/dependabot.yml` + `supply-chain.yml` | PASS; cooldown present on all 3 ecosystems |
| `bash -n scripts/create.sh`; `plutil -lint` on generated plist | PASS; `Umask => 63` |

No secrets were added or found; there is nothing for the owner to rotate.

## Residual risk

1. **Same-user evidence fabrication remains possible (SEC-07/DEV-01).** The peer-impersonation path is closed, but the monitored agent can run the genuine emitter and submit well-formed semantic events. This is inherent to a design where the emitter is spawned by the agent; Pause and ingestion are not tamper controls against that agent. `readme.md` now says so.
2. **Unbounded session/transcript growth (SEC-03/PENT-04).** Distinct session ids can still create unlimited `~/.agentsnitch/sessions/<id>/events.jsonl` files; transcript GC and a live-session cap are not implemented.
3. **Predictable temp/backup paths in `hookctl` (SEC-04).** Same-user only; no privilege boundary crossed.
4. **A crash while paused still leaves no `pause_gap` row (SEC-08).** The interval is invisible in the transcript; only the pause code comment over-promises.
5. **Proxy body cap is a behaviour change.** Buffered (preview/full) bodies over 32 MiB now get a clean 413/502 instead of being proxied. Metadata-only bodies are still buffered up to the same cap (bounded, not streamed) and lose their body hashes. If larger capture-mode transfers are required, make the limit configurable rather than removing it.
6. **Peer authentication now costs one `lsof` exec per event** (~45 ms measured on this Mac). It fails closed if `lsof` is unavailable, which would reject legitimate peers rather than silently trust them.
7. **No daemon log rotation (PENT-05)** and no automated socket-bind-window test (QA-04); the umask change is reviewed but not race-tested.
8. **Unfixed process/CI gaps:** Swift NE cache leak (SEC-A05), release-environment unlock script (SEC-A09), system-trust presence-vs-trust reporting (SEC-A12), Swift typecheck in CI (QA-07), real lint target (QA-09), fuzzing (QA-10), installer tests (QA-11), TruffleHog offline parity (QA-12).
