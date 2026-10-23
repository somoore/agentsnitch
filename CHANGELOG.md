# Changelog

All notable changes to AgentSnitch are recorded here.

## [Unreleased]

- No public release notes queued yet.

## [v0.1.0-pre-alpha.8] - 2026-10-23

Security maintenance release.

- Go toolchain 1.26.10 (fixes GO-2026-6809 in `crypto/x509` and earlier standard-library advisories).
- UI: `plist` 1.10.3 pulls `quick-xml` 0.42, fixing RUSTSEC-2026-0194 and RUSTSEC-2026-0195; the cargo-deny exemptions for them are removed so a regression fails CI.
- Rust and GitHub Actions dependencies refreshed and SHA-pinned.
- Local ad-hoc installs keep their explicit trust settings.
- Transcript file close errors are handled explicitly.

## [v0.1.0-pre-alpha.7] - 2026-06-09

- Remove required-reviewer gating on `release-signing` so tag-triggered release
  workflows can start automatically and complete without manual environment
  approval stalls.

- Keep changelog-driven release-note generation for the macOS release workflow.

## [v0.1.0-pre-alpha.6] - 2026-06-09

- Handle known Go runtime `xpc_*` leak signal in stress guardrails and record the allowlist in release scripts.
- Add schema normalization for generated Tauri schema artifacts in the build pipeline.
- Improve build/release runtime checks and status reporting around UI listener readiness.

## [v0.1.0-pre-alpha.5] - 2026-06-09

- Added baseline pre-alpha packaging and release signing/integrity flow.
