# Changelog

All notable changes to AgentSnitch are recorded here.

## [Unreleased]

- No public release notes queued yet.

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
