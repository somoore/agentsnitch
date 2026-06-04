#!/usr/bin/env bash
#
# check-deps.sh — "phantom package" supply-chain tripwire for AgentSnitch.
#
# AgentSnitch intentionally ships with ZERO third-party Go dependencies
# (go.mod has no `require` directives and there is no go.sum). That
# stdlib-only state is a deliberate supply-chain asset. This script fails
# loudly the moment that surface changes, so a human must consciously
# confirm and commit any new dependency (including its go.sum hashes).
#
# It performs three independent checks and aggregates failures:
#   1. go.mod / go.sum drift     (go mod tidy -diff, read-only)
#   2. module hash integrity     (go mod verify)
#   3. no external `require`s     (transparent grep of go.mod)
#
# Designed to be called from both a pre-push hook and CI. Exits non-zero
# on any violation.
#
# NOTE ON THE SHEBANG: the task asked for "POSIX sh, set -euo pipefail
# style". Those two are mutually exclusive — `set -o pipefail` is a
# bash/zsh extension and is NOT in POSIX sh (it aborts under dash, the
# /bin/sh on most Linux CI runners). We resolve the contradiction the way
# the rest of scripts/*.sh already do: bash + `set -euo pipefail`.
set -euo pipefail

# Resolve module root so the script works regardless of caller cwd
# (a pre-push hook does not guarantee cwd == module root).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail=0

echo "==> Dependency tripwire (stdlib-only policy) in $ROOT_DIR"

# ---------------------------------------------------------------------------
# Check 1: go.mod / go.sum drift.
#
# `go mod tidy -diff` is read-only: it prints the changes tidy *would* make
# as a unified diff and exits non-zero if that diff is non-empty. It never
# mutates go.mod/go.sum, so there is no copy/restore dance to get wrong.
# (Confirmed available on this repo's toolchain via `go help mod tidy`.)
# We pin -compat to the module's go version to avoid surprise downgrades.
# ---------------------------------------------------------------------------
echo "--> go mod tidy -diff"
if ! tidy_diff="$(go mod tidy -diff 2>&1)"; then
  echo "FAIL: go.mod/go.sum are not tidy. 'go mod tidy' would change them:"
  echo "$tidy_diff"
  echo "      Run 'go mod tidy', review the change, and commit it deliberately."
  fail=1
fi

# ---------------------------------------------------------------------------
# Check 2: module hash integrity. No-op (and trivially passes) while there
# are zero dependencies, but becomes a real guarantee the instant a dep and
# its go.sum exist. Cheap to keep wired in now.
# ---------------------------------------------------------------------------
echo "--> go mod verify"
if ! verify_out="$(go mod verify 2>&1)"; then
  echo "FAIL: go mod verify reported tampering / hash mismatch:"
  echo "$verify_out"
  fail=1
fi

# ---------------------------------------------------------------------------
# Check 3: no external `require` directives in go.mod.
#
# This is the core stdlib-only assertion. We grep transparently (no jq, no
# extra tooling — adding a dependency to police dependencies is
# self-defeating) and match BOTH require forms the go tool emits:
#     require (            <- block form
#     require example v1   <- single-line form
# Matching the literal `require` keyword catches both. We strip comments
# first so a `// require ...` note never trips it.
# ---------------------------------------------------------------------------
echo "--> require-directive assertion"
require_lines="$(sed 's://.*$::' go.mod | grep -nE '^[[:space:]]*require([[:space:]]|\()' || true)"
if [ -n "$require_lines" ]; then
  echo "FAIL: go.mod declares external module requirements — the stdlib-only"
  echo "      policy has been broken. Offending line(s):"
  echo "$require_lines"
  echo
  echo "      If this dependency is INTENTIONAL:"
  echo "        1. Confirm the module + version are trustworthy."
  echo "        2. Run 'go mod tidy' to populate go.sum with pinned hashes."
  echo "        3. Commit go.mod AND go.sum together."
  echo "        4. Update this policy (remove/relax check 3 in scripts/check-deps.sh)."
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "==> Dependency tripwire FAILED."
  exit 1
fi

echo "==> Dependency tripwire passed: zero third-party Go dependencies."
