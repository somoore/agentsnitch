#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   AGENTSNITCH_PERF_CSV=path/to/run.csv \
#   AGENTSNITCH_PERF_MAX_DAEMON_RSS_KB=350000 \
#   AGENTSNITCH_PERF_MAX_DAEMON_CPU_P95=210 \
#   ./scripts/check-stress-guardrail.sh
#
# Optional:
#   AGENTSNITCH_PERF_BASELINE_CSV=path/to/baseline.csv
#   AGENTSNITCH_PERF_RSS_PCT_DELTA=0.20
#   AGENTSNITCH_PERF_CPU_P95_PCT_DELTA=0.20
#   AGENTSNITCH_PERF_LEAK_DIR=path/to/extended/snapshots
#   AGENTSNITCH_PERF_LEAK_ALLOWLIST=xpc_date_t

CSV="${AGENTSNITCH_PERF_CSV:-}"
MAX_RSS_KB="${AGENTSNITCH_PERF_MAX_DAEMON_RSS_KB:-350000}"
MAX_CPU_P95="${AGENTSNITCH_PERF_MAX_DAEMON_CPU_P95:-210}"
BASELINE_CSV="${AGENTSNITCH_PERF_BASELINE_CSV:-}"
RSS_PCT_DELTA="${AGENTSNITCH_PERF_RSS_PCT_DELTA:-0.20}"
CPU_P95_PCT_DELTA="${AGENTSNITCH_PERF_CPU_PCT_DELTA:-0.20}"
LEAK_DIR="${AGENTSNITCH_PERF_LEAK_DIR:-}"
LEAK_ALLOWLIST="${AGENTSNITCH_PERF_LEAK_ALLOWLIST:-xpc_date_t}"

if [[ -z "$CSV" ]]; then
  echo "AGENTSNITCH_PERF_CSV is required (path to stress CSV)" >&2
  exit 1
fi

if [[ ! -f "$CSV" ]]; then
  echo "Cannot read stress CSV: $CSV" >&2
  exit 1
fi

python3 - "$CSV" "$BASELINE_CSV" "$MAX_RSS_KB" "$MAX_CPU_P95" "$RSS_PCT_DELTA" "$CPU_P95_PCT_DELTA" "$LEAK_DIR" "$LEAK_ALLOWLIST" <<'PY'
import csv
import glob
import statistics
import sys
import re
import os

run_csv, baseline_csv, max_rss_kb, max_cpu_p95, rss_pct_delta, cpu_pct_delta, leak_dir, leak_allowlist = sys.argv[1:]
max_rss_kb = int(max_rss_kb)
max_cpu_p95 = float(max_cpu_p95)
rss_pct_delta = float(rss_pct_delta)
cpu_pct_delta = float(cpu_pct_delta)
allowlist = [entry.strip() for entry in leak_allowlist.split(",") if entry.strip()]


def parse_p95(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise RuntimeError(f"no data in {path}")

    def to_float(value):
        if value in ("", "-"):
            return None
        return float(value)

    rss_vals = sorted(v for v in (to_float(r["daemon_rss_kb"]) for r in rows) if v is not None)
    cpu_vals = sorted(v for v in (to_float(r["daemon_cpu"]) for r in rows) if v is not None)
    if not rss_vals or not cpu_vals:
        raise RuntimeError(f"missing daemon metric rows in {path}")

    p95_rss = rss_vals[int(0.95 * len(rss_vals)) - 1]
    p99_rss = rss_vals[int(0.99 * len(rss_vals)) - 1]
    p95_cpu = cpu_vals[int(0.95 * len(cpu_vals)) - 1]
    p99_cpu = cpu_vals[int(0.99 * len(cpu_vals)) - 1]

    return {
        "rows": len(rows),
        "daemon_rss_kb_p95": p95_rss,
        "daemon_rss_kb_p99": p99_rss,
        "daemon_cpu_p95": p95_cpu,
        "daemon_cpu_p99": p99_cpu,
    }


def parse_leak_file(path, allowed):
    with open(path, "r", errors="replace") as f:
        lines = f.readlines()

    total = 0
    for line in lines:
        m = re.match(r"^Process .*: (\d+) leaks? for .*", line.strip())
        if m:
            total = int(m.group(1))
            break

    if total == 0:
        return []

    hits = []
    parsed_root_leak = False
    for line in lines:
        m = re.match(r"\s*\d+ \(\d+ bytes\) ROOT LEAK: <([^ >]+)", line)
        if not m:
            continue
        parsed_root_leak = True
        leak_symbol = m.group(1)
        if leak_symbol not in allowed:
            hits.append(leak_symbol)

    if total > 0 and not parsed_root_leak:
        # Conservative fallback: if we failed to parse roots, still fail-fast on unknown structure.
        hits.append("<unparsed_root_leak>")

    return hits


def parse_leaks_in_dir(leak_dir, allowed):
    leak_paths = sorted(glob.glob(os.path.join(leak_dir, "*daemon.leaks")))
    if not leak_paths:
        return []

    unexpected = []
    for path in leak_paths:
        unexpected.extend([(path, leak) for leak in parse_leak_file(path, allowed)])
    return unexpected

run_metrics = parse_p95(run_csv)

violations = []
if run_metrics["daemon_rss_kb_p95"] > max_rss_kb:
    violations.append(f"daemon_rss_kb_p95 {run_metrics['daemon_rss_kb_p95']:.0f} > max {max_rss_kb}")
if run_metrics["daemon_cpu_p95"] > max_cpu_p95:
    violations.append(f"daemon_cpu_p95 {run_metrics['daemon_cpu_p95']:.1f} > max {max_cpu_p95}")

baseline = None
if baseline_csv:
    if baseline_csv != "-":
        if baseline_csv and not baseline_csv.strip():
            baseline = None
        else:
            baseline = parse_p95(baseline_csv)

if baseline is not None:
    rss_limit = baseline["daemon_rss_kb_p95"] * (1.0 + rss_pct_delta)
    cpu_limit = baseline["daemon_cpu_p95"] * (1.0 + cpu_pct_delta)
    if run_metrics["daemon_rss_kb_p95"] > rss_limit:
        violations.append(
            f"daemon_rss_kb_p95 {run_metrics['daemon_rss_kb_p95']:.0f} > baseline+{rss_pct_delta:.0%} "
            f"({baseline['daemon_rss_kb_p95']:.0f} -> {rss_limit:.0f})"
        )
    if run_metrics["daemon_cpu_p95"] > cpu_limit:
        violations.append(
            f"daemon_cpu_p95 {run_metrics['daemon_cpu_p95']:.1f} > baseline+{cpu_pct_delta:.0%} "
            f"({baseline['daemon_cpu_p95']:.1f} -> {cpu_limit:.1f})"
        )

print(f"rows={run_metrics['rows']}")
print(f"daemon_rss_kb_p95={run_metrics['daemon_rss_kb_p95']:.0f}")
print(f"daemon_rss_kb_p99={run_metrics['daemon_rss_kb_p99']:.0f}")
print(f"daemon_cpu_p95={run_metrics['daemon_cpu_p95']:.1f}")
print(f"daemon_cpu_p99={run_metrics['daemon_cpu_p99']:.1f}")
if baseline is not None:
    print(f"baseline_rows={baseline['rows']}")
    print(f"baseline_rss_p95={baseline['daemon_rss_kb_p95']:.0f}")
    print(f"baseline_cpu_p95={baseline['daemon_cpu_p95']:.1f}")

if leak_dir:
    unexpected_leaks = parse_leaks_in_dir(leak_dir, allowlist)
    if unexpected_leaks:
        violations.append("unexpected process memory leaks detected outside allowlist:")
        by_file = {}
        for path, symbol in unexpected_leaks:
            by_file.setdefault(path, set()).add(symbol)
        for path, symbols in sorted(by_file.items()):
            violations.append(f"  {os.path.basename(path)}: {', '.join(sorted(symbols))}")

if violations:
    print("FAIL:")
    for v in violations:
        print(f"  - {v}")
    sys.exit(1)

print("PASS: stress guardrails within threshold")
PY
