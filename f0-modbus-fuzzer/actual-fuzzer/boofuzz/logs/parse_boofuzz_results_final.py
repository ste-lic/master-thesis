#!/usr/bin/env python3
"""
Parses one or more boofuzz results databases produced by
boofuzz_modbus_esp32.py (HeartbeatAnomalyMonitor) and reports:

  - Coverage actually achieved per request (accounting for boofuzz's own
    crash_threshold_element auto-abandonment after repeated failures).
  - Every crash detected, classified by its REAL signature type --
    "Stack smashing protect failure!", "Guru Meditation Error", a
    heartbeat timeout (hang), or canary drift -- rather than by a
    theoretical source-level threshold. We deliberately do NOT classify
    against the .ino's documented trigger conditions (quantity>125,
    address>=10, byteCount>20): two independent full-coverage runs
    showed those specific values never crash the board, while quantity
    values around 91-93, address=13, and byte_count=4 reproducibly do.
    Reporting the exact observed mutation is more honest than forcing
    it into a threshold that real hardware has already contradicted.
  - Reproducibility across multiple runs: for each distinct (request,
    field, value) that triggered a crash, how many of the given runs
    reproduced it, and discovery-time mean/stdev across those runs --
    the boofuzz-side equivalent of the reproducibility table built for
    the Flipper Zero campaign.

Usage:
    python3 parse_boofuzz_results.py run1.db run2.db ... run10.db
"""

import argparse
import re
import statistics
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime


CRASH_TYPES = {
    "stack_smashing": b"Stack smashing protect failure",
    "guru_meditation": b"Guru Meditation Error",
}

_output_lines = []


def log(msg: str = ""):
    """Collects the line for writing to the output text file. Does not
    print to console -- the file is the only output."""
    _output_lines.append(msg)


def parse_timestamp(ts: str) -> datetime:
    """boofuzz stores timestamps like '[2026-07-21 09:32:57,730]'."""
    return datetime.strptime(ts.strip("[]"), "%Y-%m-%d %H:%M:%S,%f")


def load_cases(cur):
    """Returns {test_case_number: (name, timestamp)}."""
    cur.execute("SELECT name, number, timestamp FROM cases")
    return {number: (name, parse_timestamp(ts)) for name, number, ts in cur.fetchall()}


def load_failures(cur):
    """Returns [(test_case_index, description, timestamp), ...] for every
    'fail' step -- i.e. every crash HeartbeatAnomalyMonitor.post_send()
    flagged."""
    cur.execute(
        "SELECT test_case_index, description, timestamp FROM steps "
        "WHERE type='fail' ORDER BY rowid"
    )
    return [(idx, desc, parse_timestamp(ts)) for idx, desc, ts in cur.fetchall()]


def classify_crash_type(synopsis: str) -> str:
    synopsis_bytes = synopsis.encode(errors="ignore")
    for label, marker in CRASH_TYPES.items():
        if marker in synopsis_bytes:
            return label
    if "No heartbeat" in synopsis:
        return "hung"
    if "Canary" in synopsis:
        return "canary_drift"
    return "other"


# Matches e.g. "fc06_write_single_register:[fc06_write_single_register.body.address_lo:13]"
MUTATION_RE = re.compile(r"^([a-z0-9_]+):\[([a-z0-9_.]+):(\-?\d+)(?:,|\])")


def parse_mutation(case_name: str):
    """Returns (request_name, field_name, value) or (case_name, None, None)
    if the label doesn't match the expected single-field-mutated shape."""
    m = MUTATION_RE.match(case_name)
    if not m:
        return case_name, None, None
    request_name, qualified_field, value = m.groups()
    field_name = qualified_field.split(".")[-1]
    return request_name, field_name, int(value)


def coverage_per_request(cases):
    counts = defaultdict(int)
    for name, _ts in cases.values():
        request_name, _field, _value = parse_mutation(name)
        counts[request_name] += 1
    return dict(counts)


def summarize_run(db_path: str):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cases = load_cases(cur)
    failures = load_failures(cur)
    con.close()

    if not cases:
        log(f"{db_path}: no test cases found (empty or unexpected schema)")
        return None

    run_start = min(ts for _, ts in cases.values())
    records = []
    for test_case_index, description, fail_ts in failures:
        case_name, _case_ts = cases.get(test_case_index, ("<unknown>", fail_ts))
        request_name, field_name, value = parse_mutation(case_name)
        records.append({
            "test_case_index": test_case_index,
            "request": request_name,
            "field": field_name,
            "value": value,
            "crash_type": classify_crash_type(description),
            "discovery_ms": (fail_ts - run_start).total_seconds() * 1000,
            "synopsis": description,
        })

    coverage = coverage_per_request(cases)

    log(f"=== {db_path} ===")
    log(f"Total test cases run: {len(cases)}")
    log("Coverage per request: " + ", ".join(f"{k}={v}" for k, v in coverage.items()))
    log(f"Total crashes detected: {len(records)}")
    for rec in records:
        log(
            f"  +{rec['discovery_ms']/1000:6.1f}s  test_case={rec['test_case_index']:4d}  "
            f"{rec['crash_type']:16s}  {rec['request']}.{rec['field']}={rec['value']}"
        )
    log()

    return {"db_path": db_path, "cases": cases, "records": records, "coverage": coverage}


def aggregate_reproducibility(runs):
    """Groups crash records by (request, field, value, crash_type) across
    all runs and reports how many runs reproduced each one, plus
    discovery-time mean/stdev -- the boofuzz-side equivalent of the
    Flipper campaign's reproducibility table."""
    groups = defaultdict(list)
    for run in runs:
        if run is None:
            continue
        for rec in run["records"]:
            key = (rec["request"], rec["field"], rec["value"], rec["crash_type"])
            groups[key].append(rec["discovery_ms"])

    n_runs = len([r for r in runs if r is not None])

    log("=== Reproducibility across all runs ===")
    log(f"({n_runs} run(s) analyzed)\n")
    for (request, field, value, crash_type), times in sorted(
        groups.items(), key=lambda kv: -len(kv[1])
    ):
        mean = statistics.mean(times)
        stdev = statistics.pstdev(times) if len(times) > 1 else 0.0
        log(
            f"{request}.{field}={value}  [{crash_type}]  "
            f"reproduced in {len(times)}/{n_runs} runs  "
            f"discovery time {mean/1000:.1f}s ± {stdev/1000:.2f}s"
        )
    log()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("db_files", nargs="+", help="One or more boofuzz .db files")
    parser.add_argument(
        "-o", "--output",
        default="boofuzz_analysis_results.txt",
        help="Text file to write the report to (default: boofuzz_analysis_results.txt)",
    )
    args = parser.parse_args()

    runs = [summarize_run(db_path) for db_path in args.db_files]

    if len(args.db_files) > 1:
        aggregate_reproducibility(runs)

    with open(args.output, "w") as f:
        f.write("\n".join(_output_lines) + "\n")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    sys.exit(main())
