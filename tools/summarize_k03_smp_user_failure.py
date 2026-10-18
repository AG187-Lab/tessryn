#!/usr/bin/env python3
"""Publish only fixed status, exit and log hashes after unsuccessful SMP user work."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from tools.k03_smp_user_protocol import CASES, digest, regular_bytes, strict_json, write_json
STATUSES = {"pass", "fail", "captured", "completed", "timeout", "cancelled", "log_limit", "unavailable"}


def object_at(path):
    try:
        value = strict_json(regular_bytes(path, 2 << 20)); return value if type(value) is dict else {}
    except (OSError, ValueError, RecursionError): return {}


def metadata(path):
    try:
        data = regular_bytes(path, 1 << 20); return {"sha256": digest(data), "size_bytes": len(data)}
    except (OSError, ValueError): return {"sha256": None, "size_bytes": None}


def process(row, stdout, stderr):
    row = row if type(row) is dict else {}; status, code = row.get("status"), row.get("returncode")
    return {"status": status if type(status) is str and status in STATUSES else "unavailable",
        "returncode": code if type(code) is int and -(1 << 31) <= code < 1 << 31 else None,
        "stdout": metadata(stdout), "stderr": metadata(stderr)}


def summarize(root):
    builds = {}
    for twin in ("a", "b"):
        base = root / twin; value = object_at(base / "manifest.json") or object_at(base / "build-failure.json")
        rows = value.get("compile"); rows = rows if type(rows) is list else []
        builds[twin] = {case: process(next((r for r in rows if type(r) is dict and r.get("role") == case), {}),
            base / case / "stdout.log", base / case / "stderr.log") for case in CASES}
    cases = {case: process(object_at(root / case / "result.json").get("execution"), root / case / "stdout.log", root / case / "stderr.log") for case in CASES}
    rows = object_at(root / "host/result.json").get("receipts"); rows = rows if type(rows) is list else []
    host = {role: process(next((r for r in rows if type(r) is dict and r.get("role") == role), {}),
        root / "host" / (role + "-stdout.log"), root / "host" / (role + "-stderr.log")) for role in ("build", "tests")}
    return {"format": "tessryn-k03-smp-user-failure-summary/v1", "raw_output_published": False, "builds": builds, "cases": cases, "host": host}


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("--root", type=Path, default=ROOT / "build/k03-smp-user"); args = p.parse_args()
    try:
        args.root.mkdir(parents=True, exist_ok=True); write_json(args.root / "failure-summary.json", summarize(args.root))
    except (OSError, ValueError): p.exit(1, "SMP user failure metadata unavailable\n")
    print("SMP user failure metadata retained; raw diagnostics excluded")
if __name__ == "__main__": main()
