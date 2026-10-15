#!/usr/bin/env python3
"""Publish fixed region failure metadata without failed raw host diagnostics."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.k02_region_protocol import CASES, digest, regular_bytes, strict_json, write_json

STATUSES = {"pass", "fail", "failed", "captured", "completed", "timeout", "cancelled", "log_limit", "unavailable"}


def object_at(path):
    try:
        value = strict_json(regular_bytes(path, 2 << 20))
        return value if type(value) is dict else {}
    except (OSError, ValueError, RecursionError):
        return {}


def log_metadata(path):
    try:
        data = regular_bytes(path, 1 << 20)
        return {"status": "retained_locally", "sha256": digest(data), "size_bytes": len(data)}
    except (OSError, ValueError):
        return {"status": "unavailable", "sha256": None, "size_bytes": None}


def child(value, stdout, stderr):
    value = value if type(value) is dict else {}
    status, code = value.get("status"), value.get("returncode")
    return {"status": status if type(status) is str and status in STATUSES else "unavailable",
        "returncode": code if type(code) is int and -(1 << 31) <= code < 1 << 31 else None,
        "stdout": log_metadata(stdout), "stderr": log_metadata(stderr)}


def summarize(root):
    builds = {}
    for build in ("a", "b"):
        directory = root / build
        value = object_at(directory / "manifest.json") or object_at(directory / "build-failure.json")
        receipts = value.get("compile")
        receipts = receipts if type(receipts) is list else []
        rows = {}
        for role in ("core", *CASES):
            receipt = next((row for row in receipts if type(row) is dict and row.get("role") == role), {})
            logs = directory if role == "core" else directory / role
            rows[role] = child(receipt, logs / (role + "-stdout.log"), logs / (role + "-stderr.log"))
        builds[build] = rows
    cases = {}
    for case in CASES:
        directory = root / case
        value = object_at(directory / "result.json")
        execution = value.get("execution")
        row = child(execution, directory / "stdout.log", directory / "stderr.log")
        status = value.get("status")
        row["capture_status"] = status if type(status) is str and status in STATUSES else "unavailable"
        cases[case] = row
    host_value = object_at(root / "host/result.json").get("receipts")
    host_value = host_value if type(host_value) is list else []
    host = {}
    for role in ("library", "test-build", "tests"):
        receipt = next((row for row in host_value if type(row) is dict and row.get("role") == role), {})
        host[role] = child(receipt, root / "host" / (role + "-stdout.log"), root / "host" / (role + "-stderr.log"))
    return {"format": "tessryn-k02-region-failure-summary/v1", "raw_output_published": False,
        "qualification": "not_established", "builds": builds, "cases": cases, "host": host}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT / "build/k02-region-service")
    args = parser.parse_args()
    try:
        args.root.mkdir(parents=True, exist_ok=True)
        write_json(args.root / "failure-summary.json", summarize(args.root))
    except (OSError, ValueError):
        parser.exit(1, "Region failure metadata unavailable\n")
    print("Region failure metadata retained; raw output excluded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
