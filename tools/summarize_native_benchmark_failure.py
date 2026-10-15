#!/usr/bin/env python3
"""Publish fixed failure metadata without raw diagnostics or workspace paths."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools.build_native_kernel_benchmarks import regular_bytes, write_json

STATUSES = {"completed", "timeout", "cancelled", "log_limit", "unavailable", "fail", "failed"}


def object_at(path: Path) -> dict:
    try:
        value = json.loads(regular_bytes(path, 2 << 20))
        return value if type(value) is dict else {}
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {}


def log_metadata(path: Path) -> dict:
    try:
        data = regular_bytes(path, 1 << 20)
    except (OSError, ValueError):
        return {"status": "unavailable", "sha256": None, "size": None}
    return {"status": "retained_locally", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def child_metadata(value, root: Path, prefix: str) -> dict:
    value = value if type(value) is dict else {}
    status = value.get("status")
    code = value.get("returncode")
    return {"status": status if type(status) is str and status in STATUSES else "unavailable",
            "returncode": code if type(code) is int and -(1 << 31) <= code < 1 << 31 else None,
            "stdout": log_metadata(root / (prefix + "-stdout.log")),
            "stderr": log_metadata(root / (prefix + "-stderr.log"))}


def summarize(root: Path) -> dict:
    manifest = object_at(root / "image/manifest.json")
    result = object_at(root / "run-1/result.json")
    receipts = object_at(root / "run-1/run_receipts.json")
    compiled = manifest.get("compile")
    compiled = compiled if type(compiled) is list else []
    return {"schema_version": 1, "kind": "native_benchmark_failure_metadata",
            "native_qualification": False, "raw_logs_uploaded": False,
            "build_status": manifest.get("status") if manifest.get("status") in ("built", "failed") else "unavailable",
            "run_status": result.get("status") if result.get("status") in ("observed", "failed") else "unavailable",
            "compile": {name: child_metadata(compiled[index] if index < len(compiled) else {}, root / "image", name)
                        for index, name in enumerate(("memory", "scheduler", "kernel"))},
            "execution": child_metadata(receipts.get("execution"), root / "run-1", "qemu")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT / "build/native-benchmarks")
    args = parser.parse_args()
    try:
        args.root.mkdir(parents=True, exist_ok=True)
        write_json(args.root / "failure-summary.json", summarize(args.root))
    except (OSError, ValueError):
        parser.exit(1, "native benchmark failure summary unavailable\n")
    print("Native benchmark failure metadata retained; raw logs excluded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
