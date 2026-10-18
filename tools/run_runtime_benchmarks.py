#!/usr/bin/env python3
"""Preregister and capture two complete repeats of each emulator runtime lane."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import verify_runtime_benchmarks as verify
from tools.build_native_kernel_benchmarks import exclusive_directory
from tools.build_fixture import source_identity
from tools.g03.process import ProcessResult

LOADED_SOURCE = verify.read_regular(ROOT, "tools/run_runtime_benchmarks.py", 2 << 20)


def run_stage(command, cwd, timeout, max_log_bytes):
    """Bound a trusted CLI while allowing its nested process owner time to reap.

    The inner adapters own separate compiler/emulator sessions. Their installed
    cancellation handler needs its full 0.2s termination plus 1s reaping bound;
    an outer 0.2s hard-kill grace would destroy that owner prematurely.
    """
    verify.require(type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0, "invalid stage timeout")
    verify.require(type(command) is list and bool(command)
                   and all(type(arg) is str and arg and "\0" not in arg for arg in command), "invalid stage command")
    verify.integer(max_log_bytes, 1, 1 << 20, "stage log bound")
    started, output, handlers, cancelled = time.monotonic(), {"stdout": bytearray(), "stderr": bytearray()}, {}, False
    status, reason = "completed", "trusted stage completed"
    def cancel(*_):
        nonlocal cancelled
        cancelled = True
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, cancel)
    child = None
    try:
        with selectors.DefaultSelector() as selector:
            child = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, env={"PATH": os.defpath, "LANG": "C", "TZ": "UTC"})
            try:
                for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                while selector.get_map() or child.poll() is None:
                    if cancelled:
                        status, reason = "cancelled", "stage cancelled"
                        break
                    if time.monotonic() - started >= timeout:
                        status, reason = "timeout", "stage deadline exceeded"
                        break
                    for key, _ in selector.select(.05):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        available = max_log_bytes - sum(map(len, output.values()))
                        output[key.data].extend(block[:available])
                        if len(block) > available:
                            status, reason = "log_limit", "stage log budget exceeded"
                            break
                    if status != "completed":
                        break
            except (KeyboardInterrupt, OSError):
                status, reason = "cancelled", "stage interrupted"
            finally:
                def group(sig):
                    try:
                        os.killpg(child.pid, sig)
                    except ProcessLookupError:
                        pass
                try:
                    group(signal.SIGTERM)
                    grace_end = time.monotonic() + 3.5
                    # Drain and discard after the bounded captured prefix. This
                    # prevents a full diagnostic pipe from blocking inner reap.
                    while child.poll() is None and time.monotonic() < grace_end:
                        for key, _ in selector.select(.02):
                            try:
                                if not os.read(key.fileobj.fileno(), 65536):
                                    selector.unregister(key.fileobj)
                            except OSError:
                                selector.unregister(key.fileobj)
                    group(signal.SIGKILL)
                    child.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    status, reason = "fail", "stage process cleanup failed"
                    try:
                        child.kill()
                        child.wait(timeout=1)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                finally:
                    child.stdout.close()
                    child.stderr.close()
    except OSError:
        status, reason = "unavailable", "stage launch unavailable"
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    return ProcessResult(status, reason, child.returncode if child is not None else None,
                         time.monotonic() - started, bytes(output["stdout"]), bytes(output["stderr"]))


def write_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as stream:
        stream.write(data)


def write_json(path, value):
    write_bytes(path, (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode())


def sanitize(data):
    text = data.decode("utf8", errors="replace")
    text = re.sub(r"(?<![A-Za-z0-9])/(?:[^\s\x00\"'<>])+", "<host-path>", text)
    return text.encode()[:len(data)].decode("utf8", errors="ignore").encode()


def ensure_registered(root, registration, registered_bytes):
    verify.require(verify.read_regular(ROOT, "tools/run_runtime_benchmarks.py", 2 << 20) == LOADED_SOURCE,
                   "loaded runner changed")
    verify.require(verify.read_regular(root, "registration.json", 2 << 20) == registered_bytes, "registration changed")
    verify.require(verify.same_json(source_identity(), registration["source"]), "source changed after preregistration")
    verify.require(verify.runtime_hashes() == registration["runtime_sha256"], "runtime changed after preregistration")
    for ref in registration["runtime_sources"]:
        verify.file_ref(root, ref, "retained runtime", 16 << 20)
    verify.file_ref(root, registration["profile"], "profile")


def run(out: Path, *, allow_qemu=False):
    verify.require(allow_qemu is True, "runtime capture requires --allow-qemu")
    verify.require(verify.read_regular(ROOT, "tools/run_runtime_benchmarks.py", 2 << 20) == LOADED_SOURCE,
                   "loaded runner changed")
    profile_data = verify.read_regular(ROOT, verify.PROFILE, 1 << 20)
    profile = verify.validate_profile(verify.strict_json(profile_data))
    source = source_identity()
    verify.require(source.get("dirty") is False, "runtime capture requires clean committed source")
    runtime = verify.runtime_hashes()
    verify.validate_source(source, runtime)
    out = exclusive_directory(Path(out))
    result = {"format": "tessryn-runtime-benchmark-result/v1", "status": "failed", "valid": False,
              "registration_sha256": None, "summary": None, "failure_stage": "preregistration"}
    receipts = {"format": "tessryn-runtime-benchmark-stages/v1", "stages": []}
    registered_bytes = None
    started = time.monotonic()
    try:
        write_bytes(out / "profile.json", profile_data)
        source_refs = []
        for name, expected in runtime.items():
            data = verify.read_regular(ROOT, name, 16 << 20)
            verify.require(verify.digest(data) == expected, "runtime changed during retention")
            write_bytes(out / "sources" / name, data)
            source_refs.append(verify.reference(out, "sources/" + name))
        registration = {"format": "tessryn-runtime-benchmark-registration/v1", "scope": verify.SCOPE,
                        "created_at_utc": datetime.now(timezone.utc).isoformat(),
                        "profile": verify.reference(out, "profile.json"), "source": source,
                        "runtime_sha256": runtime, "runtime_sources": source_refs, "stages": verify.stage_plan(),
                        "final_verifier": verify.final_verifier(),
                        "capture_authentication": "unverified_offline", "hardware_qualified": False,
                        "inference_qualified": False}
        write_json(out / "registration.json", registration)
        registered_bytes = verify.read_regular(out, "registration.json", 2 << 20)
        result["registration_sha256"] = verify.digest(registered_bytes)
        relative = out.relative_to(ROOT).as_posix()
        for plan in verify.stage_plan():
            result["failure_stage"] = plan["id"]
            ensure_registered(out, registration, registered_bytes)
            remaining = profile["limits"]["wall_seconds"] - (time.monotonic() - started)
            verify.require(remaining >= plan["timeout_seconds"] + 6, "runtime deadline exhausted before bounded stage")
            arguments = [arg.replace("<run>", relative) for arg in plan["arguments"]]
            command = [sys.executable, str(ROOT / plan["tool"]), *arguments]
            stage_started = datetime.now(timezone.utc).isoformat()
            execution = run_stage(command, ROOT, plan["timeout_seconds"], profile["limits"]["stage_log_bytes"])
            stage_completed = datetime.now(timezone.utc).isoformat()
            complete = execution.status == "completed" and execution.returncode == 0
            refs = {}
            for stream in ("stdout", "stderr"):
                data = getattr(execution, stream)
                if not complete:
                    write_bytes(out / ".private" / (plan["id"] + "-" + stream + ".log"), data)
                    data = b"stage failed; original diagnostics private\n"
                else:
                    data = sanitize(data)
                name = "stages/" + plan["id"] + "-" + stream + ".log"
                write_bytes(out / name, data)
                refs[stream] = verify.reference(out, name)
            receipts["stages"].append({"id": plan["id"], "status": execution.status,
                                       "returncode": execution.returncode, "elapsed_seconds": execution.elapsed_seconds,
                                       **refs, "diagnostic_semantics": "sanitized_nonmeasurement",
                                       "started_at_utc": stage_started, "completed_at_utc": stage_completed})
            verify.require(complete, "bounded runtime stage failed")
            ensure_registered(out, registration, registered_bytes)
        write_json(out / "stages.json", receipts)
        result["failure_stage"] = "combined-verification"
        verify.require(time.monotonic() - started <= profile["limits"]["wall_seconds"] - 306,
                       "insufficient deadline for final verification")
        stage_started = datetime.now(timezone.utc).isoformat()
        execution = run_stage([sys.executable, str(ROOT / "tools/verify_runtime_benchmarks.py"), relative,
                               "--recompute-only", "--expected-registration-sha256", result["registration_sha256"]],
                              ROOT, 300, profile["limits"]["stage_log_bytes"])
        stage_completed = datetime.now(timezone.utc).isoformat()
        complete = execution.status == "completed" and execution.returncode == 0
        refs = {}
        for stream in ("stdout", "stderr"):
            data = getattr(execution, stream)
            if not complete:
                write_bytes(out / ".private" / ("combined-verification-" + stream + ".log"), data)
                data = b"verification failed; original diagnostics private\n"
            else:
                data = sanitize(data)
            name = "stages/combined-verification-" + stream + ".log"
            write_bytes(out / name, data)
            refs[stream] = verify.reference(out, name)
        write_json(out / "verification-receipt.json", {"id": "combined-verification", "status": execution.status,
                   "returncode": execution.returncode, "elapsed_seconds": execution.elapsed_seconds,
                   **refs, "diagnostic_semantics": "sanitized_nonmeasurement",
                   "started_at_utc": stage_started, "completed_at_utc": stage_completed})
        verify.require(complete, "bounded final verification failed")
        verified = verify.strict_json(execution.stdout)
        verify.require(verified["registration_sha256"] == result["registration_sha256"], "final registration differs")
        ensure_registered(out, registration, registered_bytes)
        verify.require(time.monotonic() - started <= profile["limits"]["wall_seconds"], "runtime verification exceeded deadline")
        result.update(status="observed", valid=True, summary=verified["summary"], failure_stage=None)
    except (OSError, ValueError, TypeError, KeyError, ImportError):
        pass
    if not (out / "stages.json").exists():
        write_json(out / "stages.json", receipts)
    write_json(out / "result.json", result)
    if not result["valid"]:
        write_json(out / "failure-summary.json", {"format": "tessryn-runtime-benchmark-failure/v1",
                   "status": "failed", "failure_stage": result["failure_stage"], "hardware_qualified": False,
                   "raw_host_diagnostics": "private_not_uploaded"})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-qemu", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args.out, allow_qemu=args.allow_qemu)
    except (OSError, ValueError, TypeError, KeyError, ImportError):
        print(json.dumps({"status": "failed", "failure_stage": "preflight", "hardware_qualified": False}))
        return 1
    print(json.dumps({"status": result["status"], "failure_stage": result["failure_stage"],
                      "registration_sha256": result["registration_sha256"], "hardware_qualified": False}))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
