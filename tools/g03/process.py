"""Bound a subprocess session, including inherited pipes and output volume."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import threading
import time


@dataclass(frozen=True)
class ProcessResult:
    status: str
    reason: str
    returncode: int | None
    elapsed_seconds: float
    stdout: bytes
    stderr: bytes


def run_bounded(command: list[str], cwd: Path, timeout_seconds: float,
                max_log_bytes: int) -> ProcessResult:
    """Own child/pipes until completion; kill the session on any bounded failure.

    No shell, inherited stdin, credentials, or user configuration is passed. This
    process boundary is resource cleanup, not protection against emulator exploits.
    KeyboardInterrupt is converted to a cancellation result after cleanup.
    """
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
        raise ValueError("timeout_seconds must be positive and finite")
    if isinstance(max_log_bytes, bool) or not isinstance(max_log_bytes, int) or max_log_bytes <= 0:
        raise ValueError("max_log_bytes must be a positive integer")
    if not command or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command):
        raise ValueError("command must contain nonempty strings")
    selector = selectors.DefaultSelector()  # Allocate before any child is owned.
    started = time.monotonic()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    cancelled = False
    handlers = {}

    def request_cancel(*_: object) -> None:
        nonlocal cancelled
        cancelled = True

    # Defer normal host cancellation until ownership of the child is established.
    # Python resets these handlers on exec; the child receives ordinary signals.
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, request_cancel)
    try:
        child = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True,
                                 env={"PATH": os.defpath, "LANG": "C", "TZ": "UTC"})
    except OSError as error:
        selector.close()
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        return ProcessResult("unavailable", f"process launch failed: {type(error).__name__}",
                             None, time.monotonic() - started, b"", b"")

    def kill_group(sig: int) -> None:
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass

    status, reason = "completed", "process exited and captured pipes reached EOF"
    with selector:
        try:
            for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
                assert pipe is not None
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map() or child.poll() is None:
                if cancelled:
                    status, reason = "cancelled", "execution cancelled by host signal"
                    break
                remaining = started + timeout_seconds - time.monotonic()
                if remaining <= 0:
                    status, reason = "timeout", "execution or pipe drain exceeded deadline"
                    break
                for key, _ in selector.select(min(remaining, 0.05)):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    available = max_log_bytes - sum(map(len, output.values()))
                    output[key.data].extend(block[:available])
                    if len(block) > available:
                        status, reason = "log_limit", "combined stdout/stderr exceeded log budget"
                        break
                if status != "completed":
                    break
        except KeyboardInterrupt:
            status, reason = "cancelled", "execution cancelled by host signal"
        except OSError as error:
            status, reason = "fail", f"process capture failed: {type(error).__name__}"
        finally:
            # Always kill remaining descendants, even when the process leader has
            # exited. A descendant may close its pipes and keep running otherwise.
            cleanup_errors = []
            try:
                try:
                    kill_group(signal.SIGTERM)
                except OSError as error:
                    cleanup_errors.append(type(error).__name__)
                if child.poll() is None:
                    try:
                        child.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
                try:
                    kill_group(signal.SIGKILL)
                except OSError as error:
                    cleanup_errors.append(type(error).__name__)
                # A denied group signal must not skip reaping the owned leader.
                # This fallback cannot establish descendant cleanup; any group
                # error is retained as an explicit failure, even if it succeeds.
                if child.poll() is None:
                    try:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    except OSError as error:
                        cleanup_errors.append(type(error).__name__)
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    cleanup_errors.append("reaping deadline exceeded")
            finally:
                for pipe in (child.stdout, child.stderr):
                    try:
                        pipe.close()
                    except OSError as error:
                        cleanup_errors.append(type(error).__name__)
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)
            if cleanup_errors:
                status = "fail"
                reason += "; process session cleanup failed: " + ", ".join(sorted(set(cleanup_errors)))
    return ProcessResult(status, reason, child.returncode,
                         time.monotonic() - started, bytes(output["stdout"]), bytes(output["stderr"]))
