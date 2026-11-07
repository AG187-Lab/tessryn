#!/usr/bin/env python3
"""Build, capture and verify the opt-in two-CPU CPL3 budget experiment."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import math
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_fixture import source_identity
from tools.build_k02_native import compile_flags, dependency_paths
from tools.build_k03_smp_user import coff_binding as inherited_coff_binding
from tools.build_kernel import compiler_profile, copy_notices, inspect_pe
from tools.g03.process import run_bounded
from tools.k01_media import make_disk
from tools.k02_region_protocol import (digest, file_ref, fresh_output, read_ref, regular_bytes, require,
    retain_private_error, strict_json, write_json)
from tools.k03_smp_budget_protocol import (ARTIFACT_TYPE, CASES, COMPILER_ROLES, COMPILER_SOURCES,
    DESCRIPTOR_SYMBOL, LIBRARY, PROFILE, PROFILE_NAME, RUNTIME_FILES, SCHEDULER_SHA256,
    SCHEDULER_SOURCE, SCOPE, artifacts, case_flags, compile_log, descriptor_bytes, format_name)
from tools.k03_smp_user_protocol import MAX_LOG_BYTES
from tools.k03_smp_user_provenance import canonical, committed_sources
from tools.run_k03_smp_user import launcher_command, qemu_command
from tools.setup_uefi import verify_installation
from tools.verify_k03_smp_user import completed, validate_notices, verify_host

BUILD_NAME = "smp-budget-build"
ENV = Path("/usr/bin/env")
PASS_REASON = "source-bound original two-CPU LAPIC preemption and budget protocol matched"
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, struct.error, subprocess.SubprocessError)
REF_FIELDS = {"path", "sha256", "size_bytes"}
FIRMWARE_FILES = {"code": "code.fd", "vars": "vars.fd", "notice": "NOTICE"}


def _read_json(path):
    return strict_json(regular_bytes(path, 2 << 20))


def _inventory(rows, expected, extra=()):
    require(type(rows) is list and len(rows) == len(expected)
        and all(type(row) is dict and set(row) == REF_FIELDS | set(extra) for row in rows)
        and {row["path"] for row in rows} == set(expected), "SMP budget file inventory differs")
    return {row["path"]: row for row in rows}


def runtime_hashes():
    return {name: digest(regular_bytes(ROOT / name, 16 << 20)) for name in RUNTIME_FILES}


def _commands(profile, output, snapshot, prefix, linker):
    remap = [f"--remap-path-prefix={prefix}=rust-toolchain", f"--remap-path-prefix={output}={BUILD_NAME}",
        f"--remap-path-prefix={snapshot}=tessryn"]
    library = output / LIBRARY
    flags = ["--crate-name=tessryn_scheduler" if arg == "--crate-name=tessryn_owned_memory" else arg
        for arg in compile_flags(profile, True)]
    commands = {"scheduler": [SCHEDULER_SOURCE, *flags, "-Dwarnings",
        f"--emit=link,dep-info={output}/scheduler/kernel.d", *remap, "-o", str(library)]}
    for case in CASES:
        directory = output / case
        commands[case] = ["kernel/main.rs", *profile["toolchain"]["rust_flags"], "-Dwarnings", *case_flags(case),
            f"--emit=link,obj={directory}/kernel.obj,dep-info={directory}/kernel.d", *remap,
            "-Clinker=" + str(linker), "--extern", f"tessryn_scheduler={library}", "-o", str(directory / "BOOTX64.EFI")]
    return commands


def expected_commands(profile):
    linker = Path(profile["linker"])
    prefix = ROOT / "build/uefi"
    require(linker.is_relative_to(prefix), "SMP budget linker is outside the pinned toolchain")
    return _commands(profile, Path(BUILD_NAME), Path("tessryn"), Path("rust-toolchain"),
        Path("rust-toolchain") / linker.relative_to(prefix))


def expected_dependencies():
    return {"scheduler": [SCHEDULER_SOURCE], **{case: sorted(set(COMPILER_SOURCES) - {SCHEDULER_SOURCE}) for case in CASES}}


def coff_binding(obj, efi, case):
    """Bind the budget descriptor after PR68's full COFF and payload validation."""
    inherited = inherited_coff_binding(obj, efi, "rendezvous", fault_entry=case == "fault")
    _, _, _, table, count, _, _ = struct.unpack_from("<HHIIIHH", obj)
    strings = table + count * 18
    found, index = [], 0
    while index < count:
        row = table + index * 18
        name = obj[row:row + 8]
        if name[:4] == bytes(4):
            offset = strings + struct.unpack_from("<I", name, 4)[0]
            name = obj[offset:obj.index(0, offset)]
        else:
            name = name.rstrip(b"\0")
        start, section, _, storage, auxiliary = struct.unpack_from("<IhHBB", obj, row + 8)
        if name == DESCRIPTOR_SYMBOL.encode():
            require(storage == 2 and 1 <= section <= struct.unpack_from("<H", obj, 2)[0], "SMP budget descriptor is not externally defined")
            found.append((20 + (section - 1) * 40, start))
        index += 1 + auxiliary
    require(len(found) == 1, "SMP budget descriptor symbol missing or ambiguous")
    section, start = found[0]
    size, raw, reloc = struct.unpack_from("<III", obj, section + 16)
    reloc_count = struct.unpack_from("<H", obj, section + 32)[0]
    flags = struct.unpack_from("<I", obj, section + 36)[0]
    expected = descriptor_bytes(case); length = len(expected)
    require(raw and start + length <= size and flags & 0x40000000 and not flags & 0xa0000080,
        "SMP budget descriptor is not in initialized read-only COFF data")
    widths = {0: 0, 1: 8, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4, 7: 4, 8: 4, 9: 4, 10: 2, 11: 4, 12: 1, 13: 4, 14: 4, 16: 4}
    for index in range(reloc_count):
        address, _, kind = struct.unpack_from("<IIH", obj, reloc + index * 10)
        width = widths[kind]
        require(width == 0 or address + width <= start or start + length <= address, "SMP budget COFF fixup overlaps descriptor")
    require(obj[raw + start:raw + start + length] == expected, "SMP budget compiled descriptor differs")
    offset = efi.find(expected)
    require(offset >= 0 and efi.find(expected, offset + 1) < 0, "SMP budget descriptor not unique in linked EFI")
    pe = struct.unpack_from("<I", efi, 60)[0]; first = pe + 24 + struct.unpack_from("<H", efi, pe + 20)[0]
    matches = []
    for index, row in enumerate(inspect_pe(efi)["sections"]):
        raw = struct.unpack_from("<I", efi, first + index * 40 + 20)[0]
        if raw <= offset and offset + length <= raw + min(row["size_bytes"], row["virtual_size"]):
            require(row["flags"] & 0x40000000 and not row["flags"] & 0xa0000000, "SMP budget linked descriptor is writable or executable")
            matches.append(row["rva"] + offset - raw)
    require(len(matches) == 1 and matches[0] + length <= inherited["bootstrap"]["image_size"], "SMP budget linked descriptor section differs")
    return {"context": inherited, "budget": {"size_bytes": length, "sha256": digest(expected), "efi_file_offset": offset, "efi_rva": matches[0]}}


def _scheduler_archive(data):
    # The pinned x64 UEFI rlib has two COFF linker indices, a long-name
    # table, Rust metadata and one codegen-unit object. Never execute it.
    require(data.startswith(b"!<arch>\n"), "SMP budget scheduler lacks a regular COFF archive header")
    roles = (b"/", b"/", b"//", b"lib.rmeta/", b"/0")
    cursor = 8
    for role in roles:
        header = data[cursor:cursor + 60]
        require(len(header) == 60 and header[:16].strip() == role and header[58:] == b"`\n"
            and header[48:58].strip().isdigit(), "SMP budget scheduler archive member header differs")
        size = int(header[48:58]); start = cursor + 60; end = start + size
        require(0 < size and end + (size & 1) <= len(data) and (not size & 1 or data[end:end + 1] == b"\n"),
            "SMP budget scheduler archive member extent differs")
        payload = data[start:end]
        if role == b"//":
            require(re.fullmatch(rb"libtessryn_scheduler\.tessryn_scheduler\.[0-9a-f]+-cgu\.0\.rcgu\.o\0\n?", payload),
                "SMP budget scheduler codegen unit name differs")
        if role in (b"lib.rmeta/", b"/0"):
            require(size >= 60 and payload[:2] == b"\x64\x86" and payload[16:18] == b"\0\0"
                and payload[20:28].rstrip(b"\0") == (b".rmeta" if role == b"lib.rmeta/" else b".text"),
                "SMP budget scheduler metadata/object is not the admitted x64 COFF member")
        cursor = end + (size & 1)
    require(cursor == len(data), "SMP budget scheduler archive has trailing or extra members")


def _receipt(out, role, process):
    row = {"role": role, "status": process.status, "returncode": process.returncode, "elapsed_seconds": process.elapsed_seconds}
    for stream in ("stdout", "stderr"):
        path = out / compile_log(role, stream); path.write_bytes(getattr(process, stream)); row[stream] = file_ref(out, path)
    return row


def build(out):
    out = fresh_output(out); receipts = []
    try:
        source, runtime, profile = source_identity(), runtime_hashes(), compiler_profile()
        retained = {name: regular_bytes(ROOT / name, 16 << 20) for name in COMPILER_SOURCES}
        require(digest(retained[SCHEDULER_SOURCE]) == SCHEDULER_SHA256, "SMP budget original scheduler changed")
        prefix = ROOT / "build/uefi"; bindings = {}; dependencies = {}; commands = {}
        with tempfile.TemporaryDirectory(prefix="source-", dir=out) as temporary:
            snapshot = Path(temporary)
            for name, data in retained.items():
                path = snapshot / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(0o400)
            for role, args in _commands(profile, out, snapshot, prefix, profile["linker"]).items():
                directory = out / role; directory.mkdir()
                process = run_bounded([str(profile["compiler"]), *args], snapshot, 90, MAX_LOG_BYTES)
                row = _receipt(out, role, process); receipts.append(row)
                require(completed(row), "SMP budget compilation failed; original diagnostics retained privately")
                require(all(not any(str(path).encode() in getattr(process, stream) for path in (ROOT, snapshot))
                    for stream in ("stdout", "stderr")), "SMP budget successful compiler logs contain local paths")
                dep = directory / "kernel.d"
                dependencies[role] = dependency_paths(regular_bytes(dep, 1 << 20).decode(), snapshot,
                    {out / LIBRARY} if role != "scheduler" else set())
                dep.unlink()
                commands[role] = [arg.replace(str(snapshot), "tessryn").replace(str(prefix), "rust-toolchain").replace(str(out), BUILD_NAME) for arg in args]
                if role == "scheduler":
                    _scheduler_archive(regular_bytes(out / LIBRARY))
                else:
                    image = regular_bytes(directory / "BOOTX64.EFI")
                    bindings[role] = coff_binding(regular_bytes(directory / "kernel.obj"), image, role)
                    (directory / "boot.img").write_bytes(make_disk(image))
            require(all(regular_bytes(snapshot / name, 16 << 20) == data for name, data in retained.items()), "SMP budget source snapshot changed")
        require(dependencies == expected_dependencies() and commands == expected_commands(profile), "SMP budget actual compiler closure or command differs")
        refs = []
        for name in sorted(set(retained) | set(runtime)):
            path = out / "sources" / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(retained[name] if name in retained else regular_bytes(ROOT / name, 16 << 20)); refs.append(file_ref(out, path))
        manifest = {"format": format_name("build"), "artifact_type": ARTIFACT_TYPE, "scope": SCOPE, "qualification": "not_established",
            "source": source, "source_files": {name: digest(data) for name, data in retained.items()}, "runtime_files": runtime,
            "retained_sources": refs, "toolchain": profile["toolchain"], "profile": PROFILE, "cases": list(CASES),
            "compiler_dependencies": dependencies, "compile_commands": commands, "compile": receipts, "bindings": bindings,
            "artifacts": [{**file_ref(out, out / name), "role": role} for name, role in artifacts().items()], "notices": copy_notices(out)}
        require(source_identity() == source and runtime_hashes() == runtime and verify_installation() == profile["toolchain"]["setup"]
            and all(regular_bytes(ROOT / name, 16 << 20) == data for name, data in retained.items()), "SMP budget inputs changed during build")
        write_json(out / "manifest.json", manifest); return manifest
    except ERRORS as error:
        retain_private_error(out, error)
        write_json(out / "build-failure.json", {"status": "fail", "reason": type(error).__name__, "compile": receipts})
        raise


def validate_build(path):
    path = Path(path); root = path.parent; m = _read_json(path)
    require(type(m) is dict and set(m) == {"format", "artifact_type", "scope", "qualification", "source", "source_files", "runtime_files",
        "retained_sources", "toolchain", "profile", "cases", "compiler_dependencies", "compile_commands", "compile", "bindings", "artifacts", "notices"}
        and m["format"] == format_name("build") and m["artifact_type"] == ARTIFACT_TYPE and m["scope"] == SCOPE
        and m["qualification"] == "not_established" and m["cases"] == list(CASES) and canonical(m["profile"]) == canonical(PROFILE)
        and m["compiler_dependencies"] == expected_dependencies(), "SMP budget build contract differs")
    files, runtime = m["source_files"], m["runtime_files"]
    require(type(files) is dict and set(files) == set(COMPILER_SOURCES) and type(runtime) is dict and set(runtime) == set(RUNTIME_FILES)
        and files[SCHEDULER_SOURCE] == SCHEDULER_SHA256, "SMP budget retained source closure differs")
    expected = {"sources/" + name: sha for name, sha in (files | runtime).items()}
    for name, row in _inventory(m["retained_sources"], expected).items():
        require(digest(read_ref(root, row, 16 << 20)) == expected[name], "SMP budget retained source digest differs")
    expected = artifacts(); data = {}
    for name, row in _inventory(m["artifacts"], expected, ("role",)).items():
        require(row["role"] == expected[name], "SMP budget artifact role differs"); data[name] = read_ref(root, row)
    _scheduler_archive(data[LIBRARY])
    require(type(m["bindings"]) is dict and set(m["bindings"]) == set(CASES), "SMP budget binding set differs")
    for case in CASES:
        image, obj, disk = (data[f"{case}/{name}"] for name in ("BOOTX64.EFI", "kernel.obj", "boot.img"))
        require(coff_binding(obj, image, case) == m["bindings"][case] and make_disk(image) == disk, "SMP budget image/object/media binding differs")
    rows = m["compile"]
    require(type(rows) is list and [row.get("role") for row in rows if type(row) is dict] == list(COMPILER_ROLES)
        and len(rows) == len(COMPILER_ROLES), "SMP budget compile receipts differ")
    for row in rows:
        require(set(row) == {"role", "status", "returncode", "elapsed_seconds", "stdout", "stderr"} and completed(row), "SMP budget compile did not finish")
        for stream in ("stdout", "stderr"):
            ref = row[stream]; _inventory([ref], [compile_log(row["role"], stream)])
            require(str(ROOT).encode() not in read_ref(root, ref, MAX_LOG_BYTES), "SMP budget compiler log contains local paths")
    validate_notices(root, m["notices"], m["toolchain"]["setup"])
    return m


def validate_source(m):
    source = m["source"]
    require(type(source) is dict and set(source) == {"revision", "dirty", "tree_sha256", "snapshot_algorithm"}
        and source["dirty"] is False and source["snapshot_algorithm"] == "git-worktree-v2", "SMP budget acceptance needs clean committed source")
    sources = committed_sources(source["revision"]); snapshot = hashlib.sha256()
    for name, (mode, data) in sorted(sources.items()):
        snapshot.update(name.encode() + b"\0" + mode.encode() + b"\0" + digest(data).encode() + b"\0")
    require(snapshot.hexdigest() == source["tree_sha256"], "SMP budget complete Git snapshot differs")
    for name, sha in (m["source_files"] | m["runtime_files"]).items():
        require(name in sources and digest(sources[name][1]) == sha, "SMP budget retained inputs differ from Git")
        if name in m["runtime_files"]:
            require(regular_bytes(ROOT / name, 16 << 20) == sources[name][1], "SMP budget reviewed runtime differs from Git")
    for name in ("LICENSE", "NOTICE"):
        data = sources[name][1]
        require(any(row["path"] == "notices/tessryn-" + name and row["sha256"] == digest(data) and row["size_bytes"] == len(data)
            for row in m["notices"]), "SMP budget notice differs from committed source")
    return {"revision": source["revision"], "tree_sha256": source["tree_sha256"],
        "compiler_dependencies": len(COMPILER_SOURCES), "runtime_files": len(RUNTIME_FILES)}


def validate_toolchain(m):
    profile = compiler_profile()
    require(canonical(m["toolchain"]) == canonical(profile["toolchain"]) and m["compile_commands"] == expected_commands(profile),
        "SMP budget compiler/toolchain command differs from checked host")
    return profile["toolchain"]["setup"]


def _selected(m, case):
    return [row for row in m["artifacts"] if row["role"] in ("scheduler", case)]


def _registration(m, manifest_raw, case, launcher_sha256, timeout):
    setup = m["toolchain"]["setup"]
    return {"format": format_name("registration"), "case": case, "scope": SCOPE, "qualification": "not_established",
        "capture_origin": "local_runner_claim_unverified_offline", "manifest_sha256": digest(manifest_raw), "selected_artifacts": _selected(m, case),
        "evaluator_sha256": digest(canonical(m["runtime_files"]).encode()), "command": qemu_command(), "timeout_seconds": timeout,
        "max_log_bytes": MAX_LOG_BYTES, "emulator_sha256": setup["verified_tools"]["qemu"]["sha256"],
        "launcher": {"executable": str(ENV), "sha256": launcher_sha256, "temporary_scope": "private owned directory removed after child reap"},
        "firmware": [{"path": "firmware/" + name, **{key: setup["firmware"][role][key] for key in ("sha256", "size_bytes")}}
            for role, name in FIRMWARE_FILES.items()]}


def _result(case, timeout):
    return {"format": format_name("result"), "case": case, "status": "fail", "reason": "inputs incomplete", "scope": SCOPE,
        "qualification": "not_established", "capture_only": False, "manifest_sha256": None, "registration_sha256": None,
        "evaluator_sha256": None, "observations": None, "logs": [], "execution": {"status": "unavailable", "returncode": None,
            "elapsed_seconds": 0, "command": qemu_command(), "timeout_seconds": timeout, "max_log_bytes": MAX_LOG_BYTES}}


def _timeout(value):
    require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 60, "SMP budget timeout exceeds the bounded profile")
    return value


def run(manifest_path, out, case, *, allow_qemu=False, capture_only=False, timeout=30):
    require(case in CASES and type(allow_qemu) is bool and type(capture_only) is bool, "SMP budget case or opt-in differs")
    out = fresh_output(out); result = _result(case, _timeout(timeout)); result["capture_only"] = capture_only; stdout = stderr = b""
    try:
        require(allow_qemu, "SMP budget capture requires explicit --allow-qemu")
        manifest_path = Path(manifest_path).absolute(); manifest_raw = regular_bytes(manifest_path, 2 << 20)
        m = validate_build(manifest_path); runtime = runtime_hashes(); setup = validate_toolchain(m)
        require(m["runtime_files"] == runtime and all(digest(regular_bytes(ROOT / name, 16 << 20)) == sha
            for name, sha in m["source_files"].items()), "SMP budget capture checkout differs from build")
        qemu = ROOT / "build/toolchain/bin/qemu-system-x86_64"
        env_sha = digest(regular_bytes(ENV, 16 << 20)); qemu_sha = digest(regular_bytes(qemu, 256 << 20))
        registration = _registration(m, manifest_raw, case, env_sha, timeout)
        require(registration["emulator_sha256"] == qemu_sha, "SMP budget checked emulator differs")
        (out / "firmware").mkdir()
        for role, row in zip(FIRMWARE_FILES, registration["firmware"]):
            source = setup["firmware"][role]; data = regular_bytes(ROOT / "build/uefi" / source["path"], 16 << 20)
            require(len(data) == row["size_bytes"] and digest(data) == row["sha256"], "SMP budget firmware differs from pinned bytes")
            (out / row["path"]).write_bytes(data)
        disk = next(row for row in registration["selected_artifacts"] if row["path"] == case + "/boot.img")
        registration["created_at_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        write_json(out / "registration.json", registration)
        result.update(manifest_sha256=registration["manifest_sha256"], evaluator_sha256=registration["evaluator_sha256"],
            registration_sha256=digest(regular_bytes(out / "registration.json")))
        write_json(out / "result.json", result)
        with tempfile.TemporaryDirectory(prefix="tessryn-smp-budget-", dir=Path("/tmp").resolve()) as temporary:
            scratch = Path(temporary); scratch.chmod(0o700)
            for row in registration["firmware"][:2]: (scratch / Path(row["path"]).name).write_bytes(read_ref(out, row, 16 << 20))
            (scratch / "boot.img").write_bytes(read_ref(manifest_path.parent, disk))
            execution = run_bounded(launcher_command(qemu, scratch), scratch, timeout, MAX_LOG_BYTES)
        stdout, stderr = execution.stdout, execution.stderr
        result["execution"].update(status=execution.status, returncode=execution.returncode, elapsed_seconds=execution.elapsed_seconds)
        require(runtime_hashes() == runtime and regular_bytes(manifest_path, 2 << 20) == manifest_raw and verify_installation() == setup
            and digest(regular_bytes(qemu, 256 << 20)) == qemu_sha and digest(regular_bytes(ENV, 16 << 20)) == env_sha
            and all(digest(regular_bytes(ROOT / name, 16 << 20)) == sha for name, sha in m["source_files"].items()),
            "SMP budget capture inputs changed during execution")
        for row in registration["selected_artifacts"]: read_ref(manifest_path.parent, row)
        for row in registration["firmware"]: read_ref(out, row, 16 << 20)
        require(execution.status == "completed" and execution.returncode == 33, "SMP budget guest did not exit cleanly")
        if capture_only: result.update(status="captured", reason="diagnostic capture; no protocol acceptance")
        else:
            from tools.k03_smp_budget_trace import parse_transcript
            result.update(status="pass", reason=PASS_REASON, observations=parse_transcript(case, stdout, 33, stderr, m["bindings"][case]))
    except ERRORS as error:
        retain_private_error(out, error); result.update(reason="SMP budget capture rejected: " + type(error).__name__)
    for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
        (out / name).write_bytes(data); result["logs"].append(file_ref(out, out / name))
    write_json(out / "result.json", result); return result


def verify_capture(path, manifest_path, m, *, launcher_sha256=None):
    """Replay receipts. The portable auditor supplies the archived launcher digest explicitly."""
    from tools.k03_smp_budget_trace import parse_transcript
    path = Path(path); value = _read_json(path); case = value.get("case")
    registration_raw = regular_bytes(path.parent / "registration.json", 2 << 20); registration = strict_json(registration_raw)
    timeout = _timeout(registration.get("timeout_seconds"))
    expected = _result(case, timeout)
    require(case in CASES and set(value) == set(expected) and value["format"] == expected["format"] and value["scope"] == SCOPE
        and value["qualification"] == "not_established" and value["status"] == "pass" and value["reason"] == PASS_REASON
        and value["capture_only"] is False and value["registration_sha256"] == digest(registration_raw), "SMP budget capture lacks complete acceptance")
    env_sha = digest(regular_bytes(ENV, 16 << 20)) if launcher_sha256 is None else launcher_sha256
    require(type(env_sha) is str and re.fullmatch("[0-9a-f]{64}", env_sha), "SMP budget launcher digest malformed")
    expected_registration = _registration(m, regular_bytes(manifest_path, 2 << 20), case, env_sha, timeout)
    created = registration.get("created_at_utc")
    require(type(created) is str and len(created) <= 64 and datetime.fromisoformat(created.replace("Z", "+00:00")).utcoffset()
        == timezone.utc.utcoffset(None), "SMP budget capture registration time is not UTC")
    require(canonical(registration) == canonical({**expected_registration, "created_at_utc": created}) and all(value[key] == registration[key]
        for key in ("manifest_sha256", "evaluator_sha256")), "SMP budget registration input identity differs")
    for row in registration["firmware"]: read_ref(path.parent, row, 16 << 20)
    execution = value["execution"]; elapsed = execution.get("elapsed_seconds")
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= timeout + 2
        and canonical(execution) == canonical({**expected["execution"], "status": "completed", "returncode": 33, "elapsed_seconds": elapsed}),
        "SMP budget actual process receipt differs")
    logs = _inventory(value["logs"], ("stdout.log", "stderr.log"))
    stdout, stderr = (read_ref(path.parent, logs[name], MAX_LOG_BYTES) for name in ("stdout.log", "stderr.log"))
    require(len(stdout) + len(stderr) <= MAX_LOG_BYTES, "SMP budget raw logs exceed registered bound")
    observations = parse_transcript(case, stdout, 33, stderr, m["bindings"][case])
    require(canonical(value["observations"]) == canonical(observations), "SMP budget stored observations differ from raw replay")
    return observations


def verify(first, second, host_result, results):
    first, second = Path(first).absolute(), Path(second).absolute()
    require(first.parent.resolve() != second.parent.resolve() and not first.samefile(second), "SMP budget twin manifests require distinct directories/inodes")
    a, b = validate_build(first), validate_build(second)
    require(all(canonical(a[key]) == canonical(b[key]) for key in a if key != "compile"), "SMP budget twin builds differ")
    identities = set()
    for path, manifest in ((first, a), (second, b)):
        for row in manifest["artifacts"]:
            st = (path.parent / row["path"]).stat(); identity = st.st_dev, st.st_ino
            require(identity not in identities, "SMP budget twins require independent artifact inodes"); identities.add(identity)
    provenance = validate_source(a); validate_toolchain(a); host = verify_host(host_result, a); observations = {}
    for path in results:
        value = _read_json(path); case = value.get("case")
        require(case in CASES and case not in observations, "SMP budget missing, duplicate or unknown case")
        observations[case] = verify_capture(path, first, a)
    require(set(observations) == set(CASES), "SMP budget verification needs every fresh case")
    return {"format": format_name("verification"), "status": "pass", "scope": SCOPE, "qualification": "not_established",
        "source": a["source"], "provenance": provenance, "twin_artifacts": len(artifacts()), "host_parser": host,
        "observations": observations, "capture_authentication": "unverified_offline"}


def failure_summary(root):
    """Only bounded status, return code and hashes; never upload failed raw bytes."""
    def meta(path):
        try: return file_ref(root, path)
        except ERRORS: return None
    def value(path):
        try:
            row = _read_json(path); return row if type(row) is dict else {}
        except ERRORS: return {}
    def status(row, paths):
        code = row.get("returncode"); state = row.get("status")
        return {"status": state if type(state) is str and state in ("completed", "timeout", "cancelled", "log_limit", "unavailable") else "unavailable",
            "returncode": code if type(code) is int and -(1 << 31) <= code < 1 << 31 else None, "logs": [meta(path) for path in paths]}
    captures = {}
    for case in CASES:
        base = root / case; row = value(base / "result.json").get("execution")
        captures[case] = status(row if type(row) is dict else {}, [base / (stream + ".log") for stream in ("stdout", "stderr")])
    twins = {}
    for name in ("a", "b"):
        base = root / name; rows = (value(base / "manifest.json") or value(base / "build-failure.json")).get("compile")
        rows = {row.get("role"): row for row in rows if type(row) is dict and type(row.get("role")) is str} if type(rows) is list else {}
        twins[name] = {role: status(rows.get(role, {}), [base / compile_log(role, stream) for stream in ("stdout", "stderr")]) for role in COMPILER_ROLES}
    return {"format": format_name("failure-summary"), "raw_output_published": False, "captures": captures, "twins": twins}


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest="operation", required=True)
    b = sub.add_parser("build"); b.add_argument("--out", type=Path, required=True)
    r = sub.add_parser("run"); r.add_argument("--out", type=Path, required=True); r.add_argument("--manifest", type=Path, required=True)
    r.add_argument("--case", choices=CASES, required=True); r.add_argument("--allow-qemu", action="store_true"); r.add_argument("--capture-only", action="store_true")
    v = sub.add_parser("verify"); v.add_argument("--result", type=Path, action="append", required=True)
    for name in ("first", "second", "host-result", "out"): v.add_argument("--" + name, type=Path, required=True)
    f = sub.add_parser("failure-summary"); f.add_argument("--root", type=Path, default=ROOT / "build" / PROFILE_NAME)
    args = parser.parse_args()
    try:
        if args.operation == "build":
            build(args.out); print("SMP budget cases built; qualification not established")
        elif args.operation == "run":
            result = run(args.manifest, args.out, args.case, allow_qemu=args.allow_qemu, capture_only=args.capture_only)
            print(canonical({key: result[key] for key in ("case", "status", "reason", "qualification")}))
            return 0 if result["status"] in ("pass", "captured") else 1
        elif args.operation == "verify":
            require(not args.out.exists(), "SMP budget verification output exists")
            report = verify(args.first, args.second, args.host_result, args.result); args.out.parent.mkdir(parents=True, exist_ok=True); write_json(args.out, report)
            print("All SMP budget cases verified; physical scheduling qualification unavailable")
        else:
            args.root.mkdir(parents=True, exist_ok=True); write_json(args.root / "failure-summary.json", failure_summary(args.root))
            print("SMP budget failure metadata retained; raw diagnostics excluded")
    except ERRORS as error:
        parser.exit(1, "SMP budget " + args.operation + " rejected: " + type(error).__name__ + "\n")
    return 0


if __name__ == "__main__": raise SystemExit(main())
