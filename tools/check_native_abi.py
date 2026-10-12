#!/usr/bin/env python3
"""Compile C/Rust ABI probes and preserve bounded host conformance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.g02.codec import DescriptorError, PROFILE, SCALARS, contract, decode, encode
from tools.g03.process import run_bounded
from tools.setup_toolchain import regular_tree_digest, rust_target_library_digest


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def leaves(layout: str, value: dict, definitions: dict, prefix: str = "", base: int = 0):
    for field in definitions["layouts"][layout]["fields"]:
        name, kind = field["name"], field["type"]
        member = prefix + name
        offset = base + field["offset"]
        if kind in SCALARS:
            yield member, kind, offset, value[name]
        else:
            yield from leaves(kind, value[name], definitions, member + ".", offset)


def probe_source(definitions: dict, vectors: list[dict], language: str) -> str:
    """Exercise authored types/helpers against independently retained byte frames."""
    c = language == "c"
    lines = ['#include "native.h"', '#include <stdio.h>'] if c else [
        '#![no_std]', '#[path="native.rs"] mod abi;']
    # Compare the compiled native definitions with the independent JSON contract,
    # rather than trusting only assertions maintained alongside each native type.
    for name, layout in definitions["layouts"].items():
        typename = layout["c_type" if c else "rust_type"]
        if c:
            lines += [f'_Static_assert(sizeof({typename})=={layout["size"]},"JSON size");',
                      f'_Static_assert(_Alignof({typename})=={layout["alignment"]},"JSON alignment");']
            lines += [f'_Static_assert(offsetof({typename},{f["name"]})=={f["offset"]},"JSON offset");'
                      for f in layout["fields"]]
            for field in layout["fields"]:
                field_type = (f"uint{field['type'][1:]}_t" if field["type"] in SCALARS else
                              definitions["layouts"][field["type"]]["c_type"])
                lines += [f'_Static_assert(_Generic((({typename}*)0)->{field["name"]},'
                          f'{field_type}:1,default:0),"JSON type");']
        else:
            lines += ['const _: () = {', f'assert!(core::mem::size_of::<abi::{typename}>()=={layout["size"]});',
                      f'assert!(core::mem::align_of::<abi::{typename}>()=={layout["alignment"]});']
            lines += [f'assert!(core::mem::offset_of!(abi::{typename},{f["name"]})=={f["offset"]});'
                      for f in layout["fields"]]
            lines += ['};']
            lines += [f'#[allow(dead_code)] fn check_{name.lower()}_types(value: abi::{typename}) {{']
            for field in layout["fields"]:
                field_type = (field["type"] if field["type"] in SCALARS else
                              "abi::" + definitions["layouts"][field["type"]]["rust_type"])
                lines += [f'let _: {field_type} = value.{field["name"]};']
            lines += ['}']
    constants = {"ABI_MAJOR": definitions["abi"]["major"], "ABI_MINOR": definitions["abi"]["minor"],
                 "ABI_FEATURE_MASK": definitions["abi"]["feature_mask"]}
    for group, prefix in (("kinds", "KIND_"), ("operations", "OP_"), ("statuses", "STATUS_"), ("milestones", "MILESTONE_")):
        constants.update({prefix + name.upper(): value for name, value in definitions[group].items()})
    for name, value in constants.items():
        lines.append(f'_Static_assert(TESSRYN_{name}=={value},"JSON constant");' if name.startswith("ABI_") and c else
                     f'_Static_assert(TESSRYN_ABI_{name}=={value},"JSON constant");' if c else
                     f'const _: () = assert!(abi::{name}=={value});')
    # Verify exported kind constants can be assigned directly to Header.kind.
    lines += ['int main(void) {', 'uint16_t kind = TESSRYN_ABI_KIND_SUBMISSION; (void)kind;'] if c else [
        'const _: u16 = abi::KIND_SUBMISSION;']
    for index, vector in enumerate(vectors):
        name = vector["name"]
        if not re.fullmatch("[a-zA-Z0-9_-]+", name):
            raise ValueError("invalid vector name")
        layout = definitions["layouts"][vector["layout"]]
        size = layout["size"]
        data = bytes.fromhex(vector["hex"])
        raw = ",".join(str(b) for b in data)
        typename = layout["c_type" if c else "rust_type"]
        if c:
            lines += ["{", f"{typename} value = {{0}};", f"uint8_t expected[{size}] = {{{raw}}};",
                      f"uint8_t encoded[{size}] = {{0}};"]
        else:
            lines += ["const _: () = {", f"let expected: [u8;{size}] = [{raw}];"]
        for member, kind, offset, number in leaves(vector["layout"], vector["values"], definitions):
            bits, width = int(kind[1:]), SCALARS[kind][1]
            if c:
                lines += [f"value.{member} = UINT{bits}_C({number});",
                          f"if (tessryn_abi_read_le{bits}(expected+{offset}) != value.{member}) return {index + 1};",
                          f"tessryn_abi_write_le{bits}(encoded+{offset}, value.{member});"]
            else:
                chunk = ",".join(f"expected[{offset + i}]" for i in range(width))
                lines += [f"assert!(abi::read_le{bits}([{chunk}]) == {number});",
                          f"let encoded = abi::write_le{bits}({number});"]
                lines += [f"assert!(encoded[{i}] == expected[{offset + i}]);" for i in range(width)]
        if c:
            lines += [f'printf("{name}:");', f'for (size_t i=0;i<{size};++i) {{',
                      f'if (encoded[i] != expected[i]) return {index + 1}; printf("%02x",encoded[i]);',
                      '}', 'puts("");', '}']
        else:
            lines += ['};']
    lines += ['return 0;', '}'] if c else []
    return "\n".join(lines) + "\n"


def execute(command: list[str], cwd: Path, *, retain_stderr: bool = False) -> str:
    result = run_bounded(command, cwd, 60, 262144)
    if result.status != "completed" or result.returncode != 0:
        # Compiler messages may contain host paths. Keep public failure receipts portable.
        message = result.stderr.decode(errors="replace").replace(str(ROOT), "<repo>").replace(str(cwd), "<probe>")
        raise ValueError(f"{Path(command[0]).name} {result.status}/{result.returncode}: {message[:4000]}")
    return result.stdout.decode() + (result.stderr.decode() if retain_stderr else "")


def select_tool(name: str) -> Path:
    found = shutil.which(name)
    if not found:
        raise ValueError(f"required compiler unavailable: {name}")
    return Path(found).resolve()


def verify(output: Path, rustc: Path, cc: Path) -> dict:
    definitions = contract()
    vectors = json.loads((PROFILE / "vectors.json").read_text())
    lock = json.loads((ROOT / "toolchain.lock.json").read_text())
    rust_version = execute([str(rustc), "--version", "--verbose"], ROOT)
    if (f"release: {lock['rust']['version']}\n" not in rust_version or
            f"commit-hash: {lock['rust']['revision']}\n" not in rust_version):
        raise ValueError("Rust version/revision differs from toolchain.lock.json")
    cc_version = execute([str(cc), "--version"], ROOT).splitlines()[0]
    sysroot = Path(execute([str(rustc), "--print", "sysroot"], ROOT).strip())
    receipt_path = sysroot / "installed.json"
    if not receipt_path.is_file():
        raise ValueError("verified Rust installation receipt missing; run setup_toolchain.py --rust-only")
    receipt = json.loads(receipt_path.read_text())
    if (type(receipt) is not dict or type(receipt.get("verified_tools")) is not dict or
            type(receipt["verified_tools"].get("rustc")) is not dict):
        raise ValueError("malformed Rust installation receipt")
    host = next(line[6:] for line in rust_version.splitlines() if line.startswith("host: "))
    target_digest = rust_target_library_digest(sysroot, lock["rust"]["target"])
    runtime_digest = regular_tree_digest(sysroot / "lib")
    if (receipt.get("schema_version") != 1 or receipt.get("host") != host or
            receipt.get("lock_sha256") != digest(ROOT / "toolchain.lock.json") or
            receipt.get("verified_tools", {}).get("rustc", {}).get("sha256") != digest(rustc) or
            receipt.get("rust_target_library_tree_sha256") != target_digest or
            receipt.get("rust_library_tree_sha256") != runtime_digest):
        raise ValueError("Rust binary/libraries do not match checksum-verified installation")
    checks = []
    for vector in vectors["positive"]:
        raw = bytes.fromhex(vector["hex"])
        if decode(vector["layout"], raw) != vector["values"] or encode(vector["layout"], vector["values"]) != raw:
            raise ValueError(f"golden frame mismatch: {vector['name']}")
        checks.append({"name": vector["name"], "expected": "accept", "observed": "accept",
                       "frame_sha256": hashlib.sha256(raw).hexdigest()})
    for vector in vectors["negative"]:
        try:
            decode(vector["layout"], bytes.fromhex(vector["hex"]))
        except DescriptorError as error:
            checks.append({"name": vector["name"], "expected": "reject", "observed": "reject", "reason": str(error)})
        else:
            raise ValueError(f"malformed frame accepted: {vector['name']}")
    expected_output = "".join(f"{v['name']}:{v['hex'].lower()}\n" for v in vectors["positive"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="g02-probes-", dir=output.parent) as temporary:
        work = Path(temporary)
        for name in ("native.h", "native.rs"):
            shutil.copyfile(PROFILE / name, work / name)
        (work / "probe.c").write_text(probe_source(definitions, vectors["positive"], "c"))
        (work / "probe.rs").write_text(probe_source(definitions, vectors["positive"], "rust"))
        execute([str(cc), "-std=c11", "-Wall", "-Wextra", "-Werror", "probe.c", "-o", "c-probe"], work)
        # no_std target compilation exercises the x86-64 target layouts without boot or execution.
        execute([str(rustc), "--edition=2021", "--crate-type=rlib", "--target", lock["rust"]["target"],
                 "native.rs", "-o", "native-x86_64.rlib"], work)
        execute([str(rustc), "--edition=2021", "-A", "dead_code", "--crate-type=rlib", "--target", lock["rust"]["target"],
                 "probe.rs", "-o", "rust-byte-probe.rlib"], work)
        observed = execute([str(work / "c-probe")], work)
        if observed != expected_output:
            raise ValueError("C byte roundtrip mismatch")
        probe_hashes = {name: digest(work / name) for name in ("probe.c", "probe.rs")}
    test_output = execute([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_native*.py", "-v"], ROOT,
                          retain_stderr=True)
    source = execute(["/usr/bin/git", "rev-parse", "HEAD"], ROOT).strip()
    dirty = bool(execute(["/usr/bin/git", "status", "--porcelain"], ROOT).strip())
    files = sorted([p for p in PROFILE.iterdir() if p.is_file()] + list((ROOT / "tools" / "g02").glob("*.py")) +
                   list((ROOT / "tests").glob("test_native*.py")) + [Path(__file__).resolve(), ROOT / "toolchain.lock.json"])
    result = {"schema_version": 1, "kind": "g02_host_conformance", "status": "passed",
              "scope": "host_layout_bytes_and_reference_state_machine", "source_revision": source, "source_dirty": dirty,
              "abi": definitions["abi"], "toolchains": {"rust": {"version": rust_version.strip(), "sha256": digest(rustc),
                                                        "setup_receipt_sha256": digest(receipt_path),
                                                        "target_library_tree_sha256": target_digest,
                                                        "runtime_library_tree_sha256": runtime_digest},
                                                        "c": {"version": cc_version, "sha256": digest(cc)}},
              "sources": {p.relative_to(ROOT).as_posix(): digest(p) for p in files},
              "generated_probes": probe_hashes, "binary_vectors": checks, "c_probe_output": observed,
              "compiled_checks": ["c11_host_layout_and_roundtrip", "rust_freestanding_x86_64_layout_and_const_byte_vectors"],
              "reference_tests": {"status": "passed", "log": test_output},
              "unavailable": ["native_service_execution", "memory_isolation", "queue_ordering", "DMA", "GPU", "Homa"]}
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "g02-result.json")
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--cc", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    # Never leave a previous successful receipt at the requested destination on a failed run.
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"schema_version": 1, "kind": "g02_host_conformance", "status": "incomplete"}) + "\n")
    try:
        pinned = ROOT / "build" / "toolchain" / "bin" / "rustc"
        rustc = args.rustc.resolve() if args.rustc else pinned if pinned.exists() else select_tool("rustc")
        result = verify(output, rustc, args.cc.resolve() if args.cc else select_tool("cc"))
    except (OSError, ValueError, KeyError) as error:
        print(f"G02 conformance failed: {error}", file=sys.stderr)
        output.write_text(json.dumps({"schema_version": 1, "kind": "g02_host_conformance", "status": "failed"}) + "\n")
        return 1
    print(f"G02 host conformance passed: {len(result['binary_vectors'])} byte vectors and C/Rust layout checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
