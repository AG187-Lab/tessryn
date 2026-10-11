#!/usr/bin/env python3
"""Verify two independent fixture builds and retained emulator evidence."""

import argparse
import hashlib
from pathlib import Path

from g03.evidence import load_json, parse_json, registration_digest, validate_registration, validate_result
from run_emulator import MARKER, evaluator_hash, fixture_command, regular_bytes, verified_artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--result", type=Path, action="append", default=[])
    parser.add_argument("--registration", type=Path, default=Path("evidence/fixture-registration.json"))
    args = parser.parse_args()
    try:
        manifest_bytes = [regular_bytes(path) for path in (args.first, args.second)]
        manifests = [parse_json(data) for data in manifest_bytes]
        for path, manifest in zip((args.first, args.second), manifests):
            verified_artifact(path, "pass", manifest)
            verified_artifact(path, "hang", manifest)
        if manifest_bytes[0] != manifest_bytes[1]:
            raise ValueError("fresh build manifests differ")
        registration = parse_json(regular_bytes(args.registration))
        validate_registration(registration)
        if registration["subject"] != "test_fixture" or registration["registration_state"] != "fixture_protocol":
            raise ValueError("fixture evidence requires the fixture protocol registration")
        for result_path in args.result:
            result = parse_json(regular_bytes(result_path))
            validate_result(result)
            manifest_hash = hashlib.sha256(manifest_bytes[0]).hexdigest()
            registration_hash = registration_digest(registration)
            if result["bindings"]["artifact_manifest"] != manifest_hash:
                raise ValueError("result manifest binding differs")
            if result["bindings"]["registration"] != registration_hash:
                raise ValueError("result registration binding differs")
            if result["bindings"]["evaluator"] != evaluator_hash():
                raise ValueError("result evaluator binding differs from current trusted tooling")
            if result["subject"] != "test_fixture" or result["execution"]["command"] not in [fixture_command("pass"), fixture_command("hang")]:
                raise ValueError("result does not use the trusted fixture profile")
            emulator = result["execution"]["emulator"]
            pinned_version = load_json(Path(__file__).resolve().parents[1] / "toolchain.lock.json")["qemu"]["version"]
            if emulator is not None and (emulator["version"] != pinned_version
                                        or emulator["binary_sha256"] != manifests[0]["toolchain"]["qemu"]["sha256"]):
                raise ValueError("result emulator identity differs from pinned manifest provenance")
            logs = {}
            for log in result["logs"]:
                contents = regular_bytes(result_path.parent / log["path"])
                if hashlib.sha256(contents).hexdigest() != log["sha256"] or len(contents) != log["size_bytes"]:
                    raise ValueError("retained log hash or length differs")
                if log["path"] in logs:
                    raise ValueError("duplicate log path")
                logs[log["path"]] = contents
            if set(logs) != {"stdout.log", "stderr.log"}:
                raise ValueError("fixture evidence requires both captured streams")
            if result["status"] == "pass" and (result["execution"]["returncode"] != 33 or MARKER not in logs["stdout.log"]
                                               or result["execution"]["command"] != fixture_command("pass")):
                raise ValueError("retained fixture pass does not match marker and debug-exit status")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Fixture verification failed: {type(error).__name__}: {error}\n")
    print(f"Identical verified manifests/artifacts; {len(args.result)} result/log bundles verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
