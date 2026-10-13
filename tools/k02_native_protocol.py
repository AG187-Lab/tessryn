"""Validate an offline K02 trace contract, never authenticate native execution.

The expectations file must be supplied independently from the transcript by the
reviewer/build owner. It binds exact probes and retained-artifact hashes. Those
assertions still need source, image, raw-log and runtime review: matching JSON
cannot prove a CPU executed an instruction or installed/invalidated a PTE.
This schema is evaluator preparation, not a kernel or public native wire ABI.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "planning/k02-native-cases.json"
SOURCE_PATHS = ("planning/k02-native-cases.json", "tools/k02_native_protocol.py")
MAX_BYTES = 1_048_576
DOMAINS = ("A", "B", "C", "D")
HANDLES = ("A", "B", "B_byte", "B_writeonly", "D", "old_B", "replacement_B", "C")
LEASES = ("A", "B", "D", "old_B", "replacement_B")
PAGES = ("unauthorized", "readonly", "guard", "kernel", "policy", "page_table",
         "data_nx", "revoked_B", "revoked_D", "reuse_B", "reuse_C")
SENTINELS = ("unauthorized", "readonly", "kernel", "policy", "page_table", "C")
BINDING_HASHES = ("kernel_image_sha256", "toolchain_sha256", "evaluator_sha256",
                  "raw_capture_sha256")
COMMITS = ("kernel_source_commit", "core_source_commit", "adapter_source_commit")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def keys(value, names, label):
    require(type(value) is dict and set(value) == set(names), "invalid " + label + " keys")


def integer(value, low=0, high=(1 << 64) - 1):
    require(type(value) is int and low <= value <= high, "invalid integer")


def digest(value, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value),
            "invalid artifact digest")


def canonical(value):
    integer(value)
    require(value < 1 << 47 or value >= (1 << 64) - (1 << 47), "noncanonical address")


def page(value, physical=False):
    integer(value, 4096, (1 << 48) - 4096 if physical else (1 << 64) - 4096)
    require(value % 4096 == 0, "unaligned page")
    if not physical:
        canonical(value)


def strict_json(raw):
    """Reject ambiguous JSON before accepting any protocol fields."""
    require(len(raw) <= MAX_BYTES, "input byte limit exceeded")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite JSON number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invalid JSON") from error
    remaining = [5000]

    def bounded(item, depth):
        remaining[0] -= 1
        require(depth <= 12 and remaining[0] >= 0, "JSON structure limit exceeded")
        require(type(item) in (dict, list, str, int, bool), "unsupported JSON value")
        if type(item) is dict:
            require(len(item) <= 128, "object limit exceeded")
            for key, child in item.items():
                require(len(key) <= 80, "key length exceeded")
                bounded(child, depth + 1)
        elif type(item) is list:
            require(len(item) <= 256, "array limit exceeded")
            for child in item:
                bounded(child, depth + 1)
        elif type(item) is str:
            require(len(item) <= 4096, "string length exceeded")
        elif type(item) is int:
            integer(item)

    bounded(value, 0)
    return value


def read_bytes(path):
    """Retain one bounded regular-file read for hashing or strict decoding."""
    require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK"), "bounded file reads unavailable")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "input must be a regular file")
        require(info.st_size <= MAX_BYTES, "input byte limit exceeded")
        contents = stream.read(MAX_BYTES + 1)
    require(len(contents) <= MAX_BYTES, "input byte limit exceeded")
    return contents


def read_json(path):
    return strict_json(read_bytes(path))


try:
    PROTOCOL_SHA256 = hashlib.sha256(read_bytes(Path(__file__).resolve(strict=True))).hexdigest()
except (OSError, RuntimeError, ValueError):
    # Defer an unavailable initialization binding to the public CLI failure.
    PROTOCOL_SHA256 = None


def source_hashes():
    return {name: hashlib.sha256(read_bytes(ROOT / name)).hexdigest()
            for name in SOURCE_PATHS}


def exact(actual, expected):
    """Python's bool/int equality must not make a malformed trace pass."""
    require(type(actual) is type(expected), "field type mismatch")
    if type(expected) is dict:
        keys(actual, expected, "record")
        for key in expected:
            exact(actual[key], expected[key])
    elif type(expected) is list:
        require(len(actual) == len(expected), "record count mismatch")
        for item, required in zip(actual, expected):
            exact(item, required)
    else:
        require(actual == expected, "record value mismatch")


def validate_expectations(value, contract, hashes):
    keys(value, ("schema", "binding", "profile", "domains", "roots", "handles",
                 "leases", "reuse_frame", "pages", "code", "probe_rips", "user_cs",
                 "sentinels", "case_contexts"), "expectations")
    exact(value["schema"], "tessryn-k02-native-expectations/v1")
    exact(value["profile"], contract["profile"])
    binding = value["binding"]
    keys(binding, COMMITS + BINDING_HASHES + ("protocol_sources_sha256", "environment"), "binding")
    for name in COMMITS:
        digest(binding[name], 40)
    for name in BINDING_HASHES:
        digest(binding[name])
    exact(binding["protocol_sources_sha256"], hashes)
    require(binding["environment"] in ("synthetic", "original_kernel_emulator", "physical_hardware"),
            "invalid execution environment")
    for name in ("domains", "roots"):
        keys(value[name], DOMAINS, name)
    for identity in value["domains"].values():
        integer(identity, 1)
    for root in value["roots"].values():
        page(root, physical=True)
    for name in ("domains", "roots"):
        require(len(set(value[name].values())) == 4, "domains and roots must be distinct")
    keys(value["handles"], HANDLES, "handles")
    for name, handle in value["handles"].items():
        keys(handle, ("slot", "generation", "domain"), "capability")
        integer(handle["slot"], 0, (1 << 32) - 1)
        integer(handle["generation"], 1, (1 << 32) - 1)
        expected_domain = "B" if name in ("old_B", "replacement_B", "B_writeonly", "B_byte") else name
        exact(handle["domain"], value["domains"][expected_domain])
    keys(value["leases"], LEASES, "leases")
    for lease in value["leases"].values():
        keys(lease, ("slot", "generation"), "lease")
        integer(lease["slot"], 0, (1 << 32) - 1)
        integer(lease["generation"], 1, (1 << 32) - 1)
    for name in ("handles", "leases"):
        old, replacement = value[name]["old_B"], value[name]["replacement_B"]
        require(old["slot"] == replacement["slot"] and
                replacement["generation"] == old["generation"] + 1,
                "replacement identity must advance the same slot")
        for other in (("B", "D") if name == "leases" else ("B",)):
            require(value[name][other]["slot"] != old["slot"], "live identity aliases reused slot")
    require(value["leases"]["B"]["slot"] != value["leases"]["D"]["slot"],
            "descendant leases must be distinct")
    require(len({value["handles"][name]["slot"] for name in ("B", "old_B", "B_byte", "B_writeonly")}) == 4,
            "distinct B authorities must have separate slots")
    page(value["reuse_frame"], physical=True)
    require(value["reuse_frame"] not in value["roots"].values(), "reuse frame overlaps page tables")
    keys(value["pages"], PAGES, "pages")
    for name, address in value["pages"].items():
        page(address)
        if name not in ("kernel", "policy", "page_table"):
            require(address < 1 << 47, "user page must be in the lower canonical half")
    require(len(set(value["pages"].values())) == len(PAGES), "probe pages must be distinct")
    require(value["pages"]["guard"] == value["pages"]["readonly"] + 4096,
            "guard must immediately follow the shared page")
    keys(value["code"], ("start", "end"), "probe code")
    page(value["code"]["start"])
    page(value["code"]["end"])
    require(value["code"]["start"] < value["code"]["end"] < 1 << 47,
            "invalid user probe code range")
    for address in value["pages"].values():
        require(not value["code"]["start"] <= address < value["code"]["end"],
                "data/supervisor probe overlaps executable probe code")
    keys(value["probe_rips"], contract["faults"], "probe instructions")
    for name, rip in value["probe_rips"].items():
        canonical(rip)
        if name == "nx_fetch":
            exact(rip, value["pages"]["data_nx"])
        else:
            require(value["code"]["start"] <= rip < value["code"]["end"],
                    "probe RIP outside trusted probe code")
    require(len(set(value["probe_rips"].values())) == len(contract["faults"]), "probe RIPs must be distinct")
    integer(value["user_cs"], 1, 65535)
    require(value["user_cs"] & 3 == 3 and value["user_cs"] & 4 == 0 and
            value["user_cs"] >> 3 != 0, "invalid CPL3 GDT selector")
    keys(value["sentinels"], SENTINELS, "sentinels")
    for sentinel in value["sentinels"].values():
        digest(sentinel)
    keys(value["case_contexts"], contract["cases"], "case contexts")
    for context in value["case_contexts"].values():
        keys(context, ("id", "raw_capture_sha256", "initial_state"), "case context")
        digest(context["id"])
        digest(context["raw_capture_sha256"])
        exact(context["initial_state"], contract["case_state"])
    for field in ("id", "raw_capture_sha256"):
        require(len({context[field] for context in value["case_contexts"].values()}) == len(contract["cases"]),
                "cases must bind independent fresh capture contexts")


def expected_cases(value, contract):
    """Expand fixed obligations using independently bound addresses/identities."""
    domains, roots, handles, leases = (value[key] for key in ("domains", "roots", "handles", "leases"))
    pages, sentinels = value["pages"], value["sentinels"]
    cases = []

    def case(name, events):
        context = value["case_contexts"][name]
        boot = event("fresh_boot", context_id=context["id"],
                     reset="original_kernel_entry", untrusted_state_retained=False)
        cases.append({"case": name, "context": context, "events": [boot] + events})

    def event(name, **fields):
        return {"event": name, **fields}

    def fault(name):
        spec = contract["faults"][name]
        return event("page_fault", probe=name, domain=domains[spec["domain"]],
                     root=roots[spec["domain"]], vector=14, cs=value["user_cs"],
                     rip=value["probe_rips"][name], cr2=pages[spec["page"]],
                     error_code=spec["error_code"], recovered=True)

    def sentinel(name):
        return event("sentinel_unchanged", page=pages["reuse_C" if name == "C" else name],
                     before_sha256=sentinels[name], after_sha256=sentinels[name])

    def denied(operation, handle, **fields):
        return event("dispatch_denied", caller=domains["B"], operation=operation,
                     origin="CPL3", cs=value["user_cs"],
                     capability=handles[handle], pte_published=False,
                     charge_released=False, **fields)

    def mapping(domain, page_name, lease, writable=True):
        return event("mapping_installed", domain=domains[domain], root=roots[domain],
                     page=pages[page_name], length=4096, readable=True, writable=writable,
                     executable=False, physical_frame=value["reuse_frame"],
                     lease=leases[lease], charge_retained=True)

    def owned(handle):
        return event("backing_owned", capability=handles[handle], physical_frame=value["reuse_frame"],
                     length=4096, charge_owner=handles[handle]["domain"], committed_pages=1,
                     reserved_pages=0, charged_pages=1)

    def prime(domain, page_name, lease, writable=True):
        return event("mapping_primed", domain=domains[domain], root=roots[domain],
                     page=pages[page_name], physical_frame=value["reuse_frame"],
                     lease=leases[lease], read_executed=True,
                     write_executed=writable, charge_retained=True)

    def teardown(domain, page_name, lease):
        common = {"domain": domains[domain], "root": roots[domain], "page": pages[page_name],
                  "physical_frame": value["reuse_frame"], "lease": leases[lease], "charge_retained": True}
        return [event("fence", **common), event("clear_pte", **common),
                event("invalidate", method="cr3_reload", **common),
                event("quiesce", trusted=True, **common)]

    case("caller_forgery", [owned("A"), denied("map", "A", claimed_caller=domains["A"]),
                            event("owner_retained", capability=handles["A"])])
    delegated_read = event("delegated", parent=handles["A"], child=handles["B"],
                           offset=0, length=4096, rights=5)
    privileged = ([owned("A"), delegated_read, mapping("B", "readonly", "B", writable=False)] +
         [denied(operation, "B", submitted_lease=leases["B"], denial_reason="untrusted_origin")
          for operation in ("fence", "quiesce", "allocator_admin", "complete_lease", "activate_reserved")])
    privileged += [event("fence", domain=domains["B"], root=roots["B"], page=pages["readonly"],
                         physical_frame=value["reuse_frame"], lease=leases["B"], charge_retained=True,
                         trusted=True, phase="fenced", pte_installed=True),
                   denied("quiesce", "B", submitted_lease=leases["B"], lease_phase="fenced",
                          pte_installed=True, denial_reason="untrusted_origin"),
                   event("mapping_owner_retained", domain=domains["B"], root=roots["B"],
                         page=pages["readonly"], physical_frame=value["reuse_frame"], lease=leases["B"],
                         phase="fenced", pte_installed=True, charge_retained=True),
                   event("owner_retained", capability=handles["A"], charge_retained=True)]
    case("trusted_operation_forgery", privileged)
    case("unauthorized_read", [owned("A"), mapping("A", "unauthorized", "A", writable=False),
                               event("read_observed", domain=domains["A"], page=pages["unauthorized"],
                                     sha256=sentinels["unauthorized"]), fault("unauthorized_read")])
    case("read_only_sharing", [owned("A"), event("delegated", parent=handles["A"], child=handles["B"],
                                   offset=0, length=4096, rights=5),
                               mapping("B", "readonly", "B", writable=False),
                               event("read_observed", domain=domains["B"], page=pages["readonly"],
                                     sha256=sentinels["readonly"]), fault("readonly_write"), sentinel("readonly")])
    case("exact_bounds", [owned("A"), delegated_read, mapping("B", "readonly", "B", writable=False),
                          fault("guard_read"),
                          event("delegated", parent=handles["A"], child=handles["B_byte"],
                                offset=1, length=4094, rights=5),
                          denied("map_byte_slice", "B_byte", capability_offset=1, capability_length=4094,
                                 offset=0, length=4094, denial_reason="Alignment"),
                          denied("map_byte_slice", "B_byte", capability_offset=1, capability_length=4094,
                                 offset=0, length=4096, denial_reason="Bounds"),
                          *teardown("B", "readonly", "B"),
                          event("lease_released", lease=leases["B"],
                                physical_frame=value["reuse_frame"], charge_retained=True),
                          event("delegated", parent=handles["A"], child=handles["B_writeonly"],
                                offset=0, length=4096, rights=6),
                          denied("map_without_read", "B_writeonly", rights=6,
                                 denial_reason="InsufficientRights")])
    case("kernel_isolation", [record for name in ("kernel", "policy", "page_table")
         for record in (fault(name + "_read"), fault(name + "_write"), sentinel(name))])
    case("data_nx", [owned("A"), delegated_read, mapping("B", "data_nx", "B", writable=False),
                     event("nx_confirmed", supported=True, enabled=True), fault("nx_fetch")])
    recursive = [owned("A"),
                 event("delegated", parent=handles["A"], child=handles["B"], offset=0, length=4096, rights=21),
                 event("delegated", parent=handles["B"], child=handles["D"], offset=0, length=4096, rights=5)]
    for domain in ("B", "D"):
        recursive += [mapping(domain, "revoked_" + domain, domain, writable=False),
                      prime(domain, "revoked_" + domain, domain, writable=False)]
    recursive += [event("descendants_revoked", root_capability=handles["A"],
                        descendants=[handles["B"], handles["D"]], charge_retained=True)]
    for domain in ("B", "D"):
        recursive += [event("revoked_request_denied", domain=domains[domain], capability=handles[domain],
                            lease=leases[domain], operation=operation, charge_retained=True)
                      for operation in ("map", "complete_lease")]
        recursive += teardown(domain, "revoked_" + domain, domain)
    recursive += [event("mapping_leases_released", leases=[leases["B"], leases["D"]], charge_retained=True)]
    for domain in ("B", "D"):
        recursive += [fault("recursive_" + domain + "_read"), fault("recursive_" + domain + "_write")]
    recursive += [event("capabilities_released", capabilities=[handles["D"], handles["B"], handles["A"]],
                        charge_released=True)]
    case("recursive_revocation", recursive)
    reuse = [owned("old_B"), mapping("B", "reuse_B", "old_B"), prime("B", "reuse_B", "old_B"),
             event("revoked", capability=handles["old_B"], physical_frame=value["reuse_frame"], charge_retained=True)]
    reuse += teardown("B", "reuse_B", "old_B")
    reuse += [event("lease_released", lease=leases["old_B"], physical_frame=value["reuse_frame"], charge_retained=True),
              event("capability_released", capability=handles["old_B"],
                    physical_frame=value["reuse_frame"], charge_released=True),
              event("scrubbed", physical_frame=value["reuse_frame"], length=4096, trusted=True),
              event("reassigned", physical_frame=value["reuse_frame"], capability=handles["C"],
                    domain=domains["C"], root=roots["C"], page=pages["reuse_C"],
                    initial_sha256=sentinels["C"]), fault("reuse_B_read"), fault("reuse_B_write"), sentinel("C")]
    case("writable_reuse", reuse)
    stale = [owned("old_B"), mapping("B", "reuse_B", "old_B"), prime("B", "reuse_B", "old_B"),
             event("revoked", capability=handles["old_B"], physical_frame=value["reuse_frame"], charge_retained=True)]
    stale += teardown("B", "reuse_B", "old_B")
    stale += [event("lease_released", lease=leases["old_B"], physical_frame=value["reuse_frame"], charge_retained=True),
              event("capability_released", capability=handles["old_B"],
                    physical_frame=value["reuse_frame"], charge_released=True),
              event("retired_generation", capability=handles["old_B"], lease=leases["old_B"], released=True),
              event("scrubbed", physical_frame=value["reuse_frame"], length=4096, trusted=True), owned("C"),
              event("victim_initialized", capability=handles["C"], domain=domains["C"], root=roots["C"],
                    physical_frame=value["reuse_frame"], page=pages["reuse_C"], length=4096,
                    initial_sha256=sentinels["C"]),
              event("delegated", parent=handles["C"], child=handles["replacement_B"],
                    offset=0, length=4096, rights=5),
              mapping("B", "reuse_B", "replacement_B", writable=False),
              denied("release_stale_capability", "old_B", replacement=handles["replacement_B"],
                     denial_reason="StaleHandle"),
              event("backend_stale_lease_denied", operation="fence", origin="trusted_backend", trusted=True,
                    submitted_lease=leases["old_B"], replacement_lease=leases["replacement_B"],
                    denial_reason="StaleLease", replacement_phase="active", pte_installed=True,
                    charge_released=False),
              event("replacement_retained", capability=handles["replacement_B"],
                    domain=domains["B"], root=roots["B"], page=pages["reuse_B"],
                    physical_frame=value["reuse_frame"], lease=leases["replacement_B"],
                    phase="active", pte_installed=True, charge_retained=True),
              event("replacement_read_authorized", caller=domains["B"], capability=handles["replacement_B"],
                    offset=0, length=4096, physical_frame=value["reuse_frame"]),
              event("fence", domain=domains["B"], root=roots["B"], page=pages["reuse_B"],
                    physical_frame=value["reuse_frame"], lease=leases["replacement_B"],
                    trusted=True, phase="fenced", pte_installed=True, charge_retained=True), sentinel("C")]
    case("stale_identities", stale)
    exact([item["case"] for item in cases], contract["cases"])
    return cases


def validate(transcript, expectations):
    hashes = source_hashes()
    require(PROTOCOL_SHA256 is not None and hashes["tools/k02_native_protocol.py"] == PROTOCOL_SHA256,
            "protocol source changed since initialization")
    contract_bytes = read_bytes(CONTRACT_PATH)
    require(hashlib.sha256(contract_bytes).hexdigest() == hashes["planning/k02-native-cases.json"],
            "contract source changed during validation")
    contract = strict_json(contract_bytes)
    exact(source_hashes(), hashes)
    validate_expectations(expectations, contract, hashes)
    keys(transcript, ("schema", "evidence_kind", "binding", "profile", "cases"), "transcript")
    exact(transcript["schema"], "tessryn-k02-native-protocol/v1")
    require(transcript["evidence_kind"] in ("synthetic_fixture", "external_capture"), "invalid evidence kind")
    synthetic = expectations["binding"]["environment"] == "synthetic"
    require((transcript["evidence_kind"] == "synthetic_fixture") == synthetic,
            "evidence kind/environment mismatch")
    exact(transcript["binding"], expectations["binding"])
    exact(transcript["profile"], contract["profile"])
    exact(transcript["cases"], expected_cases(expectations, contract))
    exact(source_hashes(), hashes)
    return {"schema": "tessryn-k02-native-protocol-result/v1", "kind": "protocol_validation",
            "status": "passed", "evidence_kind": transcript["evidence_kind"], "case_count": len(contract["cases"]),
            "native_qualification": "not_established", "hardware_authentication": "unavailable",
            "protocol_sources_sha256": hashes}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expectations", type=Path, required=True,
                        help="independently supplied source/artifact/probe bindings")
    args = parser.parse_args(argv)
    try:
        result = validate(read_json(args.input), read_json(args.expectations))
    except (ValueError, OSError, TypeError, KeyError) as error:
        reason = str(error) if isinstance(error, ValueError) else "input unavailable or malformed"
        result = {"schema": "tessryn-k02-native-protocol-result/v1", "kind": "protocol_validation",
                  "status": "failed", "reason": reason, "native_qualification": "not_established",
                  "hardware_authentication": "unavailable"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
