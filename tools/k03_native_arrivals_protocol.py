"""Fixed input encoding for native execution of the PR #70 workload."""

from tools.k02_region_protocol import ROOT, digest, regular_bytes, require, strict_json

SCENARIOS = ("steady", "burst", "overload")
COUNTS = (8, 12, 30)
QUANTUMS = (4, 16)
ARM_ORDER = (4, 16, 16, 4)
DIRECTED = "directed"
DIRECTED_OFFERS = (
    {"id": 1, "domain": 1, "arrival": 0, "work": 64, "cancel": 1, "class": "prefill"},
    {"id": 2, "domain": 2, "arrival": 0, "work": 1, "cancel": 1, "class": "decode"},
    {"id": 3, "domain": 3, "arrival": 4, "work": 1, "cancel": None, "class": "control"},
)
SCHEDULE = ((DIRECTED, 4),) + tuple((scenario, quantum) for scenario in SCENARIOS for quantum in ARM_ORDER)
CLASSES = {"decode": 1, "prefill": 2, "control": 3}
PROFILE_FILE = "planning/scheduled-arrival-profile.json"
PROFILE_MAX_BYTES = 8192
PROFILE_SHA256 = "940916c8f90de732bfff6848dcf43e806c6b1efda53f67704a752fd32f4e1cbe"
PROFILE_MAGIC = b"TESSRYN-ARRIVE1\0"
PROFILE_SYMBOL = "K03_SMP_WORKLOAD_PROFILE"
PROFILE_INCLUDE = "kernel/smp_workload_profile.bin"
CONFIG_NAME = "opt/tessryn/scheduled-arrivals"
CONFIG_FILE = "selector.bin"
TICK_NS = 10
SCALE_NS = 10_000_000
HARD_QUANTUM_UNIT_NS = 20_000_000
SOFT_DIVISOR = 4
WORK_ITERATIONS = 64_000
RUN_LIMIT_NS = 24_000_000_000
TIMEOUT_SECONDS = 30
MAX_LOG_BYTES = 1 << 20
SCOPE = "Original-kernel native scheduled arrivals in pinned QEMU virtual time."


def load_profile(data=None):
    """Accept only the exact preregistered host workload, with its class labels."""
    if data is None:
        data = regular_bytes(ROOT / PROFILE_FILE, PROFILE_MAX_BYTES)
    require(type(data) is bytes and digest(data) == PROFILE_SHA256, "native workload differs from PR #70")
    profile = strict_json(data)
    require(type(profile) is dict and set(profile) == {"format", "quantums", "scenarios"}
            and profile["format"] == "tessryn-scheduled-arrival-profile/v1"
            and profile["quantums"] == list(QUANTUMS), "native workload header differs")
    scenarios = profile["scenarios"]
    require(type(scenarios) is dict and tuple(scenarios) == SCENARIOS, "native workload scenarios differ")
    cancels = 0
    for scenario, count in zip(SCENARIOS, COUNTS, strict=True):
        offers = scenarios[scenario]
        require(type(offers) is list and len(offers) == count, "native workload offer count differs")
        previous = 0
        for id_, offer in enumerate(offers, 1):
            require(type(offer) is dict and set(offer) == {"id", "domain", "arrival", "work", "cancel", "class"}
                    and all(type(offer[key]) is int for key in ("id", "domain", "arrival", "work"))
                    and offer["id"] == id_ and 1 <= offer["domain"] <= 4
                    and previous <= offer["arrival"] <= 255 and 1 <= offer["work"] <= 255
                    and offer["class"] in CLASSES, "native workload offer differs")
            previous = offer["arrival"]
            cancel = offer["cancel"]
            if cancel is not None:
                require(type(cancel) is int and max(1, previous) <= cancel <= 255,
                        "native workload cancellation differs")
                cancels += 1
    require(cancels == 8, "native workload cancellation count differs")
    return profile


def profile_bytes(profile):
    """Generate the packed immutable offer table consumed by the kernel."""
    rows = bytearray(PROFILE_MAGIC + bytes(COUNTS))
    for scenario in SCENARIOS:
        for offer in profile["scenarios"][scenario]:
            rows.extend((offer["id"], offer["domain"], offer["arrival"], offer["work"],
                         offer["cancel"] or 0, CLASSES[offer["class"]]))
    require(len(rows) == 319, "native compiled offer table size differs")
    return bytes(rows)


def config_bytes(scenario, quantum):
    selectors = (*SCENARIOS, DIRECTED)
    require(scenario in selectors and type(quantum) is int and quantum in QUANTUMS,
            "unknown native workload scenario or quantum")
    return bytes((selectors.index(scenario), quantum))


def offers_for(profile, scenario):
    require(scenario in (*SCENARIOS, DIRECTED), "unknown native workload scenario")
    return DIRECTED_OFFERS if scenario == DIRECTED else profile["scenarios"][scenario]
