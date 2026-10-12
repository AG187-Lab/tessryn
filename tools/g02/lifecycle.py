"""Original host reference for proposed authority/lifetime rules, not a kernel.

Integers are bounded without wrap. One acquire represents one bounded device
ownership interval. Completion and explicit device/transfer quiescence are
separate; this deliberately conservative reference does not model real DMA.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field


U64_MAX = (1 << 64) - 1
U32_MAX = (1 << 32) - 1
RIGHTS = frozenset({"read", "write", "submit", "delegate"})
MILESTONES = ("received", "launches_stopped", "output_fenced", "reclaimed")


class ContractError(ValueError):
    """An action violates the proposed contract; state remains unchanged."""


@dataclass(frozen=True)
class Handle:
    domain: int
    slot: int
    generation: int


@dataclass
class _Domain:
    budget: int
    epoch: int
    charged: int = 0
    completion_sequence: int = 0
    generations: dict[int, int] = field(default_factory=dict)


@dataclass
class _Capability:
    handle: Handle
    region: int
    offset: int
    length: int
    rights: frozenset[str]
    parent: Handle | None = None
    revoked: bool = False


@dataclass
class _Region:
    owner: int
    charge: int
    ownership_generation: int = 0
    owners: set[tuple[int, int]] = field(default_factory=set)


@dataclass
class _Operation:
    region: int
    epoch: int
    ownership: int
    offset: int
    length: int
    right: str
    phase: str = "acquired"
    completed: bool = False
    quiesced: bool = False


def _integer(value: int, label: str, minimum: int = 0, maximum: int = U64_MAX) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(f"{label} is outside its unsigned bounded range")
    return value


def _rights(value: frozenset[str]) -> frozenset[str]:
    if not isinstance(value, (set, frozenset)) or not value or not value <= RIGHTS:
        raise ContractError("unknown or empty rights")
    return frozenset(value)


def _range(offset: int, length: int, ceiling: int) -> None:
    _integer(offset, "offset")
    _integer(length, "length", 1)
    if offset > U64_MAX - length or offset + length > ceiling:
        raise ContractError("region range overflows or exceeds its capability")


class LifecycleModel:
    """Single-threaded executable specification with explicit caller domains.

    Delegation is a bounded view of the same charged backing memory. A parent
    cannot be released before its descendants. Request tombstones are retained
    to forbid ID replay. Concurrent reads may overlap; any overlapping write
    requires prior device quiescence. Slots, handle generations and ownership
    generations obey ABI u32 bounds; other counters obey u64 bounds. Production
    storage and concurrency are outside scope.
    """

    def __init__(self, counter_limit: int = U64_MAX):
        self.counter_limit = _integer(counter_limit, "counter limit", 1)
        self.domains: dict[int, _Domain] = {}
        self.capabilities: dict[Handle, _Capability] = {}
        self.regions: dict[int, _Region] = {}
        self.operations: dict[tuple[int, int], _Operation] = {}
        self.region_sequence = 0

    def snapshot(self) -> dict:
        """Detached state for conformance assertions; no live references escape."""
        return deepcopy(self.__dict__)

    def _domain(self, domain: int) -> _Domain:
        _integer(domain, "domain", 1)
        if domain not in self.domains:
            raise ContractError("unknown domain")
        return self.domains[domain]

    def _capability(self, domain: int, handle: Handle, active: bool = True) -> _Capability:
        self._domain(domain)
        if not isinstance(handle, Handle):
            raise ContractError("invalid handle")
        _integer(handle.domain, "domain", 1)
        for name in ("slot", "generation"):
            _integer(getattr(handle, name), name, 1, U32_MAX)
        if handle.domain != domain:
            raise ContractError("cross-domain handle")
        cap = self.capabilities.get(handle)
        if cap is None:
            raise ContractError("stale or unknown handle")
        if active and cap.revoked:
            raise ContractError("revoked authority")
        return cap

    def _new_handle(self, domain: int) -> Handle:
        state = self._domain(domain)
        occupied = {h.slot for h in self.capabilities if h.domain == domain}
        handle_limit = min(self.counter_limit, U32_MAX)
        for slot in range(1, min(len(state.generations) + 1, handle_limit) + 1):
            generation = state.generations.get(slot, 0)
            if slot not in occupied and generation < handle_limit:
                return Handle(domain, slot, generation + 1)
        raise ContractError("capability namespace exhausted without wrap")

    def _install(self, cap: _Capability) -> Handle:
        self.capabilities[cap.handle] = cap
        self.domains[cap.handle.domain].generations[cap.handle.slot] = cap.handle.generation
        return cap.handle

    def _operation(self, domain: int, operation_id: int) -> _Operation:
        self._domain(domain)
        _integer(operation_id, "operation ID", 1)
        operation = self.operations.get((domain, operation_id))
        if operation is None:
            raise ContractError("unknown operation")
        return operation

    def create_domain(self, domain: int, budget: int, epoch: int = 1) -> None:
        _integer(domain, "domain", 1)
        _integer(budget, "budget")
        _integer(epoch, "epoch", 1, self.counter_limit)
        if domain in self.domains:
            raise ContractError("domain identity already exists")
        self.domains[domain] = _Domain(budget, epoch)

    def advance_epoch(self, domain: int, epoch: int) -> None:
        state = self._domain(domain)
        _integer(epoch, "epoch", 1, self.counter_limit)
        if epoch <= state.epoch:
            raise ContractError("placement epoch cannot replay or wrap")
        state.epoch = epoch

    def allocate(self, domain: int, committed: int, reserved: int = 0,
                 rights: frozenset[str] = RIGHTS) -> Handle:
        state = self._domain(domain)
        _integer(committed, "committed", 1)
        _integer(reserved, "reserved")
        rights = _rights(rights)
        if committed > U64_MAX - reserved:
            raise ContractError("memory charge overflows")
        charge = committed + reserved
        if charge > state.budget - state.charged:
            raise ContractError("committed plus reserved memory exceeds budget")
        if self.region_sequence == self.counter_limit:
            raise ContractError("region identity exhausted without wrap")
        handle = self._new_handle(domain)
        region = self.region_sequence + 1
        cap = _Capability(handle, region, 0, committed, rights)
        self.regions[region] = _Region(domain, charge)
        self.region_sequence = region
        state.charged += charge
        return self._install(cap)

    def delegate(self, domain: int, handle: Handle, target_domain: int,
                 rights: frozenset[str], offset: int = 0, length: int | None = None) -> Handle:
        parent = self._capability(domain, handle)
        self._domain(target_domain)
        rights = _rights(rights)
        if "delegate" not in parent.rights or not rights <= parent.rights:
            raise ContractError("delegation cannot amplify authority")
        if length is None:
            length = parent.length
        _range(offset, length, parent.length)
        child = self._new_handle(target_domain)
        return self._install(_Capability(child, parent.region, parent.offset + offset,
                                         length, rights, parent=handle))

    def acquire(self, domain: int, handle: Handle, operation_id: int, epoch: int,
                offset: int, length: int, right: str = "write") -> int:
        cap = self._capability(domain, handle)
        state = self._domain(domain)
        _integer(operation_id, "operation ID", 1)
        _integer(epoch, "epoch", 1, self.counter_limit)
        if type(right) is not str or right not in {"read", "write"} or not {"submit", right} <= cap.rights:
            raise ContractError("insufficient submission authority")
        _range(offset, length, cap.length)
        key = (domain, operation_id)
        if key in self.operations or epoch != state.epoch:
            raise ContractError("operation ID replay or stale placement epoch")
        region = self.regions[cap.region]
        absolute_offset = cap.offset + offset
        absolute_end = absolute_offset + length
        for owner in region.owners:
            pending = self.operations[owner]
            if (absolute_offset < pending.offset + pending.length and pending.offset < absolute_end
                    and (right == "write" or pending.right == "write")):
                raise ContractError("overlapping ownership requires device quiescence")
        if region.ownership_generation >= min(self.counter_limit, U32_MAX):
            raise ContractError("ownership generation exhausted without wrap")
        ownership = region.ownership_generation + 1
        self.operations[key] = _Operation(cap.region, epoch, ownership, absolute_offset, length, right)
        region.ownership_generation = ownership
        region.owners.add(key)
        return ownership

    def complete(self, domain: int, operation_id: int, epoch: int,
                 ownership: int, sequence: int) -> None:
        op = self._operation(domain, operation_id)
        state = self._domain(domain)
        _integer(epoch, "epoch", 1, self.counter_limit)
        _integer(ownership, "ownership", 1, min(self.counter_limit, U32_MAX))
        _integer(sequence, "sequence", 1, self.counter_limit)
        if (op.completed or op.phase not in {"acquired", "received", "launches_stopped"}
                or epoch != op.epoch or epoch != state.epoch
                or ownership != op.ownership or sequence != state.completion_sequence + 1):
            raise ContractError("fenced, stale or out-of-sequence completion")
        op.completed = True
        if op.phase == "acquired":
            op.phase = "completed"
        state.completion_sequence = sequence

    def revoke(self, domain: int, handle: Handle) -> None:
        self._capability(domain, handle)
        affected = {handle}
        while True:
            children = {h for h, cap in self.capabilities.items() if cap.parent in affected}
            if children <= affected:
                break
            affected |= children
        for descendant in affected:
            self.capabilities[descendant].revoked = True

    def release(self, domain: int, handle: Handle) -> None:
        cap = self._capability(domain, handle, active=False)
        region = self.regions[cap.region]
        if region.owners or any(c.parent == handle for c in self.capabilities.values()):
            raise ContractError("outstanding ownership or delegated capability prevents release")
        del self.capabilities[handle]
        if not any(c.region == cap.region for c in self.capabilities.values()):
            self.domains[region.owner].charged -= region.charge
            del self.regions[cap.region]

    def cancel(self, domain: int, operation_id: int, milestone: str) -> None:
        op = self._operation(domain, operation_id)
        expected = "received" if op.phase == "acquired" else (
            MILESTONES[MILESTONES.index(op.phase) + 1]
            if op.phase in MILESTONES[:-1] else None)
        if (milestone not in MILESTONES or milestone != expected
                or (milestone == "reclaimed" and not op.quiesced)):
            raise ContractError("cancellation milestone skipped, replayed or not quiesced")
        op.phase = milestone

    def quiesce(self, domain: int, operation_id: int) -> None:
        op = self._operation(domain, operation_id)
        if op.quiesced or op.phase not in {"completed", "output_fenced"}:
            raise ContractError("quiescence requires completion or fenced cancellation")
        self.regions[op.region].owners.remove((domain, operation_id))
        op.quiesced = True
