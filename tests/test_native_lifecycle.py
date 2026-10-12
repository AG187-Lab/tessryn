"""Synthetic host reference traces; no native isolation or DMA result is claimed."""

import unittest

from tools.g02.lifecycle import ContractError, Handle, LifecycleModel, RIGHTS, U32_MAX, U64_MAX


class LifecycleConformanceTests(unittest.TestCase):
    def setUp(self):
        self.model = LifecycleModel()
        self.model.create_domain(1, 256)
        self.model.create_domain(2, 64)

    def unchanged(self, action):
        before = self.model.snapshot()
        with self.assertRaises(ContractError):
            action()
        self.assertEqual(self.model.snapshot(), before)

    def test_overlapping_write_views_require_quiescence_in_every_domain(self):
        parent = self.model.allocate(1, 64)
        child = self.model.delegate(1, parent, 2, RIGHTS, 16, 32)
        first = self.model.acquire(1, parent, 1, 1, 16, 16)
        self.unchanged(lambda: self.model.acquire(2, child, 1, 1, 0, 16))
        self.unchanged(lambda: self.model.acquire(2, child, 1, 1, 0, 16, "read"))
        # Completion does not prove the device no longer owns the bytes.
        self.model.complete(1, 1, 1, first, 1)
        self.unchanged(lambda: self.model.acquire(2, child, 1, 1, 0, 16))
        self.model.quiesce(1, 1)
        second = self.model.acquire(2, child, 1, 1, 0, 16)
        self.model.complete(2, 1, 1, second, 1)
        self.model.quiesce(2, 1)

    def test_overlapping_reads_and_disjoint_writes_preserve_independent_ownership(self):
        parent = self.model.allocate(1, 64)
        child = self.model.delegate(1, parent, 2, RIGHTS, 8, 32)
        first = self.model.acquire(1, parent, 1, 1, 8, 16, "read")
        second = self.model.acquire(2, child, 1, 1, 0, 16, "read")
        # The child view begins at backing byte 8; byte 24 is disjoint.
        third = self.model.acquire(2, child, 2, 1, 16, 16, "write")
        self.unchanged(lambda: self.model.acquire(1, parent, 2, 1, 8, 16, "write"))
        self.unchanged(lambda: self.model.acquire(1, parent, 2, 1, 23, 2, "read"))
        self.model.complete(1, 1, 1, first, 1)
        self.model.quiesce(1, 1)
        self.unchanged(lambda: self.model.acquire(1, parent, 2, 1, 8, 16, "write"))
        self.model.complete(2, 1, 1, second, 1)
        self.model.quiesce(2, 1)
        self.model.acquire(1, parent, 2, 1, 8, 16, "write")
        self.model.complete(2, 2, 1, third, 2)

    def test_malformed_access_modes_reject_atomically(self):
        handle = self.model.allocate(1, 32)
        for right in ([], {}, None, True, 1, ("read",), "execute"):
            with self.subTest(right=right):
                self.unchanged(lambda: self.model.acquire(1, handle, 1, 1, 0, 8, right))

    def test_abi_u32_generations_retire_at_wire_limit_while_epochs_remain_u64(self):
        # Advance synthetic fixture counters to boundary values without billions
        # of actions. The next public actions must still produce wire-safe refs.
        parent = self.model.allocate(1, 64)
        self.model.domains[2].generations[1] = U32_MAX - 1
        last = self.model.delegate(1, parent, 2, RIGHTS, 0, 32)
        self.assertEqual(last, Handle(2, 1, U32_MAX))
        self.model.release(2, last)
        replacement = self.model.delegate(1, parent, 2, RIGHTS, 0, 32)
        self.assertEqual(replacement, Handle(2, 2, 1))
        self.unchanged(lambda: self.model.acquire(2, Handle(2, 1, U32_MAX + 1), 1, 1, 0, 8))
        self.unchanged(lambda: self.model.acquire(2, Handle(2, U32_MAX + 1, 1), 1, 1, 0, 8))
        self.model.advance_epoch(1, U32_MAX + 1)
        region = self.model.regions[self.model.capabilities[parent].region]
        region.ownership_generation = U32_MAX - 1
        ownership = self.model.acquire(1, parent, 1, U32_MAX + 1, 0, 16)
        self.assertEqual(ownership, U32_MAX)
        self.unchanged(lambda: self.model.acquire(1, parent, 2, U32_MAX + 1, 16, 16))
        self.unchanged(lambda: self.model.complete(1, 1, U32_MAX + 1, U32_MAX + 1, 1))
        self.model.domains[1].completion_sequence = U32_MAX
        self.model.complete(1, 1, U32_MAX + 1, ownership, U32_MAX + 1)
        self.model.quiesce(1, 1)
        self.unchanged(lambda: self.model.acquire(1, parent, 2, U32_MAX + 1, 0, 16))

    def test_shared_view_retains_backing_charge_until_every_owner_is_released(self):
        parent = self.model.allocate(1, 64, reserved=32)
        child = self.model.delegate(1, parent, 2, frozenset({"read", "submit"}), 16, 32)
        self.assertEqual(self.model.domains[1].charged, 96)
        self.assertEqual(self.model.domains[2].charged, 0)
        self.unchanged(lambda: self.model.release(1, parent))
        ownership = self.model.acquire(2, child, 10, 1, 7, 25, "read")
        self.unchanged(lambda: self.model.release(2, child))
        self.model.complete(2, 10, 1, ownership, 1)
        self.unchanged(lambda: self.model.release(2, child))
        self.model.quiesce(2, 10)
        self.model.release(2, child)
        self.assertEqual(self.model.domains[1].charged, 96)
        self.model.release(1, parent)
        self.assertEqual(self.model.domains[1].charged, 0)
        self.assertFalse(self.model.regions)

    def test_committed_and_reserved_growth_are_both_admitted_before_allocation(self):
        self.model.allocate(1, 32, reserved=192)
        self.assertEqual(self.model.domains[1].charged, 224)
        self.unchanged(lambda: self.model.allocate(1, 24, reserved=9))
        self.model.allocate(1, 24, reserved=8)
        self.assertEqual(self.model.domains[1].charged, 256)
        self.unchanged(lambda: self.model.allocate(1, 1))

    def test_ranges_use_committed_view_and_reject_unsigned_overflow(self):
        handle = self.model.allocate(1, 32, reserved=32)
        for offset, length in ((32, 1), (1, 32), (U64_MAX, 2), (-1, 1), (0, 0), (True, 1)):
            with self.subTest(offset=offset, length=length):
                self.unchanged(lambda: self.model.acquire(1, handle, 1, 1, offset, length))
                self.unchanged(lambda: self.model.delegate(1, handle, 2, RIGHTS, offset, length))
        self.unchanged(lambda: self.model.allocate(1, U64_MAX, reserved=1))
        self.model.acquire(1, handle, 1, 1, 0, 32)

    def test_cross_domain_and_forged_generation_never_establish_authority(self):
        handle = self.model.allocate(1, 32)
        for caller, presented in ((2, handle), (1, Handle(1, handle.slot, 99)),
                                  (1, Handle(True, handle.slot, 1)), (1, None)):
            with self.subTest(caller=caller, presented=presented):
                self.unchanged(lambda: self.model.acquire(caller, presented, 1, 1, 0, 8))
                self.unchanged(lambda: self.model.revoke(caller, presented))
                self.unchanged(lambda: self.model.release(caller, presented))

    def test_delegation_can_reduce_but_cannot_amplify_rights_or_bounds(self):
        handle = self.model.allocate(1, 64)
        child = self.model.delegate(1, handle, 2, frozenset({"read", "submit", "delegate"}), 8, 16)
        self.unchanged(lambda: self.model.acquire(2, child, 1, 1, 0, 16, "write"))
        self.unchanged(lambda: self.model.delegate(2, child, 1, RIGHTS, 0, 16))
        self.unchanged(lambda: self.model.delegate(2, child, 1, frozenset({"read"}), 1, 16))
        grandchild = self.model.delegate(2, child, 1, frozenset({"read"}), 0, 16)
        self.unchanged(lambda: self.model.acquire(1, grandchild, 1, 1, 0, 8, "read"))
        self.unchanged(lambda: self.model.delegate(1, grandchild, 2, frozenset({"read"})))

    def test_revocation_blocks_descendants_but_outstanding_work_still_owns_memory(self):
        handle = self.model.allocate(1, 64)
        child = self.model.delegate(1, handle, 2, RIGHTS, 0, 32)
        grandchild = self.model.delegate(2, child, 1, RIGHTS, 0, 16)
        ownership = self.model.acquire(2, child, 1, 1, 0, 16)
        self.model.revoke(1, handle)
        for caller, cap in ((1, handle), (2, child), (1, grandchild)):
            self.unchanged(lambda: self.model.acquire(caller, cap, 2, 1, 0, 8))
            self.unchanged(lambda: self.model.release(caller, cap))
        self.unchanged(lambda: self.model.delegate(2, child, 1, RIGHTS))
        self.model.complete(2, 1, 1, ownership, 1)
        self.unchanged(lambda: self.model.release(1, grandchild))
        self.model.quiesce(2, 1)
        self.model.release(1, grandchild)
        self.model.release(2, child)
        self.model.release(1, handle)
        replacement = self.model.allocate(1, 16)
        self.assertEqual(replacement.slot, handle.slot)
        self.assertGreater(replacement.generation, handle.generation)
        self.unchanged(lambda: self.model.acquire(1, handle, 3, 1, 0, 8))

    def test_cancel_receipt_launch_stop_output_fence_and_reclaim_are_distinct(self):
        handle = self.model.allocate(1, 32)
        first = self.model.acquire(1, handle, 1, 1, 0, 16)
        second = self.model.acquire(1, handle, 2, 1, 16, 16)
        self.unchanged(lambda: self.model.cancel(1, 1, "output_fenced"))
        self.unchanged(lambda: self.model.quiesce(1, 1))
        self.model.cancel(1, 1, "received")
        self.model.complete(1, 1, 1, first, 1)  # Receipt alone does not fence output.
        self.model.cancel(1, 1, "launches_stopped")
        self.unchanged(lambda: self.model.cancel(1, 1, "reclaimed"))
        self.model.cancel(1, 1, "output_fenced")
        self.unchanged(lambda: self.model.release(1, handle))
        self.unchanged(lambda: self.model.cancel(1, 1, "reclaimed"))
        self.model.quiesce(1, 1)
        self.model.cancel(1, 1, "reclaimed")
        self.unchanged(lambda: self.model.quiesce(1, 1))
        self.model.cancel(1, 2, "received")
        self.model.cancel(1, 2, "launches_stopped")
        self.model.cancel(1, 2, "output_fenced")
        self.unchanged(lambda: self.model.complete(1, 2, 1, second, 2))
        self.unchanged(lambda: self.model.release(1, handle))
        self.model.quiesce(1, 2)
        self.model.cancel(1, 2, "reclaimed")
        self.model.release(1, handle)

    def test_stale_epoch_fences_output_without_releasing_device_ownership(self):
        handle = self.model.allocate(1, 32)
        ownership = self.model.acquire(1, handle, 1, 1, 0, 16)
        self.model.advance_epoch(1, 2)
        self.unchanged(lambda: self.model.complete(1, 1, 1, ownership, 1))
        self.unchanged(lambda: self.model.complete(1, 1, 2, ownership, 1))
        self.unchanged(lambda: self.model.acquire(1, handle, 2, 1, 0, 16))
        self.unchanged(lambda: self.model.advance_epoch(1, 1))
        self.unchanged(lambda: self.model.release(1, handle))
        for milestone in ("received", "launches_stopped", "output_fenced"):
            self.model.cancel(1, 1, milestone)
        self.model.quiesce(1, 1)
        self.model.cancel(1, 1, "reclaimed")
        fresh = self.model.acquire(1, handle, 2, 2, 0, 16)
        self.model.complete(1, 2, 2, fresh, 1)

    def test_launch_stop_can_still_deliver_pending_output_and_requires_a_fence(self):
        handle = self.model.allocate(1, 32)
        ownership = self.model.acquire(1, handle, 1, 1, 0, 16)
        self.model.cancel(1, 1, "received")
        self.model.cancel(1, 1, "launches_stopped")
        self.unchanged(lambda: self.model.quiesce(1, 1))
        self.model.complete(1, 1, 1, ownership, 1)
        self.unchanged(lambda: self.model.release(1, handle))
        self.unchanged(lambda: self.model.quiesce(1, 1))
        self.model.cancel(1, 1, "output_fenced")
        self.model.quiesce(1, 1)
        self.model.cancel(1, 1, "reclaimed")
        self.model.release(1, handle)

    def test_invalid_configuration_cannot_replace_or_partially_install_authority(self):
        handle = self.model.allocate(1, 32)
        self.unchanged(lambda: self.model.create_domain(1, 0))
        for rights in (frozenset(), frozenset({"kernel_memory"}), "read"):
            with self.subTest(rights=rights):
                self.unchanged(lambda: self.model.allocate(1, 1, rights=rights))
                self.unchanged(lambda: self.model.delegate(1, handle, 2, rights))
        self.unchanged(lambda: self.model.delegate(1, handle, 99, RIGHTS))
        for operation_id in (0, -1, True, U64_MAX + 1):
            self.unchanged(lambda: self.model.acquire(1, handle, operation_id, 1, 0, 16))

    def test_completion_sequence_ownership_and_request_identity_cannot_replay(self):
        handle = self.model.allocate(1, 64)
        first = self.model.acquire(1, handle, 1, 1, 0, 16)
        second = self.model.acquire(1, handle, 2, 1, 16, 16)
        self.unchanged(lambda: self.model.complete(1, 1, 1, second, 1))
        self.unchanged(lambda: self.model.complete(1, 1, 1, first, 2))
        self.model.complete(1, 2, 1, second, 1)  # Completion order can differ from submission order.
        self.unchanged(lambda: self.model.complete(1, 2, 1, second, 2))
        self.unchanged(lambda: self.model.complete(1, 1, 1, first, 1))
        self.model.complete(1, 1, 1, first, 2)
        self.model.quiesce(1, 1)
        self.model.quiesce(1, 2)
        self.model.release(1, handle)
        replacement = self.model.allocate(1, 64)
        self.unchanged(lambda: self.model.acquire(1, replacement, 1, 1, 0, 16))
        self.unchanged(lambda: self.model.complete(2, 1, 1, first, 1))
        self.unchanged(lambda: self.model.cancel(1, 1, None))

    def test_generations_retire_exhausted_slots_instead_of_aliasing_old_handles(self):
        self.model = LifecycleModel(counter_limit=2)
        self.model.create_domain(1, 64)
        self.model.create_domain(2, 64)
        parent = self.model.allocate(1, 32)
        issued = []
        for _ in range(4):
            child = self.model.delegate(1, parent, 2, RIGHTS)
            issued.append(child)
            self.model.release(2, child)
        self.assertEqual([(h.slot, h.generation) for h in issued], [(1, 1), (1, 2), (2, 1), (2, 2)])
        self.unchanged(lambda: self.model.delegate(1, parent, 2, RIGHTS))
        for old in issued:
            self.unchanged(lambda: self.model.acquire(2, old, 1, 1, 0, 8))

    def test_region_ownership_epoch_and_completion_counters_stop_without_wrapping(self):
        self.model = LifecycleModel(counter_limit=2)
        self.model.create_domain(1, 128)
        first = self.model.allocate(1, 32)
        second = self.model.allocate(1, 32)
        self.unchanged(lambda: self.model.allocate(1, 1))
        one = self.model.acquire(1, first, 1, 1, 0, 8)
        two = self.model.acquire(1, first, 2, 1, 8, 8)
        self.unchanged(lambda: self.model.acquire(1, first, 3, 1, 16, 8))
        three = self.model.acquire(1, second, 3, 1, 0, 8)
        self.model.complete(1, 1, 1, one, 1)
        self.model.complete(1, 2, 1, two, 2)
        self.unchanged(lambda: self.model.complete(1, 3, 1, three, 3))
        self.unchanged(lambda: self.model.complete(1, 3, 1, three, 1))
        self.model.advance_epoch(1, 2)
        self.unchanged(lambda: self.model.advance_epoch(1, 3))
        self.unchanged(lambda: self.model.advance_epoch(1, 1))


if __name__ == "__main__":
    unittest.main()
