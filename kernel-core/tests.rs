//! Host adversarial traces against the same policy core compiled freestanding.
//! These tests establish policy denials and lifetime rules, not CPU fault or DMA isolation.

extern crate std;

use crate::{Access, CapabilityRef, Error, FramePool, FrameRange, MemoryPolicy, Rights, PAGE_SIZE};
use std::{format, vec, vec::Vec};

const BASE: u64 = 0x10_0000;
type Policy = MemoryPolicy<3, 8, 16, 16, 32>;

fn range(start: u64, pages: u64) -> FrameRange {
    FrameRange::new(start, pages).unwrap()
}

fn policy() -> Policy {
    let mut state = Policy::new(36, &[]).unwrap();
    state.add_free_extent(range(BASE, 32)).unwrap();
    state.create_domain(1, 24).unwrap();
    state.create_domain(2, 8).unwrap();
    state.create_domain(3, 8).unwrap();
    state
}

fn allocate(state: &mut Policy, caller: u64, pages: u64, rights: Rights) -> CapabilityRef {
    state.allocate(caller, pages, 0, rights, |_| Ok(())).unwrap()
}

/// Check every trusted field, including generations, allocator extents and counters.
fn denied<P: core::fmt::Debug, T: core::fmt::Debug>(
    state: &mut P,
    action: impl FnOnce(&mut P) -> Result<T, Error>,
) -> Error {
    let before = format!("{state:?}");
    let error = action(state).expect_err("an adversarial action unexpectedly succeeded");
    assert_eq!(format!("{state:?}"), before, "rejection partially changed trusted state");
    error
}

/// Original test-only memory backend; its bytes are never authority in the core.
struct MockBacking {
    bytes: Vec<u8>,
    scrubbed: Vec<FrameRange>,
    fail: bool,
}

impl MockBacking {
    fn new(pages: usize) -> Self {
        Self { bytes: vec![0xa5; pages * PAGE_SIZE as usize], scrubbed: Vec::new(), fail: false }
    }

    fn bounds(&self, extent: FrameRange) -> core::ops::Range<usize> {
        let start = usize::try_from(extent.start().checked_sub(BASE).unwrap()).unwrap();
        let length = usize::try_from(extent.pages() * PAGE_SIZE).unwrap();
        assert!(start + length <= self.bytes.len());
        start..start + length
    }

    fn scrub(&mut self, extent: FrameRange) -> Result<(), ()> {
        if self.fail { return Err(()); }
        let bounds = self.bounds(extent);
        self.bytes[bounds].fill(0);
        self.scrubbed.push(extent);
        Ok(())
    }

    fn fill(&mut self, extent: FrameRange, byte: u8) {
        let bounds = self.bounds(extent);
        self.bytes[bounds].fill(byte);
    }

    fn contents(&self, extent: FrameRange) -> &[u8] {
        &self.bytes[self.bounds(extent)]
    }
}

#[test]
fn caller_namespace_cannot_be_established_by_a_presented_domain_number() {
    let mut state = policy();
    let owned = allocate(&mut state, 1, 1, Rights::ALL);
    let spoofed = CapabilityRef { domain: 2, ..owned };
    denied(&mut state, |s| s.authorize(2, owned, Rights::READ, 0, 1));
    denied(&mut state, |s| s.authorize(2, spoofed, Rights::READ, 0, 1));
    denied(&mut state, |s| s.revoke(2, owned));
    denied(&mut state, |s| s.release_capability(2, owned));
    denied(&mut state, |s| s.delegate(2, owned, 3, Rights::READ, 0, 1));
    denied(&mut state, |s| s.authorize(99, owned, Rights::READ, 0, 1));
    let forged = CapabilityRef { generation: owned.generation + 1, ..owned };
    assert_eq!(denied(&mut state, |s| s.authorize(1, forged, Rights::READ, 0, 1)), Error::StaleHandle);
}

#[test]
fn slot_zero_is_present_with_nonzero_domain_and_generation() {
    let mut state = policy();
    let owned = allocate(&mut state, 1, 1, Rights::ALL);
    assert_eq!(owned.slot, 0, "slot zero is a valid ABI capability slot");
    assert_ne!(owned.generation, 0);
    state.authorize(1, owned, Rights::READ, 0, 1).unwrap();
    denied(&mut state, |s| s.authorize(1, CapabilityRef { generation: 0, ..owned }, Rights::READ, 0, 1));
    denied(&mut state, |s| s.authorize(1, CapabilityRef { domain: 0, ..owned }, Rights::READ, 0, 1));
    denied(&mut state, |s| s.authorize(1, CapabilityRef { slot: u32::MAX, ..owned }, Rights::READ, 0, 1));
    denied(&mut state, |s| s.authorize(1, CapabilityRef::default(), Rights::READ, 0, 1));
}

#[test]
fn rights_decoder_rejects_unknown_bits_instead_of_amplifying_authority() {
    for bits in [0, 32, 64, 128, 255, Rights::READ.bits() | 32] {
        assert_eq!(Rights::from_bits(bits), Err(Error::InvalidAuthority));
    }
    assert_eq!(Rights::from_bits(Rights::READ.bits() | Rights::WRITE.bits()).unwrap(), Rights::READ | Rights::WRITE);
}

#[test]
fn delegation_reduces_rights_and_translates_nested_byte_bounds() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 2, Rights::ALL);
    let rights = Rights::READ | Rights::DELEGATE | Rights::SUBMIT;
    let child = state.delegate(1, parent, 2, rights, 8, 32).unwrap();
    let grandchild = state.delegate(2, child, 3, Rights::READ, 4, 8).unwrap();
    state.authorize(3, grandchild, Rights::READ, 0, 8).unwrap();
    assert_eq!(denied(&mut state, |s| s.authorize(2, child, Rights::WRITE, 0, 1)), Error::InsufficientRights);
    denied(&mut state, |s| s.delegate(2, child, 3, Rights::ALL, 0, 8));
    denied(&mut state, |s| s.delegate(2, child, 3, Rights::READ, 25, 8));
    denied(&mut state, |s| s.delegate(3, grandchild, 1, Rights::READ, 0, 1));
    denied(&mut state, |s| s.authorize(3, grandchild, Rights::READ, 8, 1));
    denied(&mut state, |s| s.delegate(1, parent, 99, Rights::READ, 0, 1));
}

#[test]
fn nested_views_conflict_at_their_absolute_backing_offsets() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 1, Rights::ALL);
    let child = state.delegate(1, parent, 2, Rights::ALL, 16, 64).unwrap();
    let grandchild = state.delegate(2, child, 3, Rights::ALL, 8, 16).unwrap();
    let writer = state.acquire(3, grandchild, Access::Write, 0, 16).unwrap();
    // Grandchild bytes [0,16) are backing bytes [24,40), not [0,16) or [8,24).
    state.acquire(1, parent, Access::Read, 23, 1).unwrap();
    denied(&mut state, |s| s.acquire(1, parent, Access::Read, 24, 1));
    denied(&mut state, |s| s.acquire(1, parent, Access::Read, 39, 1));
    state.acquire(1, parent, Access::Read, 40, 1).unwrap();
    state.complete(3, writer).unwrap();
    denied(&mut state, |s| s.acquire(1, parent, Access::Read, 24, 1));
    state.quiesce(writer).unwrap();
    state.acquire(1, parent, Access::Read, 24, 16).unwrap();
}

#[test]
fn unsigned_ranges_and_empty_authority_are_rejected_without_mutation() {
    let mut state = policy();
    let owned = allocate(&mut state, 1, 1, Rights::ALL);
    for (offset, length) in [(PAGE_SIZE, 1), (1, PAGE_SIZE), (u64::MAX, 2), (0, 0)] {
        denied(&mut state, |s| s.authorize(1, owned, Rights::READ, offset, length));
        denied(&mut state, |s| s.delegate(1, owned, 2, Rights::READ, offset, length));
        denied(&mut state, |s| s.acquire(1, owned, Access::Read, offset, length));
    }
    let empty = Rights::READ & Rights::WRITE;
    denied(&mut state, |s| s.allocate(1, 1, 0, empty, |_| Ok(())));
    denied(&mut state, |s| s.delegate(1, owned, 2, empty, 0, 1));
    denied(&mut state, |s| s.authorize(1, owned, empty, 0, 1));
    denied(&mut state, |s| s.allocate(1, u64::MAX, 1, Rights::ALL, |_| Ok(())));
}

#[test]
fn committed_and_reserved_pages_are_admitted_before_installation() {
    let mut state = policy();
    let owned = state.allocate(2, 3, 5, Rights::ALL, |_| Ok(())).unwrap();
    let account = state.accounting(2).unwrap();
    assert_eq!((account.budget_pages, account.charged_pages, account.committed_pages, account.reserved_pages), (8, 8, 3, 5));
    denied(&mut state, |s| s.allocate(2, 1, 0, Rights::ALL, |_| panic!("budget rejection must precede scrub")));
    denied(&mut state, |s| s.authorize(2, owned, Rights::READ, 3 * PAGE_SIZE, 1));
    state.release_capability(2, owned).unwrap();
    assert_eq!(state.accounting(2).unwrap().charged_pages, 0);
    denied(&mut state, |s| s.allocate(1, 0, 1, Rights::ALL, |_| Ok(())));
}

#[test]
fn sharing_preserves_original_charge_until_the_last_descendant_is_released() {
    let mut state = policy();
    let parent = state.allocate(1, 2, 3, Rights::ALL, |_| Ok(())).unwrap();
    let child = state.delegate(1, parent, 2, Rights::READ | Rights::DELEGATE, 0, PAGE_SIZE).unwrap();
    let grandchild = state.delegate(2, child, 3, Rights::READ, 0, PAGE_SIZE).unwrap();
    assert_eq!(state.region_info(2, child).unwrap().charge_owner, 1);
    assert_eq!(state.accounting(1).unwrap().charged_pages, 5);
    assert_eq!(state.accounting(2).unwrap().charged_pages, 0);
    assert_eq!(state.accounting(3).unwrap().charged_pages, 0);
    denied(&mut state, |s| s.release_capability(1, parent));
    denied(&mut state, |s| s.release_capability(2, child));
    state.release_capability(3, grandchild).unwrap();
    state.release_capability(2, child).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 5);
    state.release_capability(1, parent).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
}

#[test]
fn scrub_failure_never_installs_authority_or_spends_a_generation() {
    let mut state = policy();
    let mut memory = MockBacking::new(32);
    memory.fail = true;
    assert_eq!(denied(&mut state, |s| s.allocate(1, 2, 1, Rights::ALL, |r| memory.scrub(r))), Error::ScrubFailed);
    assert!(memory.scrubbed.is_empty());
    memory.fail = false;
    let cap = state.allocate(1, 2, 1, Rights::ALL, |r| memory.scrub(r)).unwrap();
    assert_eq!((cap.slot, cap.generation), (0, 1));
    let backing = state.region_info(1, cap).unwrap().backing;
    assert_eq!(backing.pages(), 3, "reserved backing must also be scrubbed and retained");
    assert_eq!(memory.scrubbed, [backing]);
    assert!(memory.contents(backing).iter().all(|byte| *byte == 0));
    denied(&mut state, |s| s.authorize(1, cap, Rights::READ, 2 * PAGE_SIZE, 1));
}

#[test]
fn recycled_frames_are_scrubbed_before_a_different_domain_receives_authority() {
    let mut state = policy();
    let mut memory = MockBacking::new(32);
    let original = state.allocate(1, 2, 0, Rights::ALL, |r| memory.scrub(r)).unwrap();
    let first_backing = state.region_info(1, original).unwrap().backing;
    memory.fill(first_backing, 0x5a);
    state.release_capability(1, original).unwrap();
    memory.fail = true;
    denied(&mut state, |s| s.allocate(2, 2, 0, Rights::ALL, |r| memory.scrub(r)));
    assert!(memory.contents(first_backing).iter().all(|byte| *byte == 0x5a));
    memory.fail = false;
    let replacement = state.allocate(2, 2, 0, Rights::ALL, |r| memory.scrub(r)).unwrap();
    let second_backing = state.region_info(2, replacement).unwrap().backing;
    assert_eq!(second_backing, first_backing);
    assert!(memory.contents(second_backing).iter().all(|byte| *byte == 0));
    denied(&mut state, |s| s.authorize(1, original, Rights::READ, 0, 1));
    denied(&mut state, |s| s.authorize(1, replacement, Rights::READ, 0, 1));
}

#[test]
fn partially_failed_scrub_changes_no_trusted_allocation_or_authority_state() {
    let mut state = policy();
    let mut memory = MockBacking::new(32);
    assert_eq!(denied(&mut state, |s| s.allocate(1, 2, 0, Rights::ALL, |backing| {
        memory.fill(range(backing.start(), 1), 0);
        Err(())
    })), Error::ScrubFailed);
    assert_eq!(state.frames().allocated_pages(), 0);
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
    let cap = state.allocate(2, 2, 0, Rights::ALL, |r| memory.scrub(r)).unwrap();
    let backing = state.region_info(2, cap).unwrap().backing;
    assert!(memory.contents(backing).iter().all(|byte| *byte == 0));
}

#[test]
fn byte_views_cannot_expose_their_containing_page_through_mapping_rounding() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 2, Rights::ALL);
    let child = state.delegate(1, parent, 2, Rights::ALL, 8, 16).unwrap();
    state.authorize(2, child, Rights::READ, 0, 16).unwrap();
    denied(&mut state, |s| s.map_intent(2, child, Access::Read, 0, 16));
    denied(&mut state, |s| s.map_intent(2, child, Access::Read, 0, PAGE_SIZE));
    denied(&mut state, |s| s.map_intent(1, parent, Access::Read, 1, PAGE_SIZE));
    denied(&mut state, |s| s.map_intent(1, parent, Access::Read, 0, PAGE_SIZE - 1));
    let page = state.delegate(1, parent, 2, Rights::READ | Rights::MAP, PAGE_SIZE, PAGE_SIZE).unwrap();
    let mapping = state.map_intent(2, page, Access::Read, 0, PAGE_SIZE).unwrap();
    denied(&mut state, |s| s.map_intent(2, page, Access::Write, 0, PAGE_SIZE));
    state.fence(mapping).unwrap();
    state.quiesce(mapping).unwrap();
}

#[test]
fn mapping_requires_map_authority_and_submission_requires_submit_authority() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 1, Rights::ALL);
    let read = state.delegate(1, parent, 2, Rights::READ, 0, PAGE_SIZE).unwrap();
    denied(&mut state, |s| s.map_intent(2, read, Access::Read, 0, PAGE_SIZE));
    denied(&mut state, |s| s.acquire(2, read, Access::Read, 0, 1));
    let map = state.delegate(1, parent, 2, Rights::READ | Rights::MAP, 0, PAGE_SIZE).unwrap();
    let mapped = state.map_intent(2, map, Access::Read, 0, PAGE_SIZE).unwrap();
    denied(&mut state, |s| s.complete(2, mapped));
    state.fence(mapped).unwrap();
    state.quiesce(mapped).unwrap();
}

#[test]
fn write_only_operations_cannot_be_promoted_to_readable_writable_mappings() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 1, Rights::ALL);
    let write_only = state.delegate(1, parent, 2, Rights::WRITE | Rights::MAP | Rights::SUBMIT, 0, PAGE_SIZE).unwrap();
    assert_eq!(denied(&mut state, |s| s.authorize(2, write_only, Rights::READ, 0, 1)), Error::InsufficientRights);
    assert_eq!(denied(&mut state, |s| s.map_intent(2, write_only, Access::Write, 0, PAGE_SIZE)), Error::InsufficientRights);
    denied(&mut state, |s| s.map_intent(2, write_only, Access::Read, 0, PAGE_SIZE));
    denied(&mut state, |s| s.acquire(2, write_only, Access::Read, 0, 1));
    let operation = state.acquire(2, write_only, Access::Write, 0, 16).unwrap();
    state.complete(2, operation).unwrap();
    state.quiesce(operation).unwrap();
    let mapped_cap = state.delegate(1, parent, 2, Rights::READ | Rights::WRITE | Rights::MAP, 0, PAGE_SIZE).unwrap();
    let mapping = state.map_intent(2, mapped_cap, Access::Write, 0, PAGE_SIZE).unwrap();
    state.fence(mapping).unwrap();
    state.quiesce(mapping).unwrap();
}

#[test]
fn cross_domain_aliases_conflict_by_backing_interval_until_quiescence() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 2, Rights::ALL);
    let child = state.delegate(1, parent, 2, Rights::ALL, 8, 32).unwrap();
    let first = state.acquire(1, parent, Access::Read, 8, 16).unwrap();
    let second = state.acquire(2, child, Access::Read, 0, 16).unwrap();
    let disjoint = state.acquire(2, child, Access::Write, 16, 16).unwrap();
    denied(&mut state, |s| s.acquire(1, parent, Access::Write, 8, 16));
    denied(&mut state, |s| s.acquire(1, parent, Access::Read, 23, 2));
    state.complete(1, first).unwrap();
    denied(&mut state, |s| s.acquire(1, parent, Access::Write, 8, 16));
    state.quiesce(first).unwrap();
    denied(&mut state, |s| s.acquire(1, parent, Access::Write, 8, 16));
    state.complete(2, second).unwrap();
    state.quiesce(second).unwrap();
    let replacement = state.acquire(1, parent, Access::Write, 8, 16).unwrap();
    state.complete(1, replacement).unwrap();
    state.quiesce(replacement).unwrap();
    state.complete(2, disjoint).unwrap();
    state.quiesce(disjoint).unwrap();
}

#[test]
fn cpu_mapping_intents_and_service_owners_share_one_conflict_ledger() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 2, Rights::ALL);
    let child = state.delegate(1, parent, 2, Rights::ALL, 0, 2 * PAGE_SIZE).unwrap();
    let mapping = state.map_intent(1, parent, Access::Read, 0, PAGE_SIZE).unwrap();
    let read = state.acquire(2, child, Access::Read, 0, 16).unwrap();
    let disjoint = state.map_intent(2, child, Access::Write, PAGE_SIZE, PAGE_SIZE).unwrap();
    denied(&mut state, |s| s.acquire(2, child, Access::Write, 0, 1));
    denied(&mut state, |s| s.map_intent(2, child, Access::Write, 0, PAGE_SIZE));
    denied(&mut state, |s| s.acquire(1, parent, Access::Read, PAGE_SIZE, 1));
    state.fence(mapping).unwrap();
    denied(&mut state, |s| s.acquire(2, child, Access::Write, 0, 1));
    state.quiesce(mapping).unwrap();
    denied(&mut state, |s| s.acquire(2, child, Access::Write, 0, 1));
    state.complete(2, read).unwrap();
    state.quiesce(read).unwrap();
    state.acquire(2, child, Access::Write, 0, 1).unwrap();
    state.fence(disjoint).unwrap();
    state.quiesce(disjoint).unwrap();
}

#[test]
fn revoke_denies_descendant_access_and_completion_but_retains_owners() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 2, Rights::ALL);
    let child = state.delegate(1, parent, 2, Rights::ALL, 0, PAGE_SIZE).unwrap();
    let grandchild = state.delegate(2, child, 3, Rights::ALL, 0, PAGE_SIZE).unwrap();
    let owner = state.acquire(2, child, Access::Write, 0, 16).unwrap();
    state.revoke(1, parent).unwrap();
    for (caller, cap) in [(1, parent), (2, child), (3, grandchild)] {
        denied(&mut state, |s| s.authorize(caller, cap, Rights::READ, 0, 1));
        denied(&mut state, |s| s.acquire(caller, cap, Access::Read, 0, 1));
        denied(&mut state, |s| s.map_intent(caller, cap, Access::Read, 0, PAGE_SIZE));
    }
    denied(&mut state, |s| s.delegate(2, child, 3, Rights::READ, 0, 1));
    denied(&mut state, |s| s.complete(2, owner));
    denied(&mut state, |s| s.quiesce(owner));
    denied(&mut state, |s| s.release_capability(3, grandchild));
    assert_eq!(state.accounting(1).unwrap().charged_pages, 2);
    state.fence(owner).unwrap();
    denied(&mut state, |s| s.release_capability(3, grandchild));
    state.quiesce(owner).unwrap();
    state.release_capability(3, grandchild).unwrap();
    state.release_capability(2, child).unwrap();
    state.release_capability(1, parent).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
}

#[test]
fn reverse_domain_descendant_chain_is_revoked_across_repeated_propagation_passes() {
    let mut state = policy();
    let parent = allocate(&mut state, 3, 2, Rights::ALL);
    let child = state.delegate(3, parent, 2, Rights::ALL, 0, PAGE_SIZE).unwrap();
    let grandchild = state.delegate(2, child, 1, Rights::ALL, 0, PAGE_SIZE).unwrap();
    let descendant = state.delegate(1, grandchild, 3, Rights::ALL, 0, PAGE_SIZE).unwrap();
    let unrelated = allocate(&mut state, 2, 1, Rights::ALL);
    // Descendants in domains 1 and 2 precede their parents in table traversal.
    state.revoke(3, parent).unwrap();
    for (caller, cap) in [(3, parent), (2, child), (1, grandchild), (3, descendant)] {
        assert_eq!(denied(&mut state, |s| s.authorize(caller, cap, Rights::READ, 0, 1)), Error::Revoked);
        assert_eq!(denied(&mut state, |s| s.acquire(caller, cap, Access::Read, 0, 1)), Error::Revoked);
        assert_eq!(denied(&mut state, |s| s.delegate(caller, cap, 2, Rights::READ, 0, 1)), Error::Revoked);
    }
    state.authorize(2, unrelated, Rights::READ, 0, 1).unwrap();
    denied(&mut state, |s| s.release_capability(3, parent));
    state.release_capability(3, descendant).unwrap();
    state.release_capability(1, grandchild).unwrap();
    state.release_capability(2, child).unwrap();
    state.release_capability(3, parent).unwrap();
    assert_eq!(state.accounting(3).unwrap().charged_pages, 0);
    assert_eq!(state.accounting(2).unwrap().charged_pages, 1);
}

#[test]
fn revoked_mapping_intent_retains_backing_until_teardown_and_final_release() {
    let mut state = policy();
    let parent = state.allocate(1, 2, 1, Rights::ALL, |_| Ok(())).unwrap();
    let child = state.delegate(1, parent, 2, Rights::READ | Rights::MAP, 0, PAGE_SIZE).unwrap();
    let mapping = state.map_intent(2, child, Access::Read, 0, PAGE_SIZE).unwrap();
    let backing = state.region_info(1, parent).unwrap().backing;
    state.revoke(1, parent).unwrap();
    denied(&mut state, |s| s.map_intent(2, child, Access::Read, 0, PAGE_SIZE));
    denied(&mut state, |s| s.complete(2, mapping));
    denied(&mut state, |s| s.quiesce(mapping));
    denied(&mut state, |s| s.release_capability(2, child));
    denied(&mut state, |s| s.release_capability(1, parent));
    assert_eq!(state.accounting(1).unwrap().charged_pages, 3);
    assert_eq!(state.frames().allocated_pages(), backing.pages());
    state.fence(mapping).unwrap();
    denied(&mut state, |s| s.release_capability(2, child));
    assert_eq!(state.frames().allocated_pages(), backing.pages());
    // The trusted acknowledgment represents native unmap/TLB teardown still to implement.
    state.quiesce(mapping).unwrap();
    denied(&mut state, |s| s.quiesce(mapping));
    assert_eq!(state.accounting(1).unwrap().charged_pages, 3);
    state.release_capability(2, child).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 3);
    state.release_capability(1, parent).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
    assert_eq!(state.frames().allocated_pages(), 0);
}

#[test]
fn completion_is_not_quiescence_and_cannot_free_a_shared_region() {
    let mut state = policy();
    let parent = allocate(&mut state, 1, 1, Rights::ALL);
    let child = state.delegate(1, parent, 2, Rights::ALL, 0, PAGE_SIZE).unwrap();
    let owner = state.acquire(2, child, Access::Read, 0, 16).unwrap();
    denied(&mut state, |s| s.complete(1, owner));
    denied(&mut state, |s| s.quiesce(owner));
    state.complete(2, owner).unwrap();
    denied(&mut state, |s| s.complete(2, owner));
    denied(&mut state, |s| s.release_capability(2, child));
    denied(&mut state, |s| s.release_capability(1, parent));
    state.quiesce(owner).unwrap();
    denied(&mut state, |s| s.quiesce(owner));
    state.release_capability(2, child).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 1);
    state.release_capability(1, parent).unwrap();
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
}

#[test]
fn stale_lease_cannot_complete_fence_or_quiesce_a_replacement_owner() {
    let mut state = policy();
    let owned = allocate(&mut state, 1, 1, Rights::ALL);
    let old = state.acquire(1, owned, Access::Read, 0, 16).unwrap();
    state.complete(1, old).unwrap();
    state.quiesce(old).unwrap();
    let current = state.acquire(1, owned, Access::Read, 0, 16).unwrap();
    assert_ne!(old, current);
    denied(&mut state, |s| s.complete(1, old));
    denied(&mut state, |s| s.fence(old));
    denied(&mut state, |s| s.quiesce(old));
    denied(&mut state, |s| s.quiesce(current));
    state.fence(current).unwrap();
    denied(&mut state, |s| s.complete(1, current));
    denied(&mut state, |s| s.fence(current));
    state.quiesce(current).unwrap();
}

#[test]
fn capability_generation_exhaustion_retires_the_slot_without_aba() {
    let mut state = policy();
    // Only this fixture seeds an otherwise unreachable counter boundary.
    state.capabilities[0][0].generation = u32::MAX - 1;
    let final_cap = allocate(&mut state, 1, 1, Rights::ALL);
    assert_eq!((final_cap.slot, final_cap.generation), (0, u32::MAX));
    state.release_capability(1, final_cap).unwrap();
    let replacement = allocate(&mut state, 1, 1, Rights::ALL);
    assert_eq!((replacement.slot, replacement.generation), (1, 1));
    denied(&mut state, |s| s.authorize(1, final_cap, Rights::READ, 0, 1));
}

#[test]
fn ownership_generation_exhaustion_retires_the_owner_slot_without_aba() {
    let mut state = policy();
    let owned = allocate(&mut state, 1, 1, Rights::ALL);
    state.owners[0].generation = u32::MAX - 1;
    let final_owner = state.acquire(1, owned, Access::Read, 0, 1).unwrap();
    assert_eq!((final_owner.slot(), final_owner.generation()), (0, u32::MAX));
    state.complete(1, final_owner).unwrap();
    state.quiesce(final_owner).unwrap();
    let replacement = state.acquire(1, owned, Access::Read, 0, 1).unwrap();
    assert_eq!((replacement.slot(), replacement.generation()), (1, 1));
    denied(&mut state, |s| s.quiesce(final_owner));
    state.complete(1, replacement).unwrap();
    state.quiesce(replacement).unwrap();
}

#[test]
fn physical_inventory_rejects_quarantine_overlap_and_address_width() {
    let quarantine = range(BASE + 4 * PAGE_SIZE, 2);
    let mut state = Policy::new(36, &[quarantine]).unwrap();
    state.add_free_extent(range(BASE, 4)).unwrap();
    assert_eq!(denied(&mut state, |s| s.add_free_extent(range(BASE + 3 * PAGE_SIZE, 2))), Error::Excluded);
    denied(&mut state, |s| s.add_free_extent(range(BASE, 1)));
    denied(&mut state, |s| s.add_free_extent(range(1 << 36, 1)));
    assert!(FrameRange::new(BASE + 1, 1).is_err());
    assert!(FrameRange::new(BASE, 0).is_err());
    assert!(FrameRange::new(u64::MAX - (PAGE_SIZE - 1), 1).is_err());
    assert!(FrameRange::new(BASE, u64::MAX).is_err());
    state.create_domain(1, 4).unwrap();
    let owned = state.allocate(1, 4, 0, Rights::ALL, |_| Ok(())).unwrap();
    assert_eq!(state.region_info(1, owned).unwrap().backing, range(BASE, 4));
    denied(&mut state, |s| s.add_free_extent(range(BASE, 4)));
}

#[test]
fn physical_allocation_failure_does_not_charge_or_install_a_capability() {
    let mut state = Policy::new(36, &[]).unwrap();
    state.add_free_extent(range(BASE, 2)).unwrap();
    state.create_domain(1, 8).unwrap();
    denied(&mut state, |s| s.allocate(1, 3, 0, Rights::ALL, |_| panic!("no backing must reject before scrub")));
    let owned = state.allocate(1, 2, 0, Rights::ALL, |_| Ok(())).unwrap();
    assert_eq!((owned.slot, owned.generation), (0, 1));
    assert_eq!(state.accounting(1).unwrap().charged_pages, 2);
}

#[test]
fn namespace_and_owner_capacity_failures_leave_every_counter_unchanged() {
    type Small = MemoryPolicy<2, 2, 2, 2, 8>;
    let mut state = Small::new(36, &[]).unwrap();
    state.add_free_extent(range(BASE, 8)).unwrap();
    state.create_domain(1, 8).unwrap();
    denied(&mut state, |s| s.create_domain(1, 1));
    state.create_domain(2, 8).unwrap();
    denied(&mut state, |s| s.create_domain(3, 8));
    let parent = state.allocate(1, 2, 0, Rights::ALL, |_| Ok(())).unwrap();
    let child = state.delegate(1, parent, 1, Rights::READ, 0, 1).unwrap();
    denied(&mut state, |s| s.delegate(1, parent, 1, Rights::READ, 0, 1));
    denied(&mut state, |s| s.allocate(1, 1, 0, Rights::ALL, |_| panic!("cap capacity must precede scrub")));
    let first = state.acquire(1, parent, Access::Read, 0, 1).unwrap();
    let second = state.acquire(1, parent, Access::Read, 0, 1).unwrap();
    denied(&mut state, |s| s.acquire(1, parent, Access::Read, 0, 1));
    state.complete(1, first).unwrap();
    state.quiesce(first).unwrap();
    state.complete(1, second).unwrap();
    state.quiesce(second).unwrap();
    state.release_capability(1, child).unwrap();
    state.release_capability(1, parent).unwrap();
}

#[test]
fn region_capacity_failure_cannot_leave_an_orphaned_charge() {
    type Small = MemoryPolicy<1, 1, 4, 4, 8>;
    let mut state = Small::new(36, &[]).unwrap();
    state.add_free_extent(range(BASE, 4)).unwrap();
    state.create_domain(1, 4).unwrap();
    let first = state.allocate(1, 1, 0, Rights::ALL, |_| Ok(())).unwrap();
    denied(&mut state, |s| s.allocate(1, 1, 0, Rights::ALL, |_| panic!("region capacity must precede scrub")));
    state.release_capability(1, first).unwrap();
    state.allocate(1, 4, 0, Rights::ALL, |_| Ok(())).unwrap();
}

#[test]
fn allocator_metadata_capacity_is_preflighted_before_splitting_or_scrubbing() {
    type Small = MemoryPolicy<1, 2, 2, 2, 1>;
    let mut state = Small::new(36, &[]).unwrap();
    state.add_free_extent(range(BASE, 2)).unwrap();
    state.create_domain(1, 2).unwrap();
    denied(&mut state, |s| s.add_free_extent(range(BASE + 4 * PAGE_SIZE, 1)));
    denied(&mut state, |s| s.allocate(1, 1, 0, Rights::ALL, |_| panic!("split capacity must precede scrub")));
    let whole = state.allocate(1, 2, 0, Rights::ALL, |_| Ok(())).unwrap();
    state.release_capability(1, whole).unwrap();
    state.allocate(1, 2, 0, Rights::ALL, |_| Ok(())).unwrap();
}

#[test]
fn adjacent_freed_extents_coalesce_for_a_larger_reallocation() {
    let mut state = Policy::new(36, &[]).unwrap();
    state.add_free_extent(range(BASE, 4)).unwrap();
    state.create_domain(1, 4).unwrap();
    let mut caps = Vec::new();
    for _ in 0..4 { caps.push(state.allocate(1, 1, 0, Rights::ALL, |_| Ok(())).unwrap()); }
    for index in [1, 3, 0, 2] { state.release_capability(1, caps[index]).unwrap(); }
    assert_eq!(state.accounting(1).unwrap().charged_pages, 0);
    let whole = state.allocate(1, 4, 0, Rights::ALL, |_| Ok(())).unwrap();
    assert_eq!(state.region_info(1, whole).unwrap().backing, range(BASE, 4));
    for old in caps { denied(&mut state, |s| s.authorize(1, old, Rights::READ, 0, 1)); }
}

#[test]
fn frame_pool_rejects_forged_partial_release_and_coalesces_external_free_extents() {
    let mut pool = FramePool::<8>::new(36, &[range(BASE + 8 * PAGE_SIZE, 2)]).unwrap();
    pool.add_free_extent(range(BASE, 2)).unwrap();
    pool.add_free_extent(range(BASE + 2 * PAGE_SIZE, 2)).unwrap();
    assert_eq!(pool.available_pages(), 4);
    let first = pool.allocate(2).unwrap();
    let second = pool.allocate(2).unwrap();
    assert_eq!((pool.available_pages(), pool.allocated_pages()), (0, 4));
    denied(&mut pool, |p| p.release(range(first.start(), 1)));
    denied(&mut pool, |p| p.release(range(second.start() + PAGE_SIZE, 1)));
    denied(&mut pool, |p| p.add_free_extent(first));
    pool.release(second).unwrap();
    pool.release(first).unwrap();
    assert_eq!((pool.available_pages(), pool.allocated_pages()), (4, 0));
    assert_eq!(pool.allocate(4).unwrap(), range(BASE, 4));
}
