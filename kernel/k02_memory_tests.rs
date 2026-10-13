// Host-only adapter checks. Physical inventories are explicitly synthetic;
// only zero_page's byte erasure executes on a real host-owned buffer here.
use super::*;
use core::mem::size_of_val;

fn synthetic_state() -> NativeMemory {
    let extent = FrameRange::new(0x10_0000, 16).unwrap();
    let mut policy = Policy::new(40, &[]).unwrap();
    policy.add_free_extent(extent).unwrap();
    policy.create_domain(DOMAIN_A, DOMAIN_BUDGET_PAGES).unwrap();
    policy.create_domain(DOMAIN_B, DOMAIN_BUDGET_PAGES).unwrap();
    let mut admitted = [None; EXTENT_CAPACITY];
    admitted[0] = Some(extent);
    NativeMemory { policy, admitted, admitted_count: 1, scrubbed_pages: 0 }
}

fn synthetic_page(state: &mut NativeMemory, caller: u64) -> CapabilityRef {
    // Explicit mock of physical erasure for policy-only lease checks. Never
    // invoke NativeMemory::allocate_page on a fabricated physical address.
    state.policy.allocate(caller, 1, 0, Rights::ALL, |_| Ok(())).unwrap()
}

#[test]
fn final_handoff_copies_numeric_inventory_and_subtracts_live_pages() {
    let mut descriptors = [
        crate::uefi::Descriptor { kind: 7, padding: 0, start: 0x10_0000, virtual_start: 0, pages: 16, attributes: 0 },
        crate::uefi::Descriptor { kind: 7, padding: 0, start: 0x20_0000, virtual_start: 0, pages: 4, attributes: 1 << 63 },
        crate::uefi::Descriptor { kind: 2, padding: 0, start: 0x30_0000, virtual_start: 0, pages: 4, attributes: 0 },
    ];
    let descriptor_address = descriptors.as_ptr() as u64;
    let map_start = descriptor_address & !(PAGE_SIZE - 1);
    let map_end = (descriptor_address + size_of_val(&descriptors) as u64 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let image_start = core::cmp::min(ptr::addr_of!(DESCRIPTORS) as u64,
        core::cmp::min(ptr::addr_of!(MEMORY) as u64, ptr::addr_of!(INITIALIZED) as u64)) & !(PAGE_SIZE - 1);
    let image_end = core::cmp::max(ptr::addr_of!(DESCRIPTORS) as u64 + size_of::<[BootDescriptor; DESCRIPTOR_CAPACITY]>() as u64,
        core::cmp::max(ptr::addr_of!(MEMORY) as u64 + size_of::<NativeMemory>() as u64,
                     ptr::addr_of!(INITIALIZED) as u64 + 1));
    let image_end = (image_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let mut handoff = crate::uefi::Handoff { map: descriptors.as_ptr().cast(),
        map_length: size_of_val(&descriptors), descriptor_size: size_of::<crate::uefi::Descriptor>(),
        stack: crate::uefi::Range { start: 0x1000, end: 0x2000 },
        map_allocation: crate::uefi::Range { start: map_start, end: map_end },
        image: crate::uefi::Range { start: image_start, end: image_end },
        framebuffer: Some(crate::uefi::Range { start: 0x10_3003, end: 0x10_4001 }),
        high_scratch: None, physical_bits: 48, scratch: 0x10_0000 };
    // This host stub owns its raw descriptor buffer and static adapter storage.
    // It validates copying/planning only; it never allocates or dereferences the
    // synthetic physical extents and claims no successful firmware transition.
    handoff.map_length += 1;
    assert!(matches!(unsafe { initialize(&handoff) }, Err(MemoryError::Bounds)));
    handoff.map_length -= 1;
    let state = unsafe { initialize(&handoff).unwrap() };
    assert_eq!(state.available_pages(), 13); // one scratch + two rounded GOP pages
    assert_eq!(state.allocated_pages(), 0);
    assert_eq!(state.scrubbed_pages(), 0);
    let required = [handoff.image, handoff.stack, handoff.map_allocation,
        crate::uefi::Range { start: handoff.scratch, end: handoff.scratch + PAGE_SIZE },
        handoff.framebuffer.unwrap()];
    for admitted in state.admitted[..state.admitted_count].iter().flatten() {
        assert!(admitted.end() <= LOW_LIMIT);
        for live in required { assert!(admitted.end() <= live.start || live.end <= admitted.start()); }
    }
    descriptors[0].start = 0x40_0000;
    assert_eq!(descriptors[0].start, 0x40_0000);
    assert_eq!(state.available_pages(), 13); // copied plan never rereads the map
    assert!(matches!(unsafe { initialize(&handoff) }, Err(MemoryError::Phase)));
}

#[test]
fn volatile_scrub_erases_whole_page_and_preserves_both_guards() {
    #[repr(C, align(4096))]
    struct Guarded { before: [u64; 512], page: [u64; 512], after: [u64; 512] }
    let sentinel = 0x5445_5353_5259_4e02;
    let mut memory = Guarded { before: [sentinel; 512], page: [sentinel; 512], after: [sentinel; 512] };
    // SAFETY: this is an aligned exclusive real host-owned page between guards.
    unsafe { zero_page(memory.page.as_mut_ptr()); }
    assert_eq!(memory.page, [0; 512]);
    assert_eq!(memory.before, [sentinel; 512]);
    assert_eq!(memory.after, [sentinel; 512]);
}

#[test]
fn scrub_admission_rejects_null_high_gaps_and_multi_page_work() {
    let admitted = [Some(FrameRange::new(0x1000, 2).unwrap()), Some(FrameRange::new(0x5000, 1).unwrap())];
    assert!(admitted_page(FrameRange::new(0x1000, 1).unwrap(), &admitted));
    assert!(admitted_page(FrameRange::new(0x2000, 1).unwrap(), &admitted));
    assert!(admitted_page(FrameRange::new(0x5000, 1).unwrap(), &admitted));
    for range in [FrameRange::new(0, 1).unwrap(), FrameRange::new(0x3000, 1).unwrap(),
                  FrameRange::new(0x1000, 2).unwrap(), FrameRange::new(LOW_LIMIT, 1).unwrap()] {
        assert!(!admitted_page(range, &admitted));
    }
}

#[test]
fn trusted_caller_identity_and_readonly_lease_are_enforced() {
    let mut state = synthetic_state();
    let root = synthetic_page(&mut state, DOMAIN_A);
    assert!(matches!(state.map_page(DOMAIN_B, root, Access::Read), Err(MemoryError::InvalidAuthority)));
    let shared = state.delegate_readonly(DOMAIN_A, root, DOMAIN_B).unwrap();
    assert!(matches!(state.map_page(DOMAIN_B, shared, Access::Write), Err(MemoryError::InsufficientRights)));
    let page = state.map_page(DOMAIN_B, shared, Access::Read).unwrap();
    assert_eq!(page.physical, 0x10_0000);
    assert!(!page.writable);
    assert!(matches!(state.complete(DOMAIN_B, page.lease), Err(MemoryError::WrongLeaseKind)));
}

#[test]
fn operation_completion_retains_backing_until_trusted_quiescence() {
    let mut state = synthetic_state();
    let root = synthetic_page(&mut state, DOMAIN_A);
    let writing = state.acquire_page(DOMAIN_A, root, Access::Write).unwrap();
    state.complete(DOMAIN_A, writing.lease).unwrap();
    assert!(matches!(state.release(DOMAIN_A, root), Err(MemoryError::Busy)));
    assert!(matches!(state.map_page(DOMAIN_A, root, Access::Read), Err(MemoryError::Busy)));
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 1);
    // Policy-only synthetic acknowledgment. This test makes no TLB claim.
    unsafe { state.quiesce(writing.lease).unwrap(); }
    state.release(DOMAIN_A, root).unwrap();
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 0);
    assert_eq!(state.allocated_pages(), 0);
    assert_eq!(state.available_pages(), 16);
}

#[test]
fn revoked_mapping_remains_owned_through_fence_until_quiescence() {
    let mut state = synthetic_state();
    let root = synthetic_page(&mut state, DOMAIN_A);
    let shared = state.delegate_readonly(DOMAIN_A, root, DOMAIN_B).unwrap();
    let mapping = state.map_page(DOMAIN_B, shared, Access::Read).unwrap();
    state.revoke(DOMAIN_A, root).unwrap();
    assert!(matches!(state.map_page(DOMAIN_B, shared, Access::Read), Err(MemoryError::Revoked)));
    assert!(matches!(unsafe { state.quiesce(mapping.lease) }, Err(MemoryError::Phase)));
    state.fence(mapping.lease).unwrap();
    assert!(matches!(state.release(DOMAIN_B, shared), Err(MemoryError::Busy)));
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 1);
    unsafe { state.quiesce(mapping.lease).unwrap(); }
    state.release(DOMAIN_B, shared).unwrap();
    state.release(DOMAIN_A, root).unwrap();
    assert!(matches!(state.fence(mapping.lease), Err(MemoryError::StaleLease)));
    assert!(matches!(state.map_page(DOMAIN_A, root, Access::Read), Err(MemoryError::StaleHandle)));
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 0);
}
