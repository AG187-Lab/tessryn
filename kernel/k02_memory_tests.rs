// Host-only adapter checks. Physical inventories are explicitly synthetic;
// only zero_page's byte erasure executes on a real host-owned buffer here.
use super::*;
use core::mem::size_of_val;

fn synthetic_state() -> NativeMemory {
    let extent = FrameRange::new(0x10_0000, 16).unwrap();
    let mut policy = Policy::new(40, &[]).unwrap();
    policy.add_free_extent(extent).unwrap();
    for domain in [DOMAIN_A, DOMAIN_B, DOMAIN_C, DOMAIN_D] {
        policy.create_domain(domain, DOMAIN_BUDGET_PAGES).unwrap();
    }
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
        core::cmp::max(ptr::addr_of!(MEMORY) as u64 + size_of::<ProtectedSlot>() as u64,
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
fn trusted_initializer_checks_last_word_zero_before_any_payload_store() {
    #[repr(C, align(4096))]
    struct Guarded { before: [u64; 512], page: [u64; 512], after: [u64; 512] }
    let guard = 0x5445_5353_4755_4152;
    let seed = 0x5445_5353_4e45_5743;
    let mut memory = Guarded { before: [guard; 512], page: [0; 512], after: [guard; 512] };
    memory.page[511] = guard;
    let dirty = memory.page;
    // Last-word rejection proves all 512 words are checked before the first
    // payload store; an interleaved check/fill would have changed prior words.
    assert_eq!(unsafe { initialize_zeroed_page(memory.page.as_mut_ptr(), seed) }, Err(()));
    assert_eq!(memory.page, dirty);
    unsafe {
        zero_page(memory.page.as_mut_ptr());
        initialize_zeroed_page(memory.page.as_mut_ptr(), seed).unwrap();
    }
    for (index, value) in memory.page.into_iter().enumerate() { assert_eq!(value, seed ^ index as u64); }
    assert_eq!(memory.before, [guard; 512]);
    assert_eq!(memory.after, [guard; 512]);
}

#[test]
fn failed_private_initializer_publishes_no_capability_charge_or_lease() {
    let mut state = synthetic_state();
    #[repr(C, align(4096))]
    struct ModelPage([u64; 512]);
    let mut buffer = ModelPage([0; 512]);
    buffer.0[511] = 1;
    let before = format!("{:?}", state.policy);
    // Deliberately failed zero verification in an explicit synthetic physical
    // model exercises the original Core callback's publication boundary. Native
    // allocate_initialized_page performs real zero_page before this verifier.
    let result = state.policy.allocate(DOMAIN_C, 1, 0, Rights::ALL, |_range| {
        unsafe { initialize_zeroed_page(buffer.0.as_mut_ptr(), 7) }
    });
    assert_eq!(result, Err(MemoryError::ScrubFailed));
    assert_eq!(format!("{:?}", state.policy), before);
    assert_eq!(state.accounting(DOMAIN_C).unwrap().charged_pages, 0);
    assert_eq!(state.allocated_pages(), 0);
    assert_eq!(state.scrubbed_pages(), 0);
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

#[test]
fn four_domains_keep_original_owner_charge_and_reject_claimed_identity() {
    assert!(size_of::<NativeMemory>() <= 32 * 1024);
    assert_eq!(size_of::<ProtectedSlot>(), 24_576);
    assert_eq!(offset_of!(ProtectedSlot, memory), 0);
    assert_eq!(ptr::addr_of!(MEMORY) as u64 % PAGE_SIZE, 0);
    let mut state = synthetic_state();
    let root = synthetic_page(&mut state, DOMAIN_A);
    let b = state.delegate(DOMAIN_A, root, DOMAIN_B,
        Rights::READ | Rights::MAP | Rights::DELEGATE, 0, PAGE_SIZE).unwrap();
    let d = state.delegate(DOMAIN_B, b, DOMAIN_D, Rights::READ | Rights::MAP, 0, PAGE_SIZE).unwrap();
    for (caller, handle) in [(DOMAIN_A, root), (DOMAIN_B, b), (DOMAIN_D, d)] {
        let region = state.region_info(caller, handle).unwrap();
        assert_eq!(region.charge_owner, DOMAIN_A);
        assert_eq!(region.committed_pages, 1);
        assert_eq!(region.reserved_pages, 0);
        assert_eq!(region.backing.start(), 0x10_0000);
    }
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 1);
    for caller in [DOMAIN_B, DOMAIN_C, DOMAIN_D] {
        assert_eq!(state.accounting(caller).unwrap().charged_pages, 0);
    }
    let before = format!("{:?}", state.policy);
    assert_eq!(state.authorize(DOMAIN_B, root, Rights::READ, 0, 1), Err(MemoryError::InvalidAuthority));
    assert_eq!(state.region_info(DOMAIN_C, b), Err(MemoryError::InvalidAuthority));
    assert_eq!(state.create_domain(5, 16), Err(MemoryError::InvalidAuthority));
    assert_eq!(state.create_domain(0, 16), Err(MemoryError::InvalidAuthority));
    assert_eq!(state.create_domain(DOMAIN_D, 16), Err(MemoryError::DuplicateDomain));
    assert_eq!(format!("{:?}", state.policy), before);
}

#[test]
fn bounded_delegation_preserves_rights_bounds_alignment_order_without_owners() {
    let mut state = synthetic_state();
    let root = synthetic_page(&mut state, DOMAIN_A);
    let byte = state.delegate(DOMAIN_A, root, DOMAIN_B, Rights::READ | Rights::MAP,
        1, PAGE_SIZE - 2).unwrap();
    let view = state.authorize(DOMAIN_B, byte, Rights::READ, 0, PAGE_SIZE - 2).unwrap();
    assert_eq!(view, RegionView { physical_start: 0x10_0001, length: PAGE_SIZE - 2 });
    let no_read = state.delegate(DOMAIN_A, root, DOMAIN_B, Rights::WRITE | Rights::MAP, 0, PAGE_SIZE).unwrap();
    let before = format!("{:?}", state.policy);
    for (handle, access, offset, length, error) in [
        (byte, Access::Read, 0, PAGE_SIZE - 2, MemoryError::Alignment),
        (byte, Access::Read, 0, PAGE_SIZE, MemoryError::Bounds),
        (byte, Access::Read, 0, 0, MemoryError::Empty),
        (byte, Access::Read, u64::MAX, 2, MemoryError::Overflow),
        (byte, Access::Write, 0, PAGE_SIZE, MemoryError::InsufficientRights),
        (no_read, Access::Write, 1, 1, MemoryError::InsufficientRights),
    ] {
        assert!(matches!(state.map_intent(DOMAIN_B, handle, access, offset, length), Err(actual) if actual == error));
        assert_eq!(format!("{:?}", state.policy), before);
    }
    assert_eq!(state.authorize(DOMAIN_B, byte, Rights::WRITE, 0, 1), Err(MemoryError::InsufficientRights));
    assert_eq!(state.delegate(DOMAIN_B, byte, DOMAIN_D, Rights::READ, 0, 1), Err(MemoryError::InsufficientRights));
    state.release(DOMAIN_B, byte).unwrap();
    state.release(DOMAIN_B, no_read).unwrap();
    state.release(DOMAIN_A, root).unwrap(); // rejected mappings leaked no lease
    assert_eq!(state.allocated_pages(), 0);
}

#[test]
fn admitted_guard_preserves_alignment_error_and_rejects_before_lease_publication() {
    let mut state = synthetic_state();
    let root = synthetic_page(&mut state, DOMAIN_A);
    // Explicit inconsistent host metadata tests the adapter's additional guard;
    // a real NativeMemory publishes its policy and admission bounds together.
    state.admitted_count = 0;
    let before = format!("{:?}", state.policy);
    assert!(matches!(state.map_intent(DOMAIN_A, root, Access::Read, 1, 1), Err(MemoryError::Alignment)));
    assert!(matches!(state.map_intent(DOMAIN_A, root, Access::Read, 0, PAGE_SIZE), Err(MemoryError::Excluded)));
    assert!(matches!(state.acquire(DOMAIN_A, root, Access::Read, 0, 1), Err(MemoryError::Excluded)));
    assert_eq!(format!("{:?}", state.policy), before);
    let extent = [Some(FrameRange::new(0x1000, 1).unwrap())];
    assert!(admitted_view(RegionView { physical_start: 0x1001, length: 4095 }, &extent));
    for view in [RegionView { physical_start: 0, length: 1 },
                 RegionView { physical_start: 0x1000, length: 0 },
                 RegionView { physical_start: 0x1000, length: 4097 },
                 RegionView { physical_start: u64::MAX, length: 2 },
                 RegionView { physical_start: LOW_LIMIT, length: 1 }] {
        assert!(!admitted_view(view, &extent));
    }
}

#[test]
fn byte_write_only_operations_do_not_create_cpu_mapping_authority() {
    let mut state = synthetic_state();
    let root = synthetic_page(&mut state, DOMAIN_A);
    let write = state.delegate(DOMAIN_A, root, DOMAIN_B, Rights::WRITE | Rights::SUBMIT, 17, 100).unwrap();
    let operation = state.acquire(DOMAIN_B, write, Access::Write, 23, 7).unwrap();
    assert_eq!(operation.physical, 0x10_0028);
    assert_eq!(operation.length, 7);
    assert!(operation.writable);
    assert_eq!(state.authorize(DOMAIN_B, write, Rights::READ, 0, 1), Err(MemoryError::InsufficientRights));
    assert!(matches!(state.map_intent(DOMAIN_B, write, Access::Write, 0, 100), Err(MemoryError::InsufficientRights)));
    assert_eq!(state.release(DOMAIN_A, root), Err(MemoryError::Busy));
    state.complete(DOMAIN_B, operation.lease).unwrap();
    assert_eq!(state.release(DOMAIN_B, write), Err(MemoryError::Busy));
    // Explicit synthetic completed-operation acknowledgment, no hardware claim.
    unsafe { state.quiesce(operation.lease).unwrap(); }
    state.release(DOMAIN_B, write).unwrap();
    state.release(DOMAIN_A, root).unwrap();
}

#[test]
fn recursive_revocation_holds_charge_until_each_descendant_teardown_finishes() {
    let mut state = synthetic_state();
    let root = synthetic_page(&mut state, DOMAIN_A);
    let b = state.delegate(DOMAIN_A, root, DOMAIN_B,
        Rights::READ | Rights::MAP | Rights::DELEGATE, 0, PAGE_SIZE).unwrap();
    let d = state.delegate(DOMAIN_B, b, DOMAIN_D, Rights::READ | Rights::MAP, 0, PAGE_SIZE).unwrap();
    let b_mapping = state.map_intent(DOMAIN_B, b, Access::Read, 0, PAGE_SIZE).unwrap();
    let d_mapping = state.map_intent(DOMAIN_D, d, Access::Read, 0, PAGE_SIZE).unwrap();
    assert_eq!(b_mapping.physical, d_mapping.physical);
    state.revoke(DOMAIN_A, root).unwrap();
    for (caller, handle) in [(DOMAIN_A, root), (DOMAIN_B, b), (DOMAIN_D, d)] {
        assert_eq!(state.authorize(caller, handle, Rights::READ, 0, 1), Err(MemoryError::Revoked));
        assert_eq!(state.region_info(caller, handle), Err(MemoryError::Revoked));
        assert!(matches!(state.map_intent(caller, handle, Access::Read, 0, PAGE_SIZE), Err(MemoryError::Revoked)));
    }
    assert_eq!(state.complete(DOMAIN_B, b_mapping.lease), Err(MemoryError::Revoked));
    assert_eq!(state.release(DOMAIN_A, root), Err(MemoryError::Busy));
    state.fence(b_mapping.lease).unwrap();
    unsafe { state.quiesce(b_mapping.lease).unwrap(); }
    assert_eq!(state.release(DOMAIN_B, b), Err(MemoryError::Busy));
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 1);
    assert_eq!(unsafe { state.quiesce(d_mapping.lease) }, Err(MemoryError::Phase));
    state.fence(d_mapping.lease).unwrap();
    assert_eq!(state.release(DOMAIN_D, d), Err(MemoryError::Busy));
    unsafe { state.quiesce(d_mapping.lease).unwrap(); }
    assert_eq!(state.release(DOMAIN_B, b), Err(MemoryError::Busy)); // D capability still retained
    state.release(DOMAIN_D, d).unwrap();
    state.release(DOMAIN_B, b).unwrap();
    state.release(DOMAIN_A, root).unwrap();
    assert_eq!(state.allocated_pages(), 0);
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 0);
}

#[test]
fn last_allocation_reuses_exact_frame_scrubs_host_model_and_rejects_stale_ids() {
    let mut state = synthetic_state();
    let _persistent_stack = synthetic_page(&mut state, DOMAIN_B);
    let root = synthetic_page(&mut state, DOMAIN_A); // target allocated LAST
    let backing = state.region_info(DOMAIN_A, root).unwrap().backing;
    let old_b = state.delegate(DOMAIN_A, root, DOMAIN_B,
        Rights::READ | Rights::WRITE | Rights::MAP, 0, PAGE_SIZE).unwrap();
    let old_mapping = state.map_intent(DOMAIN_B, old_b, Access::Write, 0, PAGE_SIZE).unwrap();
    state.revoke(DOMAIN_A, root).unwrap();
    state.fence(old_mapping.lease).unwrap();
    assert_eq!(state.release(DOMAIN_B, old_b), Err(MemoryError::Busy));
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 1);
    unsafe { state.quiesce(old_mapping.lease).unwrap(); }
    state.release(DOMAIN_B, old_b).unwrap();
    state.release(DOMAIN_A, root).unwrap();
    assert_eq!(state.accounting(DOMAIN_A).unwrap().charged_pages, 0);

    #[repr(C, align(4096))]
    struct ModelPage([u64; 512]);
    let mut modeled_backing = ModelPage([0x5445_5353_5354_414c; 512]);
    // The address is synthetic. This explicit host model binds that exact
    // numerical frame to one real exclusive host buffer for erasure only. The
    // production allocate_page callback dereferences admitted physical RAM.
    let replacement = state.policy.allocate(DOMAIN_C, 1, 0, Rights::ALL, |range| {
        if range != backing { return Err(()); }
        unsafe { zero_page(modeled_backing.0.as_mut_ptr()); }
        Ok(())
    }).unwrap();
    assert_eq!(state.region_info(DOMAIN_C, replacement).unwrap().backing, backing);
    assert_eq!(modeled_backing.0, [0; 512]);
    let replacement_b = state.delegate_readonly(DOMAIN_C, replacement, DOMAIN_B).unwrap();
    assert_eq!(replacement_b.slot, old_b.slot);
    assert_eq!(replacement_b.generation, old_b.generation + 1);
    let replacement_mapping = state.map_intent(DOMAIN_B, replacement_b, Access::Read, 0, PAGE_SIZE).unwrap();
    assert_eq!(replacement_mapping.lease.slot(), old_mapping.lease.slot());
    assert_eq!(replacement_mapping.lease.generation(), old_mapping.lease.generation() + 1);
    let before = format!("{:?}", state.policy);
    assert_eq!(state.release(DOMAIN_B, old_b), Err(MemoryError::StaleHandle));
    assert_eq!(state.fence(old_mapping.lease), Err(MemoryError::StaleLease));
    assert_eq!(state.complete(DOMAIN_B, old_mapping.lease), Err(MemoryError::StaleLease));
    assert_eq!(state.authorize(DOMAIN_B, old_b, Rights::READ, 0, PAGE_SIZE), Err(MemoryError::StaleHandle));
    assert_eq!(format!("{:?}", state.policy), before);
    assert_eq!(state.accounting(DOMAIN_C).unwrap().charged_pages, 1);
}

#[test]
fn an_earlier_released_hole_does_not_imply_next_allocation_reuses_it() {
    let mut state = synthetic_state();
    let early = synthetic_page(&mut state, DOMAIN_A);
    let early_frame = state.region_info(DOMAIN_A, early).unwrap().backing;
    let _persistent = synthetic_page(&mut state, DOMAIN_B);
    state.release(DOMAIN_A, early).unwrap();
    let next = synthetic_page(&mut state, DOMAIN_C);
    assert_ne!(state.region_info(DOMAIN_C, next).unwrap().backing, early_frame);
}

#[test]
fn last_target_reuses_exact_frame_when_its_free_extent_was_consumed() {
    let mut state = synthetic_state();
    let mut policy = Policy::new(40, &[]).unwrap();
    let extents = [(0x10_0000, 1), (0x20_0000, 1), (0x30_0000, 8)];
    state.admitted.fill(None);
    state.admitted_count = extents.len();
    for (index, (start, pages)) in extents.into_iter().enumerate() {
        let extent = FrameRange::new(start, pages).unwrap();
        policy.add_free_extent(extent).unwrap();
        state.admitted[index] = Some(extent);
    }
    for domain in [DOMAIN_A, DOMAIN_B, DOMAIN_C, DOMAIN_D] { policy.create_domain(domain, 16).unwrap(); }
    state.policy = policy;
    let _persistent = synthetic_page(&mut state, DOMAIN_B); // consumes first slot
    let target = synthetic_page(&mut state, DOMAIN_A); // consumes second slot
    let frame = state.region_info(DOMAIN_A, target).unwrap().backing;
    assert_eq!(frame.start(), 0x20_0000);
    state.release(DOMAIN_A, target).unwrap();
    let next = synthetic_page(&mut state, DOMAIN_C);
    assert_eq!(state.region_info(DOMAIN_C, next).unwrap().backing, frame);
}
