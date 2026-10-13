//! Host checks of boot inventory admission; these do not prove firmware exit or
//! native address-space isolation. The bounded oracle classifies individual
//! pages independently of the planner's interval normalization.

extern crate std;

use crate::{
    BootDescriptor, BootInventory, BootRange, BootReservations, Error, FrameRange, Rights,
    PAGE_SIZE,
};
use std::{format, vec, vec::Vec};

const BASE: u64 = 0x10_0000;
const LOW_END: u64 = 1 << 32;
const RUNTIME: u64 = 1 << 63;

fn descriptor(kind: u32, start: u64, pages: u64) -> BootDescriptor {
    BootDescriptor { kind, start, pages, attributes: 0 }
}

fn bytes(start: u64, length: u64) -> BootRange {
    BootRange { start, length }
}

// Four distinct allocations are adjacent, so their normalized exclusion uses
// one slot. They sit outside the conventional test bank unless specified.
fn reservations() -> BootReservations {
    BootReservations {
        image: bytes(PAGE_SIZE, PAGE_SIZE),
        stack: bytes(2 * PAGE_SIZE, PAGE_SIZE),
        memory_map: bytes(3 * PAGE_SIZE, PAGE_SIZE),
        scratch: bytes(4 * PAGE_SIZE, PAGE_SIZE),
        framebuffer: None,
        high_scratch: None,
    }
}

fn extent_numbers<const F: usize>(inventory: &BootInventory<F>) -> Vec<(u64, u64)> {
    inventory.extents().map(|range| (range.start(), range.pages())).collect()
}

fn excluded_numbers<const F: usize>(inventory: &BootInventory<F>) -> Vec<(u64, u64)> {
    inventory.exclusions().map(|range| (range.start(), range.pages())).collect()
}

fn admitted_pages<const F: usize>(inventory: &BootInventory<F>) -> Vec<u64> {
    inventory.extents()
        .flat_map(|range| (0..range.pages()).map(move |page| range.start() + page * PAGE_SIZE))
        .collect()
}

fn permutations<T: Copy>(items: &[T]) -> Vec<Vec<T>> {
    fn visit<T: Copy>(items: &mut [T], at: usize, result: &mut Vec<Vec<T>>) {
        if at == items.len() {
            result.push(items.to_vec());
            return;
        }
        for index in at..items.len() {
            items.swap(at, index);
            visit(items, at + 1, result);
            items.swap(at, index);
        }
    }
    let mut items = items.to_vec();
    let mut result = Vec::new();
    visit(&mut items, 0, &mut result);
    result
}

// A page is excluded when any live byte intersects it; this deliberately does
// not sort, merge or outward-round ranges as the implementation does.
fn page_oracle(
    descriptors: &[BootDescriptor],
    live: BootReservations,
    extra: &[BootRange],
    bank_start: u64,
    bank_pages: u64,
) -> Vec<u64> {
    (0..bank_pages)
        .map(|page| bank_start + page * PAGE_SIZE)
        .filter(|start| {
            *start < LOW_END && descriptors.iter().any(|descriptor| {
                descriptor.kind == 7 && descriptor.attributes & RUNTIME == 0
                    && *start >= descriptor.start
                    && *start + PAGE_SIZE <= descriptor.start + descriptor.pages * PAGE_SIZE
            })
        })
        .filter(|start| {
            [live.image, live.stack, live.memory_map, live.scratch]
                .into_iter().chain(live.framebuffer).chain(live.high_scratch)
                .chain(extra.iter().copied())
                .all(|range| range.start >= *start + PAGE_SIZE || range.start + range.length <= *start)
        })
        .collect()
}

#[test]
fn boot_inventory_admits_only_nonruntime_conventional_memory() {
    for kind in (0..=15).chain([u32::MAX]) {
        let map = [descriptor(kind, BASE, 2)];
        let inventory = BootInventory::<4>::plan(36, &map, reservations(), &[]).unwrap();
        assert_eq!(inventory.available_pages(), if kind == 7 { 2 } else { 0 }, "kind {kind}");
    }
    for attributes in [RUNTIME, RUNTIME | 1, u64::MAX] {
        let map = [BootDescriptor { attributes, ..descriptor(7, BASE, 2) }];
        let inventory = BootInventory::<4>::plan(36, &map, reservations(), &[]).unwrap();
        assert_eq!(inventory.available_pages(), 0);
    }
    // Attribute bits other than RUNTIME do not change the admitted memory kind.
    let map = [BootDescriptor { attributes: RUNTIME - 1, ..descriptor(7, BASE, 2) }];
    assert_eq!(BootInventory::<4>::plan(36, &map, reservations(), &[]).unwrap().available_pages(), 2);
}

#[test]
fn boot_inventory_empty_or_wholly_quarantined_maps_have_no_allocator_authority() {
    for map in [vec![], vec![descriptor(4, BASE, 2)], vec![descriptor(7, LOW_END, 2)]] {
        let inventory = BootInventory::<4>::plan(36, &map, reservations(), &[]).unwrap();
        assert_eq!(inventory.available_pages(), 0);
        assert!(inventory.extents().next().is_none());
        let mut policy = inventory.into_policy::<1, 1, 1, 1>().unwrap();
        policy.create_domain(1, 1).unwrap();
        assert_eq!(policy.allocate(1, 1, 0, Rights::ALL, |_| panic!("empty inventory must not scrub")), Err(Error::Capacity));
    }
}

#[test]
fn boot_inventory_unsorted_adjacent_descriptors_coalesce_before_capacity_check() {
    let map = [descriptor(7, BASE + 2 * PAGE_SIZE, 1), descriptor(7, BASE, 1), descriptor(7, BASE + PAGE_SIZE, 1)];
    for order in permutations(&map) {
        let inventory = BootInventory::<1>::plan(36, &order, reservations(), &[]).unwrap();
        assert_eq!(extent_numbers(&inventory), [(BASE, 3)]);
        assert_eq!(inventory.available_pages(), 3);
        assert_eq!(excluded_numbers(&inventory), [(PAGE_SIZE, 4)]);
    }
}

#[test]
fn boot_inventory_rejects_descriptor_overlap_even_when_both_ranges_are_quarantined() {
    for (left_kind, right_kind, start) in [(7, 4, BASE), (4, u32::MAX, BASE), (7, 7, LOW_END)] {
        let map = [descriptor(left_kind, start, 2), descriptor(right_kind, start + PAGE_SIZE, 2)];
        for order in permutations(&map) {
            assert_eq!(BootInventory::<8>::plan(36, &order, reservations(), &[]), Err(Error::Overlap));
        }
    }
    let map = [descriptor(7, BASE, 2), descriptor(7, BASE, 2)];
    assert_eq!(BootInventory::<8>::plan(36, &map, reservations(), &[]), Err(Error::Overlap));
    let adjacent = [descriptor(7, BASE, 2), descriptor(4, BASE + 2 * PAGE_SIZE, 2)];
    assert_eq!(extent_numbers(&BootInventory::<8>::plan(36, &adjacent, reservations(), &[]).unwrap()), [(BASE, 2)]);
}

#[test]
fn boot_inventory_validates_malformed_descriptors_in_every_memory_class() {
    for kind in [7, 4, u32::MAX] {
        for (map, error) in [
            (descriptor(kind, BASE, 0), Error::Empty),
            (descriptor(kind, BASE + 1, 1), Error::Alignment),
            (descriptor(kind, BASE, u64::MAX), Error::Overflow),
            (descriptor(kind, u64::MAX - (PAGE_SIZE - 1), 1), Error::Overflow),
            (descriptor(kind, (1 << 36) - PAGE_SIZE, 2), Error::PhysicalWidth),
        ] {
            assert_eq!(BootInventory::<8>::plan(36, &[map], reservations(), &[]), Err(error), "kind {kind}");
        }
    }
}

#[test]
fn boot_inventory_physical_width_endpoints_are_checked_before_high_quarantine() {
    for bits in [0, 31, 53, 64, u8::MAX] {
        assert_eq!(BootInventory::<4>::plan(bits, &[], reservations(), &[]), Err(Error::PhysicalWidth));
    }
    for bits in [32, 36, 52] {
        let limit = 1u64 << bits;
        let map = [descriptor(7, limit - PAGE_SIZE, 1)];
        let inventory = BootInventory::<4>::plan(bits, &map, reservations(), &[]).unwrap();
        assert_eq!(inventory.available_pages(), u64::from(bits == 32));
        let past_end = [descriptor(4, limit - PAGE_SIZE, 2)];
        assert_eq!(BootInventory::<4>::plan(bits, &past_end, reservations(), &[]), Err(Error::PhysicalWidth));
        let last_byte = [bytes(limit - 1, 1)];
        let inventory = BootInventory::<4>::plan(bits, &[], reservations(), &last_byte).unwrap();
        assert_eq!(excluded_numbers(&inventory).last(), Some(&(limit - PAGE_SIZE, 1)));
        assert_eq!(BootInventory::<4>::plan(bits, &[], reservations(), &[bytes(limit - 1, 2)]), Err(Error::PhysicalWidth));
    }
}

#[test]
fn boot_inventory_clips_low_aperture_without_admitting_high_handoff_memory() {
    let map = [descriptor(7, LOW_END + 8 * PAGE_SIZE, 2), descriptor(7, LOW_END - 2 * PAGE_SIZE, 4)];
    let mut live = reservations();
    live.high_scratch = Some(bytes(LOW_END + 8 * PAGE_SIZE, PAGE_SIZE));
    let inventory = BootInventory::<8>::plan(36, &map, live, &[]).unwrap();
    assert_eq!(extent_numbers(&inventory), [(LOW_END - 2 * PAGE_SIZE, 2)]);
    assert_eq!(inventory.available_pages(), 2);
    assert!(inventory.exclusions().any(|range| range.start() == LOW_END + 8 * PAGE_SIZE));
    assert_eq!(BootInventory::<8>::plan(32, &map, live, &[]), Err(Error::PhysicalWidth));
}

#[test]
fn boot_inventory_reserves_every_live_handoff_allocation_including_conventional_scratch() {
    let map = [descriptor(7, BASE, 16)];
    let live = BootReservations {
        image: bytes(BASE + PAGE_SIZE + 5, PAGE_SIZE),
        stack: bytes(BASE + 3 * PAGE_SIZE, PAGE_SIZE),
        memory_map: bytes(BASE + 5 * PAGE_SIZE, PAGE_SIZE),
        scratch: bytes(BASE + 7 * PAGE_SIZE, PAGE_SIZE),
        framebuffer: Some(bytes(BASE + 9 * PAGE_SIZE + 5, PAGE_SIZE)),
        high_scratch: Some(bytes(BASE + 13 * PAGE_SIZE, PAGE_SIZE)),
    };
    let extra = [bytes(BASE + 15 * PAGE_SIZE, PAGE_SIZE)];
    let inventory = BootInventory::<16>::plan(36, &map, live, &extra).unwrap();
    let expected = [0, 4, 6, 8, 11, 12, 14].map(|page| BASE + page * PAGE_SIZE);
    assert_eq!(admitted_pages(&inventory), expected);
    assert_eq!(inventory.available_pages(), 7);
    assert_eq!(admitted_pages(&inventory), page_oracle(&map, live, &extra, BASE, 16));
}

#[test]
fn boot_inventory_required_allocations_cannot_share_a_rounded_page() {
    let mut live = reservations();
    live.image = bytes(BASE + 1, PAGE_SIZE);
    live.stack = bytes(BASE + PAGE_SIZE + 1, 1);
    // The byte intervals are disjoint but both retain the second physical page.
    assert_eq!(BootInventory::<8>::plan(36, &[], live, &[]), Err(Error::Overlap));
    for field in 0..3 {
        let mut live = reservations();
        match field {
            0 => live.image = live.scratch,
            1 => live.stack = live.scratch,
            _ => live.memory_map = live.scratch,
        }
        assert_eq!(BootInventory::<8>::plan(36, &[], live, &[]), Err(Error::Overlap));
    }
}

#[test]
fn boot_inventory_optional_high_scratch_may_duplicate_the_baseline_scratch() {
    let mut live = reservations();
    live.scratch = bytes(LOW_END + PAGE_SIZE, PAGE_SIZE);
    live.high_scratch = Some(live.scratch);
    let inventory = BootInventory::<4>::plan(36, &[descriptor(7, BASE, 1)], live, &[]).unwrap();
    assert_eq!(excluded_numbers(&inventory), [(PAGE_SIZE, 3), (LOW_END + PAGE_SIZE, 1)]);
    assert_eq!(inventory.available_pages(), 1);
}

#[test]
fn boot_inventory_rejects_zero_overflowing_or_malformed_live_reservations() {
    for field in 0..6 {
        let mut live = reservations();
        let empty = bytes(BASE, 0);
        match field {
            0 => live.image = empty,
            1 => live.stack = empty,
            2 => live.memory_map = empty,
            3 => live.scratch = empty,
            4 => live.framebuffer = Some(empty),
            _ => live.high_scratch = Some(empty),
        }
        assert_eq!(BootInventory::<8>::plan(36, &[], live, &[]), Err(Error::Empty));
    }
    assert_eq!(BootInventory::<8>::plan(36, &[], reservations(), &[bytes(BASE, 0)]), Err(Error::Empty));
    assert_eq!(BootInventory::<8>::plan(52, &[], reservations(), &[bytes(u64::MAX - 1, 2)]), Err(Error::Overflow));
    let mut live = reservations();
    live.scratch = bytes(BASE + 1, PAGE_SIZE);
    assert_eq!(BootInventory::<8>::plan(36, &[], live, &[]), Err(Error::Alignment));
    for length in [1, PAGE_SIZE - 1, PAGE_SIZE + 1, 2 * PAGE_SIZE] {
        live.scratch = bytes(BASE, length);
        assert_eq!(BootInventory::<8>::plan(36, &[], live, &[]), Err(Error::Bounds));
    }
}

#[test]
fn boot_inventory_exclusions_normalize_nested_overlapping_adjacent_and_bridging_inputs() {
    let extra = [
        bytes(BASE + 3 * PAGE_SIZE, PAGE_SIZE),
        bytes(BASE + PAGE_SIZE + 3, 2 * PAGE_SIZE),
        bytes(BASE + 2 * PAGE_SIZE + 7, 1),
        bytes(BASE + 4 * PAGE_SIZE, PAGE_SIZE),
    ];
    for order in permutations(&extra) {
        let inventory = BootInventory::<2>::plan(36, &[descriptor(7, BASE, 7)], reservations(), &order).unwrap();
        assert_eq!(excluded_numbers(&inventory), [(PAGE_SIZE, 4), (BASE + PAGE_SIZE, 4)]);
        assert_eq!(extent_numbers(&inventory), [(BASE, 1), (BASE + 5 * PAGE_SIZE, 2)]);
        assert_eq!(inventory.available_pages(), 3);
    }
}

#[test]
fn boot_inventory_exclusion_can_span_distinct_extents_and_quarantined_gaps() {
    let map = [descriptor(7, BASE, 3), descriptor(4, BASE + 3 * PAGE_SIZE, 2), descriptor(7, BASE + 5 * PAGE_SIZE, 3)];
    let extra = [bytes(BASE + 2 * PAGE_SIZE + 1, 3 * PAGE_SIZE)];
    let inventory = BootInventory::<4>::plan(36, &map, reservations(), &extra).unwrap();
    assert_eq!(extent_numbers(&inventory), [(BASE, 2), (BASE + 6 * PAGE_SIZE, 2)]);
    assert_eq!(inventory.available_pages(), 4);
}

#[test]
fn boot_inventory_output_capacity_applies_to_final_normalized_tables() {
    // One exclusion fits, but two disconnected admitted extents do not.
    let disconnected = [descriptor(7, BASE, 1), descriptor(7, BASE + 2 * PAGE_SIZE, 1)];
    assert_eq!(BootInventory::<1>::plan(36, &disconnected, reservations(), &[]), Err(Error::Capacity));
    assert_eq!(BootInventory::<2>::plan(36, &disconnected, reservations(), &[]).unwrap().extents().count(), 2);
    let split = [bytes(BASE + PAGE_SIZE, PAGE_SIZE)];
    assert_eq!(BootInventory::<1>::plan(36, &[descriptor(7, BASE, 3)], reservations(), &split), Err(Error::Capacity));
    let inventory = BootInventory::<2>::plan(36, &[descriptor(7, BASE, 3)], reservations(), &split).unwrap();
    assert_eq!(extent_numbers(&inventory), [(BASE, 1), (BASE + 2 * PAGE_SIZE, 1)]);
    let extras = [bytes(BASE, PAGE_SIZE), bytes(BASE + 2 * PAGE_SIZE, PAGE_SIZE), bytes(BASE + 4 * PAGE_SIZE, PAGE_SIZE)];
    let inventory = BootInventory::<4>::plan(36, &[], reservations(), &extras).unwrap();
    assert_eq!(inventory.exclusions().count(), 4);
    assert_eq!(BootInventory::<3>::plan(36, &[], reservations(), &extras), Err(Error::Capacity));
    assert_eq!(BootInventory::<0>::plan(36, &[], reservations(), &[]), Err(Error::Capacity));
    // A late bridging input must not fail on transient exclusion count.
    let bridging = [bytes(BASE, PAGE_SIZE), bytes(BASE + 2 * PAGE_SIZE, PAGE_SIZE), bytes(BASE + PAGE_SIZE, PAGE_SIZE)];
    for order in permutations(&bridging) {
        let inventory = BootInventory::<2>::plan(36, &[], reservations(), &order).unwrap();
        assert_eq!(excluded_numbers(&inventory), [(PAGE_SIZE, 4), (BASE, 3)]);
    }
}

#[test]
fn boot_inventory_bounded_inputs_reject_excess_without_publishing_a_plan() {
    let map: Vec<_> = (0..4096).map(|page| descriptor(4, BASE + page * PAGE_SIZE, 1)).collect();
    assert_eq!(BootInventory::<1>::plan(36, &map, reservations(), &[]).unwrap().available_pages(), 0);
    let mut over_limit = map;
    over_limit.push(descriptor(4, BASE + 4096 * PAGE_SIZE, 1));
    assert_eq!(BootInventory::<1>::plan(36, &over_limit, reservations(), &[]), Err(Error::Capacity));
    let extra = vec![bytes(BASE, PAGE_SIZE); 4092];
    assert_eq!(BootInventory::<2>::plan(36, &[], reservations(), &extra).unwrap().exclusions().count(), 2);
    let mut extra_over_limit = extra;
    extra_over_limit.push(bytes(BASE, PAGE_SIZE));
    assert_eq!(BootInventory::<2>::plan(36, &[], reservations(), &extra_over_limit), Err(Error::Capacity));
}

#[test]
fn boot_inventory_matches_independent_page_oracle_under_bounded_input_permutations() {
    let map = [
        descriptor(7, BASE, 6),
        descriptor(4, BASE + 6 * PAGE_SIZE, 4),
        descriptor(7, BASE + 10 * PAGE_SIZE, 7),
        BootDescriptor { attributes: RUNTIME, ..descriptor(7, BASE + 17 * PAGE_SIZE, 3) },
    ];
    let extra = [
        bytes(BASE + PAGE_SIZE + 1, PAGE_SIZE),
        bytes(BASE + 11 * PAGE_SIZE, PAGE_SIZE),
        bytes(BASE + 12 * PAGE_SIZE + 2, PAGE_SIZE - 2),
        bytes(BASE + 11 * PAGE_SIZE + 3, 1),
    ];
    let mut live = reservations();
    live.framebuffer = Some(bytes(BASE + 15 * PAGE_SIZE + PAGE_SIZE - 1, 2));
    let expected = page_oracle(&map, live, &extra, BASE, 20);
    let canonical = BootInventory::<16>::plan(36, &map, live, &extra).unwrap();
    for map_order in permutations(&map) {
        for exclusion_order in permutations(&extra) {
            let inventory = BootInventory::<16>::plan(36, &map_order, live, &exclusion_order).unwrap();
            assert_eq!(admitted_pages(&inventory), expected);
            assert_eq!(inventory.available_pages(), expected.len() as u64);
            assert_eq!(inventory, canonical, "descriptor or exclusion order changed the complete plan");
        }
    }
}

#[test]
fn boot_inventory_policy_scrubs_and_reuses_only_admitted_pages() {
    let map = [descriptor(7, BASE, 16)];
    let live = BootReservations {
        image: bytes(BASE + PAGE_SIZE + 5, PAGE_SIZE),
        stack: bytes(BASE + 3 * PAGE_SIZE, PAGE_SIZE),
        memory_map: bytes(BASE + 5 * PAGE_SIZE, PAGE_SIZE),
        scratch: bytes(BASE + 7 * PAGE_SIZE, PAGE_SIZE),
        framebuffer: Some(bytes(BASE + 9 * PAGE_SIZE + 5, PAGE_SIZE)),
        high_scratch: Some(bytes(BASE + 13 * PAGE_SIZE, PAGE_SIZE)),
    };
    let extra = [bytes(BASE + 15 * PAGE_SIZE, PAGE_SIZE)];
    let allowed = page_oracle(&map, live, &extra, BASE, 16);
    let inventory = BootInventory::<32>::plan(36, &map, live, &extra).unwrap();
    let mut policy = inventory.into_policy::<2, 16, 16, 16>().unwrap();
    policy.create_domain(1, 16).unwrap();
    policy.create_domain(2, 16).unwrap();
    let mut backing = vec![0xa5; 16 * PAGE_SIZE as usize];
    let mut first = Vec::new();
    for expected in &allowed {
        let capability = policy.allocate(1, 1, 0, Rights::ALL, |range| {
            assert_eq!((range.start(), range.pages()), (*expected, 1));
            let offset = (range.start() - BASE) as usize;
            backing[offset..offset + PAGE_SIZE as usize].fill(0);
            Ok(())
        }).unwrap();
        let region = policy.region_info(1, capability).unwrap();
        assert_eq!(region.backing, FrameRange::new(*expected, 1).unwrap());
        let offset = (*expected - BASE) as usize;
        assert!(backing[offset..offset + PAGE_SIZE as usize].iter().all(|byte| *byte == 0));
        backing[offset..offset + PAGE_SIZE as usize].fill(0x5a);
        first.push(capability);
    }
    assert_eq!(policy.frames().available_pages(), 0);
    let before = format!("{policy:?}");
    assert_eq!(policy.allocate(1, 1, 0, Rights::ALL, |_| panic!("excluded pages cannot be scrubbed")), Err(Error::Capacity));
    assert_eq!(format!("{policy:?}"), before);
    for capability in first.iter().rev().copied() {
        policy.release_capability(1, capability).unwrap();
    }
    assert_eq!(policy.frames().available_pages(), allowed.len() as u64);
    let mut reused = Vec::new();
    for _ in &allowed {
        let capability = policy.allocate(2, 1, 0, Rights::ALL, |range| {
            assert_eq!(range.pages(), 1);
            assert!(allowed.contains(&range.start()));
            let offset = (range.start() - BASE) as usize;
            assert!(backing[offset..offset + PAGE_SIZE as usize].iter().all(|byte| *byte == 0x5a));
            backing[offset..offset + PAGE_SIZE as usize].fill(0);
            reused.push(range.start());
            Ok(())
        }).unwrap();
        let range = policy.region_info(2, capability).unwrap().backing;
        let offset = (range.start() - BASE) as usize;
        assert!(backing[offset..offset + PAGE_SIZE as usize].iter().all(|byte| *byte == 0));
    }
    reused.sort_unstable();
    assert_eq!(reused, allowed);
    for old in first {
        assert!(policy.authorize(1, old, Rights::READ, 0, 1).is_err());
        assert!(policy.release_capability(1, old).is_err());
    }
    for page in 0..16 {
        let start = BASE + page as u64 * PAGE_SIZE;
        if !allowed.contains(&start) {
            assert!(backing[page * PAGE_SIZE as usize..(page + 1) * PAGE_SIZE as usize].iter().all(|byte| *byte == 0xa5));
        }
    }
}
