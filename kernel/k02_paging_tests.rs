use super::*;
use std::vec::Vec;

const BASE: u64 = 0x20_0000;
const BACKING: u64 = 0x100_0000;

fn ready<const N: usize>(base: u64) -> Tables<N> {
    let mut tables = Tables::empty();
    tables.reset(48, base).unwrap();
    tables.map_supervisor_range(Range { start: 0, end: LOW_LIMIT }).unwrap();
    tables
}
fn snapshot<const N: usize>(tables: &Tables<N>) -> (Vec<[u64; 512]>, usize, usize, usize, bool, [Option<Mapping>; USER_LEAF_CAPACITY]) {
    (tables.pages.iter().map(|page| page.0).collect(), tables.used, tables.supervisor_leaves,
     tables.user_leaves, tables.sealed, tables.mappings)
}
fn reject_unchanged<const N: usize>(tables: &mut Tables<N>, va: u64, pa: u64, access: UserAccess, error: Error) {
    let before = snapshot(tables);
    assert_eq!(tables.map_data(va, pa, access), Err(error));
    assert_eq!(snapshot(tables), before);
}

#[test]
fn exact_readonly_and_writable_nx_with_supervisor_ancestors() {
    let mut tables = ready::<16>(BASE);
    tables.map_data(USER_BASE, BACKING, UserAccess::ReadOnly).unwrap();
    tables.map_data(USER_BASE + PAGE_BYTES, BACKING + PAGE_BYTES, UserAccess::ReadWrite).unwrap();
    for (offset, writable) in [(0, false), (PAGE_BYTES, true)] {
        let entry = tables.user_translation(USER_BASE + offset + PAGE_BYTES - 1).unwrap();
        assert_eq!(entry, Translation { physical: BACKING + offset + PAGE_BYTES - 1,
            page_bytes: PAGE_BYTES, user: true, writable, executable: false });
    }
    assert_eq!(tables.user_translation(USER_BASE - 1), None);
    assert_eq!(tables.user_translation(USER_BASE + 2 * PAGE_BYTES), None);
    assert_eq!(tables.user_translation(BASE), None);
    assert!(!tables.translate(LOW_LIMIT - 1).unwrap().user);
    assert_eq!(tables.user_leaf_count(), 2);
    tables.validate().unwrap();
}

#[test]
fn domains_have_distinct_roots_and_foreign_page_is_absent() {
    let mut a = ready::<16>(BASE);
    let mut b = ready::<16>(BASE + 0x20_0000);
    a.map_data(USER_BASE + 0x3000, BACKING, UserAccess::ReadWrite).unwrap();
    b.map_data(USER_BASE + 0x1000, BACKING + PAGE_BYTES, UserAccess::ReadWrite).unwrap();
    assert_ne!(a.root(), b.root());
    assert_eq!(b.translation(USER_BASE + 0x3000), None);
    assert_eq!(a.translation(USER_BASE + 0x1000), None);
    assert!(!a.translate(b.protected_page_physical().unwrap()).unwrap().user);
    assert!(!b.translate(a.protected_page_physical().unwrap()).unwrap().user);
    a.validate().unwrap(); b.validate().unwrap();
}

#[test]
fn trusted_code_is_readonly_executable_and_data_cannot_gain_exec() {
    let mut tables = ready::<16>(BASE);
    tables.map_trusted_code(USER_BASE, BACKING).unwrap();
    assert_eq!(tables.user_translation(USER_BASE).unwrap(), Translation {
        physical: BACKING, page_bytes: PAGE_BYTES, user: true, writable: false, executable: true });
    reject_unchanged(&mut tables, USER_BASE + PAGE_BYTES, BACKING, UserAccess::ReadWrite, Error::WriteExecuteAlias);
    tables.map_data(USER_BASE + PAGE_BYTES, BACKING + PAGE_BYTES, UserAccess::ReadWrite).unwrap();
    let before = snapshot(&tables);
    assert_eq!(tables.map_trusted_code(USER_BASE + 2 * PAGE_BYTES, BACKING + PAGE_BYTES), Err(Error::WriteExecuteAlias));
    assert_eq!(snapshot(&tables), before);
    tables.validate().unwrap();
}

#[test]
fn all_mapping_budget_and_collision_failures_are_atomic() {
    let mut insufficient = ready::<7>(BASE);
    assert_eq!(insufficient.table_count(), 6);
    reject_unchanged(&mut insufficient, USER_BASE, BACKING, UserAccess::ReadWrite, Error::TableBudget);
    assert_eq!(insufficient.translation(USER_BASE), None);
    let mut tables = ready::<16>(BASE);
    tables.map_supervisor_range(Range { start: USER_BASE, end: USER_BASE + HUGE_PAGE }).unwrap();
    reject_unchanged(&mut tables, USER_BASE, BACKING, UserAccess::ReadOnly, Error::Collision);
    tables.map_data(USER_BASE + HUGE_PAGE, BACKING, UserAccess::ReadOnly).unwrap();
    reject_unchanged(&mut tables, USER_BASE + HUGE_PAGE, BACKING + PAGE_BYTES, UserAccess::ReadWrite, Error::Collision);
}

#[test]
fn rejects_alignment_width_guard_and_whole_table_object_aliases() {
    let mut tables = ready::<16>(BASE);
    for (va, pa, error) in [(USER_BASE + 1, BACKING, Error::Alignment),
        (USER_BASE, BACKING + 1, Error::Alignment), (USER_BASE - PAGE_BYTES, BACKING, Error::UserAddress),
        (GUARD, BACKING, Error::Guard), (CANONICAL_LIMIT, BACKING, Error::NonCanonical),
        (USER_BASE, 1 << 48, Error::PhysicalWidth), (USER_BASE, u64::MAX & !4095, Error::Overflow),
        (USER_BASE, BASE, Error::ProtectedBacking),
        (USER_BASE, BASE + Tables::<16>::object_bytes() - PAGE_BYTES, Error::ProtectedBacking)] {
        reject_unchanged(&mut tables, va, pa, UserAccess::ReadOnly, error);
    }
    assert!(Tables::<16>::object_bytes() > 16 * PAGE_BYTES);
    assert_eq!(tables.object_range().unwrap().end, BASE + Tables::<16>::object_bytes());
    assert_eq!(tables.protected_page_physical(), Ok(BASE));
}

#[test]
fn mandatory_low_map_and_high_pool_coverage_before_user_installation() {
    let mut missing = Tables::<16>::empty(); missing.reset(48, BASE).unwrap();
    reject_unchanged(&mut missing, USER_BASE, BACKING, UserAccess::ReadOnly, Error::SupervisorInvalid);
    let high = 0x2_0000_0000;
    let mut tables = ready::<16>(high);
    reject_unchanged(&mut tables, USER_BASE, BACKING, UserAccess::ReadOnly, Error::PoolMapping);
    tables.map_supervisor_range(tables.object_range().unwrap()).unwrap();
    tables.map_data(USER_BASE, BACKING, UserAccess::ReadOnly).unwrap();
    assert!(!tables.translate(high).unwrap().user);
    tables.validate().unwrap();
}

#[test]
fn preserves_sparse_high_supervisor_ranges_and_rejects_late_seeding() {
    let mut tables = ready::<32>(BASE);
    let mut original = crate::paging::Tables::empty(); original.reset(48, 0x40_0000).unwrap();
    original.map_range(Range { start: 0, end: LOW_LIMIT }).unwrap();
    for (start, length) in [(0x8_0000_1000, 0x9000), (0x80_0000_1000, 0x3000), (0x100_0000_1234, 0x410000)] {
        let range = Range::checked(start, length).unwrap();
        tables.map_supervisor_range(range).unwrap(); original.map_range(range).unwrap();
        for address in [start - (start % HUGE_PAGE), start, start + length - 1] {
            assert_eq!(tables.translation(address), original.translation(address));
            assert!(!tables.translate(address).unwrap().user);
        }
    }
    tables.map_data(USER_BASE, BACKING, UserAccess::ReadOnly).unwrap();
    let before = snapshot(&tables);
    assert_eq!(tables.map_supervisor_range(Range { start: 0, end: LOW_LIMIT }), Err(Error::SupervisorSealed));
    assert_eq!(snapshot(&tables), before);
    tables.validate().unwrap();
}

#[test]
fn unmap_removes_only_exact_leaf_and_does_not_recycle_page_tables() {
    let mut tables = ready::<16>(BASE);
    tables.map_data(USER_BASE, BACKING, UserAccess::ReadWrite).unwrap();
    tables.map_data(USER_BASE + PAGE_BYTES, BACKING + PAGE_BYTES, UserAccess::ReadOnly).unwrap();
    let count = tables.table_count();
    assert_eq!(tables.unmap_user(USER_BASE), Ok(RemovedPage { virtual_page: USER_BASE, physical_page: BACKING }));
    assert_eq!(tables.translation(USER_BASE), None);
    assert_eq!(tables.translation(USER_BASE + PAGE_BYTES), Some(BACKING + PAGE_BYTES));
    assert_eq!(tables.table_count(), count);
    assert_eq!(tables.unmap_user(USER_BASE), Err(Error::NotMapped));
    assert_eq!(tables.unmap_user(BASE), Err(Error::UserAddress));
    tables.map_data(USER_BASE, BACKING + 2 * PAGE_BYTES, UserAccess::ReadOnly).unwrap();
    assert_eq!(tables.table_count(), count);
    assert_eq!(tables.translation(USER_BASE), Some(BACKING + 2 * PAGE_BYTES));
    tables.validate().unwrap();
}

#[test]
fn every_parent_and_leaf_user_bit_is_required_and_corruption_is_refused() {
    for level in 0..4 {
        let mut tables = ready::<16>(BASE);
        tables.map_data(USER_BASE, BACKING, UserAccess::ReadOnly).unwrap();
        let slots = [0, 4, 0, 0];
        let mut index = 0;
        for slot in slots.iter().take(level) { index = tables.link(tables.pages[index].0[*slot]).unwrap(); }
        tables.pages[index].0[slots[level]] &= !USER;
        assert_eq!(tables.user_translation(USER_BASE), None);
        assert_eq!(tables.validate(), Err(Error::Corrupt));
    }
    let mut tables = ready::<16>(BASE);
    let directory = tables.link(tables.pages[tables.link(tables.pages[0].0[0]).unwrap()].0[0]).unwrap();
    tables.pages[directory].0[0] |= USER;
    assert_eq!(tables.validate(), Err(Error::Corrupt));
}

#[test]
fn hardware_accessed_dirty_bits_do_not_change_authority() {
    let mut tables = ready::<16>(BASE);
    tables.map_data(USER_BASE, BACKING, UserAccess::ReadWrite).unwrap();
    let slots = [0, 4, 0, 0]; let mut table = 0;
    for (level, slot) in slots.iter().enumerate() {
        tables.pages[table].0[*slot] |= ACCESSED;
        if level == 3 { tables.pages[table].0[*slot] |= DIRTY; }
        else { table = tables.link(tables.pages[table].0[*slot]).unwrap(); }
    }
    tables.validate().unwrap(); tables.unmap_user(USER_BASE).unwrap(); tables.validate().unwrap();
}

#[test]
fn virtual_address_and_physical_width_are_independent() {
    let mut tables = Tables::<16>::empty(); tables.reset(32, BASE).unwrap();
    tables.map_supervisor_range(Range { start: 0, end: LOW_LIMIT }).unwrap();
    tables.map_data(USER_BASE, BACKING, UserAccess::ReadOnly).unwrap();
    assert_eq!(tables.translation(USER_BASE), Some(BACKING));
    reject_unchanged(&mut tables, USER_BASE + PAGE_BYTES, 1 << 32, UserAccess::ReadOnly, Error::PhysicalWidth);
}

#[test]
fn sparse_user_paths_capacity_and_record_limits_fail_without_exposure() {
    let mut tables = ready::<16>(BASE);
    tables.map_data(USER_BASE, BACKING, UserAccess::ReadOnly).unwrap();
    tables.map_data(1 << 39, BACKING + PAGE_BYTES, UserAccess::ReadOnly).unwrap();
    tables.map_data(2 << 39, BACKING + 2 * PAGE_BYTES, UserAccess::ReadOnly).unwrap();
    reject_unchanged(&mut tables, 3 << 39, BACKING + 3 * PAGE_BYTES, UserAccess::ReadOnly, Error::TableBudget);
    assert_eq!(tables.translation(3 << 39), None);
    let mut leaves = ready::<16>(BASE);
    for index in 0..USER_LEAF_CAPACITY {
        leaves.map_data(USER_BASE + index as u64 * PAGE_BYTES, BACKING + index as u64 * PAGE_BYTES, UserAccess::ReadOnly).unwrap();
    }
    reject_unchanged(&mut leaves, USER_BASE + USER_LEAF_CAPACITY as u64 * PAGE_BYTES,
        BACKING + USER_LEAF_CAPACITY as u64 * PAGE_BYTES, UserAccess::ReadOnly, Error::LeafBudget);
    leaves.unmap_user(USER_BASE).unwrap();
    leaves.map_data(USER_BASE + USER_LEAF_CAPACITY as u64 * PAGE_BYTES,
        BACKING + USER_LEAF_CAPACITY as u64 * PAGE_BYTES, UserAccess::ReadOnly).unwrap();
    leaves.validate().unwrap();
}

#[test]
fn supervisor_table_capacity_and_guard_fail_atomically() {
    let mut small = Tables::<5>::empty(); small.reset(48, BASE).unwrap();
    let before = snapshot(&small);
    assert_eq!(small.map_supervisor_range(Range { start: 0, end: LOW_LIMIT }), Err(Error::TableBudget));
    assert_eq!(snapshot(&small), before);
    let mut tables = ready::<16>(BASE); let before = snapshot(&tables);
    assert_eq!(tables.map_supervisor_range(Range { start: GUARD, end: GUARD + PAGE_BYTES }), Err(Error::Guard));
    assert_eq!(snapshot(&tables), before);
}

#[test]
fn rejects_retargeted_supervisor_hidden_user_leaf_and_not_present_huge_leaf() {
    let mut tables = ready::<16>(BASE);
    let pdpt = tables.link(tables.pages[0].0[0]).unwrap();
    let directory = tables.link(tables.pages[pdpt].0[0]).unwrap();
    tables.pages[directory].0[0] ^= HUGE_PAGE;
    assert_eq!(tables.validate(), Err(Error::Corrupt));
    let mut tables = ready::<16>(BASE);
    let pdpt = tables.link(tables.pages[0].0[0]).unwrap();
    let directory = tables.link(tables.pages[pdpt].0[0]).unwrap();
    tables.pages[directory].0[0] &= !PRESENT;
    assert_eq!(tables.translate(0), Err(Error::Corrupt));
    assert_eq!(tables.validate(), Err(Error::Corrupt));
    let mut tables = ready::<16>(BASE);
    tables.map_data(USER_BASE, BACKING, UserAccess::ReadOnly).unwrap();
    tables.map_data(USER_BASE + PAGE_BYTES, BACKING + PAGE_BYTES, UserAccess::ReadOnly).unwrap();
    // Forged duplicate metadata must not disguise a second unowned PTE.
    tables.mappings[1] = tables.mappings[0];
    assert_eq!(tables.validate(), Err(Error::Corrupt));
    let before = snapshot(&tables);
    assert_eq!(tables.map_data(USER_BASE + 2 * PAGE_BYTES, BACKING + 2 * PAGE_BYTES, UserAccess::ReadOnly), Err(Error::Corrupt));
    assert_eq!(snapshot(&tables), before);
}
