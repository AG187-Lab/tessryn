//! Original single-CPU K02 page-table policy. No encoded physical pointer is
//! dereferenced here. The native owner supplies this static image pool's actual
//! identity address, the complete K01 supervisor range set, and backing pages
//! admitted by its memory/capability adapter. It retains every mapping lease
//! until removal AND a real translation invalidation have completed.
//!
//! IA32_EFER.NXE must be admitted/enabled before installing a root. Changes are
//! serialized while no user instruction executes; the CPU owner switches CR3
//! or invalidates translations before resuming user code. This module neither
//! changes CR3 nor acknowledges quiescence. Intel SDM Vol. 3A, 4.5/4.6 defines
//! the four-level U/S, R/W and XD conjunctions used below.

use crate::paging::{mapping_bounds, Range, CANONICAL_LIMIT, GUARD, HUGE_PAGE, LEAF_CAPACITY, LOW_LIMIT};

pub const PAGE_BYTES: u64 = 4096;
pub const USER_BASE: u64 = LOW_LIMIT;
pub const USER_LEAF_CAPACITY: usize = 64;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const LINK_FLAGS: u64 = PRESENT | WRITE | USER | ACCESSED;
const LEAF_FLAGS: u64 = PRESENT | WRITE | USER | ACCESSED | DIRTY | NX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Uninitialized, Alignment, PhysicalWidth, NonCanonical, Guard, Overflow,
    TableBudget, LeafBudget, Collision, SupervisorSealed, SupervisorInvalid,
    UserAddress, PoolMapping, ProtectedBacking, NotMapped, Corrupt, WriteExecuteAlias,
}
impl Error {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Uninitialized => "uninitialized", Self::Alignment => "alignment",
            Self::PhysicalWidth => "physical-width", Self::NonCanonical => "noncanonical",
            Self::Guard => "guard", Self::Overflow => "overflow", Self::TableBudget => "table-budget",
            Self::LeafBudget => "leaf-budget", Self::Collision => "mapping-collision",
            Self::SupervisorSealed => "supervisor-sealed", Self::SupervisorInvalid => "supervisor-invalid",
            Self::UserAddress => "user-address", Self::PoolMapping => "pool-not-mapped",
            Self::ProtectedBacking => "protected-backing", Self::NotMapped => "not-mapped",
            Self::Corrupt => "corrupt-table", Self::WriteExecuteAlias => "write-execute-alias",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserAccess { ReadOnly, ReadWrite }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    pub physical: u64,
    pub page_bytes: u64,
    pub user: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemovedPage {
    pub virtual_page: u64,
    pub physical_page: u64,
}

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
struct Table([u64; 512]);
const EMPTY_TABLE: Table = Table([0; 512]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mapping { virtual_page: u64, physical_page: u64, writable: bool, executable: bool }

/// Every domain owns its entire table tree. Include the WHOLE object, including
/// bookkeeping/padding, in the image reservation; only the first N pages are
/// hardware paging structures. Tables are never recycled after unmapping.
#[repr(C, align(4096))]
pub struct Tables<const N: usize = 32> {
    pages: [Table; N],
    base: u64,
    used: usize,
    supervisor_leaves: usize,
    user_leaves: usize,
    bits: u8,
    sealed: bool,
    mappings: [Option<Mapping>; USER_LEAF_CAPACITY],
}

impl<const N: usize> Tables<N> {
    pub const fn empty() -> Self {
        Self { pages: [EMPTY_TABLE; N], base: 0, used: 0, supervisor_leaves: 0,
            user_leaves: 0, bits: 0, sealed: false, mappings: [None; USER_LEAF_CAPACITY] }
    }
    pub fn object_bytes() -> u64 { core::mem::size_of::<Self>() as u64 }
    pub fn root(&self) -> u64 { self.base }
    pub fn table_count(&self) -> usize { self.used }
    pub fn user_leaf_count(&self) -> usize { self.user_leaves }
    pub fn supervisor_leaf_count(&self) -> usize { self.supervisor_leaves }
    /// A supervisor-only target for the CPL3 page-table isolation probe.
    pub fn protected_page_physical(&self) -> Result<u64, Error> {
        if self.used == 0 { return Err(Error::Uninitialized); }
        Ok(self.base)
    }
    pub fn object_range(&self) -> Result<Range, Error> {
        if self.used == 0 { return Err(Error::Uninitialized); }
        Ok(Range { start: self.base, end: self.base + Self::object_bytes() })
    }
    pub fn reset(&mut self, physical_bits: u8, physical_base: u64) -> Result<(), Error> {
        if N == 0 { return Err(Error::TableBudget); }
        if physical_base % PAGE_BYTES != 0 { return Err(Error::Alignment); }
        let end = physical_base.checked_add(Self::object_bytes()).ok_or(Error::Overflow)?;
        if !(32..=52).contains(&physical_bits) || end > 1u64 << physical_bits {
            return Err(Error::PhysicalWidth);
        }
        if end > CANONICAL_LIMIT { return Err(Error::NonCanonical); }
        if end > GUARD { return Err(Error::Guard); }
        for page in &mut self.pages { page.0.fill(0); }
        self.base = physical_base;
        self.bits = physical_bits;
        self.used = 1;
        self.supervisor_leaves = 0;
        self.user_leaves = 0;
        self.sealed = false;
        self.mappings.fill(None);
        Ok(())
    }

    fn link(&self, entry: u64) -> Result<usize, Error> {
        if entry & PRESENT == 0 || entry & !(ADDRESS_MASK | LINK_FLAGS) != 0 {
            return Err(Error::Corrupt);
        }
        let offset = (entry & ADDRESS_MASK).checked_sub(self.base).ok_or(Error::Corrupt)?;
        let index = (offset / PAGE_BYTES) as usize;
        if offset % PAGE_BYTES != 0 || index >= self.used || index == 0 { return Err(Error::Corrupt); }
        Ok(index)
    }
    fn child(&mut self, table: usize, slot: usize) -> usize {
        let entry = self.pages[table].0[slot];
        if entry != 0 { return self.link(entry).expect("preflight checked supervisor link"); }
        let child = self.used;
        self.used += 1;
        self.pages[table].0[slot] = (self.base + child as u64 * PAGE_BYTES) | PRESENT | WRITE;
        child
    }
    /// Reproduce K01's identity supervisor mapping before the first user map.
    /// Root supplies the low4GiB and every admitted image/stack/map/scratch/GOP/
    /// runtime range. Preflight counts all new tables/leaves before writing.
    pub fn map_supervisor_range(&mut self, range: Range) -> Result<(), Error> {
        if self.used == 0 { return Err(Error::Uninitialized); }
        if self.sealed { return Err(Error::SupervisorSealed); }
        self.validate()?;
        let bounds = mapping_bounds(range, self.bits).map_err(|error| match error {
            crate::paging::Error::PhysicalWidth => Error::PhysicalWidth,
            crate::paging::Error::NonCanonical => Error::NonCanonical,
            crate::paging::Error::Guard => Error::Guard,
            crate::paging::Error::Overflow => Error::Overflow,
            _ => Error::SupervisorInvalid,
        })?;
        let count = (bounds.end - bounds.start) / HUGE_PAGE;
        if count > LEAF_CAPACITY as u64 { return Err(Error::LeafBudget); }
        let mut needed = 0;
        let mut leaves = 0;
        let mut previous_top = None;
        let mut previous_directory = None;
        for page in 0..count {
            let address = bounds.start + page * HUGE_PAGE;
            let top_key = address >> 39;
            let directory_key = address >> 30;
            let top = self.pages[0].0[top_key as usize];
            let directory = if top == 0 {
                if previous_top != Some(top_key) { needed += 1; }
                None
            } else {
                let pdpt = self.link(top)?;
                let link = self.pages[pdpt].0[((address >> 30) & 511) as usize];
                if link == 0 { None } else { Some(self.link(link)?) }
            };
            if let Some(directory) = directory {
                let leaf = self.pages[directory].0[((address >> 21) & 511) as usize];
                if leaf == 0 { leaves += 1; }
                else if leaf & !(ACCESSED | DIRTY) != address | PRESENT | WRITE | HUGE {
                    return Err(Error::Collision);
                }
            } else {
                if previous_directory != Some(directory_key) { needed += 1; }
                leaves += 1;
            }
            previous_top = Some(top_key);
            previous_directory = Some(directory_key);
        }
        if needed > N - self.used { return Err(Error::TableBudget); }
        if leaves > LEAF_CAPACITY - self.supervisor_leaves { return Err(Error::LeafBudget); }
        for page in 0..count {
            let address = bounds.start + page * HUGE_PAGE;
            let pdpt = self.child(0, (address >> 39) as usize);
            let directory = self.child(pdpt, ((address >> 30) & 511) as usize);
            let leaf = &mut self.pages[directory].0[((address >> 21) & 511) as usize];
            if *leaf == 0 { *leaf = address | PRESENT | WRITE | HUGE; }
        }
        self.supervisor_leaves += leaves;
        Ok(())
    }

    fn user_address(address: u64) -> Result<(), Error> {
        if address % PAGE_BYTES != 0 { return Err(Error::Alignment); }
        if address < USER_BASE { return Err(Error::UserAddress); }
        if address >= CANONICAL_LIMIT { return Err(Error::NonCanonical); }
        if address >= GUARD { return Err(Error::Guard); }
        Ok(())
    }
    fn backing(&self, physical: u64) -> Result<(), Error> {
        if physical % PAGE_BYTES != 0 { return Err(Error::Alignment); }
        let end = physical.checked_add(PAGE_BYTES).ok_or(Error::Overflow)?;
        if end > 1u64 << self.bits { return Err(Error::PhysicalWidth); }
        if physical < self.base + Self::object_bytes() && self.base < end {
            return Err(Error::ProtectedBacking);
        }
        Ok(())
    }
    pub fn map_data(&mut self, virtual_page: u64, physical_page: u64, access: UserAccess) -> Result<(), Error> {
        self.map_user(Mapping { virtual_page, physical_page, writable: access == UserAccess::ReadWrite, executable: false })
    }
    /// Trusted executable probe image only. This grants no EXEC right to a data
    /// capability. The kernel supplies separately owned, immutable code backing.
    pub fn map_trusted_code(&mut self, virtual_page: u64, physical_page: u64) -> Result<(), Error> {
        self.map_user(Mapping { virtual_page, physical_page, writable: false, executable: true })
    }
    fn map_user(&mut self, mapping: Mapping) -> Result<(), Error> {
        if self.used == 0 { return Err(Error::Uninitialized); }
        Self::user_address(mapping.virtual_page)?;
        self.backing(mapping.physical_page)?;
        if !self.sealed { self.validate_supervisor()?; } else { self.validate()?; }
        if self.mappings.iter().flatten().any(|old| old.virtual_page == mapping.virtual_page) { return Err(Error::Collision); }
        if self.mappings.iter().flatten().any(|old| old.physical_page == mapping.physical_page
            && ((old.executable && mapping.writable) || (mapping.executable && old.writable))) {
            return Err(Error::WriteExecuteAlias);
        }
        let record = self.mappings.iter().position(Option::is_none).ok_or(Error::LeafBudget)?;
        let address = mapping.virtual_page;
        let slots = [((address >> 39) & 511) as usize, ((address >> 30) & 511) as usize,
                     ((address >> 21) & 511) as usize];
        let mut parents = [0; 3];
        let mut children = [0; 3];
        let mut next = self.used;
        let mut table = 0;
        for level in 0..3 {
            parents[level] = table;
            let entry = if table < self.used { self.pages[table].0[slots[level]] } else { 0 };
            table = if entry == 0 {
                if next == N { return Err(Error::TableBudget); }
                let child = next;
                next += 1;
                child
            } else {
                if entry & HUGE != 0 { return Err(Error::Collision); }
                self.link(entry)?
            };
            children[level] = table;
        }
        let slot = ((address >> 12) & 511) as usize;
        if table < self.used && self.pages[table].0[slot] != 0 { return Err(Error::Collision); }
        // No mutation above this point: every rejection leaves the entire pool,
        // ancestor permissions, ownership bookkeeping and CR3 unchanged.
        for page in self.used..next { self.pages[page].0.fill(0); }
        self.used = next;
        for level in 0..3 {
            let old = self.pages[parents[level]].0[slots[level]];
            self.pages[parents[level]].0[slots[level]] = (self.base + children[level] as u64 * PAGE_BYTES)
                | PRESENT | WRITE | USER | (old & ACCESSED);
        }
        let flags = PRESENT | USER | if mapping.writable { WRITE } else { 0 }
            | if mapping.executable { 0 } else { NX };
        self.pages[table].0[slot] = mapping.physical_page | flags;
        self.mappings[record] = Some(mapping);
        self.user_leaves += 1;
        self.sealed = true;
        Ok(())
    }

    pub fn translate(&self, address: u64) -> Result<Translation, Error> {
        if self.used == 0 { return Err(Error::Uninitialized); }
        if address >= CANONICAL_LIMIT { return Err(Error::NonCanonical); }
        let slots = [((address >> 39) & 511) as usize, ((address >> 30) & 511) as usize,
                     ((address >> 21) & 511) as usize, ((address >> 12) & 511) as usize];
        let mut table = 0;
        let (mut user, mut writable, mut executable) = (true, true, true);
        for (level, slot) in slots.iter().copied().enumerate() {
            let entry = self.pages[table].0[slot];
            if entry == 0 { return Err(Error::NotMapped); }
            if entry & PRESENT == 0 { return Err(Error::Corrupt); }
            user &= entry & USER != 0;
            writable &= entry & WRITE != 0;
            executable &= entry & NX == 0;
            if level == 2 && entry & HUGE != 0 {
                if entry & !(ADDRESS_MASK | PRESENT | WRITE | HUGE | ACCESSED | DIRTY) != 0
                    || entry & (HUGE_PAGE - 1) & ADDRESS_MASK != 0 { return Err(Error::Corrupt); }
                return Ok(Translation { physical: (entry & ADDRESS_MASK) | (address & (HUGE_PAGE - 1)),
                    page_bytes: HUGE_PAGE, user, writable, executable });
            }
            if level == 3 {
                if entry & PRESENT == 0 || entry & !(ADDRESS_MASK | LEAF_FLAGS) != 0 { return Err(Error::Corrupt); }
                return Ok(Translation { physical: (entry & ADDRESS_MASK) | (address & (PAGE_BYTES - 1)),
                    page_bytes: PAGE_BYTES, user, writable, executable });
            }
            table = self.link(entry)?;
        }
        Err(Error::Corrupt)
    }
    pub fn translation(&self, address: u64) -> Option<u64> { self.translate(address).ok().map(|entry| entry.physical) }
    pub fn user_translation(&self, address: u64) -> Option<Translation> {
        self.translate(address).ok().filter(|entry| entry.user)
    }
    pub fn unmap_user(&mut self, virtual_page: u64) -> Result<RemovedPage, Error> {
        if self.used == 0 { return Err(Error::Uninitialized); }
        Self::user_address(virtual_page)?;
        let record = self.mappings.iter().position(|entry| entry.is_some_and(|entry| entry.virtual_page == virtual_page))
            .ok_or(Error::NotMapped)?;
        let mapping = self.mappings[record].expect("record exists");
        let observed = self.translate(virtual_page)?;
        if observed != (Translation { physical: mapping.physical_page, page_bytes: PAGE_BYTES, user: true,
            writable: mapping.writable, executable: mapping.executable }) { return Err(Error::Corrupt); }
        let pdpt = self.link(self.pages[0].0[((virtual_page >> 39) & 511) as usize])?;
        let directory = self.link(self.pages[pdpt].0[((virtual_page >> 30) & 511) as usize])?;
        let table = self.link(self.pages[directory].0[((virtual_page >> 21) & 511) as usize])?;
        self.pages[table].0[((virtual_page >> 12) & 511) as usize] = 0;
        self.mappings[record] = None;
        self.user_leaves -= 1;
        // Empty paging structures remain allocated and linked. CPU owner must
        // fence stale translations before releasing the external memory lease.
        Ok(RemovedPage { virtual_page, physical_page: mapping.physical_page })
    }

    fn validate_supervisor(&self) -> Result<(), Error> {
        self.validate()?;
        for page in 0..LOW_LIMIT / HUGE_PAGE {
            let address = page * HUGE_PAGE;
            let entry = self.translate(address).map_err(|_| Error::SupervisorInvalid)?;
            if entry.physical != address || entry.page_bytes != HUGE_PAGE || entry.user {
                return Err(Error::SupervisorInvalid);
            }
        }
        // Covers all hardware tables AND software metadata, including high
        // image pools. Identity aliases must stay supervisor-only.
        for offset in (0..Self::object_bytes()).step_by(PAGE_BYTES as usize) {
            let address = self.base + offset;
            let entry = self.translate(address).map_err(|_| Error::PoolMapping)?;
            if entry.physical != address || entry.user { return Err(Error::PoolMapping); }
        }
        Ok(())
    }
    /// Validate every reachable table, permission, record and identity leaf.
    /// Host fixtures intentionally corrupt entries to exercise this boundary.
    pub fn validate(&self) -> Result<(), Error> {
        if self.used == 0 { return Err(Error::Uninitialized); }
        if self.used > N { return Err(Error::Corrupt); }
        let mut roles = [0u8; N];
        let mut prefixes = [0u64; N];
        roles[0] = 4;
        let mut supervisors = 0;
        let mut users = 0;
        for table in 0..self.used {
            let role = roles[table];
            if role == 0 { return Err(Error::Corrupt); }
            for slot in 0..512 {
                let entry = self.pages[table].0[slot];
                if entry == 0 { continue; }
                let address = prefixes[table] | ((slot as u64) << (12 + 9 * (role - 1)));
                if role == 1 || (role == 2 && entry & HUGE != 0) {
                    if entry & PRESENT == 0 { return Err(Error::Corrupt); }
                    if role == 2 {
                        if entry & !(ACCESSED | DIRTY) != address | PRESENT | WRITE | HUGE
                            || address >= GUARD || address + HUGE_PAGE > 1u64 << self.bits {
                            return Err(Error::Corrupt);
                        }
                        supervisors += 1;
                    } else {
                        if entry & USER == 0 || entry & !(ADDRESS_MASK | LEAF_FLAGS) != 0 { return Err(Error::Corrupt); }
                        let mut records = self.mappings.iter().flatten().filter(|mapping| mapping.virtual_page == address);
                        let mapping = records.next().ok_or(Error::Corrupt)?;
                        let expected = mapping.physical_page | PRESENT | USER
                            | if mapping.writable { WRITE } else { 0 }
                            | if mapping.executable { 0 } else { NX };
                        if records.next().is_some() || entry & !(ACCESSED | DIRTY) != expected
                            || (mapping.writable && mapping.executable) { return Err(Error::Corrupt); }
                        users += 1;
                    }
                    continue;
                }
                if role == 4 && slot >= 256 { return Err(Error::Corrupt); }
                let child = self.link(entry)?;
                if child <= table || roles[child] != 0 { return Err(Error::Corrupt); }
                roles[child] = role - 1;
                prefixes[child] = address;
            }
        }
        if supervisors != self.supervisor_leaves || users != self.user_leaves
            || users != self.mappings.iter().flatten().count() { return Err(Error::Corrupt); }
        for mapping in self.mappings.iter().flatten() {
            Self::user_address(mapping.virtual_page)?;
            self.backing(mapping.physical_page)?;
            if self.translate(mapping.virtual_page)? != (Translation { physical: mapping.physical_page,
                page_bytes: PAGE_BYTES, user: true, writable: mapping.writable, executable: mapping.executable }) {
                return Err(Error::Corrupt);
            }
        }
        if self.translation(GUARD).is_some() { return Err(Error::Guard); }
        Ok(())
    }
}

#[cfg(test)]
#[path = "k02_paging_tests.rs"]
mod tests;
