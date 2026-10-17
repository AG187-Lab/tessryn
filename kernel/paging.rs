// Original bounded four-level identity paging. This module has no privileged
// operations or firmware dependencies, so host fixtures can exercise its math.
pub const LOW_LIMIT: u64 = 1 << 32;
pub const CANONICAL_LIMIT: u64 = 1 << 47;
pub const HUGE_PAGE: u64 = 1 << 21;
// Reserve the entire last 2 MiB of the lower canonical half. The fault address
// remains canonical even on CPUs whose physical address width is less than 47.
pub const GUARD: u64 = CANONICAL_LIMIT - HUGE_PAGE;
pub const TABLE_CAPACITY: usize = 128;
pub const LEAF_CAPACITY: usize = 16_384;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
// One fixed supervisor MMIO leaf, used only by the admitted HPET profile.
// PAT index 3 (PWT=PCD=1, PAT=0) must be admitted as UC by the CPU owner.
pub const HPET_LEAF: u64 = 0xfec0_0000;
pub const HPET_UC_FLAGS: u64 = 0x83 | (1 << 3) | (1 << 4) | (1 << 63);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Empty, Overflow, PhysicalWidth, NonCanonical, Guard, Alignment, TableBudget, LeafBudget, TableLink }
impl Error {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Empty => "empty-range", Self::Overflow => "range-overflow",
            Self::PhysicalWidth => "physical-address-width", Self::NonCanonical => "noncanonical-range",
            Self::Guard => "guard-overlap", Self::Alignment => "table-alignment",
            Self::TableBudget => "table-budget", Self::LeafBudget => "leaf-budget",
            Self::TableLink => "table-link",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Range { pub start: u64, pub end: u64 }
impl Range {
    pub fn checked(start: u64, length: u64) -> Result<Self, Error> {
        if length == 0 { return Err(Error::Empty); }
        let end = start.checked_add(length).ok_or(Error::Overflow)?;
        Ok(Self { start, end })
    }
    pub fn overlaps(self, other: Self) -> bool { self.start < other.end && other.start < self.end }
}

pub fn validate_range(range: Range, physical_bits: u8) -> Result<(), Error> {
    if range.start >= range.end { return Err(Error::Empty); }
    if !(32..=52).contains(&physical_bits) || range.end > (1u64 << physical_bits) {
        return Err(Error::PhysicalWidth);
    }
    if range.end > CANONICAL_LIMIT { return Err(Error::NonCanonical); }
    if range.overlaps(Range { start: GUARD, end: CANONICAL_LIMIT }) { return Err(Error::Guard); }
    Ok(())
}

pub fn mapping_bounds(range: Range, physical_bits: u8) -> Result<Range, Error> {
    validate_range(range, physical_bits)?;
    let end = range.end.checked_add(HUGE_PAGE - 1).ok_or(Error::Overflow)? & !(HUGE_PAGE - 1);
    let rounded = Range { start: range.start & !(HUGE_PAGE - 1), end };
    validate_range(rounded, physical_bits)?;
    Ok(rounded)
}

#[repr(C, align(4096))]
pub struct Table(pub [u64; 512]);

#[repr(C, align(4096))]
pub struct Tables {
    pages: [Table; TABLE_CAPACITY],
    base: u64,
    used: usize,
    leaves: usize,
    physical_bits: u8,
}

impl Tables {
    pub const fn empty() -> Self {
        Self { pages: [const { Table([0; 512]) }; TABLE_CAPACITY], base: 0, used: 0, leaves: 0, physical_bits: 0 }
    }
    // Native callers supply the identity address of this pool. Host fixtures
    // can supply a synthetic physical base; no encoded pointer is dereferenced.
    pub fn reset(&mut self, physical_bits: u8, physical_base: u64) -> Result<(), Error> {
        if physical_base % 4096 != 0 { return Err(Error::Alignment); }
        validate_range(Range::checked(physical_base, TABLE_CAPACITY as u64 * 4096)?, physical_bits)?;
        for table in &mut self.pages { table.0.fill(0); }
        self.base = physical_base;
        self.used = 1;
        self.leaves = 0;
        self.physical_bits = physical_bits;
        Ok(())
    }
    pub fn root(&self) -> u64 { self.base }
    pub fn table_count(&self) -> usize { self.used }
    pub fn leaf_count(&self) -> usize { self.leaves }

    fn link_index(&self, value: u64) -> Result<usize, Error> {
        if value & 1 == 0 || value & 0x80 != 0 { return Err(Error::TableLink); }
        let address = value & ADDRESS_MASK;
        let offset = address.checked_sub(self.base).ok_or(Error::TableLink)?;
        let index = (offset / 4096) as usize;
        if offset % 4096 != 0 || index >= self.used { return Err(Error::TableLink); }
        Ok(index)
    }
    fn child(&mut self, table: usize, slot: usize) -> Result<usize, Error> {
        let value = self.pages[table].0[slot];
        if value != 0 { return self.link_index(value); }
        if self.used == TABLE_CAPACITY { return Err(Error::TableBudget); }
        let index = self.used;
        self.used += 1;
        self.pages[table].0[slot] = (self.base + index as u64 * 4096) | 3;
        Ok(index)
    }
    pub fn map_range(&mut self, range: Range) -> Result<(), Error> {
        if self.used == 0 { return Err(Error::TableLink); }
        let bounds = mapping_bounds(range, self.physical_bits)?;
        // Also bound iterations for a huge or hostile range before walking it.
        if (bounds.end - bounds.start) / HUGE_PAGE > LEAF_CAPACITY as u64 { return Err(Error::LeafBudget); }
        let mut address = bounds.start;
        while address < bounds.end {
            let pdpt = self.child(0, ((address >> 39) & 511) as usize)?;
            let directory = self.child(pdpt, ((address >> 30) & 511) as usize)?;
            let slot = ((address >> 21) & 511) as usize;
            let previous = self.pages[directory].0[slot];
            let leaf = address | 0x83; // present, writable, supervisor, 2 MiB
            if previous == 0 {
                if self.leaves == LEAF_CAPACITY { return Err(Error::LeafBudget); }
                self.pages[directory].0[slot] = leaf;
                self.leaves += 1;
            } else if previous != leaf { return Err(Error::TableLink); }
            address += HUGE_PAGE;
        }
        Ok(())
    }
    pub fn translation(&self, address: u64) -> Option<u64> {
        if self.used == 0 || address >= CANONICAL_LIMIT { return None; }
        let pdpt = self.link_index(self.pages[0].0[((address >> 39) & 511) as usize]).ok()?;
        let directory = self.link_index(self.pages[pdpt].0[((address >> 30) & 511) as usize]).ok()?;
        let leaf = self.pages[directory].0[((address >> 21) & 511) as usize];
        if leaf & 0x81 != 0x81 { return None; }
        Some((leaf & ADDRESS_MASK & !(HUGE_PAGE - 1)) | (address & (HUGE_PAGE - 1)))
    }

    /// Change only the already mapped HPET-containing supervisor leaf. The
    /// CPU owner enables NXE, admits PAT[3]=UC and reloads CR3 before access.
    /// There is no allocation, new alias or user permission in this operation.
    pub fn set_hpet_uncached(&mut self) -> Result<(), Error> {
        let (directory, slot) = self.hpet_slot()?;
        let leaf = self.pages[directory].0[slot];
        let observed = leaf & !((1 << 5) | (1 << 6));
        if observed != HPET_LEAF | 0x83 && observed != HPET_LEAF | HPET_UC_FLAGS {
            return Err(Error::TableLink);
        }
        self.pages[directory].0[slot] = HPET_LEAF | HPET_UC_FLAGS | (leaf & ((1 << 5) | (1 << 6)));
        Ok(())
    }
    fn hpet_slot(&self) -> Result<(usize, usize), Error> {
        if self.used == 0 { return Err(Error::TableLink); }
        let pdpt = self.link_index(self.pages[0].0[((HPET_LEAF >> 39) & 511) as usize])?;
        let directory = self.link_index(self.pages[pdpt].0[((HPET_LEAF >> 30) & 511) as usize])?;
        Ok((directory, ((HPET_LEAF >> 21) & 511) as usize))
    }
    pub fn hpet_uncached(&self) -> Result<bool, Error> {
        let (directory, slot) = self.hpet_slot()?;
        Ok(self.pages[directory].0[slot] & !((1 << 5) | (1 << 6)) == HPET_LEAF | HPET_UC_FLAGS)
    }
}
