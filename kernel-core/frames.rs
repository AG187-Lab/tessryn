//! Checked physical extent bookkeeping. No address is dereferenced here.

use crate::{Error, PAGE_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameRange {
    start: u64,
    pages: u64,
}

impl FrameRange {
    pub fn new(start: u64, pages: u64) -> Result<Self, Error> {
        if pages == 0 {
            return Err(Error::Empty);
        }
        if start % PAGE_SIZE != 0 {
            return Err(Error::Alignment);
        }
        let bytes = pages.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)?;
        start.checked_add(bytes).ok_or(Error::Overflow)?;
        Ok(Self { start, pages })
    }

    pub const fn start(self) -> u64 {
        self.start
    }
    pub const fn pages(self) -> u64 {
        self.pages
    }
    pub const fn end(self) -> u64 {
        self.start + self.pages * PAGE_SIZE
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

/// At most F total free and allocated extents are admitted. A split consumes
/// an additional metadata slot before allocation. Releasing an allocated extent
/// therefore always has room to retain its entire range, in any release order.
/// Excluded ranges occupy a separate bounded table and are never admitted.
#[derive(Debug, PartialEq, Eq)]
pub struct FramePool<const F: usize> {
    physical_bits: u8,
    free: [Option<FrameRange>; F],
    allocated: [Option<FrameRange>; F],
    excluded: [Option<FrameRange>; F],
}

#[derive(Clone, Copy)]
pub(crate) struct AllocationPlan {
    free_slot: usize,
    allocated_slot: usize,
    pub(crate) range: FrameRange,
    remainder: Option<FrameRange>,
}

impl<const F: usize> FramePool<F> {
    pub fn new(physical_bits: u8, exclusions: &[FrameRange]) -> Result<Self, Error> {
        if !(32..=52).contains(&physical_bits) {
            return Err(Error::PhysicalWidth);
        }
        if exclusions.len() > F {
            return Err(Error::Capacity);
        }
        let mut pool = Self {
            physical_bits,
            free: [None; F],
            allocated: [None; F],
            excluded: [None; F],
        };
        for (index, range) in exclusions.iter().copied().enumerate() {
            pool.check_width(range)?;
            pool.excluded[index] = Some(range);
        }
        Ok(pool)
    }

    fn check_width(&self, range: FrameRange) -> Result<(), Error> {
        if range.end() > (1u64 << self.physical_bits) {
            return Err(Error::PhysicalWidth);
        }
        Ok(())
    }

    fn metadata_count(&self) -> usize {
        self.free.iter().filter(|entry| entry.is_some()).count()
            + self
                .allocated
                .iter()
                .filter(|entry| entry.is_some())
                .count()
    }

    pub fn available_pages(&self) -> u64 {
        self.free.iter().flatten().map(|range| range.pages).sum()
    }

    pub fn allocated_pages(&self) -> u64 {
        self.allocated
            .iter()
            .flatten()
            .map(|range| range.pages)
            .sum()
    }

    /// Bootstrap admits complete ranges only. Split a firmware range around
    /// exclusions before passing it here; this method never rounds or truncates.
    pub fn add_free_extent(&mut self, range: FrameRange) -> Result<(), Error> {
        self.check_width(range)?;
        if self
            .excluded
            .iter()
            .flatten()
            .any(|other| range.overlaps(*other))
        {
            return Err(Error::Excluded);
        }
        if self
            .free
            .iter()
            .chain(self.allocated.iter())
            .flatten()
            .any(|other| range.overlaps(*other))
        {
            return Err(Error::Overlap);
        }
        let adjacent = self.adjacent_slot(range);
        let slot = if let Some(slot) = adjacent {
            slot
        } else {
            if self.metadata_count() == F {
                return Err(Error::Capacity);
            }
            self.free
                .iter()
                .position(Option::is_none)
                .ok_or(Error::Capacity)?
        };
        self.insert_free(range, slot);
        Ok(())
    }

    fn adjacent_slot(&self, range: FrameRange) -> Option<usize> {
        self.free.iter().position(|entry| {
            entry.is_some_and(|other| other.end() == range.start || range.end() == other.start)
        })
    }

    fn insert_free(&mut self, range: FrameRange, destination: usize) {
        let mut start = range.start;
        let mut end = range.end();
        // Free extents are already coalesced. There can be at most one neighbor
        // on either side; iterate again to handle their order in the array.
        loop {
            let mut merged = false;
            for entry in &mut self.free {
                if let Some(other) = *entry {
                    if other.end() == start || end == other.start {
                        start = core::cmp::min(start, other.start);
                        end = core::cmp::max(end, other.end());
                        *entry = None;
                        merged = true;
                    }
                }
            }
            if !merged {
                break;
            }
        }
        self.free[destination] = Some(FrameRange {
            start,
            pages: (end - start) / PAGE_SIZE,
        });
    }

    pub(crate) fn plan_allocate(&self, pages: u64) -> Result<AllocationPlan, Error> {
        if pages == 0 {
            return Err(Error::Empty);
        }
        let bytes = pages.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)?;
        let allocated_slot = self
            .allocated
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        for (free_slot, entry) in self.free.iter().enumerate() {
            let Some(available) = *entry else {
                continue;
            };
            if available.pages < pages {
                continue;
            }
            let remainder = if available.pages == pages {
                None
            } else {
                if self.metadata_count() == F {
                    continue;
                }
                Some(FrameRange {
                    start: available.start + bytes,
                    pages: available.pages - pages,
                })
            };
            return Ok(AllocationPlan {
                free_slot,
                allocated_slot,
                range: FrameRange {
                    start: available.start,
                    pages,
                },
                remainder,
            });
        }
        Err(Error::Capacity)
    }

    pub(crate) fn commit_allocate(&mut self, plan: AllocationPlan) -> FrameRange {
        self.free[plan.free_slot] = plan.remainder;
        self.allocated[plan.allocated_slot] = Some(plan.range);
        plan.range
    }

    #[cfg(test)]
    pub(crate) fn allocate(&mut self, pages: u64) -> Result<FrameRange, Error> {
        let plan = self.plan_allocate(pages)?;
        Ok(self.commit_allocate(plan))
    }

    // Numerical extents are allocator records, not generational authority.
    // Only MemoryPolicy may release them after every capability and owner has
    // drained; exposing this method would permit a stale extent to free reuse.
    pub(crate) fn release(&mut self, range: FrameRange) -> Result<(), Error> {
        let allocated_slot = self
            .allocated
            .iter()
            .position(|entry| *entry == Some(range))
            .ok_or(Error::InvalidAuthority)?;
        let destination = self
            .adjacent_slot(range)
            .or_else(|| self.free.iter().position(Option::is_none))
            .ok_or(Error::Capacity)?;
        // The combined metadata bound guarantees destination exists: one of
        // at most F entries is the allocation being released, not a free extent.
        self.allocated[allocated_slot] = None;
        self.insert_free(range, destination);
        Ok(())
    }
}
