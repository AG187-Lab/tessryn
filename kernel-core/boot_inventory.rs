//! Conservative, allocation-free admission of copied boot-memory facts.
//!
//! This planner accepts numbers, not firmware pointers or proof of firmware
//! exit. The trusted native adapter must copy the final validated handoff after
//! successful firmware exit and CPU ownership. It must discard inventories from
//! failed exit attempts. Planning does not access RAM, release firmware memory,
//! authenticate callers or publish a native allocator.
//!
//! Only non-runtime conventional RAM below 4 GiB is admitted. Live byte ranges
//! are reserved at whole-page granularity; admitted memory is never widened.
//! Inputs may be unsorted. The fixed output tables contain sorted, coalesced
//! ranges, and input traversal is bounded independently of output capacity.

use crate::{Error, FrameRange, MemoryPolicy, PAGE_SIZE};

const CONVENTIONAL_MEMORY: u32 = 7;
const RUNTIME: u64 = 1 << 63;
const LOW_APERTURE_END: u64 = 1 << 32;
const MAX_INPUT_RANGES: usize = 4096;

/// Copied descriptor facts. This is an internal projection, not a firmware ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootDescriptor {
    pub kind: u32,
    pub start: u64,
    pub pages: u64,
    pub attributes: u64,
}

/// A live byte interval which must remain unavailable to the allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootRange {
    pub start: u64,
    pub length: u64,
}

/// Required live handoff storage plus optional retained native allocations.
///
/// `memory_map` covers the entire retained allocation, not only occupied map
/// bytes. `scratch` is exactly one aligned page and is always required, including
/// when K01 selects it from conventional RAM. In the high-handoff profile it may
/// duplicate `high_scratch`; the planner normalizes that duplicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootReservations {
    pub image: BootRange,
    pub stack: BootRange,
    pub memory_map: BootRange,
    pub scratch: BootRange,
    pub framebuffer: Option<BootRange>,
    pub high_scratch: Option<BootRange>,
}

impl BootReservations {
    fn ranges(self, extra: &[BootRange]) -> impl Iterator<Item = BootRange> + '_ {
        [self.image, self.stack, self.memory_map, self.scratch]
            .into_iter()
            .chain(self.framebuffer)
            .chain(self.high_scratch)
            .chain(extra.iter().copied())
    }

    fn validate(self, physical_bits: u8, extra: &[BootRange]) -> Result<(), Error> {
        for range in self.ranges(extra) {
            rounded_exclusion(range, physical_bits)?;
        }
        if self.scratch.start % PAGE_SIZE != 0 {
            return Err(Error::Alignment);
        }
        if self.scratch.length != PAGE_SIZE {
            return Err(Error::Bounds);
        }
        // These are distinct live allocations in the K01 handoff. Reject even
        // byte-disjoint allocations sharing a page, rather than hiding a bad
        // ownership claim by unioning it. Other exclusions may overlap safely.
        let required = [self.image, self.stack, self.memory_map, self.scratch];
        for (index, range) in required.into_iter().enumerate() {
            let range = rounded_exclusion(range, physical_bits)?;
            for previous in &required[..index] {
                if overlaps(range, rounded_exclusion(*previous, physical_bits)?) {
                    return Err(Error::Overlap);
                }
            }
        }
        Ok(())
    }
}

/// Immutable complete plan, retaining both free extents and live exclusions.
///
/// F bounds each normalized output table, rather than the number of raw inputs.
/// A valid inventory may contain no eligible pages; the resulting empty policy
/// cannot allocate backing. Construction failures never expose a partial plan.
#[derive(Debug, PartialEq, Eq)]
pub struct BootInventory<const F: usize> {
    physical_bits: u8,
    free: [FrameRange; F],
    free_count: usize,
    excluded: [FrameRange; F],
    excluded_count: usize,
    available_pages: u64,
}

impl<const F: usize> BootInventory<F> {
    /// Validate every descriptor, normalize live exclusions, and subtract them
    /// from conventional memory inside the current low identity aperture.
    ///
    /// Both descriptors and the total required/optional/extra exclusion inputs
    /// are capped at 4096. Malformed quarantined descriptors also reject the
    /// entire plan. Output capacity is checked only after normalization, so an
    /// input's position cannot cause a transient metadata-capacity rejection.
    pub fn plan(
        physical_bits: u8,
        descriptors: &[BootDescriptor],
        reservations: BootReservations,
        extra_exclusions: &[BootRange],
    ) -> Result<Self, Error> {
        if !(32..=52).contains(&physical_bits) {
            return Err(Error::PhysicalWidth);
        }
        let exclusion_inputs = 4usize
            .checked_add(usize::from(reservations.framebuffer.is_some()))
            .and_then(|n| n.checked_add(usize::from(reservations.high_scratch.is_some())))
            .and_then(|n| n.checked_add(extra_exclusions.len()))
            .ok_or(Error::Capacity)?;
        if descriptors.len() > MAX_INPUT_RANGES || exclusion_inputs > MAX_INPUT_RANGES {
            return Err(Error::Capacity);
        }
        for (index, descriptor) in descriptors.iter().copied().enumerate() {
            let range = descriptor_range(descriptor, physical_bits)?;
            for previous in &descriptors[..index] {
                if overlaps(range, descriptor_range(*previous, physical_bits)?) {
                    return Err(Error::Overlap);
                }
            }
        }
        reservations.validate(physical_bits, extra_exclusions)?;

        // Unused cells are never exposed. A one-page zero-based placeholder is
        // valid at every supported width and avoids heap or unsafe storage.
        let placeholder = FrameRange::new(0, 1)?;
        let mut inventory = Self {
            physical_bits,
            free: [placeholder; F],
            free_count: 0,
            excluded: [placeholder; F],
            excluded_count: 0,
            available_pages: 0,
        };
        inventory.normalize_exclusions(reservations, extra_exclusions)?;

        // Select descriptor ranges in address order directly from the bounded
        // input. No raw-descriptor-sized scratch array is needed on a boot stack.
        let mut previous_end = 0;
        loop {
            let next = descriptors
                .iter()
                .copied()
                .filter_map(eligible_range)
                .filter(|range| range.end() > previous_end)
                .min_by_key(|range| range.start());
            let Some(range) = next else { break };
            inventory.admit_excluding(range)?;
            previous_end = range.end();
        }
        Ok(inventory)
    }

    pub const fn available_pages(&self) -> u64 {
        self.available_pages
    }

    pub fn extents(&self) -> impl Iterator<Item = FrameRange> + '_ {
        self.free[..self.free_count].iter().copied()
    }

    pub fn exclusions(&self) -> impl Iterator<Item = FrameRange> + '_ {
        self.excluded[..self.excluded_count].iter().copied()
    }

    /// Build a complete fresh policy privately before returning ownership.
    /// No existing allocator is changed if construction rejects an input.
    pub fn into_policy<const D: usize, const R: usize, const C: usize, const O: usize>(
        self,
    ) -> Result<MemoryPolicy<D, R, C, O, F>, Error> {
        let mut policy =
            MemoryPolicy::new(self.physical_bits, &self.excluded[..self.excluded_count])?;
        for range in self.extents() {
            policy.add_free_extent(range)?;
        }
        Ok(policy)
    }

    fn normalize_exclusions(
        &mut self,
        reservations: BootReservations,
        extra: &[BootRange],
    ) -> Result<(), Error> {
        let mut previous_end = 0;
        loop {
            let mut next: Option<FrameRange> = None;
            for input in reservations.ranges(extra) {
                let range = rounded_exclusion(input, self.physical_bits)?;
                if range.end() > previous_end
                    && next.is_none_or(|candidate| range.start() < candidate.start())
                {
                    next = Some(range);
                }
            }
            let Some(next) = next else { break };
            let start = next.start();
            let mut end = next.end();
            // Every successful scan adds a previously unreached endpoint. The
            // total number of such scans across all components is input-bounded;
            // selection and closure therefore take O(n^2), including reverse
            // ordered adjacency chains, rather than consuming temporary slots.
            loop {
                let old_end = end;
                for input in reservations.ranges(extra) {
                    let range = rounded_exclusion(input, self.physical_bits)?;
                    if range.start() <= end && range.end() >= start {
                        end = core::cmp::max(end, range.end());
                    }
                }
                if end == old_end {
                    break;
                }
            }
            if self.excluded_count == F {
                return Err(Error::Capacity);
            }
            self.excluded[self.excluded_count] = FrameRange::new(start, (end - start) / PAGE_SIZE)?;
            self.excluded_count += 1;
            previous_end = end;
        }
        Ok(())
    }

    fn admit_excluding(&mut self, range: FrameRange) -> Result<(), Error> {
        let mut cursor = range.start();
        // Read exclusions by index so appending a free extent needs no copied
        // exclusion table and no simultaneous borrow of the whole inventory.
        for index in 0..self.excluded_count {
            let excluded = self.excluded[index];
            if excluded.end() <= cursor {
                continue;
            }
            if excluded.start() >= range.end() {
                break;
            }
            if excluded.start() > cursor {
                self.append_free(cursor, excluded.start())?;
            }
            cursor = core::cmp::min(range.end(), core::cmp::max(cursor, excluded.end()));
            if cursor == range.end() {
                break;
            }
        }
        if cursor < range.end() {
            self.append_free(cursor, range.end())?;
        }
        Ok(())
    }

    fn append_free(&mut self, start: u64, end: u64) -> Result<(), Error> {
        let pages = (end - start) / PAGE_SIZE;
        let range = FrameRange::new(start, pages)?;
        let available_pages = self
            .available_pages
            .checked_add(pages)
            .ok_or(Error::Overflow)?;
        if self.free_count > 0 && self.free[self.free_count - 1].end() == start {
            let previous = self.free[self.free_count - 1];
            self.free[self.free_count - 1] =
                FrameRange::new(previous.start(), (end - previous.start()) / PAGE_SIZE)?;
        } else {
            if self.free_count == F {
                return Err(Error::Capacity);
            }
            self.free[self.free_count] = range;
            self.free_count += 1;
        }
        self.available_pages = available_pages;
        Ok(())
    }
}

fn overlaps(left: FrameRange, right: FrameRange) -> bool {
    left.start() < right.end() && right.start() < left.end()
}

fn descriptor_range(descriptor: BootDescriptor, physical_bits: u8) -> Result<FrameRange, Error> {
    let range = FrameRange::new(descriptor.start, descriptor.pages)?;
    if range.end() > (1u64 << physical_bits) {
        return Err(Error::PhysicalWidth);
    }
    Ok(range)
}

// Called only after every descriptor has passed descriptor_range validation.
fn eligible_range(descriptor: BootDescriptor) -> Option<FrameRange> {
    if descriptor.kind != CONVENTIONAL_MEMORY || descriptor.attributes & RUNTIME != 0 {
        return None;
    }
    let end = core::cmp::min(
        descriptor.start + descriptor.pages * PAGE_SIZE,
        LOW_APERTURE_END,
    );
    if descriptor.start >= end {
        return None;
    }
    FrameRange::new(descriptor.start, (end - descriptor.start) / PAGE_SIZE).ok()
}

fn rounded_exclusion(range: BootRange, physical_bits: u8) -> Result<FrameRange, Error> {
    if range.length == 0 {
        return Err(Error::Empty);
    }
    let end = range
        .start
        .checked_add(range.length)
        .ok_or(Error::Overflow)?;
    let limit = 1u64 << physical_bits;
    if end > limit {
        return Err(Error::PhysicalWidth);
    }
    let start = range.start & !(PAGE_SIZE - 1);
    let end = end.checked_add(PAGE_SIZE - 1).ok_or(Error::Overflow)? & !(PAGE_SIZE - 1);
    if end > limit {
        return Err(Error::PhysicalWidth);
    }
    FrameRange::new(start, (end - start) / PAGE_SIZE)
}
