// Original native adapter for the existing owned-memory policy. Apache-2.0.
// This is a trusted single-CPU bootstrap API, never a user descriptor dispatcher.
use core::mem::{MaybeUninit, offset_of, size_of};
use core::ptr;

pub use tessryn_owned_memory::{Access, Accounting, CapabilityRef, Error as MemoryError,
    FrameRange, LeaseId, RegionInfo, RegionView, Rights};
use tessryn_owned_memory::{BootDescriptor, BootInventory, BootRange, BootReservations,
    MemoryPolicy, PAGE_SIZE};

const DESCRIPTOR_CAPACITY: usize = 4096;
const EXTENT_CAPACITY: usize = 128;
const LOW_LIMIT: u64 = 1 << 32;
type Policy = MemoryPolicy<4, 32, 32, 32, EXTENT_CAPACITY>;

pub const DOMAIN_A: u64 = 1;
pub const DOMAIN_B: u64 = 2;
pub const DOMAIN_C: u64 = 3;
pub const DOMAIN_D: u64 = 4;
pub const DOMAIN_BUDGET_PAGES: u64 = 16;

const EMPTY_DESCRIPTOR: BootDescriptor = BootDescriptor { kind: 0, start: 0, pages: 0, attributes: 0 };
static mut DESCRIPTORS: [BootDescriptor; DESCRIPTOR_CAPACITY] = [EMPTY_DESCRIPTOR; DESCRIPTOR_CAPACITY];
// Isolate every policy page from unrelated mutable statics. In particular the
// first-page kernel-isolation snapshot cannot share PROBE or neighbor storage.
#[repr(C, align(4096))]
struct ProtectedSlot { memory: MaybeUninit<NativeMemory> }
static mut MEMORY: ProtectedSlot = ProtectedSlot { memory: MaybeUninit::uninit() };
static mut INITIALIZED: bool = false;

/// Numerical page authority retained by a real mapping or operation lease.
/// The token creates no PTE and cannot acknowledge hardware teardown itself.
#[derive(Clone, Copy, Debug)]
pub struct PageLease {
    pub physical: u64,
    pub lease: LeaseId,
    pub writable: bool,
}

/// Exact checked bytes retained by the original policy's operation or mapping
/// lease. This is a private kernel adapter value, not another service wire ABI.
/// `acquire` creates no mapping authority; only `map_intent` retains a mapping.
#[derive(Clone, Copy, Debug)]
pub struct RegionLease {
    pub physical: u64,
    pub length: u64,
    pub lease: LeaseId,
    pub writable: bool,
}

/// Image-owned policy and immutable admitted-RAM bounds. All mutations require
/// exclusive access on the one boot CPU with interrupts masked. Numeric caller
/// arguments must come from protected kernel domain state, never user fields.
pub struct NativeMemory {
    policy: Policy,
    admitted: [Option<FrameRange>; EXTENT_CAPACITY],
    admitted_count: usize,
    scrubbed_pages: u64,
}

const _: () = {
    assert!(size_of::<NativeMemory>() <= 32 * 1024);
    assert!(offset_of!(ProtectedSlot, memory) == 0);
    assert!(size_of::<ProtectedSlot>() <= 32 * 1024);
    assert!(size_of::<ProtectedSlot>() % PAGE_SIZE as usize == 0);
    assert!(size_of::<[BootDescriptor; DESCRIPTOR_CAPACITY]>() <= 128 * 1024);
};

fn live_range(range: crate::uefi::Range) -> Result<BootRange, MemoryError> {
    let length = range.end.checked_sub(range.start).ok_or(MemoryError::Overflow)?;
    if length == 0 { return Err(MemoryError::Empty); }
    Ok(BootRange { start: range.start, length })
}

fn contains(start: u64, end: u64, address: u64, bytes: usize) -> bool {
    start <= address && address.checked_add(bytes as u64).is_some_and(|last| last <= end)
}

/// Construct only from the final successful firmware-exit handoff, after
/// `cpu::take_ownership`. Failed ExitBootServices attempts authorize nothing.
///
/// SAFETY: the caller owns the validated retained map/image/stack, runs alone
/// with interrupts masked and the K01 identity mappings active, and calls this
/// once. It must keep these protected tables inaccessible to user writes.
pub unsafe fn initialize(handoff: &crate::uefi::Handoff) -> Result<&'static mut NativeMemory, MemoryError> {
    // SAFETY: the one-shot serialized bootstrap contract excludes other access.
    if unsafe { ptr::addr_of!(INITIALIZED).read() } { return Err(MemoryError::Phase); }
    let descriptors_address = ptr::addr_of!(DESCRIPTORS) as u64;
    let state_address = ptr::addr_of!(MEMORY) as u64;
    if !contains(handoff.image.start, handoff.image.end, descriptors_address,
                 size_of::<[BootDescriptor; DESCRIPTOR_CAPACITY]>())
        || !contains(handoff.image.start, handoff.image.end, state_address, size_of::<ProtectedSlot>())
        || !contains(handoff.image.start, handoff.image.end, ptr::addr_of!(INITIALIZED) as u64, 1)
    { return Err(MemoryError::Excluded); }
    if handoff.descriptor_size < size_of::<crate::uefi::Descriptor>()
        || handoff.descriptor_size % 8 != 0 || handoff.map_length == 0
        || handoff.map_length % handoff.descriptor_size != 0
        || !contains(handoff.map_allocation.start, handoff.map_allocation.end,
                     handoff.map as u64, handoff.map_length)
    { return Err(MemoryError::Bounds); }
    let count = handoff.descriptors();
    if count > DESCRIPTOR_CAPACITY { return Err(MemoryError::Capacity); }
    let destination = ptr::addr_of_mut!(DESCRIPTORS).cast::<BootDescriptor>();
    for index in 0..count {
        let source = handoff.descriptor(index);
        // SAFETY: the checked fixed array holds every copied numeric descriptor.
        unsafe { destination.add(index).write(BootDescriptor {
            kind: source.kind, start: source.start, pages: source.pages, attributes: source.attributes,
        }); }
    }
    // No free-page count is used to invent physical extents. Preserve complete
    // live allocations, including unused retained-map bytes and K01 scratch.
    let reservations = BootReservations {
        image: live_range(handoff.image)?, stack: live_range(handoff.stack)?,
        memory_map: live_range(handoff.map_allocation)?,
        scratch: BootRange { start: handoff.scratch, length: PAGE_SIZE },
        framebuffer: handoff.framebuffer.map(live_range).transpose()?,
        high_scratch: handoff.high_scratch.map(live_range).transpose()?,
    };
    // Rust pointer writes must never use physical address zero, even if a
    // malformed firmware profile reports it as conventional RAM.
    let null_page = [BootRange { start: 0, length: PAGE_SIZE }];
    // SAFETY: only initialized copies are exposed; no firmware pointers enter
    // the existing pure planner. It checks every descriptor and exclusion.
    let copied = unsafe { core::slice::from_raw_parts(destination, count) };
    let inventory = BootInventory::<EXTENT_CAPACITY>::plan(handoff.physical_bits,
        copied, reservations, &null_page)?;
    let mut admitted = [None; EXTENT_CAPACITY];
    let mut admitted_count = 0;
    for extent in inventory.extents() {
        admitted[admitted_count] = Some(extent);
        admitted_count += 1;
    }
    let state = NativeMemory { policy: inventory.into_policy()?, admitted, admitted_count, scrubbed_pages: 0 };
    // SAFETY: publication follows complete planning. This object is inside the
    // protected image and its lifetime lasts until this fresh boot terminates.
    unsafe {
        ptr::addr_of_mut!(MEMORY).cast::<NativeMemory>().write(state);
        ptr::addr_of_mut!(INITIALIZED).write(true);
        Ok(&mut *ptr::addr_of_mut!(MEMORY).cast::<NativeMemory>())
    }
}

fn admitted_page(range: FrameRange, admitted: &[Option<FrameRange>]) -> bool {
    range.pages() == 1 && range.start() != 0 && range.end() <= LOW_LIMIT
        && admitted.iter().flatten().any(|extent|
            extent.start() <= range.start() && range.end() <= extent.end())
}

fn admitted_view(view: RegionView, admitted: &[Option<FrameRange>]) -> bool {
    view.physical_start != 0 && view.length != 0
        && view.physical_start.checked_add(view.length).is_some_and(|end|
            end <= LOW_LIMIT && admitted.iter().flatten().any(|extent|
                extent.start() <= view.physical_start && end <= extent.end()))
}

/// SAFETY: exactly one valid, exclusively owned, aligned writable page exists
/// at `page`. Native callers additionally prove it belongs to admitted low RAM.
unsafe fn zero_page(page: *mut u64) {
    for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
        // Volatile writes make actual erasure part of the native operation;
        // ordinary optimized stores or a success-only callback are insufficient.
        unsafe { page.add(index).write_volatile(0); }
    }
}

/// SAFETY: the exclusive aligned page is valid for every volatile load/store.
/// Verify the ENTIRE erased page before any fixture payload store. Returning an
/// error publishes no payload; the allocator can then abandon its private plan.
unsafe fn initialize_zeroed_page(page: *mut u64, seed: u64) -> Result<(), ()> {
    for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
        if unsafe { page.add(index).read_volatile() } != 0 { return Err(()); }
    }
    for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
        unsafe { page.add(index).write_volatile(seed ^ index as u64); }
    }
    Ok(())
}

impl NativeMemory {
    pub fn protected_state_address(&self) -> u64 { self as *const Self as u64 }
    pub fn available_pages(&self) -> u64 { self.policy.frames().available_pages() }
    pub fn allocated_pages(&self) -> u64 { self.policy.frames().allocated_pages() }
    pub fn scrubbed_pages(&self) -> u64 { self.scrubbed_pages }
    pub fn accounting(&self, domain: u64) -> Result<Accounting, MemoryError> { self.policy.accounting(domain) }

    pub fn create_domain(&mut self, domain: u64, budget_pages: u64) -> Result<(), MemoryError> {
        if ![DOMAIN_A, DOMAIN_B, DOMAIN_C, DOMAIN_D].contains(&domain) { return Err(MemoryError::InvalidAuthority); }
        self.policy.create_domain(domain, budget_pages)
    }

    /// The first slice allocates exactly one committed page and no reservation.
    /// The original policy chooses and charges the backing before its callback;
    /// only actual successful erasure can install capability authority.
    pub fn allocate_page(&mut self, caller: u64) -> Result<CapabilityRef, MemoryError> {
        self.allocate_private_page(caller, None)
    }

    /// Trusted boot-fixture initialization, never a user allocator operation.
    /// `caller` and `seed` come from protected kernel context. Core admission
    /// checks precede this private callback; full erasure and zero verification
    /// precede payload initialization and capability/charge publication. No
    /// operation or mapping lease is consumed while this backing is private.
    pub fn allocate_initialized_page(&mut self, caller: u64, seed: u64) -> Result<CapabilityRef, MemoryError> {
        self.allocate_private_page(caller, Some(seed))
    }

    fn allocate_private_page(&mut self, caller: u64, seed: Option<u64>) -> Result<CapabilityRef, MemoryError> {
        let scrubbed_pages = self.scrubbed_pages.checked_add(1).ok_or(MemoryError::Overflow)?;
        let admitted = &self.admitted[..self.admitted_count];
        let rights = Rights::READ | Rights::WRITE | Rights::MAP | Rights::SUBMIT | Rights::DELEGATE;
        let handle = self.policy.allocate(caller, 1, 0, rights, |range| {
            if !admitted_page(range, admitted) { return Err(()); }
            // SAFETY: BootInventory admitted conventional RAM in the live K01
            // low identity map; policy owns the allocation exclusively and all
            // boot exclusions and protected state have been removed.
            unsafe { zero_page(range.start() as *mut u64); }
            if let Some(seed) = seed {
                // SAFETY: this same exclusive admitted page remains private
                // inside the allocation callback. Verification completes before
                // the first payload store; Core publishes only after Ok.
                unsafe { initialize_zeroed_page(range.start() as *mut u64, seed)?; }
            }
            Ok(())
        })?;
        self.scrubbed_pages = scrubbed_pages;
        Ok(handle)
    }

    pub fn delegate_readonly(&mut self, caller: u64, parent: CapabilityRef,
                             target: u64) -> Result<CapabilityRef, MemoryError> {
        self.delegate(caller, parent, target, Rights::READ | Rights::MAP, 0, PAGE_SIZE)
    }

    /// The protected dispatcher supplies `caller`; a claimed descriptor domain
    /// can neither select this identity nor administer another namespace.
    pub fn delegate(&mut self, caller: u64, parent: CapabilityRef, target: u64,
                    rights: Rights, offset: u64, length: u64) -> Result<CapabilityRef, MemoryError> {
        self.policy.delegate(caller, parent, target, rights, offset, length)
    }

    /// Checked numeric inspection only. This installs no PTE or lease and is
    /// never a substitute for retaining ownership across actual CPU access.
    pub fn authorize(&self, caller: u64, handle: CapabilityRef, rights: Rights,
                     offset: u64, length: u64) -> Result<RegionView, MemoryError> {
        self.policy.authorize(caller, handle, rights, offset, length)
    }

    pub fn region_info(&self, caller: u64, handle: CapabilityRef) -> Result<RegionInfo, MemoryError> {
        self.policy.region_info(caller, handle)
    }

    fn checked_view(&self, caller: u64, handle: CapabilityRef, rights: Rights,
                    offset: u64, length: u64) -> Result<RegionView, MemoryError> {
        let view = self.policy.authorize(caller, handle, rights, offset, length)?;
        if !admitted_view(view, &self.admitted[..self.admitted_count]) { return Err(MemoryError::Excluded); }
        Ok(view)
    }

    /// Retains exact complete pages without rounding byte authority outward.
    /// The core performs its original alignment/bounds/right checks before
    /// installing an owner; errors are returned unchanged, with no partial PTE.
    pub fn map_intent(&mut self, caller: u64, handle: CapabilityRef, access: Access,
                      offset: u64, length: u64) -> Result<RegionLease, MemoryError> {
        let rights = match access {
            Access::Read => Rights::READ | Rights::MAP,
            Access::Write => Rights::READ | Rights::WRITE | Rights::MAP,
        };
        // The core's pure authorization preserves rights/bounds ordering. For
        // a valid page-aligned backing, physical and absolute offset alignment
        // are equivalent; check it before the extra admitted-RAM guard so that
        // the guard cannot hide the original Alignment result. The core then
        // repeats its own checks before publishing the lease.
        let view = self.policy.authorize(caller, handle, rights, offset, length)?;
        if view.physical_start % PAGE_SIZE != 0 || view.length % PAGE_SIZE != 0 {
            return Err(MemoryError::Alignment);
        }
        if !admitted_view(view, &self.admitted[..self.admitted_count]) { return Err(MemoryError::Excluded); }
        let lease = self.policy.map_intent(caller, handle, access, offset, length)?;
        Ok(RegionLease { physical: view.physical_start, length: view.length,
            lease, writable: access == Access::Write })
    }

    /// Bounded byte operation, including write-only service operations. No
    /// mapping permission is added and no byte view is widened to a page.
    pub fn acquire(&mut self, caller: u64, handle: CapabilityRef, access: Access,
                   offset: u64, length: u64) -> Result<RegionLease, MemoryError> {
        let rights = match access {
            Access::Read => Rights::READ | Rights::SUBMIT,
            Access::Write => Rights::WRITE | Rights::SUBMIT,
        };
        let view = self.checked_view(caller, handle, rights, offset, length)?;
        let lease = self.policy.acquire(caller, handle, access, offset, length)?;
        Ok(RegionLease { physical: view.physical_start, length: view.length,
            lease, writable: access == Access::Write })
    }

    fn checked_page(&self, caller: u64, handle: CapabilityRef, access: Access,
                    mapping: bool) -> Result<u64, MemoryError> {
        let mut rights = Rights::READ;
        if access == Access::Write { rights = rights | Rights::WRITE; }
        if mapping { rights = rights | Rights::MAP; }
        let view = self.policy.authorize(caller, handle, rights, 0, PAGE_SIZE)?;
        let range = FrameRange::new(view.physical_start, 1)?;
        if !admitted_page(range, &self.admitted[..self.admitted_count]) { return Err(MemoryError::Excluded); }
        Ok(view.physical_start)
    }

    pub fn map_page(&mut self, caller: u64, handle: CapabilityRef,
                    access: Access) -> Result<PageLease, MemoryError> {
        let physical = self.checked_page(caller, handle, access, true)?;
        let lease = self.policy.map_intent(caller, handle, access, 0, PAGE_SIZE)?;
        Ok(PageLease { physical, lease, writable: access == Access::Write })
    }

    pub fn acquire_page(&mut self, caller: u64, handle: CapabilityRef,
                        access: Access) -> Result<PageLease, MemoryError> {
        let physical = self.checked_page(caller, handle, access, false)?;
        let lease = self.policy.acquire(caller, handle, access, 0, PAGE_SIZE)?;
        Ok(PageLease { physical, lease, writable: access == Access::Write })
    }

    /// Operation completion retains ownership; mapping tokens cannot complete.
    pub fn complete(&mut self, caller: u64, lease: LeaseId) -> Result<(), MemoryError> {
        self.policy.complete(caller, lease)
    }
    pub fn fence(&mut self, lease: LeaseId) -> Result<(), MemoryError> { self.policy.fence(lease) }
    /// SAFETY: for a mapping, the root must first remove every relevant PTE and
    /// complete its declared TLB invalidation. For an operation all accesses
    /// must have ended. User-originated acknowledgments are never sufficient.
    pub unsafe fn quiesce(&mut self, lease: LeaseId) -> Result<(), MemoryError> { self.policy.quiesce(lease) }
    pub fn release(&mut self, caller: u64, handle: CapabilityRef) -> Result<(), MemoryError> {
        self.policy.release_capability(caller, handle)
    }
    pub fn revoke(&mut self, caller: u64, handle: CapabilityRef) -> Result<(), MemoryError> {
        self.policy.revoke(caller, handle)
    }
}

#[cfg(test)]
#[path = "k02_memory_tests.rs"]
mod tests;
