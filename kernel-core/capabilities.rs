//! Trusted, serialized capability and ownership tables, without a dispatcher.

use crate::{CapabilityRef, Error, FramePool, FrameRange, PAGE_SIZE};
use core::ops::{BitAnd, BitOr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    pub const EMPTY: Self = Self(0);
    pub const READ: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const MAP: Self = Self(4);
    pub const SUBMIT: Self = Self(8);
    pub const DELEGATE: Self = Self(16);
    pub const ALL: Self = Self(31);

    pub fn from_bits(bits: u8) -> Result<Self, Error> {
        let rights = Self(bits);
        rights.validate()?;
        Ok(rights)
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    fn validate(self) -> Result<(), Error> {
        if self.0 == 0 || self.0 & !Self::ALL.0 != 0 {
            return Err(Error::InvalidAuthority);
        }
        Ok(())
    }
}

impl BitOr for Rights {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl BitAnd for Rights {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}
impl Access {
    fn right(self) -> Rights {
        match self {
            Self::Read => Rights::READ,
            Self::Write => Rights::WRITE,
        }
    }
}

/// Internal ownership identity, distinct from a wire capability. It cannot be
/// constructed from untrusted descriptor fields and never wraps its generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseId {
    slot: u32,
    generation: u32,
}
impl LeaseId {
    pub const fn slot(self) -> u32 {
        self.slot
    }
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accounting {
    pub budget_pages: u64,
    pub charged_pages: u64,
    pub committed_pages: u64,
    pub reserved_pages: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionInfo {
    pub backing: FrameRange,
    pub charge_owner: u64,
    pub committed_pages: u64,
    pub reserved_pages: u64,
}

/// A checked numerical slice for trusted kernel code. It installs no mapping,
/// carries no CPU/DMA permission and is not an ownership lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionView {
    pub physical_start: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Domain {
    id: u64,
    accounting: Accounting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Region {
    backing: FrameRange,
    owner: usize,
    committed_pages: u64,
    reserved_pages: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Capability {
    region: usize,
    offset: u64,
    length: u64,
    rights: Rights,
    parent: Option<CapabilityRef>,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapabilitySlot {
    generation: u32,
    value: Option<Capability>,
}
impl CapabilitySlot {
    const EMPTY: Self = Self {
        generation: 0,
        value: None,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerKind {
    Operation,
    Mapping,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Active,
    Completed,
    Fenced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owner {
    authority: CapabilityRef,
    region: usize,
    offset: u64,
    length: u64,
    access: Access,
    kind: OwnerKind,
    phase: Phase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OwnerSlot {
    generation: u32,
    value: Option<Owner>,
}
impl OwnerSlot {
    const EMPTY: Self = Self {
        generation: 0,
        value: None,
    };
}

/// D domains, R backing regions, C capability slots per domain, O outstanding
/// owners and F physical extent metadata slots. Numeric caller identities must
/// be supplied by trusted code; this policy cannot authenticate a native caller.
/// Domains are not deleted or recycled in this initial core.
#[derive(Debug, PartialEq, Eq)]
pub struct MemoryPolicy<
    const D: usize,
    const R: usize,
    const C: usize,
    const O: usize,
    const F: usize,
> {
    frames: FramePool<F>,
    domains: [Option<Domain>; D],
    regions: [Option<Region>; R],
    capabilities: [[CapabilitySlot; C]; D],
    owners: [OwnerSlot; O],
}

impl<const D: usize, const R: usize, const C: usize, const O: usize, const F: usize>
    MemoryPolicy<D, R, C, O, F>
{
    pub fn new(physical_bits: u8, exclusions: &[FrameRange]) -> Result<Self, Error> {
        if C > u32::MAX as usize || O > u32::MAX as usize {
            return Err(Error::Capacity);
        }
        Ok(Self {
            frames: FramePool::new(physical_bits, exclusions)?,
            domains: [None; D],
            regions: [None; R],
            capabilities: [[CapabilitySlot::EMPTY; C]; D],
            owners: [OwnerSlot::EMPTY; O],
        })
    }

    pub fn frames(&self) -> &FramePool<F> {
        &self.frames
    }
    pub fn add_free_extent(&mut self, range: FrameRange) -> Result<(), Error> {
        self.frames.add_free_extent(range)
    }

    pub fn create_domain(&mut self, domain: u64, budget_pages: u64) -> Result<(), Error> {
        if domain == 0 {
            return Err(Error::InvalidAuthority);
        }
        if self
            .domains
            .iter()
            .flatten()
            .any(|entry| entry.id == domain)
        {
            return Err(Error::DuplicateDomain);
        }
        let slot = self
            .domains
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.domains[slot] = Some(Domain {
            id: domain,
            accounting: Accounting {
                budget_pages,
                charged_pages: 0,
                committed_pages: 0,
                reserved_pages: 0,
            },
        });
        Ok(())
    }

    fn domain_index(&self, domain: u64) -> Result<usize, Error> {
        self.domains
            .iter()
            .position(|entry| entry.is_some_and(|value| value.id == domain))
            .ok_or(Error::UnknownDomain)
    }

    pub fn accounting(&self, domain: u64) -> Result<Accounting, Error> {
        let index = self.domain_index(domain)?;
        Ok(self.domains[index]
            .expect("domain index validated")
            .accounting)
    }

    fn capability(
        &self,
        caller: u64,
        handle: CapabilityRef,
        active: bool,
    ) -> Result<(usize, usize, Capability), Error> {
        let domain = self.domain_index(caller)?;
        if handle.domain != caller || handle.domain == 0 || handle.generation == 0 {
            return Err(Error::InvalidAuthority);
        }
        let slot = handle.slot as usize;
        let stored = self.capabilities[domain]
            .get(slot)
            .ok_or(Error::StaleHandle)?;
        if stored.generation != handle.generation {
            return Err(Error::StaleHandle);
        }
        let value = stored.value.ok_or(Error::StaleHandle)?;
        if active && value.revoked {
            return Err(Error::Revoked);
        }
        Ok((domain, slot, value))
    }

    fn next_capability(&self, domain: usize) -> Result<CapabilityRef, Error> {
        let slot = self.capabilities[domain]
            .iter()
            .position(|entry| entry.value.is_none() && entry.generation < u32::MAX)
            .ok_or(Error::Capacity)?;
        Ok(CapabilityRef {
            domain: self.domains[domain].expect("domain index validated").id,
            slot: slot as u32,
            generation: self.capabilities[domain][slot].generation + 1,
        })
    }

    fn install_capability(&mut self, domain: usize, handle: CapabilityRef, value: Capability) {
        self.capabilities[domain][handle.slot as usize] = CapabilitySlot {
            generation: handle.generation,
            value: Some(value),
        };
    }

    /// Reserves and scrubs the complete committed+reserved physical allocation.
    /// Every admission/capacity/arithmetic check precedes the callback. A failed
    /// scrub changes no policy state and makes no frame authority visible.
    /// The trusted callback must actually erase the range before returning Ok.
    pub fn allocate<S>(
        &mut self,
        caller: u64,
        committed_pages: u64,
        reserved_pages: u64,
        rights: Rights,
        mut scrub: S,
    ) -> Result<CapabilityRef, Error>
    where
        S: FnMut(FrameRange) -> Result<(), ()>,
    {
        let domain = self.domain_index(caller)?;
        rights.validate()?;
        if committed_pages == 0 {
            return Err(Error::Empty);
        }
        let total = committed_pages
            .checked_add(reserved_pages)
            .ok_or(Error::Overflow)?;
        let length = committed_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::Overflow)?;
        total.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)?;
        let accounting = self.domains[domain]
            .expect("domain index validated")
            .accounting;
        if total > accounting.budget_pages - accounting.charged_pages {
            return Err(Error::Budget);
        }
        let region = self
            .regions
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let handle = self.next_capability(domain)?;
        let plan = self.frames.plan_allocate(total)?;
        scrub(plan.range).map_err(|()| Error::ScrubFailed)?;
        let backing = self.frames.commit_allocate(plan);
        self.regions[region] = Some(Region {
            backing,
            owner: domain,
            committed_pages,
            reserved_pages,
        });
        let state = &mut self.domains[domain]
            .as_mut()
            .expect("domain index validated")
            .accounting;
        state.charged_pages += total;
        state.committed_pages += committed_pages;
        state.reserved_pages += reserved_pages;
        self.install_capability(
            domain,
            handle,
            Capability {
                region,
                offset: 0,
                length,
                rights,
                parent: None,
                revoked: false,
            },
        );
        Ok(handle)
    }

    /// Activates already charged reservation pages on an exclusive original
    /// root. This is a trusted administrative operation: caller identity and
    /// scrubbing must come from protected kernel code, not descriptor fields.
    /// All aliases and operation/mapping owners must be released first. The
    /// newly exposed tail is scrubbed before replacing the root generation;
    /// physical backing, total charge, budget and rights remain unchanged.
    pub fn activate_reserved<S>(
        &mut self,
        caller: u64,
        root: CapabilityRef,
        pages: u64,
        mut scrub: S,
    ) -> Result<CapabilityRef, Error>
    where
        S: FnMut(FrameRange) -> Result<(), ()>,
    {
        let (domain, slot, capability) = self.capability(caller, root, true)?;
        let region = self.regions[capability.region].expect("capability retains its region");
        let committed_bytes = region
            .committed_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::Overflow)?;
        if region.owner != domain
            || capability.parent.is_some()
            || capability.offset != 0
            || capability.length != committed_bytes
        {
            return Err(Error::InvalidAuthority);
        }
        if pages == 0 {
            return Err(Error::Empty);
        }
        if pages > region.reserved_pages {
            return Err(Error::Bounds);
        }
        if self
            .owners
            .iter()
            .filter_map(|entry| entry.value)
            .any(|owner| owner.region == capability.region)
            || self
                .capabilities
                .iter()
                .enumerate()
                .any(|(other_domain, entries)| {
                    entries.iter().enumerate().any(|(other_slot, entry)| {
                        (other_domain != domain || other_slot != slot)
                            && entry
                                .value
                                .is_some_and(|value| value.region == capability.region)
                    })
                })
        {
            return Err(Error::Busy);
        }
        let generation = root.generation.checked_add(1).ok_or(Error::Capacity)?;
        let length = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|bytes| capability.length.checked_add(bytes))
            .ok_or(Error::Overflow)?;
        let committed_pages = region
            .committed_pages
            .checked_add(pages)
            .ok_or(Error::Overflow)?;
        let reserved_pages = region
            .reserved_pages
            .checked_sub(pages)
            .ok_or(Error::Overflow)?;
        let accounting = self.domains[domain]
            .expect("domain index validated")
            .accounting;
        let updated_accounting = Accounting {
            committed_pages: accounting
                .committed_pages
                .checked_add(pages)
                .ok_or(Error::Overflow)?,
            reserved_pages: accounting
                .reserved_pages
                .checked_sub(pages)
                .ok_or(Error::Overflow)?,
            ..accounting
        };
        let tail_start = region
            .backing
            .start()
            .checked_add(committed_bytes)
            .ok_or(Error::Overflow)?;
        let tail = FrameRange::new(tail_start, pages)?;
        let replacement = CapabilityRef {
            generation,
            ..root
        };
        let updated_region = Region {
            committed_pages,
            reserved_pages,
            ..region
        };
        let updated_capability = Capability {
            length,
            ..capability
        };
        scrub(tail).map_err(|()| Error::ScrubFailed)?;
        self.regions[capability.region] = Some(updated_region);
        self.domains[domain]
            .as_mut()
            .expect("domain index validated")
            .accounting = updated_accounting;
        self.install_capability(domain, replacement, updated_capability);
        Ok(replacement)
    }

    fn bounded_slice(capability: Capability, offset: u64, length: u64) -> Result<u64, Error> {
        if length == 0 {
            return Err(Error::Empty);
        }
        offset.checked_add(length).ok_or(Error::Overflow)?;
        if offset > capability.length || length > capability.length - offset {
            return Err(Error::Bounds);
        }
        capability.offset.checked_add(offset).ok_or(Error::Overflow)
    }

    pub fn delegate(
        &mut self,
        caller: u64,
        parent: CapabilityRef,
        target: u64,
        rights: Rights,
        offset: u64,
        length: u64,
    ) -> Result<CapabilityRef, Error> {
        let (_, _, capability) = self.capability(caller, parent, true)?;
        let domain = self.domain_index(target)?;
        rights.validate()?;
        if !capability.rights.contains(Rights::DELEGATE) || !capability.rights.contains(rights) {
            return Err(Error::InsufficientRights);
        }
        let absolute = Self::bounded_slice(capability, offset, length)?;
        let handle = self.next_capability(domain)?;
        self.install_capability(
            domain,
            handle,
            Capability {
                region: capability.region,
                offset: absolute,
                length,
                rights,
                parent: Some(parent),
                revoked: false,
            },
        );
        Ok(handle)
    }

    pub fn authorize(
        &self,
        caller: u64,
        handle: CapabilityRef,
        right: Rights,
        offset: u64,
        length: u64,
    ) -> Result<RegionView, Error> {
        let (_, _, capability) = self.capability(caller, handle, true)?;
        right.validate()?;
        if !capability.rights.contains(right) {
            return Err(Error::InsufficientRights);
        }
        let absolute = Self::bounded_slice(capability, offset, length)?;
        let region = self.regions[capability.region].expect("capability retains its region");
        let physical_start = region
            .backing
            .start()
            .checked_add(absolute)
            .ok_or(Error::Overflow)?;
        Ok(RegionView {
            physical_start,
            length,
        })
    }

    pub fn region_info(&self, caller: u64, handle: CapabilityRef) -> Result<RegionInfo, Error> {
        let (_, _, capability) = self.capability(caller, handle, true)?;
        let region = self.regions[capability.region].expect("capability retains its region");
        Ok(RegionInfo {
            backing: region.backing,
            charge_owner: self.domains[region.owner]
                .expect("region retains its domain")
                .id,
            committed_pages: region.committed_pages,
            reserved_pages: region.reserved_pages,
        })
    }

    fn acquire_owner(
        &mut self,
        caller: u64,
        handle: CapabilityRef,
        access: Access,
        offset: u64,
        length: u64,
        kind: OwnerKind,
    ) -> Result<LeaseId, Error> {
        let (_, _, capability) = self.capability(caller, handle, true)?;
        let required = match (kind, access) {
            (OwnerKind::Operation, _) => access.right() | Rights::SUBMIT,
            (OwnerKind::Mapping, Access::Read) => Rights::READ | Rights::MAP,
            (OwnerKind::Mapping, Access::Write) => Rights::READ | Rights::WRITE | Rights::MAP,
        };
        if !capability.rights.contains(required) {
            return Err(Error::InsufficientRights);
        }
        let absolute = Self::bounded_slice(capability, offset, length)?;
        if kind == OwnerKind::Mapping && (absolute % PAGE_SIZE != 0 || length % PAGE_SIZE != 0) {
            return Err(Error::Alignment);
        }
        // Absolute intervals make delegated and mapped aliases participate in
        // the same conflict check. Completion/fencing retains these intervals.
        let end = absolute + length;
        if self
            .owners
            .iter()
            .filter_map(|entry| entry.value)
            .any(|owner| {
                owner.region == capability.region
                    && absolute < owner.offset + owner.length
                    && owner.offset < end
                    && (access == Access::Write || owner.access == Access::Write)
            })
        {
            return Err(Error::Busy);
        }
        let slot = self
            .owners
            .iter()
            .position(|entry| entry.value.is_none() && entry.generation < u32::MAX)
            .ok_or(Error::Capacity)?;
        let generation = self.owners[slot].generation + 1;
        self.owners[slot] = OwnerSlot {
            generation,
            value: Some(Owner {
                authority: handle,
                region: capability.region,
                offset: absolute,
                length,
                access,
                kind,
                phase: Phase::Active,
            }),
        };
        Ok(LeaseId {
            slot: slot as u32,
            generation,
        })
    }

    pub fn acquire(
        &mut self,
        caller: u64,
        handle: CapabilityRef,
        access: Access,
        offset: u64,
        length: u64,
    ) -> Result<LeaseId, Error> {
        self.acquire_owner(caller, handle, access, offset, length, OwnerKind::Operation)
    }

    /// Records a pending or installed mapping's ownership only. A native mapper
    /// must serialize installation with revocation, install exact authorized
    /// pages, and keep this lease until unmap and translation invalidation finish.
    /// Writable mappings require READ, WRITE and MAP: an x86 writable page also
    /// permits reads. A write-only capability may authorize a bounded write
    /// operation, but cannot authorize a writable CPU mapping on this profile.
    pub fn map_intent(
        &mut self,
        caller: u64,
        handle: CapabilityRef,
        access: Access,
        offset: u64,
        length: u64,
    ) -> Result<LeaseId, Error> {
        self.acquire_owner(caller, handle, access, offset, length, OwnerKind::Mapping)
    }

    fn owner(&self, lease: LeaseId) -> Result<(usize, Owner), Error> {
        let slot = lease.slot as usize;
        let stored = self.owners.get(slot).ok_or(Error::StaleLease)?;
        if lease.generation == 0 || stored.generation != lease.generation {
            return Err(Error::StaleLease);
        }
        Ok((slot, stored.value.ok_or(Error::StaleLease)?))
    }

    /// Execution completion fences no hardware and releases no ownership.
    /// A revoked capability cannot publish a completion.
    pub fn complete(&mut self, caller: u64, lease: LeaseId) -> Result<(), Error> {
        let (slot, owner) = self.owner(lease)?;
        self.capability(caller, owner.authority, true)?;
        if owner.kind != OwnerKind::Operation {
            return Err(Error::WrongLeaseKind);
        }
        if owner.phase != Phase::Active {
            return Err(Error::Phase);
        }
        self.owners[slot]
            .value
            .as_mut()
            .expect("lease index validated")
            .phase = Phase::Completed;
        Ok(())
    }

    /// Trusted backend records fenced output/canceled mapping intent. This is
    /// distinct from acknowledging that CPU/device accesses have quiesced.
    pub fn fence(&mut self, lease: LeaseId) -> Result<(), Error> {
        let (slot, owner) = self.owner(lease)?;
        if owner.phase != Phase::Active {
            return Err(Error::Phase);
        }
        self.owners[slot]
            .value
            .as_mut()
            .expect("lease index validated")
            .phase = Phase::Fenced;
        Ok(())
    }

    /// Trusted backend acknowledgment only: after actual completion/drain/reset
    /// or unmapping and required translation invalidation. An untrusted request
    /// must never be allowed to assert this acknowledgment itself.
    pub fn quiesce(&mut self, lease: LeaseId) -> Result<(), Error> {
        let (slot, owner) = self.owner(lease)?;
        if owner.phase == Phase::Active {
            return Err(Error::Phase);
        }
        self.owners[slot].value = None;
        Ok(())
    }

    pub fn revoke(&mut self, caller: u64, handle: CapabilityRef) -> Result<(), Error> {
        let (domain, slot, _) = self.capability(caller, handle, true)?;
        self.capabilities[domain][slot]
            .value
            .as_mut()
            .expect("capability index validated")
            .revoked = true;
        // Every pass marks at least one previously active descendant or stops;
        // the loop is bounded by the fixed D*C capability storage.
        loop {
            let mut changed = false;
            for domain in 0..D {
                for slot in 0..C {
                    let Some(capability) = self.capabilities[domain][slot].value else {
                        continue;
                    };
                    if capability.revoked {
                        continue;
                    }
                    let Some(parent) = capability.parent else {
                        continue;
                    };
                    let parent_revoked = self
                        .domain_index(parent.domain)
                        .ok()
                        .and_then(|index| self.capabilities[index].get(parent.slot as usize))
                        .filter(|entry| entry.generation == parent.generation)
                        .and_then(|entry| entry.value)
                        .is_some_and(|value| value.revoked);
                    if parent_revoked {
                        self.capabilities[domain][slot]
                            .value
                            .as_mut()
                            .expect("capability index validated")
                            .revoked = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }

    pub fn release_capability(&mut self, caller: u64, handle: CapabilityRef) -> Result<(), Error> {
        let (domain, slot, capability) = self.capability(caller, handle, false)?;
        if self
            .owners
            .iter()
            .filter_map(|entry| entry.value)
            .any(|owner| owner.region == capability.region)
            || self
                .capabilities
                .iter()
                .flatten()
                .filter_map(|entry| entry.value)
                .any(|child| child.parent == Some(handle))
        {
            return Err(Error::Busy);
        }
        let another_reference =
            self.capabilities
                .iter()
                .enumerate()
                .any(|(other_domain, entries)| {
                    entries.iter().enumerate().any(|(other_slot, entry)| {
                        (other_domain != domain || other_slot != slot)
                            && entry
                                .value
                                .is_some_and(|value| value.region == capability.region)
                    })
                });
        if !another_reference {
            let region = self.regions[capability.region].expect("capability retains its region");
            // FramePool validates before mutation and reserves metadata at
            // allocation, so a valid final release always has storage available.
            self.frames.release(region.backing)?;
            let accounting = &mut self.domains[region.owner]
                .as_mut()
                .expect("region retains its domain")
                .accounting;
            accounting.charged_pages -= region.committed_pages + region.reserved_pages;
            accounting.committed_pages -= region.committed_pages;
            accounting.reserved_pages -= region.reserved_pages;
            self.regions[capability.region] = None;
        }
        self.capabilities[domain][slot].value = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
