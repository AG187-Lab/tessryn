//! Allocation-free ownership policy for a future privileged kernel boundary.
//!
//! This library records authority, physical extents and outstanding ownership.
//! It performs no memory access, page-table installation, authentication or DMA
//! fencing. Caller identities and backend acknowledgments must come from trusted
//! native code. All state changes require exclusive access to the policy.
#![no_std]
#![forbid(unsafe_code)]

#[allow(unused_attributes)]
#[path = "../interfaces/abi-v1/native.rs"]
pub mod abi;

mod capabilities;
mod boot_inventory;
mod frames;

pub use abi::CapabilityRef;
pub use capabilities::{Access, Accounting, LeaseId, MemoryPolicy, RegionInfo, RegionView, Rights};
pub use boot_inventory::{BootDescriptor, BootInventory, BootRange, BootReservations};
pub use frames::{FramePool, FrameRange};

#[cfg(test)]
mod boot_inventory_tests;

pub const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Empty,
    Overflow,
    Alignment,
    PhysicalWidth,
    Excluded,
    Overlap,
    Capacity,
    UnknownDomain,
    DuplicateDomain,
    InvalidAuthority,
    StaleHandle,
    Revoked,
    InsufficientRights,
    Bounds,
    Budget,
    Busy,
    StaleLease,
    Phase,
    WrongLeaseKind,
    ScrubFailed,
}
