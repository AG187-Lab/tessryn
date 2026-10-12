//! Provisional Tessryn ABI v1.0. Apache-2.0. Host contract evidence only.
//! Explicit scalar little-endian encoding is required; repr(C) is layout,
//! not serialization. Never turn untrusted bytes into a typed reference.
#![no_std]

pub const ABI_MAJOR: u16 = 1;
pub const ABI_MINOR: u16 = 0;
pub const ABI_FEATURE_MASK: u64 = 0;

pub const KIND_NEGOTIATION: u16 = 1;
pub const KIND_REGION: u16 = 2;
pub const KIND_SUBMISSION: u16 = 3;
pub const KIND_COMPLETION: u16 = 4;

pub const OP_COPY: u32 = 1;
pub const OP_EXECUTE: u32 = 2;
pub const OP_TRANSFER: u32 = 3;
pub const OP_CANCEL: u32 = 4;
pub const OP_FENCE: u32 = 5;
pub const OP_RELEASE: u32 = 6;

pub const STATUS_OK: u32 = 0;
pub const STATUS_INVALID_DESCRIPTOR: u32 = 1;
pub const STATUS_UNSUPPORTED_VERSION: u32 = 2;
pub const STATUS_INVALID_AUTHORITY: u32 = 3;
pub const STATUS_STALE_HANDLE: u32 = 4;
pub const STATUS_OUT_OF_BOUNDS: u32 = 5;
pub const STATUS_INSUFFICIENT_CAPACITY: u32 = 6;
pub const STATUS_ADMISSION_REJECTED: u32 = 7;
pub const STATUS_DEADLINE_EXPIRED: u32 = 8;
pub const STATUS_DEVICE_FAULT: u32 = 9;
pub const STATUS_CANCELLED: u32 = 10;
pub const STATUS_STALE_EPOCH: u32 = 11;
pub const STATUS_INCOMPATIBLE_FORMAT: u32 = 12;
pub const STATUS_PARTIAL_STREAM: u32 = 13;
pub const STATUS_BACKPRESSURE: u32 = 14;
pub const STATUS_PEER_FAULT: u32 = 15;

pub const MILESTONE_NONE: u32 = 0;
pub const MILESTONE_SUBMISSION_ACCEPTED: u32 = 1;
pub const MILESTONE_EXECUTION_COMPLETED: u32 = 2;
pub const MILESTONE_CANCELLATION_RECEIVED: u32 = 3;
pub const MILESTONE_LAUNCHES_STOPPED: u32 = 4;
pub const MILESTONE_OUTPUT_FENCED: u32 = 5;
pub const MILESTONE_MEMORY_RECLAIMED: u32 = 6;
pub const MILESTONE_FAULT_REPORTED: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub major: u16,
    pub minor: u16,
    pub size: u32,
    pub kind: u16,
    pub flags: u16,
    pub reserved: u32,
}
const _: () = {
    assert!(core::mem::size_of::<Header>() == 16);
    assert!(core::mem::align_of::<Header>() == 4);
    assert!(core::mem::offset_of!(Header, major) == 0);
    assert!(core::mem::offset_of!(Header, minor) == 2);
    assert!(core::mem::offset_of!(Header, size) == 4);
    assert!(core::mem::offset_of!(Header, kind) == 8);
    assert!(core::mem::offset_of!(Header, flags) == 10);
    assert!(core::mem::offset_of!(Header, reserved) == 12);
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityRef {
    pub slot: u32,
    pub generation: u32,
    pub domain: u64,
}
const _: () = {
    assert!(core::mem::size_of::<CapabilityRef>() == 16);
    assert!(core::mem::align_of::<CapabilityRef>() == 8);
    assert!(core::mem::offset_of!(CapabilityRef, slot) == 0);
    assert!(core::mem::offset_of!(CapabilityRef, generation) == 4);
    assert!(core::mem::offset_of!(CapabilityRef, domain) == 8);
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Negotiation {
    pub header: Header,
    pub min_major: u16,
    pub min_minor: u16,
    pub max_major: u16,
    pub max_minor: u16,
    pub required_features: u64,
    pub supported_features: u64,
    pub domain: u64,
}
const _: () = {
    assert!(core::mem::size_of::<Negotiation>() == 48);
    assert!(core::mem::align_of::<Negotiation>() == 8);
    assert!(core::mem::offset_of!(Negotiation, header) == 0);
    assert!(core::mem::offset_of!(Negotiation, min_major) == 16);
    assert!(core::mem::offset_of!(Negotiation, min_minor) == 18);
    assert!(core::mem::offset_of!(Negotiation, max_major) == 20);
    assert!(core::mem::offset_of!(Negotiation, max_minor) == 22);
    assert!(core::mem::offset_of!(Negotiation, required_features) == 24);
    assert!(core::mem::offset_of!(Negotiation, supported_features) == 32);
    assert!(core::mem::offset_of!(Negotiation, domain) == 40);
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Region {
    pub header: Header,
    pub capability: CapabilityRef,
    pub owner_task: u64,
    pub length: u64,
    pub budget_id: u64,
    pub placement_epoch: u64,
}
const _: () = {
    assert!(core::mem::size_of::<Region>() == 64);
    assert!(core::mem::align_of::<Region>() == 8);
    assert!(core::mem::offset_of!(Region, header) == 0);
    assert!(core::mem::offset_of!(Region, capability) == 16);
    assert!(core::mem::offset_of!(Region, owner_task) == 32);
    assert!(core::mem::offset_of!(Region, length) == 40);
    assert!(core::mem::offset_of!(Region, budget_id) == 48);
    assert!(core::mem::offset_of!(Region, placement_epoch) == 56);
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Submission {
    pub header: Header,
    pub request_id: u64,
    pub task_id: u64,
    pub placement_epoch: u64,
    pub operation: u32,
    pub reserved: u32,
    pub region: CapabilityRef,
    pub offset: u64,
    pub length: u64,
    pub completion: CapabilityRef,
    pub dependency: CapabilityRef,
    pub budget_id: u64,
    pub deadline_ns: u64,
}
const _: () = {
    assert!(core::mem::size_of::<Submission>() == 128);
    assert!(core::mem::align_of::<Submission>() == 8);
    assert!(core::mem::offset_of!(Submission, header) == 0);
    assert!(core::mem::offset_of!(Submission, request_id) == 16);
    assert!(core::mem::offset_of!(Submission, task_id) == 24);
    assert!(core::mem::offset_of!(Submission, placement_epoch) == 32);
    assert!(core::mem::offset_of!(Submission, operation) == 40);
    assert!(core::mem::offset_of!(Submission, reserved) == 44);
    assert!(core::mem::offset_of!(Submission, region) == 48);
    assert!(core::mem::offset_of!(Submission, offset) == 64);
    assert!(core::mem::offset_of!(Submission, length) == 72);
    assert!(core::mem::offset_of!(Submission, completion) == 80);
    assert!(core::mem::offset_of!(Submission, dependency) == 96);
    assert!(core::mem::offset_of!(Submission, budget_id) == 112);
    assert!(core::mem::offset_of!(Submission, deadline_ns) == 120);
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Completion {
    pub header: Header,
    pub request_id: u64,
    pub sequence: u64,
    pub placement_epoch: u64,
    pub status: u32,
    pub milestone: u32,
    pub region: CapabilityRef,
    pub produced_length: u64,
    pub ownership_generation: u32,
    pub reserved: u32,
}
const _: () = {
    assert!(core::mem::size_of::<Completion>() == 80);
    assert!(core::mem::align_of::<Completion>() == 8);
    assert!(core::mem::offset_of!(Completion, header) == 0);
    assert!(core::mem::offset_of!(Completion, request_id) == 16);
    assert!(core::mem::offset_of!(Completion, sequence) == 24);
    assert!(core::mem::offset_of!(Completion, placement_epoch) == 32);
    assert!(core::mem::offset_of!(Completion, status) == 40);
    assert!(core::mem::offset_of!(Completion, milestone) == 44);
    assert!(core::mem::offset_of!(Completion, region) == 48);
    assert!(core::mem::offset_of!(Completion, produced_length) == 64);
    assert!(core::mem::offset_of!(Completion, ownership_generation) == 72);
    assert!(core::mem::offset_of!(Completion, reserved) == 76);
};

// Helpers accept scalar arrays obtained after a bounds check.
pub const fn read_le16(bytes: [u8; 2]) -> u16 { u16::from_le_bytes(bytes) }
pub const fn read_le32(bytes: [u8; 4]) -> u32 { u32::from_le_bytes(bytes) }
pub const fn read_le64(bytes: [u8; 8]) -> u64 { u64::from_le_bytes(bytes) }
pub const fn write_le16(value: u16) -> [u8; 2] { value.to_le_bytes() }
pub const fn write_le32(value: u32) -> [u8; 4] { value.to_le_bytes() }
pub const fn write_le64(value: u64) -> [u8; 8] { value.to_le_bytes() }
