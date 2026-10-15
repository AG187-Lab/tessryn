//! Bounded original region-request policy. The caller and Backend are trusted;
//! request bytes are untrusted. No raw user pointer or internal lease enters it.
pub use tessryn_owned_memory::{Access, Accounting, CapabilityRef, Error as MemoryError};

pub const REQUEST_MAGIC: [u8; 8] = *b"TESSRGN1";
pub const REQUEST_VERSION: u16 = 1;
pub const REQUEST_BYTES: usize = 96;
pub const OP_ALLOCATE: u32 = 1;
pub const OP_MAP: u32 = 2;
pub const OP_DELEGATE_READONLY: u32 = 3;
pub const OP_REVOKE: u32 = 4;
pub const OP_UNMAP: u32 = 5;
pub const OP_RELEASE: u32 = 6;
pub const OP_ACCOUNTING: u32 = 7;
pub const OP_YIELD: u32 = 8;
pub const OP_EXIT: u32 = 9;
const PAGE: u64 = 4096;
const NO_CAP: CapabilityRef = CapabilityRef {
    slot: 0,
    generation: 0,
    domain: 0,
};

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    InvalidDescriptor = 1,
    UnsupportedVersion = 2,
    UnsupportedOperation = 3,
    InvalidAuthority = 4,
    StaleHandle = 5,
    Revoked = 6,
    Bounds = 7,
    Alignment = 8,
    InsufficientRights = 9,
    Capacity = 10,
    Budget = 11,
    Busy = 12,
    Overflow = 13,
    BackendRejected = 14,
}
impl Status {
    pub const fn from_memory(error: MemoryError) -> Self {
        match error {
            MemoryError::UnknownDomain | MemoryError::InvalidAuthority => Self::InvalidAuthority,
            MemoryError::StaleHandle => Self::StaleHandle,
            MemoryError::Revoked => Self::Revoked,
            MemoryError::Empty | MemoryError::Bounds => Self::Bounds,
            MemoryError::Alignment => Self::Alignment,
            MemoryError::InsufficientRights => Self::InsufficientRights,
            MemoryError::Capacity => Self::Capacity,
            MemoryError::Budget => Self::Budget,
            MemoryError::Busy => Self::Busy,
            MemoryError::Overflow => Self::Overflow,
            _ => Self::BackendRejected,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Continue,
    Yield,
    Exit,
}

/// Fixed scalar fields, decoded explicitly rather than borrowing typed user RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub request_id: u64,
    pub opcode: u32,
    pub capability: CapabilityRef,
    pub arg: u64,
    pub offset: u64,
    pub length: u64,
    pub virtual_address: u64,
    pub rights: u64,
}
fn u16_at(bytes: &[u8; REQUEST_BYTES], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8; REQUEST_BYTES], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8; REQUEST_BYTES], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
impl Request {
    pub const fn new(request_id: u64, opcode: u32) -> Self {
        Self {
            request_id,
            opcode,
            capability: NO_CAP,
            arg: 0,
            offset: 0,
            length: 0,
            virtual_address: 0,
            rights: 0,
        }
    }
    pub fn encode(self) -> [u8; REQUEST_BYTES] {
        let mut bytes = [0; REQUEST_BYTES];
        bytes[..8].copy_from_slice(&REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(REQUEST_BYTES as u16).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.opcode.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.capability.slot.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.capability.generation.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.capability.domain.to_le_bytes());
        for (at, value) in [
            (48, self.arg),
            (56, self.offset),
            (64, self.length),
            (72, self.virtual_address),
            (80, self.rights),
        ] {
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    pub fn decode(bytes: &[u8; REQUEST_BYTES]) -> Result<Self, Status> {
        if bytes[..8] != REQUEST_MAGIC || u16_at(bytes, 10) != REQUEST_BYTES as u16 {
            return Err(Status::InvalidDescriptor);
        }
        if u16_at(bytes, 8) != REQUEST_VERSION {
            return Err(Status::UnsupportedVersion);
        }
        if u32_at(bytes, 12) != 0 || u32_at(bytes, 28) != 0 || u64_at(bytes, 88) != 0 {
            return Err(Status::InvalidDescriptor);
        }
        let request = Self {
            request_id: u64_at(bytes, 16),
            opcode: u32_at(bytes, 24),
            capability: CapabilityRef {
                slot: u32_at(bytes, 32),
                generation: u32_at(bytes, 36),
                domain: u64_at(bytes, 40),
            },
            arg: u64_at(bytes, 48),
            offset: u64_at(bytes, 56),
            length: u64_at(bytes, 64),
            virtual_address: u64_at(bytes, 72),
            rights: u64_at(bytes, 80),
        };
        let cap_empty = request.capability == NO_CAP;
        let trailing_empty = request.offset == 0
            && request.length == 0
            && request.virtual_address == 0
            && request.rights == 0;
        let valid = match request.opcode {
            OP_ALLOCATE => {
                cap_empty
                    && request.arg == 0
                    && request.offset == 0
                    && request.length == PAGE
                    && request.virtual_address == 0
                    && request.rights == 0
            }
            OP_MAP => request.arg == 0 && matches!(request.rights, 5 | 7),
            OP_DELEGATE_READONLY => {
                request.arg != 0 && request.virtual_address == 0 && request.rights == 5
            }
            OP_REVOKE | OP_RELEASE => request.arg == 0 && trailing_empty,
            OP_UNMAP => cap_empty && trailing_empty,
            OP_ACCOUNTING | OP_YIELD | OP_EXIT => cap_empty && request.arg == 0 && trailing_empty,
            _ => return Err(Status::UnsupportedOperation),
        };
        if !valid {
            return Err(Status::InvalidDescriptor);
        }
        if matches!(request.opcode, OP_MAP | OP_DELEGATE_READONLY) {
            if request.length == 0 {
                return Err(Status::Bounds);
            }
            request
                .offset
                .checked_add(request.length)
                .ok_or(Status::Overflow)?;
        }
        if request.opcode == OP_MAP {
            request
                .virtual_address
                .checked_add(request.length)
                .ok_or(Status::Overflow)?;
            if request.offset % PAGE != 0
                || request.length % PAGE != 0
                || request.virtual_address % PAGE != 0
            {
                return Err(Status::Alignment);
            }
        }
        Ok(request)
    }
}

/// Returns the checked byte offset. The CPU adapter additionally verifies the
/// retained physical mapping and RW/NX permissions before its one bounded copy.
pub fn checked_request_buffer(
    pointer: u64,
    supplied_length: u64,
    registered_base: u64,
    registered_length: u64,
) -> Result<u64, Status> {
    if supplied_length != REQUEST_BYTES as u64 {
        return Err(Status::InvalidDescriptor);
    }
    if pointer % 8 != 0 {
        return Err(Status::Alignment);
    }
    let registered_end = registered_base
        .checked_add(registered_length)
        .ok_or(Status::Overflow)?;
    let end = pointer
        .checked_add(supplied_length)
        .ok_or(Status::Overflow)?;
    if pointer < registered_base || end > registered_end {
        return Err(Status::Bounds);
    }
    Ok(pointer - registered_base)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    Rejected(MemoryError),
    Fatal(MemoryError),
}
impl From<MemoryError> for MapError {
    fn from(error: MemoryError) -> Self {
        Self::Rejected(error)
    }
}

/// Trusted single-CPU adapter contract. No user request can implement it.
/// `map` rejects atomically: Rejected leaves neither a PTE nor retained owner.
/// Failed cleanup must return Fatal. `unmap` returns Ok only after trusted fence,
/// exact PTE removal, translation invalidation and quiescence. It must retain
/// ownership on failure. No service/task can resume after a Fatal result.
pub trait Backend {
    type Mapping: Copy;
    fn allocate(&mut self, caller: u64) -> Result<CapabilityRef, MemoryError>;
    fn delegate_readonly(
        &mut self,
        caller: u64,
        parent: CapabilityRef,
        target: u64,
        offset: u64,
        length: u64,
    ) -> Result<CapabilityRef, MemoryError>;
    fn map(
        &mut self,
        caller: u64,
        capability: CapabilityRef,
        access: Access,
        offset: u64,
        length: u64,
        virtual_address: u64,
    ) -> Result<Self::Mapping, MapError>;
    fn unmap(&mut self, mapping: Self::Mapping) -> Result<(), MemoryError>;
    fn authorize_mapping(
        &self,
        caller: u64,
        capability: CapabilityRef,
        offset: u64,
        length: u64,
    ) -> Result<(), MemoryError>;
    fn revoke(&mut self, caller: u64, capability: CapabilityRef) -> Result<(), MemoryError>;
    fn release(&mut self, caller: u64, capability: CapabilityRef) -> Result<(), MemoryError>;
    fn accounting(&self, caller: u64) -> Result<Accounting, MemoryError>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub requests: u64,
    pub accepted: u64,
    pub rejected: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fatal {
    UnknownCaller,
    CounterOverflow,
    Backend(MemoryError),
    Teardown(MemoryError),
    RetainedAuthority(MemoryError),
    Accounting(MemoryError),
    Blocked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub request_id: u64,
    pub opcode: u32,
    pub status: Status,
    pub capability: CapabilityRef,
    pub mapping: u64,
    pub accounting: Accounting,
    pub control: Control,
}

#[derive(Clone, Copy)]
struct Mapping<M: Copy> {
    caller: u64,
    capability: CapabilityRef,
    offset: u64,
    length: u64,
    backend: M,
}
#[derive(Clone, Copy)]
struct Slot<M: Copy> {
    generation: u32,
    mapping: Option<Mapping<M>>,
}

/// Allocation-free reusable dispatcher. Caller identities are supplied only by
/// protected task state. Public mapping IDs are separate from internal leases.
pub struct Service<M: Copy, const D: usize = 2, const N: usize = 16> {
    domains: [u64; D],
    statistics: [Statistics; D],
    last_ids: [u64; D],
    slots: [Slot<M>; N],
    blocked: bool,
}
impl<M: Copy, const D: usize, const N: usize> Service<M, D, N> {
    pub fn new(domains: [u64; D]) -> Result<Self, Status> {
        if N > u32::MAX as usize
            || D == 0
            || domains
                .iter()
                .enumerate()
                .any(|(i, domain)| *domain == 0 || domains[..i].contains(domain))
        {
            return Err(Status::InvalidAuthority);
        }
        Ok(Self {
            domains,
            statistics: [Statistics::default(); D],
            last_ids: [0; D],
            slots: [Slot {
                generation: 0,
                mapping: None,
            }; N],
            blocked: false,
        })
    }
    pub fn statistics(&self, caller: u64) -> Option<Statistics> {
        self.domains
            .iter()
            .position(|domain| *domain == caller)
            .map(|i| self.statistics[i])
    }
    pub fn mapping_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.mapping.is_some())
            .count()
    }
    pub fn blocked(&self) -> bool {
        self.blocked
    }
    pub fn last_request_id(&self, caller: u64) -> Option<u64> {
        self.domains
            .iter()
            .position(|domain| *domain == caller)
            .map(|i| self.last_ids[i])
    }

    /// Trusted stopped-task cleanup; it cannot be requested as a quiescence
    /// acknowledgment by user code. Capability lifetime is the Backend journal's
    /// responsibility and remains charged until its final successful release.
    pub fn drain_mappings<B: Backend<Mapping = M>>(
        &mut self,
        caller: u64,
        backend: &mut B,
    ) -> Result<usize, Fatal> {
        if self.blocked {
            return Err(Fatal::Blocked);
        }
        let result = if !self.domains.contains(&caller) {
            Err(Fatal::UnknownCaller)
        } else {
            let mut removed = 0;
            let mut result = Ok(0);
            for slot in &mut self.slots {
                let Some(mapping) = slot.mapping.filter(|mapping| mapping.caller == caller) else {
                    continue;
                };
                if let Err(error) = backend.unmap(mapping.backend) {
                    result = Err(Fatal::Teardown(error));
                    break;
                }
                slot.mapping = None;
                removed += 1;
                result = Ok(removed);
            }
            result
        };
        if result.is_err() {
            self.blocked = true;
        }
        result
    }

    /// Trusted recursive-revocation cleanup across all domains. A successful
    /// response or peer resume is forbidden until this completes.
    pub fn drain_revoked<B: Backend<Mapping = M>>(
        &mut self,
        backend: &mut B,
    ) -> Result<usize, Fatal> {
        if self.blocked {
            return Err(Fatal::Blocked);
        }
        let result = self.drain_revoked_inner(backend);
        if result.is_err() {
            self.blocked = true;
        }
        result
    }
    fn drain_revoked_inner<B: Backend<Mapping = M>>(
        &mut self,
        backend: &mut B,
    ) -> Result<usize, Fatal> {
        let mut removed = 0;
        for slot in &mut self.slots {
            let Some(mapping) = slot.mapping else {
                continue;
            };
            match backend.authorize_mapping(
                mapping.caller,
                mapping.capability,
                mapping.offset,
                mapping.length,
            ) {
                Ok(()) => {}
                Err(MemoryError::Revoked) => {
                    backend.unmap(mapping.backend).map_err(Fatal::Teardown)?;
                    slot.mapping = None;
                    removed += 1;
                }
                Err(error) => return Err(Fatal::RetainedAuthority(error)),
            }
        }
        Ok(removed)
    }

    pub fn dispatch<B: Backend<Mapping = M>>(
        &mut self,
        caller: u64,
        bytes: &[u8; REQUEST_BYTES],
        backend: &mut B,
    ) -> Result<Response, Fatal> {
        if self.blocked {
            return Err(Fatal::Blocked);
        }
        let result = self.dispatch_inner(caller, bytes, backend);
        if result.is_err() {
            self.blocked = true;
        }
        result
    }
    fn dispatch_inner<B: Backend<Mapping = M>>(
        &mut self,
        caller: u64,
        bytes: &[u8; REQUEST_BYTES],
        backend: &mut B,
    ) -> Result<Response, Fatal> {
        let domain = self
            .domains
            .iter()
            .position(|domain| *domain == caller)
            .ok_or(Fatal::UnknownCaller)?;
        let stats = &mut self.statistics[domain];
        if stats.requests == u64::MAX || stats.accepted == u64::MAX || stats.rejected == u64::MAX {
            return Err(Fatal::CounterOverflow);
        }
        stats.requests += 1;
        let mut response = Response {
            request_id: u64_at(bytes, 16),
            opcode: u32_at(bytes, 24),
            status: Status::Ok,
            capability: NO_CAP,
            mapping: 0,
            accounting: backend.accounting(caller).map_err(Fatal::Accounting)?,
            control: Control::Continue,
        };
        response.status =
            if response.request_id == 0 || response.request_id <= self.last_ids[domain] {
                Status::InvalidDescriptor
            } else {
                // Even malformed fixed-size wire requests consume a fresh ID.
                // CPU buffer rejections may leave gaps, but replay cannot mutate.
                self.last_ids[domain] = response.request_id;
                match Request::decode(bytes) {
                    Ok(request) => self.execute(caller, request, backend, &mut response)?,
                    Err(status) => status,
                }
            };
        response.accounting = backend.accounting(caller).map_err(Fatal::Accounting)?;
        if response.status == Status::Ok {
            self.statistics[domain].accepted += 1;
        } else {
            self.statistics[domain].rejected += 1;
        }
        Ok(response)
    }
    fn execute<B: Backend<Mapping = M>>(
        &mut self,
        caller: u64,
        request: Request,
        backend: &mut B,
        response: &mut Response,
    ) -> Result<Status, Fatal> {
        let ordinary = match request.opcode {
            OP_ALLOCATE => backend
                .allocate(caller)
                .map(|cap| response.capability = cap),
            OP_MAP => {
                let Some(index) = self
                    .slots
                    .iter()
                    .position(|slot| slot.mapping.is_none() && slot.generation < u32::MAX)
                else {
                    return Ok(Status::Capacity);
                };
                let access = if request.rights == 7 {
                    Access::Write
                } else {
                    Access::Read
                };
                let mapping = match backend.map(
                    caller,
                    request.capability,
                    access,
                    request.offset,
                    request.length,
                    request.virtual_address,
                ) {
                    Ok(mapping) => mapping,
                    Err(MapError::Rejected(error)) => return Ok(Status::from_memory(error)),
                    Err(MapError::Fatal(error)) => return Err(Fatal::Backend(error)),
                };
                let slot = &mut self.slots[index];
                slot.generation += 1;
                slot.mapping = Some(Mapping {
                    caller,
                    capability: request.capability,
                    offset: request.offset,
                    length: request.length,
                    backend: mapping,
                });
                response.mapping = ((slot.generation as u64) << 32) | (index as u64 + 1);
                Ok(())
            }
            OP_DELEGATE_READONLY => {
                if !self.domains.contains(&request.arg) {
                    return Ok(Status::InvalidAuthority);
                }
                backend
                    .delegate_readonly(
                        caller,
                        request.capability,
                        request.arg,
                        request.offset,
                        request.length,
                    )
                    .map(|cap| response.capability = cap)
            }
            OP_REVOKE => {
                if let Err(error) = backend.revoke(caller, request.capability) {
                    return Ok(Status::from_memory(error));
                }
                self.drain_revoked_inner(backend)?;
                Ok(())
            }
            OP_UNMAP => {
                let raw_slot = request.arg as u32;
                let generation = (request.arg >> 32) as u32;
                let Some(slot) = raw_slot
                    .checked_sub(1)
                    .and_then(|index| self.slots.get_mut(index as usize))
                else {
                    return Ok(Status::StaleHandle);
                };
                if generation == 0 || slot.generation != generation {
                    return Ok(Status::StaleHandle);
                }
                let Some(mapping) = slot.mapping else {
                    return Ok(Status::StaleHandle);
                };
                if mapping.caller != caller {
                    return Ok(Status::InvalidAuthority);
                }
                backend.unmap(mapping.backend).map_err(Fatal::Teardown)?;
                slot.mapping = None;
                Ok(())
            }
            OP_RELEASE => backend.release(caller, request.capability),
            OP_ACCOUNTING => Ok(()),
            OP_YIELD => {
                response.control = Control::Yield;
                Ok(())
            }
            OP_EXIT => {
                response.control = Control::Exit;
                Ok(())
            }
            _ => return Ok(Status::UnsupportedOperation),
        };
        Ok(match ordinary {
            Ok(()) => Status::Ok,
            Err(error) => Status::from_memory(error),
        })
    }
}
