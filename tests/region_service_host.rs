// Actual ownership core plus a bounded fake MMU. No CPU/TLB execution claim.
#![allow(dead_code)]
#[path = "../kernel/region_service.rs"]
mod service;
use service::*;
use tessryn_owned_memory::{FrameRange, LeaseId, MemoryPolicy, Rights};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mapping {
    caller: u64,
    capability: CapabilityRef,
    lease: LeaseId,
    va: u64,
    physical: u64,
}
struct Model {
    policy: MemoryPolicy<2, 8, 16, 16, 16>,
    ram: [[u8; 4096]; 16],
    ptes: [Option<Mapping>; 16],
    events: Vec<&'static str>,
    install_rejection: bool,
    fatal_install: bool,
    fail_teardown: bool,
    bad_authority: bool,
    map_calls: usize,
}
impl Model {
    fn new() -> Self {
        let mut policy = MemoryPolicy::new(40, &[]).unwrap();
        policy
            .add_free_extent(FrameRange::new(0x10_0000, 16).unwrap())
            .unwrap();
        for caller in [1, 2] {
            policy.create_domain(caller, 8).unwrap();
        }
        Self {
            policy,
            ram: [[0x77; 4096]; 16],
            ptes: [None; 16],
            events: vec![],
            install_rejection: false,
            fatal_install: false,
            fail_teardown: false,
            bad_authority: false,
            map_calls: 0,
        }
    }
    fn pages(&self) -> u64 {
        self.policy.frames().allocated_pages()
    }
}
impl Backend for Model {
    type Mapping = Mapping;
    fn allocate(&mut self, caller: u64) -> Result<CapabilityRef, MemoryError> {
        let ram = &mut self.ram;
        self.policy.allocate(caller, 1, 0, Rights::ALL, |range| {
            let index = ((range.start() - 0x10_0000) / 4096) as usize;
            // Real writes to an exclusively owned host buffer model erasure;
            // these addresses never purport to be native physical RAM.
            ram[index].fill(0);
            Ok(())
        })
    }
    fn delegate_readonly(
        &mut self,
        caller: u64,
        parent: CapabilityRef,
        target: u64,
        offset: u64,
        length: u64,
    ) -> Result<CapabilityRef, MemoryError> {
        self.policy.delegate(
            caller,
            parent,
            target,
            Rights::READ | Rights::MAP,
            offset,
            length,
        )
    }
    fn map(
        &mut self,
        caller: u64,
        cap: CapabilityRef,
        access: Access,
        offset: u64,
        length: u64,
        va: u64,
    ) -> Result<Mapping, MapError> {
        self.map_calls += 1;
        let lease = self
            .policy
            .map_intent(caller, cap, access, offset, length)?;
        let view = self
            .policy
            .authorize(caller, cap, Rights::READ, offset, length)
            .unwrap();
        let mapping = Mapping {
            caller,
            capability: cap,
            lease,
            va,
            physical: view.physical_start,
        };
        if self.fatal_install {
            return Err(MapError::Fatal(MemoryError::Phase));
        }
        if self.install_rejection
            || self
                .ptes
                .iter()
                .flatten()
                .any(|old| old.caller == caller && old.va == va)
        {
            self.events.push("rollback_fence");
            self.policy.fence(lease).unwrap();
            self.events.push("rollback_quiesce");
            self.policy.quiesce(lease).unwrap();
            return Err(MapError::Rejected(MemoryError::Capacity));
        }
        let Some(slot) = self.ptes.iter_mut().find(|slot| slot.is_none()) else {
            self.policy.fence(lease).unwrap();
            self.policy.quiesce(lease).unwrap();
            return Err(MapError::Rejected(MemoryError::Capacity));
        };
        *slot = Some(mapping);
        self.events.push("install");
        Ok(mapping)
    }
    fn unmap(&mut self, mapping: Mapping) -> Result<(), MemoryError> {
        if self.fail_teardown {
            return Err(MemoryError::Phase);
        }
        let slot = self
            .ptes
            .iter_mut()
            .find(|slot| **slot == Some(mapping))
            .ok_or(MemoryError::StaleLease)?;
        self.policy.fence(mapping.lease)?;
        self.events.push("fence");
        *slot = None;
        self.events.push("clear_pte");
        // Explicit model acknowledgment only; actual CR3 reload is native.
        self.events.push("invalidate");
        self.policy.quiesce(mapping.lease)?;
        self.events.push("quiesce");
        Ok(())
    }
    fn authorize_mapping(
        &self,
        caller: u64,
        cap: CapabilityRef,
        offset: u64,
        length: u64,
    ) -> Result<(), MemoryError> {
        if self.bad_authority {
            return Err(MemoryError::StaleHandle);
        }
        self.policy
            .authorize(caller, cap, Rights::READ | Rights::MAP, offset, length)
            .map(|_| ())
    }
    fn revoke(&mut self, caller: u64, cap: CapabilityRef) -> Result<(), MemoryError> {
        self.policy.revoke(caller, cap)
    }
    fn release(&mut self, caller: u64, cap: CapabilityRef) -> Result<(), MemoryError> {
        self.policy.release_capability(caller, cap)
    }
    fn accounting(&self, caller: u64) -> Result<Accounting, MemoryError> {
        self.policy.accounting(caller)
    }
}
struct Fixture<const N: usize = 16> {
    service: Service<Mapping, 2, N>,
    model: Model,
    ids: [u64; 2],
}
impl<const N: usize> Fixture<N> {
    fn new() -> Self {
        Self {
            service: Service::new([1, 2]).unwrap(),
            model: Model::new(),
            ids: [0; 2],
        }
    }
    fn call(&mut self, caller: u64, mut request: Request) -> Response {
        self.ids[caller as usize - 1] += 1;
        request.request_id = self.ids[caller as usize - 1];
        self.service
            .dispatch(caller, &request.encode(), &mut self.model)
            .unwrap()
    }
    fn allocate(&mut self, caller: u64) -> CapabilityRef {
        let mut r = Request::new(0, OP_ALLOCATE);
        r.length = 4096;
        let response = self.call(caller, r);
        assert_eq!(response.status, Status::Ok);
        response.capability
    }
    fn map_request(cap: CapabilityRef, va: u64, writable: bool) -> Request {
        let mut r = Request::new(0, OP_MAP);
        r.capability = cap;
        r.length = 4096;
        r.virtual_address = va;
        r.rights = if writable { 7 } else { 5 };
        r
    }
    fn map(&mut self, caller: u64, cap: CapabilityRef, va: u64, writable: bool) -> Response {
        self.call(caller, Self::map_request(cap, va, writable))
    }
    fn unmap(&mut self, caller: u64, token: u64) -> Response {
        let mut r = Request::new(0, OP_UNMAP);
        r.arg = token;
        self.call(caller, r)
    }
    fn cap_call(&mut self, caller: u64, op: u32, cap: CapabilityRef) -> Response {
        let mut r = Request::new(0, op);
        r.capability = cap;
        self.call(caller, r)
    }
    fn delegate(&mut self, cap: CapabilityRef) -> CapabilityRef {
        let mut r = Request::new(0, OP_DELEGATE_READONLY);
        r.capability = cap;
        r.arg = 2;
        r.length = 4096;
        r.rights = 5;
        let response = self.call(1, r);
        assert_eq!(response.status, Status::Ok);
        response.capability
    }
}

#[test]
fn codec_has_exact_little_endian_offsets_and_round_trip() {
    let r = Request {
        request_id: 0x0807_0605_0403_0201,
        opcode: OP_MAP,
        capability: CapabilityRef {
            slot: 0x4433_2211,
            generation: 0x8877_6655,
            domain: 2,
        },
        arg: 0,
        offset: 4096,
        length: 8192,
        virtual_address: 0x1_0001_0000,
        rights: 7,
    };
    let bytes = r.encode();
    assert_eq!(&bytes[..16], b"TESSRGN1\x01\0\x60\0\0\0\0\0");
    assert_eq!(&bytes[16..24], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        &bytes[32..40],
        &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
    assert_eq!(Request::decode(&bytes), Ok(r));
}

#[test]
fn codec_rejects_every_header_and_reserved_region() {
    let r = Request::new(1, OP_ACCOUNTING).encode();
    for offset in [0, 7, 10, 11, 12, 15, 28, 31, 88, 95] {
        let mut bad = r;
        bad[offset] ^= 1;
        assert_eq!(
            Request::decode(&bad),
            Err(Status::InvalidDescriptor),
            "{offset}"
        );
    }
    let mut bad = r;
    bad[8] = 2;
    assert_eq!(Request::decode(&bad), Err(Status::UnsupportedVersion));
    let mut unknown = Request::new(1, 10).encode();
    unknown[24] = 255;
    assert_eq!(Request::decode(&unknown), Err(Status::UnsupportedOperation));
}

#[test]
fn strict_unused_fields_reject_trusted_or_ambiguous_operations() {
    for op in [OP_REVOKE, OP_RELEASE, OP_ACCOUNTING, OP_YIELD, OP_EXIT] {
        for offset in [48, 56, 64, 72, 80] {
            let mut bytes = Request::new(1, op).encode();
            bytes[offset] = 1;
            assert_eq!(Request::decode(&bytes), Err(Status::InvalidDescriptor));
        }
    }
    for op in [OP_UNMAP, OP_ACCOUNTING, OP_YIELD, OP_EXIT] {
        let mut r = Request::new(1, op);
        r.capability.generation = 1;
        assert_eq!(Request::decode(&r.encode()), Err(Status::InvalidDescriptor));
    }
    for rights in [0, 1, 2, 3, 4, 6, 8, 31, u64::MAX] {
        let mut r = Fixture::<16>::map_request(
            CapabilityRef {
                slot: 0,
                generation: 1,
                domain: 1,
            },
            0x1_0000_0000,
            false,
        );
        r.rights = rights;
        assert_eq!(Request::decode(&r.encode()), Err(Status::InvalidDescriptor));
    }
}

#[test]
fn checked_buffer_accepts_last_byte_extent_and_rejects_overflow_or_neighbor() {
    assert_eq!(checked_request_buffer(0x1000, 96, 0x1000, 4096), Ok(0));
    assert_eq!(checked_request_buffer(0x1fa0, 96, 0x1000, 4096), Ok(4000));
    assert_eq!(
        checked_request_buffer(0x1fa8, 96, 0x1000, 4096),
        Err(Status::Bounds)
    );
    assert_eq!(
        checked_request_buffer(0xff8, 96, 0x1000, 4096),
        Err(Status::Bounds)
    );
    assert_eq!(
        checked_request_buffer(0x1001, 96, 0x1000, 4096),
        Err(Status::Alignment)
    );
    for length in [0, 95, 97, u64::MAX] {
        assert_eq!(
            checked_request_buffer(0x1000, length, 0x1000, 4096),
            Err(Status::InvalidDescriptor)
        );
    }
    assert_eq!(
        checked_request_buffer(u64::MAX - 7, 96, 0, 4096),
        Err(Status::Overflow)
    );
    assert_eq!(
        checked_request_buffer(0x1000, 96, u64::MAX - 7, 4096),
        Err(Status::Overflow)
    );
}

#[test]
fn protected_caller_rejects_foreign_handle_without_charge_or_pte_changes() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    let charge = f.model.accounting(1).unwrap();
    assert_eq!(
        f.map(2, a, 0x1_0000_0000, false).status,
        Status::InvalidAuthority
    );
    assert_eq!(f.model.accounting(1).unwrap(), charge);
    assert_eq!(f.model.pages(), 1);
    assert_eq!(f.service.mapping_count(), 0);
    assert!(f.model.ptes.iter().all(Option::is_none));
}

#[test]
fn readonly_delegation_attenuates_write_and_redelegation_authority() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    let b = f.delegate(a);
    assert_eq!(
        f.map(2, b, 0x1_0000_0000, true).status,
        Status::InsufficientRights
    );
    assert_eq!(f.map(2, b, 0x1_0000_0000, false).status, Status::Ok);
    let mut r = Request::new(0, OP_DELEGATE_READONLY);
    r.capability = b;
    r.arg = 1;
    r.length = 4096;
    r.rights = 5;
    assert_eq!(f.call(2, r).status, Status::InsufficientRights);
    assert_eq!(f.model.accounting(1).unwrap().charged_pages, 1);
    assert_eq!(f.model.accounting(2).unwrap().charged_pages, 0);
}

#[test]
fn byte_bounds_and_alignment_never_round_authority_outward() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    let mut r = Request::new(0, OP_DELEGATE_READONLY);
    r.capability = a;
    r.arg = 2;
    r.offset = 1;
    r.length = 4094;
    r.rights = 5;
    let b = f.call(1, r).capability;
    assert_eq!(f.map(2, b, 0x1_0000_0000, false).status, Status::Bounds);
    let mut r = Fixture::<16>::map_request(a, 0x1_0000_0000, false);
    r.offset = 1;
    assert_eq!(f.call(1, r).status, Status::Alignment);
    let mut r = Fixture::<16>::map_request(a, 0x1_0000_0000, false);
    r.offset = u64::MAX;
    r.length = 4096;
    assert_eq!(f.call(1, r).status, Status::Overflow);
    assert_eq!(f.service.mapping_count(), 0);
}

#[test]
fn failed_hardware_install_rolls_back_real_core_ownership_before_rejection() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    f.model.install_rejection = true;
    assert_eq!(f.map(1, a, 0x1_0000_0000, false).status, Status::Capacity);
    assert_eq!(f.model.events, vec!["rollback_fence", "rollback_quiesce"]);
    assert_eq!(f.service.mapping_count(), 0);
    assert!(f.model.ptes.iter().all(Option::is_none));
    assert_eq!(f.cap_call(1, OP_RELEASE, a).status, Status::Ok);
    assert_eq!(f.model.pages(), 0);
}

#[test]
fn public_table_capacity_precedes_backend_map_and_retains_existing_owner() {
    let mut f = Fixture::<1>::new();
    let a = f.allocate(1);
    let first = f.map(1, a, 0x1_0000_0000, false);
    assert_eq!(first.status, Status::Ok);
    let calls = f.model.map_calls;
    assert_eq!(f.map(1, a, 0x1_0000_1000, false).status, Status::Capacity);
    assert_eq!(f.model.map_calls, calls);
    assert_eq!(f.service.mapping_count(), 1);
    assert_eq!(f.cap_call(1, OP_RELEASE, a).status, Status::Busy);
    assert_eq!(f.unmap(1, first.mapping).status, Status::Ok);
    assert_eq!(f.cap_call(1, OP_RELEASE, a).status, Status::Ok);
}

#[test]
fn mapping_id_generations_and_domain_ownership_preserve_current_mapping() {
    let mut f = Fixture::<1>::new();
    let a = f.allocate(1);
    let old = f.map(1, a, 0x1_0000_0000, false).mapping;
    assert_eq!(old, 0x1_0000_0001);
    assert_eq!(f.unmap(1, old).status, Status::Ok);
    let current = f.map(1, a, 0x1_0000_0000, false).mapping;
    assert_eq!(current, 0x2_0000_0001);
    assert_eq!(f.unmap(1, old).status, Status::StaleHandle);
    assert_eq!(f.unmap(2, current).status, Status::InvalidAuthority);
    assert_eq!(f.unmap(1, 0).status, Status::StaleHandle);
    assert_eq!(f.service.mapping_count(), 1);
    assert_eq!(f.cap_call(1, OP_RELEASE, a).status, Status::Busy);
}

#[test]
fn recursive_revoke_drains_every_retained_descendant_before_success() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    let b = f.delegate(a);
    let ma = f.map(1, a, 0x1_0000_0000, false);
    let mb = f.map(2, b, 0x1_0000_0000, false);
    assert_eq!((ma.status, mb.status), (Status::Ok, Status::Ok));
    f.model.events.clear();
    assert_eq!(f.cap_call(1, OP_REVOKE, a).status, Status::Ok);
    assert_eq!(
        f.model.events,
        vec![
            "fence",
            "clear_pte",
            "invalidate",
            "quiesce",
            "fence",
            "clear_pte",
            "invalidate",
            "quiesce"
        ]
    );
    assert_eq!(f.service.mapping_count(), 0);
    assert!(f.model.ptes.iter().all(Option::is_none));
    assert_eq!(f.map(2, b, 0x1_0000_0000, false).status, Status::Revoked);
    assert_eq!(f.cap_call(1, OP_RELEASE, a).status, Status::Busy);
    assert_eq!(f.model.pages(), 1);
    assert_eq!(f.cap_call(2, OP_RELEASE, b).status, Status::Ok);
    assert_eq!(f.cap_call(1, OP_RELEASE, a).status, Status::Ok);
    assert_eq!(f.model.pages(), 0);
}

#[test]
fn child_revocation_keeps_unaffected_peer_mapping_and_charge() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    let b = f.delegate(a);
    let ma = f.map(1, a, 0x1_0000_0000, false);
    f.map(2, b, 0x1_0000_0000, false);
    assert_eq!(f.cap_call(2, OP_REVOKE, b).status, Status::Ok);
    assert_eq!(f.service.mapping_count(), 1);
    assert!(
        f.model
            .ptes
            .iter()
            .flatten()
            .any(|mapping| mapping.caller == 1)
    );
    // Core intentionally keeps even child release Busy while peer owns backing.
    assert_eq!(f.cap_call(2, OP_RELEASE, b).status, Status::Busy);
    f.unmap(1, ma.mapping);
    assert_eq!(f.cap_call(2, OP_RELEASE, b).status, Status::Ok);
}

#[test]
fn teardown_failure_is_fatal_retains_lease_charge_and_blocks_all_dispatch() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    f.map(1, a, 0x1_0000_0000, false);
    f.model.fail_teardown = true;
    let mut r = Request::new(99, OP_REVOKE);
    r.capability = a;
    assert_eq!(
        f.service.dispatch(1, &r.encode(), &mut f.model),
        Err(Fatal::Teardown(MemoryError::Phase))
    );
    assert!(f.service.blocked());
    assert_eq!(f.service.mapping_count(), 1);
    assert_eq!(f.model.pages(), 1);
    assert_eq!(f.model.release(1, a), Err(MemoryError::Busy));
    assert_eq!(
        f.service
            .dispatch(2, &Request::new(1, OP_ACCOUNTING).encode(), &mut f.model),
        Err(Fatal::Blocked)
    );
}

#[test]
fn fatal_failed_map_cleanup_never_returns_an_ordinary_error_reply() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    f.model.fatal_install = true;
    let mut r = Fixture::<16>::map_request(a, 0x1_0000_0000, false);
    r.request_id = 2;
    assert_eq!(
        f.service.dispatch(1, &r.encode(), &mut f.model),
        Err(Fatal::Backend(MemoryError::Phase))
    );
    assert_eq!(f.model.release(1, a), Err(MemoryError::Busy));
    assert!(f.service.blocked());
}

#[test]
fn trusted_stop_drains_one_domain_then_revocation_drains_peer() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    let b = f.delegate(a);
    f.map(1, a, 0x1_0000_0000, false);
    f.map(2, b, 0x1_0000_0000, false);
    let stats = f.service.statistics(1);
    assert_eq!(f.service.drain_mappings(2, &mut f.model), Ok(1));
    assert_eq!(f.service.statistics(1), stats);
    assert_eq!(f.service.mapping_count(), 1);
    f.model.revoke(1, a).unwrap();
    assert_eq!(f.service.drain_revoked(&mut f.model), Ok(1));
    assert_eq!(f.service.drain_revoked(&mut f.model), Ok(0));
    f.model.release(2, b).unwrap();
    f.model.release(1, a).unwrap();
    assert_eq!(f.model.pages(), 0);
}

#[test]
fn unexpected_retained_authority_failure_blocks_instead_of_skipping_teardown() {
    let mut f = Fixture::<16>::new();
    let a = f.allocate(1);
    f.map(1, a, 0x1_0000_0000, false);
    f.model.bad_authority = true;
    assert_eq!(
        f.service.drain_revoked(&mut f.model),
        Err(Fatal::RetainedAuthority(MemoryError::StaleHandle))
    );
    assert!(f.service.blocked());
    assert_eq!(f.service.mapping_count(), 1);
}

#[test]
fn replay_zero_and_decreasing_ids_never_repeat_a_mutation_and_gaps_are_allowed() {
    let mut f = Fixture::<16>::new();
    let mut r = Request::new(10, OP_ALLOCATE);
    r.length = 4096;
    assert_eq!(
        f.service
            .dispatch(1, &r.encode(), &mut f.model)
            .unwrap()
            .status,
        Status::Ok
    );
    for id in [10, 9, 0] {
        r.request_id = id;
        assert_eq!(
            f.service
                .dispatch(1, &r.encode(), &mut f.model)
                .unwrap()
                .status,
            Status::InvalidDescriptor
        );
    }
    assert_eq!(f.model.pages(), 1);
    assert_eq!(f.service.last_request_id(1), Some(10));
    r.request_id = 12;
    assert_eq!(
        f.service
            .dispatch(1, &r.encode(), &mut f.model)
            .unwrap()
            .status,
        Status::Ok
    );
    assert_eq!(f.model.pages(), 2);
    assert_eq!(f.service.last_request_id(1), Some(12));
    assert_eq!(
        f.service.statistics(1),
        Some(Statistics {
            requests: 5,
            accepted: 2,
            rejected: 3
        })
    );
}

#[test]
fn malformed_wire_consumes_fresh_id_but_each_caller_has_an_independent_sequence() {
    let mut f = Fixture::<16>::new();
    let mut bytes = Request::new(50, OP_ACCOUNTING).encode();
    bytes[88] = 1;
    assert_eq!(
        f.service.dispatch(1, &bytes, &mut f.model).unwrap().status,
        Status::InvalidDescriptor
    );
    let valid = Request::new(50, OP_ALLOCATE);
    let mut valid = valid;
    valid.length = 4096;
    assert_eq!(
        f.service
            .dispatch(1, &valid.encode(), &mut f.model)
            .unwrap()
            .status,
        Status::InvalidDescriptor
    );
    assert_eq!(
        f.service
            .dispatch(2, &Request::new(1, OP_ACCOUNTING).encode(), &mut f.model)
            .unwrap()
            .status,
        Status::Ok
    );
    assert_eq!(f.model.pages(), 0);
    assert_eq!(f.service.last_request_id(1), Some(50));
}

#[test]
fn yield_exit_and_rejected_control_requests_have_no_hidden_memory_outputs() {
    let mut f = Fixture::<16>::new();
    for (op, control) in [(OP_YIELD, Control::Yield), (OP_EXIT, Control::Exit)] {
        let response = f.call(1, Request::new(0, op));
        assert_eq!(response.control, control);
        assert_eq!(response.capability, CapabilityRef::default());
        assert_eq!(response.mapping, 0);
        let mut r = Request::new(0, op);
        r.arg = 1;
        let response = f.call(1, r);
        assert_eq!(response.status, Status::InvalidDescriptor);
        assert_eq!(response.control, Control::Continue);
    }
    assert_eq!(f.model.pages(), 0);
}

#[test]
fn exact_frame_is_zeroed_again_before_successful_reuse_and_stale_cap_rejects() {
    let mut f = Fixture::<16>::new();
    let old = f.allocate(1);
    f.model.ram[0].fill(0xc3);
    assert_eq!(f.cap_call(1, OP_RELEASE, old).status, Status::Ok);
    let new = f.allocate(2);
    assert_eq!(
        f.model.policy.region_info(2, new).unwrap().backing.start(),
        0x10_0000
    );
    assert_eq!(f.model.ram[0], [0; 4096]);
    assert_eq!(f.cap_call(1, OP_RELEASE, old).status, Status::StaleHandle);
    assert_eq!(f.model.accounting(2).unwrap().charged_pages, 1);
}
