// Execute the actual timer/mapper policy against synthetic IO, never native
// privileged instructions. Hardware IRQ delivery and elapsed time need QEMU.
#![allow(dead_code)]
#[path = "../kernel/preempt_timer.rs"]
mod timer;
#[path = "../kernel/paging.rs"]
mod paging;
#[path = "../kernel/k02_paging.rs"]
mod k02_paging;
use timer::*;

#[derive(Clone)]
struct Model {
    flags: u64,
    supported: bool,
    apic: u64,
    pat: u64,
    mmio: [u64; 64],
    raw: u64,
    raw_step: u64,
    masks: [u8; 2],
    phase: [u8; 2],
    select: u8,
    irr: u8,
    isr: u8,
    reset_count: usize,
    eois: usize,
    writes: usize,
    bad_comparator: bool,
    ignore_reset: bool,
}
impl Model {
    fn new() -> Self {
        let mut mmio = [0; 64];
        mmio[0] = CAPABILITY;
        for offset in [0x100, 0x120, 0x140] { mmio[offset / 8] = 0x30; }
        Self { flags: 2, supported: true, apic: 0xfee0_0900,
            pat: 0x0007_0406_0007_0406, mmio, raw: 0, raw_step: 0,
            masks: [0xff; 2], phase: [0; 2], select: 0x0a, irr: 0, isr: 0,
            reset_count: 0, eois: 0, writes: 0, bad_comparator: false, ignore_reset: false }
    }
    fn at(&mut self, raw: u64) { self.raw = raw; }
    fn delivered(&mut self) { self.irr = 0; self.isr = 1; }
}
impl Hardware for Model {
    fn flags(&mut self) -> u64 { self.flags }
    fn supported(&mut self) -> bool { self.supported }
    fn msr(&mut self, index: u32) -> u64 { match index { 0x1b => self.apic, 0x277 => self.pat, _ => panic!("unexpected MSR") } }
    fn set_msr(&mut self, index: u32, value: u64) { assert_eq!(index, 0x1b); self.writes += 1; self.apic = value; }
    fn read(&mut self, offset: u64) -> u64 {
        if offset == 0xf0 {
            let raw = self.raw;
            self.raw = raw.saturating_add(self.raw_step);
            raw
        } else if offset == 0x108 && self.bad_comparator {
            self.mmio[offset as usize / 8] ^ 1
        } else { self.mmio[offset as usize / 8] }
    }
    fn write(&mut self, offset: u64, value: u64) {
        self.writes += 1;
        match offset {
            0xf0 => { assert_eq!(self.mmio[0x10 / 8] & 1, 0); self.raw = value; }
            0x100 | 0x120 | 0x140 => self.mmio[offset as usize / 8] = 0x30 | (value & 0x7f4e),
            0x20 => self.mmio[offset as usize / 8] &= !value,
            _ => self.mmio[offset as usize / 8] = value,
        }
    }
    fn input(&mut self, port: u16) -> u8 {
        match port { 0x21 => self.masks[0], 0xa1 => self.masks[1],
            0x20 => if self.select == 0x0b { self.isr } else { self.irr },
            _ => panic!("unexpected read port") }
    }
    fn output(&mut self, port: u16, value: u8) {
        self.writes += 1;
        match port {
            0x20 | 0xa0 => {
                let i = usize::from(port == 0xa0);
                if value == 0x11 {
                    self.phase[i] = 1;
                    if i == 0 { self.reset_count += 1; if !self.ignore_reset { self.irr = 0; self.isr = 0; } }
                } else if port == 0x20 && matches!(value, 0x0a | 0x0b) { self.select = value; }
                else if port == 0x20 && value == 0x60 { self.eois += 1; self.isr &= !1; }
                else { panic!("unexpected PIC command"); }
            }
            0x21 | 0xa1 => {
                let i = usize::from(port == 0xa1);
                if self.phase[i] != 0 {
                    self.phase[i] += 1;
                    if self.phase[i] == 4 { self.phase[i] = 0; }
                } else { self.masks[i] = value; }
            }
            0x4d0 | 0x4d1 => assert_eq!(value, 0),
            _ => panic!("unexpected write port"),
        }
    }
}
fn ready() -> Controller<Model> {
    let mut c = Controller::new(Model::new());
    c.initialize().unwrap();
    c
}

#[test]
fn conversion_is_exact_floor_and_comparator_ceil_without_wrapping() {
    assert_eq!(elapsed_ns(8, 3, PERIOD_FS), Ok(50));
    assert_eq!(elapsed_ns(3, 4, PERIOD_FS), Err(Error::Regression));
    assert_eq!(elapsed_ns(10, 0, 100_001), Ok(1));
    assert_eq!(deadline_raw(11, 7, PERIOD_FS), Ok(9));
    assert_eq!(deadline_raw(10, 7, PERIOD_FS), Ok(8));
    assert_eq!(deadline_raw(1, u64::MAX, PERIOD_FS), Err(Error::Overflow));
    assert_eq!(elapsed_ns(u64::MAX, 0, PERIOD_FS), Err(Error::Overflow));
    assert_eq!(deadline_raw(1, 0, 0), Err(Error::UnsupportedHpet));
}
#[test]
fn initialization_admits_exact_profile_masks_routes_and_disables_lapic() {
    let mut c = Controller::new(Model::new());
    let f = c.initialize().unwrap();
    assert_eq!((f.capability, f.period_fs, f.timer_count), (CAPABILITY, PERIOD_FS, 3));
    assert_eq!((f.master_mask, f.slave_mask), (255, 255));
    assert_eq!(f.apic_after, f.apic_before & !(1 << 11));
    assert_eq!(c.hardware().mmio[0x10 / 8], 3);
    for offset in [0x100, 0x120, 0x140] { assert_eq!(c.hardware().mmio[offset / 8], 0x30); }
    assert_eq!(c.initialize(), Err(Error::AlreadyInitialized));
}
#[test]
fn malformed_hpet_capabilities_period_or_feature_never_admit() {
    for bit in [0, 8, 13, 15, 32, 48] {
        let mut m = Model::new(); m.mmio[0] ^= 1 << bit;
        let mut c = Controller::new(m);
        assert_eq!(c.initialize(), Err(Error::UnsupportedHpet));
        assert_eq!(c.clock(), Err(Error::Blocked));
        assert_eq!(c.hardware().masks, [255, 255]);
    }
}
#[test]
fn cpu_pat_and_if_admission_happen_before_mmio_or_route_enable() {
    let mut m = Model::new(); m.flags |= 1 << 9;
    let mut c = Controller::new(m);
    assert_eq!(c.initialize(), Err(Error::InterruptsEnabled));
    assert_eq!(c.hardware().writes, 0);
    let mut m = Model::new(); m.apic |= 1 << 10;
    assert_eq!(Controller::new(m).initialize(), Err(Error::UnsupportedApic));
    let mut m = Model::new(); m.pat |= 6 << 24;
    assert_eq!(Controller::new(m).initialize(), Err(Error::UnsupportedPat));
    let mut m = Model::new(); m.supported = false;
    assert_eq!(Controller::new(m).initialize(), Err(Error::UnsupportedCpu));
}
#[test]
fn observed_clock_regression_and_overflow_stickily_block() {
    let mut c = ready(); c.hardware().at(100);
    assert_eq!(c.clock(), Ok(Sample { raw: 100, ns: 1000 }));
    c.hardware().at(99);
    assert_eq!(c.clock(), Err(Error::Regression));
    c.hardware().at(101); assert_eq!(c.clock(), Err(Error::Blocked));
    let mut c = ready(); c.hardware().at(u64::MAX);
    assert_eq!(c.clock(), Err(Error::Overflow));
    assert_eq!(c.hardware().masks, [255, 255]);
}
#[test]
fn real_irq_requires_exact_arm_expiry_and_pic_in_service_acknowledgement() {
    let mut c = ready(); c.hardware().at(10);
    let arm = c.arm(1000, 1).unwrap().unwrap();
    assert_eq!((arm.armed.raw, arm.target_raw, arm.readback_raw), (10, 100, 100));
    assert_eq!(c.hardware().masks, [254, 255]);
    c.hardware().at(105); c.hardware().delivered();
    let captured = c.capture_irq().unwrap();
    assert_eq!((captured.sample.ns, captured.arm.generation), (1050, 1));
    assert_eq!((captured.isr_before, captured.isr_after, captured.irr_after, captured.eoi), (1, 0, 0, 0x60));
    assert_eq!((c.hardware().eois, c.hardware().masks), (1, [255, 255]));
    assert_eq!(c.capture_irq(), Err(Error::Unarmed));
    assert_eq!(c.hardware().eois, 1);
}
#[test]
fn early_unarmed_and_forged_irqs_never_acknowledge_or_resume() {
    let mut c = ready(); assert_eq!(c.capture_irq(), Err(Error::Unarmed));
    let mut c = ready(); c.arm(1000, 1).unwrap(); c.hardware().at(99); c.hardware().delivered();
    assert_eq!(c.capture_irq(), Err(Error::EarlyIrq)); assert_eq!(c.hardware().eois, 0);
    let mut c = ready(); c.arm(1000, 1).unwrap(); c.hardware().at(100);
    assert_eq!(c.capture_irq(), Err(Error::InvalidIrq)); assert_eq!(c.hardware().eois, 0);
}
#[test]
fn cancellation_drains_irq_pending_while_kernel_if_is_zero() {
    let mut c = ready(); c.arm(1000, 1).unwrap();
    c.hardware().at(110); c.hardware().irr = 1;
    let cancel = c.cancel().unwrap();
    assert_eq!((cancel.generation, cancel.sample.ns, cancel.pending_before, cancel.pending_after), (1, 1100, 1, 0));
    assert_eq!((cancel.isr_after, c.hardware().eois), (0, 0));
    // A fresh owner cannot receive that old pending pulse. Its genuine IRQ has
    // an independent nonrecycled generation and its own comparator timestamp.
    let second = c.arm(2000, 2).unwrap().unwrap();
    assert_eq!(c.hardware().irr, 0);
    c.hardware().at(second.target_raw); c.hardware().delivered();
    assert_eq!(c.capture_irq().unwrap().arm.generation, 2);
}
#[test]
fn pending_observation_retains_arm_without_acknowledgement_or_cancellation() {
    let mut c = ready();
    let arm = c.arm(1000, 9).unwrap().unwrap();
    let config = c.hardware().mmio[0x100 / 8];
    let resets = c.hardware().reset_count;
    assert_eq!(c.pending_irq(), Ok(0));
    c.hardware().irr = 1;
    assert_eq!(c.pending_irq(), Ok(1));
    assert_eq!(c.pending_irq(), Ok(1));
    assert_eq!((c.hardware().eois, c.hardware().reset_count), (0, resets));
    assert_eq!((c.hardware().masks, c.hardware().mmio[0x100 / 8]), ([254, 255], config));
    assert_eq!(c.hardware().mmio[0x108 / 8], arm.target_raw);
    c.hardware().at(arm.target_raw); c.hardware().delivered();
    assert_eq!(c.capture_irq().unwrap().arm, arm);
    let mut c = ready(); assert_eq!(c.pending_irq(), Err(Error::Unarmed));
    let mut c = ready(); c.arm(1000, 1).unwrap(); c.hardware().irr = 2;
    assert_eq!(c.pending_irq(), Err(Error::InvalidIrq));
    assert_eq!(c.cancel(), Err(Error::Blocked));
}
#[test]
fn cancellation_rejects_unknown_pending_or_acknowledged_pic_owners() {
    for (pending, in_service) in [(2, 0), (0, 1), (0, 2), (1, 1)] {
        let mut c = ready(); c.arm(1000, 1).unwrap();
        let resets = c.hardware().reset_count;
        c.hardware().irr = pending; c.hardware().isr = in_service;
        assert_eq!(c.cancel(), Err(Error::InvalidIrq));
        // Preserve the unexpected ownership for terminal diagnosis. No EOI or
        // PIC reset may turn it into a context eligible for another dispatch.
        assert_eq!((c.hardware().irr, c.hardware().isr), (pending, in_service));
        assert_eq!((c.hardware().reset_count, c.hardware().eois), (resets, 0));
        assert_eq!(c.hardware().masks, [255, 255]);
        assert_eq!(c.clock(), Err(Error::Blocked));
        assert_eq!(c.arm(2000, 2), Err(Error::Blocked));
    }
}
#[test]
fn stale_zero_and_simultaneous_arm_generations_fail_closed() {
    let mut c = ready(); assert_eq!(c.arm(1000, 0), Err(Error::Generation));
    let mut c = ready(); c.arm(1000, 1).unwrap(); c.cancel().unwrap();
    assert_eq!(c.arm(1000, 1), Err(Error::Generation));
    let mut c = ready(); c.arm(1000, 1).unwrap();
    assert_eq!(c.arm(2000, 2), Err(Error::Armed));
    assert_eq!(c.hardware().masks, [255, 255]);
}
#[test]
fn bad_readback_and_failed_pending_drain_remain_fatal() {
    let mut c = ready(); c.hardware().bad_comparator = true;
    assert_eq!(c.arm(1000, 1), Err(Error::Hardware));
    let mut c = ready(); c.arm(1000, 1).unwrap();
    c.hardware().ignore_reset = true; c.hardware().irr = 1;
    assert_eq!(c.cancel(), Err(Error::Hardware));
    assert_eq!(c.clock(), Err(Error::Blocked));
}
#[test]
fn missed_soft_time_before_programming_consumes_grant_without_blocking_peer() {
    let mut c = ready(); c.hardware().at(100);
    c.hardware().irr = 1;
    assert_eq!(c.arm(1000, 1), Ok(None));
    assert_eq!((c.hardware().masks, c.hardware().irr, c.hardware().isr), ([255, 255], 0, 0));
    assert_eq!(c.hardware().mmio[0x100 / 8] & 0x7f4e, 0);
    assert_eq!(c.clock(), Ok(Sample { raw: 100, ns: 1000 }));
    let next = c.arm(2000, 2).unwrap().unwrap();
    c.hardware().at(next.target_raw); c.hardware().delivered();
    assert_eq!(c.capture_irq().unwrap().arm.generation, 2);
    // A separate owner may not retry the grant that never entered CPL3.
    let mut c = ready(); assert_eq!(c.arm(0, 7), Ok(None));
    assert_eq!(c.arm(1000, 7), Err(Error::Generation));
}
#[test]
fn missed_soft_time_during_programming_drains_source_and_next_owner_runs() {
    let mut c = ready(); c.hardware().raw_step = 100;
    assert_eq!(c.arm(500, 4), Ok(None));
    assert_eq!((c.hardware().masks, c.hardware().irr, c.hardware().isr), ([255, 255], 0, 0));
    assert_eq!(c.hardware().mmio[0x100 / 8] & 0x7f4e, 0);
    c.hardware().raw_step = 0;
    let next = c.arm(5000, 5).unwrap().unwrap();
    c.hardware().at(next.target_raw); c.hardware().delivered();
    assert_eq!(c.capture_irq().unwrap().arm.generation, 5);
    let mut c = ready(); c.hardware().raw_step = 100;
    assert_eq!(c.arm(500, 4), Ok(None));
    c.hardware().raw_step = 0;
    assert_eq!(c.arm(5000, 4), Err(Error::Generation));
}
#[test]
fn if_violation_blocks_resume_and_shutdown_masks_the_source() {
    let mut c = ready(); c.arm(1000, 1).unwrap();
    c.hardware().flags |= 1 << 9;
    assert_eq!(c.clock(), Err(Error::InterruptsEnabled));
    assert_eq!(c.cancel(), Err(Error::Blocked));
    let mut c = ready(); c.arm(1000, 1).unwrap();
    assert_eq!(c.shutdown().unwrap().generation, 1);
    assert_eq!((c.hardware().mmio[0x10 / 8], c.hardware().masks), (2, [255, 255]));
    assert_eq!(c.clock(), Err(Error::Blocked));
}
#[test]
fn kernel_uc_change_preserves_identity_counts_and_other_leaves() {
    let mut t = paging::Tables::empty(); t.reset(48, 0x20_0000).unwrap();
    assert!(t.set_hpet_uncached().is_err());
    t.map_range(paging::Range { start: 0, end: paging::LOW_LIMIT }).unwrap();
    let counts = (t.table_count(), t.leaf_count());
    assert!(!t.hpet_uncached().unwrap());
    t.set_hpet_uncached().unwrap(); t.set_hpet_uncached().unwrap();
    assert!(t.hpet_uncached().unwrap());
    assert_eq!(counts, (t.table_count(), t.leaf_count()));
    for address in [0, 0xfebf_ffff, HPET_BASE, 0xfedf_ffff, 0xfee0_0000, paging::LOW_LIMIT - 1] {
        assert_eq!(t.translation(address), Some(address));
    }
}
#[test]
fn both_private_roots_keep_hpet_supervisor_nx_uc_and_seal_after_user_install() {
    use k02_paging::{Tables, UserAccess, Error as PageError};
    let mut a = Tables::<16>::empty(); a.reset(48, 0x20_0000).unwrap();
    let mut b = Tables::<16>::empty(); b.reset(48, 0x40_0000).unwrap();
    for t in [&mut a, &mut b] {
        t.map_supervisor_range(paging::Range { start: 0, end: paging::LOW_LIMIT }).unwrap();
        let count = t.table_count();
        t.set_hpet_uncached().unwrap(); t.set_hpet_uncached().unwrap();
        t.map_supervisor_range(paging::Range { start: 0, end: paging::LOW_LIMIT }).unwrap();
        assert_eq!(t.table_count(), count);
        let hpet = t.translate(HPET_BASE).unwrap();
        assert!(t.hpet_uncached().unwrap());
        assert!(!hpet.user && !hpet.executable && hpet.writable);
        assert_eq!((hpet.physical, hpet.page_bytes), (HPET_BASE, paging::HUGE_PAGE));
        assert_eq!(t.user_translation(HPET_BASE), None);
        assert!(t.translate(0xfee0_0000).unwrap().executable);
        t.map_data(paging::LOW_LIMIT, 0x100_0000, UserAccess::ReadOnly).unwrap();
        assert_eq!(t.set_hpet_uncached(), Err(PageError::SupervisorSealed));
        t.validate().unwrap();
    }
}
