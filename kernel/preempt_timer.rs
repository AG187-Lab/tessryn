//! Frozen single-CPU QEMU q35 HPET/PIC adapter. It qualifies emulator virtual
//! elapsed time only, not a physical clock, interrupt-latency bound or SMP.
//!
//! Primary implementation references (the toolchain pins QEMU 11.1.2):
//! https://gitlab.com/qemu-project/qemu/-/blob/v11.1.2/hw/timer/hpet.c
//! https://gitlab.com/qemu-project/qemu/-/blob/v11.1.2/include/hw/timer/hpet.h
//! https://gitlab.com/qemu-project/qemu/-/blob/v11.1.2/hw/intc/i8259.c
//! https://gitlab.com/qemu-project/qemu/-/blob/v11.1.2/hw/i386/x86-cpu.c
//!
//! Trusted caller contract: NXE is enabled and the fixed HPET identity leaf is
//! supervisor UC/NX in every root before calling this module. No user reference
//! or mutable policy/MMU borrow crosses entry. All hardware operations require
//! IF=0. The sole IRQ is delivered while executing CPL3 with IF=1; the CPU owner
//! validates that raw frame before capture_irq. There is no STI or kernel idle.

#[cfg(target_arch = "x86_64")]
use core::arch::{asm, x86_64::__cpuid};
#[cfg(target_arch = "x86_64")]
use core::ptr;

pub const HPET_BASE: u64 = 0xfed0_0000;
pub const VECTOR: u64 = 32;
pub const PERIOD_FS: u64 = 10_000_000;
pub const CAPABILITY: u64 = (PERIOD_FS << 32) | 0x8086_a201;
const GENERAL: u64 = 0x10;
const STATUS: u64 = 0x20;
const COUNTER: u64 = 0xf0;
const TIMER0: u64 = 0x100;
const COMPARATOR0: u64 = 0x108;
const WRITABLE_TIMER: u64 = 0x7f4e;
const APIC_BASE: u32 = 0x1b;
const PAT: u32 = 0x277;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InterruptsEnabled, UnsupportedCpu, UnsupportedApic, UnsupportedPat,
    UnsupportedHpet, NotInitialized, AlreadyInitialized, Blocked, Hardware,
    Regression, Overflow, Armed, Unarmed, Generation, EarlyIrq,
    InvalidIrq,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample { pub raw: u64, pub ns: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub capability: u64,
    pub period_fs: u64,
    pub epoch_raw: u64,
    pub timer_count: u64,
    pub apic_before: u64,
    pub apic_after: u64,
    pub pat: u64,
    pub master_mask: u8,
    pub slave_mask: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm {
    pub generation: u64,
    pub armed: Sample,
    pub soft_ns: u64,
    pub target_raw: u64,
    pub readback_raw: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capture {
    pub sample: Sample,
    pub arm: Arm,
    pub isr_before: u8,
    pub isr_after: u8,
    pub irr_after: u8,
    pub eoi: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancellation {
    pub sample: Sample,
    pub generation: u64,
    pub pending_before: u8,
    pub isr_before: u8,
    pub pending_after: u8,
    pub isr_after: u8,
}

/// Hardware access is injected only by trusted kernel code or host models.
/// Native callers use the fixed global wrappers below, never user-supplied IO.
pub trait Hardware {
    fn flags(&mut self) -> u64;
    fn supported(&mut self) -> bool;
    fn msr(&mut self, index: u32) -> u64;
    fn set_msr(&mut self, index: u32, value: u64);
    fn read(&mut self, offset: u64) -> u64;
    fn write(&mut self, offset: u64, value: u64);
    fn input(&mut self, port: u16) -> u8;
    fn output(&mut self, port: u16, value: u8);
}

pub fn elapsed_ns(raw: u64, epoch: u64, period_fs: u64) -> Result<u64, Error> {
    if period_fs == 0 { return Err(Error::UnsupportedHpet); }
    let ticks = raw.checked_sub(epoch).ok_or(Error::Regression)?;
    let ns = u128::from(ticks).checked_mul(u128::from(period_fs)).ok_or(Error::Overflow)? / 1_000_000;
    u64::try_from(ns).map_err(|_| Error::Overflow)
}
pub fn deadline_raw(ns: u64, epoch: u64, period_fs: u64) -> Result<u64, Error> {
    if period_fs == 0 { return Err(Error::UnsupportedHpet); }
    // Round upward: an absolute comparator must not fire before its soft time.
    let fs = u128::from(ns) * 1_000_000;
    let ticks = fs.div_ceil(u128::from(period_fs));
    epoch.checked_add(u64::try_from(ticks).map_err(|_| Error::Overflow)?).ok_or(Error::Overflow)
}

pub struct Controller<H: Hardware> {
    io: H,
    ready: bool,
    blocked: bool,
    epoch: u64,
    last: Sample,
    generation: u64,
    armed: Option<Arm>,
}
impl<H: Hardware> Controller<H> {
    pub const fn new(io: H) -> Self {
        Self { io, ready: false, blocked: false, epoch: 0,
            last: Sample { raw: 0, ns: 0 }, generation: 0, armed: None }
    }
    fn gate(&mut self, require_ready: bool) -> Result<(), Error> {
        if self.blocked { return Err(Error::Blocked); }
        if self.io.flags() & (1 << 9) != 0 { return self.abort(Error::InterruptsEnabled); }
        if require_ready && !self.ready { return Err(Error::NotInitialized); }
        Ok(())
    }
    fn abort<T>(&mut self, error: Error) -> Result<T, Error> {
        // An error never licenses another user entry. Where initialized and IF0,
        // mask the source immediately; the owner treats every error as fatal.
        self.blocked = true;
        if self.ready && self.io.flags() & (1 << 9) == 0 {
            self.io.output(0x21, 0xff);
            self.io.output(0xa1, 0xff);
            self.io.write(TIMER0, 0);
        }
        Err(error)
    }
    fn registers(&mut self, command: u8) -> u8 {
        self.io.output(0x20, command);
        self.io.input(0x20)
    }
    fn pic_reset(&mut self) -> Result<(), Error> {
        self.io.output(0x21, 0xff);
        self.io.output(0xa1, 0xff);
        // ICW1 resets pending/in-service state. No auto EOI; cascade is masked.
        self.io.output(0x20, 0x11);
        self.io.output(0xa0, 0x11);
        self.io.output(0x21, VECTOR as u8);
        self.io.output(0xa1, VECTOR as u8 + 8);
        self.io.output(0x21, 4);
        self.io.output(0xa1, 2);
        self.io.output(0x21, 1);
        self.io.output(0xa1, 1);
        self.io.output(0x21, 0xff);
        self.io.output(0xa1, 0xff);
        // Edge-trigger IRQ0, all slave sources remain masked.
        self.io.output(0x4d0, 0);
        self.io.output(0x4d1, 0);
        if self.io.input(0x21) != 0xff || self.io.input(0xa1) != 0xff
            || self.registers(0x0a) != 0 || self.registers(0x0b) != 0 {
            return self.abort(Error::Hardware);
        }
        Ok(())
    }
    fn disable(&mut self) -> Result<(), Error> {
        self.io.output(0x21, 0xff);
        self.io.write(TIMER0, 0);
        self.io.write(STATUS, 1);
        if self.io.read(TIMER0) & WRITABLE_TIMER != 0 { return self.abort(Error::Hardware); }
        Ok(())
    }
    pub fn initialize(&mut self) -> Result<Facts, Error> {
        self.gate(false)?;
        if self.ready { return Err(Error::AlreadyInitialized); }
        if !self.io.supported() { return self.abort(Error::UnsupportedCpu); }
        let apic_before = self.io.msr(APIC_BASE);
        if apic_before & (1 << 10) != 0 { return self.abort(Error::UnsupportedApic); }
        let pat = self.io.msr(PAT);
        if (pat >> 24) & 0xff != 0 { return self.abort(Error::UnsupportedPat); }
        self.io.set_msr(APIC_BASE, apic_before & !(1 << 11));
        let apic_after = self.io.msr(APIC_BASE);
        if apic_after != apic_before & !(1 << 11) { return self.abort(Error::Hardware); }
        self.pic_reset()?;
        let capability = self.io.read(0);
        if capability != CAPABILITY { return self.abort(Error::UnsupportedHpet); }
        self.io.write(GENERAL, 0);
        for i in 0..3 {
            self.io.write(TIMER0 + i * 0x20, 0);
            if self.io.read(TIMER0 + i * 0x20) & WRITABLE_TIMER != 0 {
                return self.abort(Error::Hardware);
            }
        }
        self.io.write(STATUS, 7);
        self.io.write(COUNTER, 0);
        if self.io.read(COUNTER) != 0 { return self.abort(Error::Hardware); }
        self.io.write(GENERAL, 3); // counter on, legacy replacement on (PIT off).
        if self.io.read(GENERAL) != 3 { return self.abort(Error::Hardware); }
        self.epoch = self.io.read(COUNTER);
        self.last = Sample { raw: self.epoch, ns: 0 };
        self.ready = true;
        Ok(Facts { capability, period_fs: PERIOD_FS, epoch_raw: self.epoch,
            timer_count: 3, apic_before, apic_after, pat,
            master_mask: self.io.input(0x21), slave_mask: self.io.input(0xa1) })
    }
    pub fn clock(&mut self) -> Result<Sample, Error> {
        self.gate(true)?;
        let raw = self.io.read(COUNTER);
        if raw < self.last.raw { return self.abort(Error::Regression); }
        let ns = match elapsed_ns(raw, self.epoch, PERIOD_FS) {
            Ok(value) => value, Err(error) => return self.abort(error),
        };
        if ns < self.last.ns { return self.abort(Error::Regression); }
        let sample = Sample { raw, ns };
        self.last = sample;
        Ok(sample)
    }
    fn missed_arm(&mut self, generation: u64) -> Result<Option<Arm>, Error> {
        self.disable()?;
        self.pic_reset()?;
        // The policy still owns this unstarted grant until its trusted owner
        // stops/charges it. Consuming the hardware generation prohibits retry
        // of that grant, without blocking an unrelated domain's next grant.
        self.generation = generation;
        self.armed = None;
        Ok(None)
    }
    /// None means the advisory soft time was already missed: no user entry is
    /// authorized, and the source is disabled with IRR/ISR drained. The owner
    /// must stop this exact unstarted policy grant using actual elapsed time.
    /// All hardware, clock and identity failures remain globally blocking.
    pub fn arm(&mut self, soft_ns: u64, generation: u64) -> Result<Option<Arm>, Error> {
        self.gate(true)?;
        if self.armed.is_some() { return self.abort(Error::Armed); }
        if generation == 0 || generation <= self.generation { return self.abort(Error::Generation); }
        let armed = self.clock()?;
        if soft_ns <= armed.ns { return self.missed_arm(generation); }
        let target_raw = match deadline_raw(soft_ns, self.epoch, PERIOD_FS) {
            Ok(value) => value, Err(error) => return self.abort(error),
        };
        self.disable()?;
        self.pic_reset()?;
        self.io.write(COMPARATOR0, target_raw);
        let readback_raw = self.io.read(COMPARATOR0);
        if readback_raw != target_raw { return self.abort(Error::Hardware); }
        self.io.write(TIMER0, 4); // one-shot, edge, 64bit, no FSB/MSI.
        if self.io.read(TIMER0) & WRITABLE_TIMER != 4 { return self.abort(Error::Hardware); }
        self.io.output(0x21, 0xfe);
        if self.io.input(0x21) != 0xfe { return self.abort(Error::Hardware); }
        // Catch a comparator that elapsed during programming. No user entry is
        // allowed to inherit an already overdue arm.
        let after = self.clock()?;
        if after.raw >= target_raw { return self.missed_arm(generation); }
        let arm = Arm { generation, armed, soft_ns, target_raw, readback_raw };
        self.generation = generation;
        self.armed = Some(arm);
        Ok(Some(arm))
    }
    pub fn capture_irq(&mut self) -> Result<Capture, Error> {
        self.gate(true)?;
        let sample = self.clock()?; // first observation, before serial output.
        let Some(arm) = self.armed else { return self.abort(Error::Unarmed); };
        if sample.raw < arm.target_raw { return self.abort(Error::EarlyIrq); }
        let isr_before = self.registers(0x0b);
        if isr_before != 1 { return self.abort(Error::InvalidIrq); }
        self.disable()?;
        self.io.output(0x20, 0x60); // specific EOI IRQ0, never slave EOI.
        let isr_after = self.registers(0x0b);
        if isr_after != 0 { return self.abort(Error::Hardware); }
        self.pic_reset()?;
        let irr_after = self.registers(0x0a);
        self.armed = None;
        Ok(Capture { sample, arm, isr_before, isr_after, irr_after, eoi: 0x60 })
    }
    /// Trusted fixture observation while its current arm is retained and IF0.
    /// Selecting/reading IRR does not acknowledge, cancel or transfer the arm.
    /// The fixture polls the real clock separately; IRQ counts are never time.
    pub fn pending_irq(&mut self) -> Result<u8, Error> {
        self.gate(true)?;
        if self.armed.is_none() { return self.abort(Error::Unarmed); }
        let pending = self.registers(0x0a);
        if pending & !1 != 0 { return self.abort(Error::InvalidIrq); }
        Ok(pending)
    }
    pub fn cancel(&mut self) -> Result<Cancellation, Error> {
        self.gate(true)?;
        let sample = self.clock()?;
        let generation = self.armed.map_or(0, |arm| arm.generation);
        self.disable()?;
        let pending_before = self.registers(0x0a);
        let isr_before = self.registers(0x0b);
        // Ordinary syscall/fault cancellation can retain an unacknowledged
        // IRQ0 pulse, but it cannot own an acknowledged hardware interrupt.
        // Never normalize an unknown source/in-service owner into a clean arm.
        if pending_before & !1 != 0 || isr_before != 0 {
            return self.abort(Error::InvalidIrq);
        }
        // ICW1 clears IRR, unlike EOI. A comparator that expired with IF0 after
        // INT80 cannot transfer an old interrupt into the next dispatch.
        self.pic_reset()?;
        let pending_after = self.registers(0x0a);
        let isr_after = self.registers(0x0b);
        self.armed = None;
        Ok(Cancellation { sample, generation, pending_before, isr_before,
            pending_after, isr_after })
    }
    pub fn shutdown(&mut self) -> Result<Cancellation, Error> {
        let cancellation = self.cancel()?;
        // Leave legacy replacement active, all comparators/PIC lines masked,
        // and freeze the counter. Do not resurrect the firmware PIT/RTC route.
        self.io.write(GENERAL, 2);
        if self.io.read(GENERAL) != 2 { return self.abort(Error::Hardware); }
        self.ready = false;
        self.blocked = true;
        Ok(cancellation)
    }
    #[cfg(test)]
    pub fn hardware(&mut self) -> &mut H { &mut self.io }
}

#[cfg(target_arch = "x86_64")]
pub struct Native;
#[cfg(target_arch = "x86_64")]
impl Hardware for Native {
    fn flags(&mut self) -> u64 {
        let value;
        unsafe { asm!("pushfq", "pop {}", out(reg) value, options(preserves_flags)); }
        value
    }
    fn supported(&mut self) -> bool {
        let features = __cpuid(1).edx;
        features & ((1 << 5) | (1 << 9) | (1 << 16)) == (1 << 5) | (1 << 9) | (1 << 16)
    }
    fn msr(&mut self, index: u32) -> u64 {
        let (low, high): (u32, u32);
        unsafe { asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high, options(nostack)); }
        u64::from(low) | (u64::from(high) << 32)
    }
    fn set_msr(&mut self, index: u32, value: u64) {
        unsafe { asm!("wrmsr", in("ecx") index, in("eax") value as u32,
            in("edx") (value >> 32) as u32, options(nostack)); }
    }
    fn read(&mut self, offset: u64) -> u64 {
        unsafe { ((HPET_BASE + offset) as *const u64).read_volatile() }
    }
    fn write(&mut self, offset: u64, value: u64) {
        unsafe { ((HPET_BASE + offset) as *mut u64).write_volatile(value); }
    }
    fn input(&mut self, port: u16) -> u8 {
        let value;
        unsafe { asm!("in al, dx", in("dx") port, out("al") value, options(nostack)); }
        value
    }
    fn output(&mut self, port: u16, value: u8) {
        unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nostack)); }
    }
}
#[cfg(target_arch = "x86_64")]
static mut TIMER: Controller<Native> = Controller::new(Native);
// All wrapper calls check IF0 before hardware access. The single boot CPU never
// retains a reference to TIMER across CPL3 entry; there are no callback aliases.
#[cfg(target_arch = "x86_64")]
pub fn initialize() -> Result<Facts, Error> { unsafe { (&mut *ptr::addr_of_mut!(TIMER)).initialize() } }
#[cfg(target_arch = "x86_64")]
pub fn clock() -> Result<Sample, Error> { unsafe { (&mut *ptr::addr_of_mut!(TIMER)).clock() } }
#[cfg(target_arch = "x86_64")]
pub fn arm(soft_ns: u64, generation: u64) -> Result<Option<Arm>, Error> { unsafe { (&mut *ptr::addr_of_mut!(TIMER)).arm(soft_ns, generation) } }
#[cfg(target_arch = "x86_64")]
pub fn capture_irq() -> Result<Capture, Error> { unsafe { (&mut *ptr::addr_of_mut!(TIMER)).capture_irq() } }
#[cfg(target_arch = "x86_64")]
pub fn pending_irq() -> Result<u8, Error> { unsafe { (&mut *ptr::addr_of_mut!(TIMER)).pending_irq() } }
#[cfg(target_arch = "x86_64")]
pub fn cancel() -> Result<Cancellation, Error> { unsafe { (&mut *ptr::addr_of_mut!(TIMER)).cancel() } }
#[cfg(target_arch = "x86_64")]
pub fn shutdown() -> Result<Cancellation, Error> { unsafe { (&mut *ptr::addr_of_mut!(TIMER)).shutdown() } }
