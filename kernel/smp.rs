//! Opt-in two-CPU kernel bootstrap. No user tasks, scheduler, dynamic mappings,
//! reclamation or performance claim. All memory remains retained until exit.
//! AP never calls diagnostics; its only shared writable state is atomic.
use core::arch::{asm, global_asm, x86_64::__cpuid};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering, fence};
use crate::diagnostics::{fail, finish, print};

global_asm!(include_str!("smp_entry.S"));
const LAPIC: u64 = 0xfee0_0000;
const HPET: u64 = 0xfed0_0000;
const TIMEOUT_NS: u64 = 2_000_000_000;
const ITERATIONS: u64 = 4096;
#[repr(C)]
pub struct Contract { magic: [u8; 16], words: [u64; 10] }
#[used]
#[unsafe(no_mangle)]
pub static K03_SMP_CONTRACT: Contract = Contract {
    magic: *b"TESSRYN-SMP1\0\0\0\0",
    words: [1, cfg!(smp_case = "missing_ap") as u64, 2, LAPIC, HPET, 10_000_000, 64, 65, ITERATIONS, TIMEOUT_NS],
};
unsafe extern "sysv64" {
    static smp_trampoline_start: u8;
    static smp_trampoline_end: u8;
    static smp_trampoline_far: u8;
    static smp_trampoline_long: u8;
    fn smp_load_gdt(pointer: *const Pointer);
    fn smp_ipi_64();
    fn smp_stop_65();
    fn smp_unexpected();
    fn smp_spurious();
    fn smp_heartbeat_start(counter: *const AtomicU64) -> !;
    static smp_heartbeat_end: u8;
}
#[repr(C, packed)]
struct Pointer { limit: u16, base: u64 }
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Gate { low: u16, selector: u16, ist: u8, flags: u8, middle: u16, high: u32, reserved: u32 }
const EMPTY: Gate = Gate { low: 0, selector: 0, ist: 0, flags: 0, middle: 0, high: 0, reserved: 0 };
impl Gate {
    fn new(address: usize, ist: u8) -> Self {
        Self { low: address as u16, selector: 8, ist, flags: 0x8e,
            middle: (address >> 16) as u16, high: (address >> 32) as u32, reserved: 0 }
    }
}
#[repr(C, packed)]
struct Tss { reserved0: u32, rsp: [u64; 3], reserved1: u64, ist: [u64; 7], reserved2: u64, reserved3: u16, iomap: u16 }
#[repr(C, align(4096))]
struct Stack([u8; 64 * 1024]);
static mut AP_STACK: Stack = Stack([0; 64 * 1024]);
static mut AP_FAULT_STACK: Stack = Stack([0; 64 * 1024]);
static mut AP_TSS: Tss = Tss { reserved0: 0, rsp: [0; 3], reserved1: 0, ist: [0; 7], reserved2: 0, reserved3: 0, iomap: 104 };
static mut AP_GDT: [u64; 5] = [0, 0x00af_9a00_0000_ffff, 0x00cf_9200_0000_ffff, 0, 0];
static mut AP_IDT: [Gate; 256] = [EMPTY; 256];
static EXPECTED_AP: AtomicU64 = AtomicU64::new(u64::MAX);
static ROOT: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static ERROR: AtomicU64 = AtomicU64::new(0);
static GO: AtomicU64 = AtomicU64::new(0);
static AP_WORK: AtomicU64 = AtomicU64::new(0);
static BSP_WORK: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);
static AP_HEARTBEAT: AtomicU64 = AtomicU64::new(0);
static BSP_HEARTBEAT: AtomicU64 = AtomicU64::new(0);
static REQUEST: AtomicU64 = AtomicU64::new(0);
static ACK: AtomicU64 = AtomicU64::new(0);
static STOP_ACK: AtomicU64 = AtomicU64::new(0);
static ISR_BEFORE: AtomicU64 = AtomicU64::new(0);
static ISR_AFTER: AtomicU64 = AtomicU64::new(0);
static FACTS: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
static TRAP: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
const _: () = { assert!(size_of::<Tss>() == 104); assert!(size_of::<Gate>() == 16); assert!(size_of::<Pointer>() == 10); };

fn id() -> u64 { (__cpuid(1).ebx >> 24) as u64 }
fn msr(index: u32) -> u64 {
    let (a, d): (u32, u32);
    unsafe { asm!("rdmsr", in("ecx") index, out("eax") a, out("edx") d, options(nostack)); }
    u64::from(a) | (u64::from(d) << 32)
}
unsafe fn set_msr(index: u32, value: u64) {
    unsafe { asm!("wrmsr", in("ecx") index, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nostack)); }
}
fn read(base: u64, offset: u64) -> u32 { unsafe { ((base + offset) as *const u32).read_volatile() } }
fn write(offset: u64, value: u32) { unsafe { ((LAPIC + offset) as *mut u32).write_volatile(value); } }
fn clock() -> u64 { unsafe { ((HPET + 0xf0) as *const u64).read_volatile() } }
fn elapsed(start: u64, now: u64) -> u64 {
    now.checked_sub(start).and_then(|n| n.checked_mul(10)).unwrap_or_else(|| fail("smp-clock-regression"))
}
fn wait_ns(ns: u64) {
    let start = clock();
    let mut polls = 0u64;
    while elapsed(start, clock()) < ns {
        polls += 1;
        if polls > 200_000_000 { fail("smp-clock-stalled"); }
        core::hint::spin_loop();
    }
}
fn wait_for(value: &AtomicU64, expected: u64) -> bool {
    let start = clock();
    for _ in 0..200_000_000 {
        if ERROR.load(Ordering::Acquire) != 0 { fail("smp-ap-failure"); }
        if value.load(Ordering::Acquire) == expected { return true; }
        if elapsed(start, clock()) >= TIMEOUT_NS { return false; }
        core::hint::spin_loop();
    }
    fail("smp-clock-stalled")
}
fn send(destination: u64, command: u32) {
    let start = clock();
    let mut polls = 0u64;
    while read(LAPIC, 0x300) & (1 << 12) != 0 {
        polls += 1;
        if elapsed(start, clock()) >= TIMEOUT_NS || polls > 200_000_000 { fail("smp-icr-timeout"); }
    }
    write(0x310, (destination as u32) << 24);
    write(0x300, command);
    // INIT/SIPI delay intervals begin after the local APIC has dispatched the
    // command. Delivery completion still does not mean the peer is online.
    while read(LAPIC, 0x300) & (1 << 12) != 0 {
        polls += 1;
        if elapsed(start, clock()) >= TIMEOUT_NS || polls > 200_000_000 { fail("smp-icr-timeout"); }
    }
}
fn ensure(ok: bool) { if !ok { panic_park_if_ap(); fail("smp-profile"); } }
fn enable_lapic() {
    let base = msr(0x1b);
    ensure(base & 0xffff_ffff_ffff_f000 == LAPIC && base & (1 << 10) == 0 && base & (1 << 11) != 0);
    ensure((msr(0x277) >> 24) & 0xff == 0); // PAT[3] UC, never assume INIT reset it.
    for offset in [0x320, 0x330, 0x340, 0x350, 0x360, 0x370] { write(offset, 1 << 16); }
    write(0x80, 0);
    write(0xf0, 0x1ff);
    ensure(read(LAPIC, 0x20) >> 24 == id() as u32 && read(LAPIC, 0xf0) & 0x1ff == 0x1ff);
}
fn facts(stack_start: u64, stack_end: u64) -> [u64; 9] {
    let mut gdt = Pointer { limit: 0, base: 0 };
    let mut idt = Pointer { limit: 0, base: 0 };
    let (rsp, rip, root): (u64, u64, u64);
    let tr: u16;
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut gdt, options(nostack));
        asm!("sidt [{}]", in(reg) &mut idt, options(nostack));
        asm!("str {0:x}", out(reg) tr, options(nomem, nostack));
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
        asm!("lea {}, [rip]", out(reg) rip, options(nomem, nostack));
        asm!("mov {}, cr3", out(reg) root, options(nomem, nostack));
    }
    ensure(tr == 24 && gdt.limit == 39 && idt.limit == 4095 && rsp >= stack_start && rsp < stack_end);
    let low = unsafe { ((gdt.base + 24) as *const u64).read_unaligned() };
    let high = unsafe { ((gdt.base + 32) as *const u64).read_unaligned() };
    let tss = ((low >> 16) & 0xff_ffff) | ((low >> 32) & 0xff00_0000) | (high << 32);
    [id(), rsp, rip, gdt.base, idt.base, tss, root, stack_start, stack_end]
}
fn print_cpu(cpu: usize, f: [u64; 9]) {
    print(format_args!("TESSRYN_K03_SMP_CPU cpu={cpu} apic={} rsp={:#x} rip={:#x} gdt={:#x} idt={:#x} tss={:#x} cr3={:#x} stack_start={:#x} stack_end={:#x}\n",
        f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]));
}
pub fn panic_park_if_ap() { if msr(0x1b) & (1 << 8) == 0 { smp_ap_fail(); } }
#[unsafe(no_mangle)]
pub extern "sysv64" fn smp_ap_fail() -> ! {
    ERROR.store(1, Ordering::Release);
    unsafe { asm!("2: cli", "hlt", "jmp 2b", options(noreturn)); }
}
#[unsafe(no_mangle)]
pub extern "sysv64" fn smp_ap_entry() -> ! {
    if id() != EXPECTED_AP.load(Ordering::Acquire) { smp_ap_fail(); }
    let start = ptr::addr_of!(AP_STACK) as u64;
    let end = start + size_of::<Stack>() as u64;
    unsafe {
        let tss = ptr::addr_of_mut!(AP_TSS);
        ptr::write_unaligned(ptr::addr_of_mut!((*tss).rsp).cast::<u64>(), end);
        ptr::write_unaligned(ptr::addr_of_mut!((*tss).ist).cast::<u64>(), ptr::addr_of!(AP_FAULT_STACK) as u64 + size_of::<Stack>() as u64);
        let base = tss as u64;
        let limit = 103;
        let gdt = ptr::addr_of_mut!(AP_GDT).cast::<u64>();
        gdt.add(3).write(limit | ((base & 0xff_ffff) << 16) | (0x89 << 40) | ((base & 0xff00_0000) << 32));
        gdt.add(4).write(base >> 32);
        smp_load_gdt(&Pointer { limit: 39, base: gdt as u64 });
        let idt = ptr::addr_of_mut!(AP_IDT).cast::<Gate>();
        for vector in 0..256 { idt.add(vector).write(Gate::new(smp_unexpected as *const () as usize, if vector == 8 { 1 } else { 0 })); }
        idt.add(64).write(Gate::new(smp_ipi_64 as *const () as usize, 0));
        idt.add(65).write(Gate::new(smp_stop_65 as *const () as usize, 0));
        idt.add(255).write(Gate::new(smp_spurious as *const () as usize, 0));
        asm!("lidt [{}]", in(reg) &Pointer { limit: 4095, base: idt as u64 }, options(readonly, nostack));
    }
    enable_lapic();
    let f = facts(start, end);
    ensure(f[6] == ROOT.load(Ordering::Acquire));
    for i in 0..9 { FACTS[i].store(f[i], Ordering::Relaxed); }
    READY.store(1, Ordering::Release);
    unsafe { asm!("sti", options(nostack)); }
    while GO.load(Ordering::Acquire) == 0 { core::hint::spin_loop(); }
    for _ in 0..ITERATIONS {
        TOTAL.fetch_add(1, Ordering::SeqCst);
        // Seeing the completed count through wait_for's Acquire also observes
        // all preceding additions to the shared counter in the Rust model.
        AP_WORK.fetch_add(1, Ordering::Release);
    }
    unsafe { smp_heartbeat_start(&AP_HEARTBEAT) }
}
#[unsafe(no_mangle)]
pub extern "sysv64" fn smp_interrupt(vector: u64, frame: *const u64) {
    ensure(id() == EXPECTED_AP.load(Ordering::Acquire) && matches!(vector, 64 | 65));
    // Own AP stack and CS/root, hardware in-service bit, exact generation.
    let f = facts(ptr::addr_of!(AP_STACK) as u64, ptr::addr_of!(AP_STACK) as u64 + size_of::<Stack>() as u64);
    ensure(frame as u64 >= f[7] && (frame as u64).checked_add(168).is_some_and(|end| end <= f[8]));
    let cs = unsafe { frame.add(17).read() }; // 15 GPRs, vector, RIP, CS.
    let rip = unsafe { frame.add(16).read() };
    let flags = unsafe { frame.add(18).read() };
    let rsp = unsafe { frame.add(19).read() };
    let heartbeat = smp_heartbeat_start as *const () as u64;
    ensure(rip < ptr::addr_of!(smp_heartbeat_end) as u64
        && rip.checked_sub(heartbeat).is_some_and(|offset| matches!(offset, 0 | 4 | 6)));
    ensure(f[6] == ROOT.load(Ordering::Acquire) && cs == 8 && flags & 0x200 != 0 && rsp >= f[7] && rsp < f[8]);
    ensure(frame as u64 + 168 == rsp & !15 && (frame as u64 & !15).checked_sub(512).is_some_and(|fp| fp >= f[7]));
    let generation = REQUEST.load(Ordering::Acquire);
    let expected = ACK.load(Ordering::Relaxed) + 1;
    ensure(generation == expected && ((vector == 64 && generation <= 3) || (vector == 65 && generation == 4)));
    let offset = 0x100 + (vector / 32) * 16;
    let bit = 1 << (vector % 32);
    let before = read(LAPIC, offset);
    ensure(before == bit);
    ISR_BEFORE.store(before as u64, Ordering::Relaxed);
    write(0xb0, 0);
    let after = read(LAPIC, offset);
    ensure(after == 0);
    ISR_AFTER.store(after as u64, Ordering::Relaxed);
    for (i, value) in [rip, cs, flags, rsp, frame as u64, f[6]].into_iter().enumerate() { TRAP[i].store(value, Ordering::Relaxed); }
    if vector == 65 {
        // x86 release store emitted inside the terminal assembly guarantees
        // ACK is the last AP RAM write: no Rust epilogue, IRET or stack reuse.
        // The acknowledgement and its cache line are retained permanently.
        fence(Ordering::Release);
        unsafe { asm!("mov qword ptr [{ack}], {generation}", "2: cli", "hlt", "jmp 2b",
            ack = in(reg) &STOP_ACK, generation = in(reg) generation, options(noreturn)); }
    }
    ACK.store(generation, Ordering::Release);
}
pub fn run(handoff: &crate::uefi::Handoff) -> ! {
    let topo = &handoff.smp.topology;
    let bsp = id();
    ensure(topo.ids.contains(&(bsp as u8)) && topo.lapic == LAPIC);
    let ap = u64::from(if u64::from(topo.ids[0]) == bsp { topo.ids[1] } else { topo.ids[0] });
    ensure(__cpuid(1).edx & ((1 << 5) | (1 << 9) | (1 << 24) | (1 << 25)) == ((1 << 5) | (1 << 9) | (1 << 24) | (1 << 25)));
    ensure(__cpuid(0x8000_0001).edx & (1 << 20) != 0 && handoff.cr3 < (1 << 32));
    EXPECTED_AP.store(ap, Ordering::Release);
    ROOT.store(handoff.cr3, Ordering::Release);
    unsafe { set_msr(0xc000_0080, msr(0xc000_0080) | (1 << 11)); crate::cpu::prepare_smp_mmio(); }
    // No tables/mappings change after this point; device inputs masked.
    unsafe { crate::diagnostics::out8(0x21, 0xff); crate::diagnostics::out8(0xa1, 0xff); }
    enable_lapic();
    let cap = unsafe { (HPET as *const u64).read_volatile() };
    ensure(cap == (10_000_000u64 << 32) | 0x8086_a201);
    unsafe {
        ((HPET + 0x10) as *mut u64).write_volatile(0);
        for timer in 0..3 { ((HPET + 0x100 + timer * 0x20) as *mut u64).write_volatile(0); }
        ((HPET + 0xf0) as *mut u64).write_volatile(0);
        ((HPET + 0x20) as *mut u64).write_volatile(7);
        ((HPET + 0x10) as *mut u64).write_volatile(1);
    }
    ensure(unsafe { ((HPET + 0x10) as *const u64).read_volatile() } == 1);
    let low = handoff.smp.trampoline.start;
    let template = ptr::addr_of!(smp_trampoline_start);
    ensure(ptr::addr_of!(smp_trampoline_end) as usize - template as usize == 4096);
    unsafe {
        ptr::copy_nonoverlapping(template, low as *mut u8, 4096);
        ((low + 0x800) as *mut u32).write_unaligned(handoff.cr3 as u32);
        ((low + 0x808) as *mut u64).write_unaligned(smp_ap_entry as *const () as u64);
        ((low + 0x810) as *mut u64).write_unaligned(ptr::addr_of!(AP_STACK) as u64 + size_of::<Stack>() as u64);
        ((low + 0x83a) as *mut u32).write_unaligned((low + 0x820) as u32);
        let far = ptr::addr_of!(smp_trampoline_far) as usize - template as usize;
        let long = ptr::addr_of!(smp_trampoline_long) as usize - template as usize;
        ((low as usize + far) as *mut u32).write_unaligned((low as usize + long) as u32);
    }
    fence(Ordering::SeqCst);
    let case = if cfg!(smp_case = "missing_ap") { "missing_ap" } else { "rendezvous" };
    print(format_args!("TESSRYN_K03_SMP_BEGIN case={case} cpus=2 bsp={bsp} ap={ap} lapic={LAPIC:#x} trampoline={low:#x} cr3={:#x}\n", handoff.cr3));
    print(format_args!("TESSRYN_K03_SMP_TOPOLOGY madt="));
    for byte in &handoff.smp.madt[..handoff.smp.madt_len] { print(format_args!("{byte:02x}")); }
    print(format_args!("\n"));
    print(format_args!("TESSRYN_K03_SMP_CLOCK period_fs=10000000 start={}\n", clock()));
    print_cpu(0, facts(handoff.stack.start, handoff.stack.end));
    let start = clock();
    // INIT targets only the admitted AP. The negative case intentionally
    // withholds SIPI and must terminate via the protected timeout path.
    send(ap, 0x4500);
    wait_ns(10_000_000);
    if !cfg!(smp_case = "missing_ap") {
        send(ap, 0x4600 | (low >> 12) as u32);
        wait_ns(200_000);
        if READY.load(Ordering::Acquire) == 0 { send(ap, 0x4600 | (low >> 12) as u32); }
    }
    if !wait_for(&READY, 1) {
        if cfg!(smp_case = "missing_ap") {
            print(format_args!("TESSRYN_K03_SMP_EXPECTED_REJECTION reason=ap-start-timeout start={start} end={} timeout_ns={TIMEOUT_NS}\n", clock()));
            finish(true);
        }
        fail("smp-ap-start-timeout");
    }
    ensure(!cfg!(smp_case = "missing_ap"));
    let apfacts = core::array::from_fn(|i| FACTS[i].load(Ordering::Relaxed));
    print_cpu(1, apfacts);
    GO.store(1, Ordering::Release);
    for _ in 0..ITERATIONS { TOTAL.fetch_add(1, Ordering::SeqCst); BSP_WORK.fetch_add(1, Ordering::Relaxed); }
    ensure(wait_for(&AP_WORK, ITERATIONS));
    let hb_before = AP_HEARTBEAT.load(Ordering::Relaxed);
    let start = clock();
    let mut polls = 0u64;
    while elapsed(start, clock()) < 20_000_000 {
        polls += 1;
        if polls > 200_000_000 { fail("smp-clock-stalled"); }
        BSP_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
        ensure(ERROR.load(Ordering::Acquire) == 0);
    }
    let end = clock();
    let hb_after = AP_HEARTBEAT.load(Ordering::Relaxed);
    ensure(hb_after > hb_before && TOTAL.load(Ordering::SeqCst) == 8192);
    print(format_args!("TESSRYN_K03_SMP_WORK bsp={} ap={} total={} bsp_heartbeats={} ap_heartbeats={} ap_before={hb_before} start={start} end={end}\n",
        BSP_WORK.load(Ordering::Relaxed), AP_WORK.load(Ordering::Relaxed), TOTAL.load(Ordering::Relaxed), BSP_HEARTBEAT.load(Ordering::Relaxed), hb_after));
    for generation in 1..=3 {
        let before = AP_HEARTBEAT.load(Ordering::Relaxed);
        REQUEST.store(generation, Ordering::Release);
        send(ap, 64);
        ensure(wait_for(&ACK, generation));
        wait_ns(1_000_000);
        let after = AP_HEARTBEAT.load(Ordering::Relaxed);
        ensure(after > before);
        print(format_args!("TESSRYN_K03_SMP_IPI generation={generation} vector=64 before={} after={} ack={} heartbeat_before={before} heartbeat_after={after}",
            ISR_BEFORE.load(Ordering::Relaxed), ISR_AFTER.load(Ordering::Relaxed), ACK.load(Ordering::Relaxed)));
        print_trap();
    }
    REQUEST.store(4, Ordering::Release);
    send(ap, 65);
    ensure(wait_for(&STOP_ACK, 4));
    let heartbeat = AP_HEARTBEAT.load(Ordering::Relaxed);
    let start = clock();
    wait_ns(20_000_000);
    let end = clock();
    let stable = AP_HEARTBEAT.load(Ordering::Relaxed);
    ensure(stable == heartbeat && ERROR.load(Ordering::Acquire) == 0);
    print(format_args!("TESSRYN_K03_SMP_STOP generation=4 vector=65 before={} after={} ack=4 heartbeat={heartbeat} stable={stable} start={start} end={end}",
        ISR_BEFORE.load(Ordering::Relaxed), ISR_AFTER.load(Ordering::Relaxed)));
    print_trap();
    print(format_args!("TESSRYN_K03_SMP_PASS cpus=2 ipis=3 retained=all\n"));
    finish(true)
}
fn print_trap() {
    print(format_args!(" rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} frame={:#x} cr3={:#x}\n",
        TRAP[0].load(Ordering::Relaxed), TRAP[1].load(Ordering::Relaxed), TRAP[2].load(Ordering::Relaxed),
        TRAP[3].load(Ordering::Relaxed), TRAP[4].load(Ordering::Relaxed), TRAP[5].load(Ordering::Relaxed)));
}
