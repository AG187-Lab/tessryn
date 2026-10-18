//! Two image-bound CPL3 programs on retained, immutable private address spaces.
//! Only the BSP prints. CPU-local continuations are selected through SWAPGS,
//! never the mutable single-CPU runtime. No scheduler or budget state is shared.
use core::arch::{asm, global_asm};
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering, fence};
use crate::diagnostics::{finish, print};
use crate::k02_paging::{Tables, UserAccess};
use crate::smp::{id, msr, set_msr, read, write, clock, elapsed, wait_ns, send, ensure};
const CODE: u64 = 0x1_0000_0000;
const STACK: u64 = CODE + 0x2000;
const DATA: u64 = CODE + 0x4000;
const PEER: u64 = CODE + 0x20_0000;
const ITERATIONS: u64 = 65536;
const WINDOW: u64 = 20_000_000;
const TIMEOUT: u64 = 2_000_000_000;
const SEED: u64 = 0x5355_4552_0000_0000;
const SENTINEL: u64 = 0x534d_5055_0000_0000;
const fn case_id() -> u64 {
    if cfg!(smp_user_case = "rendezvous") { 0 }
    else if cfg!(smp_user_case = "peer_read") { 1 }
    else if cfg!(smp_user_case = "forged_ipi") { 2 } else { u64::MAX }
}
fn case_name() -> &'static str { match case_id() { 0 => "rendezvous", 1 => "peer_read", 2 => "forged_ipi", _ => { ensure(false); "invalid" } } }
#[repr(C)]
pub struct Contract { magic: [u8; 16], words: [u64; 12] }
#[used]
#[unsafe(no_mangle)]
pub static K03_SMP_USER_CONTRACT: Contract = Contract {
    magic: *b"TESSRYN-SMPUSR1\0",
    words: [1, case_id(), 2, CODE, STACK, DATA, PEER, 66, 128, ITERATIONS, TIMEOUT, WINDOW],
};
global_asm!(include_str!("smp_user_entry.S"));
unsafe extern "sysv64" {
    fn smp_user_enter(root: u64, saved: *const Saved, context: *mut Context);
    fn smp_load_gdt(pointer: *const Pointer);
    fn smp_user_ipi_66(); fn smp_user_yield_128(); fn smp_user_fault_13(); fn smp_user_fault_14(); fn smp_user_unexpected();
    fn smp_spurious();
    static smp_user_program_start: u8; static smp_user_program_end: u8;
    static smp_user_bsp_start: u8; static smp_user_warmup_start: u8;
    static smp_user_after_yield: u8; static smp_user_peer_fault: u8; static smp_user_forged_fault: u8;
    static smp_user_loop_start: u8; static smp_user_loop_end: u8;
}
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Pointer { limit: u16, base: u64 }
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Gate { low: u16, selector: u16, ist: u8, flags: u8, middle: u16, high: u32, reserved: u32 }
const EMPTY_GATE: Gate = Gate { low: 0, selector: 0, ist: 0, flags: 0, middle: 0, high: 0, reserved: 0 };
impl Gate { fn new(address: usize, ist: u8, dpl3: bool) -> Self { Self { low: address as u16, selector: 8, ist, flags: if dpl3 { 0xee } else { 0x8e }, middle: (address >> 16) as u16, high: (address >> 32) as u32, reserved: 0 } } }
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Tss { reserved0: u32, rsp: [u64; 3], reserved1: u64, ist: [u64; 7], reserved2: u64, reserved3: u16, iomap: u16 }
const EMPTY_TSS: Tss = Tss { reserved0: 0, rsp: [0; 3], reserved1: 0, ist: [0; 7], reserved2: 0, reserved3: 0, iomap: 104 };
#[repr(C, align(4096))]
struct Page([u8; 4096]);
#[repr(C, align(4096))]
struct Stack([u8; 64 * 1024]);
#[repr(C, align(4096))]
struct Data([AtomicU64; 512]);
static mut CODE_PAGES: [Page; 2] = [const { Page([0; 4096]) }; 2];
static mut STACK_PAGES: [Page; 2] = [const { Page([0; 4096]) }; 2];
static DATA_PAGES: [Data; 2] = [const { Data([const { AtomicU64::new(0) }; 512]) }; 2];
static mut PEER_PAGE: Page = Page([0; 4096]);
static mut TRAP_STACKS: [Stack; 2] = [const { Stack([0; 64 * 1024]) }; 2];
static mut FAULT_STACKS: [Stack; 2] = [const { Stack([0; 64 * 1024]) }; 2];
static mut GDT: [[u64; 7]; 2] = [[0; 7]; 2];
static mut IDT: [[Gate; 256]; 2] = [[EMPTY_GATE; 256]; 2];
static mut TSS: [Tss; 2] = [EMPTY_TSS; 2];
static mut ROOTS: [Tables<16>; 2] = [const { Tables::empty() }; 2];
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Saved { registers: [u64; 15], vector: u64, error: u64, rip: u64, cs: u64, rflags: u64, rsp: u64, ss: u64, fp: [u8; 512] }
const fn initial() -> Saved { let mut fp = [0; 512]; fp[0] = 0x7f; fp[1] = 3; fp[24] = 0x80; fp[25] = 0x1f;
    Saved { registers: [0; 15], vector: 0, error: 0, rip: CODE, cs: 0x33, rflags: 0x202, rsp: STACK + 4096 - 16, ss: 0x2b, fp } }
#[repr(C, align(16))]
struct ResetFp([u8; 512]);
#[used]
#[unsafe(no_mangle)]
static smp_user_reset_fp: ResetFp = ResetFp(initial().fp);
#[repr(C, align(16))]
struct Context { own: u64, kernel_rsp: u64, kernel_root: u64, index: u64, saved: Saved, root: u64, apic: u64 }
const EMPTY_CONTEXT: Context = Context { own: 0, kernel_rsp: 0, kernel_root: 0, index: 0, saved: initial(), root: 0, apic: 0 };
static mut CONTEXTS: [Context; 2] = [const { EMPTY_CONTEXT }; 2];
#[derive(Clone, Copy)]
struct Capture { saved: Saved, cr2: u64, frame: u64, fp: u64, root: u64, apic: u64, before: u64, after: u64, generation: u64, heartbeat: u64, kernel_rsp: u64, kernel_cr3: u64 }
const EMPTY_CAPTURE: Capture = Capture { saved: initial(), cr2: 0, frame: 0, fp: 0, root: 0, apic: 0, before: 0, after: 0, generation: 0, heartbeat: 0, kernel_rsp: 0, kernel_cr3: 0 };
// CPU0 IPI, CPU1 first trap, CPU1 resumed IPI. A Release phase publishes them.
static mut CAPTURES: [Capture; 3] = [EMPTY_CAPTURE; 3];
static IDS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static REQUEST: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static ACK: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static COMMAND: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static OVERLAP: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
static FAULT_PROGRESS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static CPU_STATE: [[AtomicU64; 11]; 2] = [const { [const { AtomicU64::new(0) }; 11] }; 2];
const _: () = { assert!(size_of::<Contract>() == 112); assert!(size_of::<Saved>() == 688); assert!(offset_of!(Saved, fp) == 176); assert!(offset_of!(Context, saved) == 32); assert!(size_of::<Tss>() == 104); assert!(size_of::<Context>() == 736); };
fn context(cpu: usize) -> *mut Context { ensure(cpu < 2); unsafe { ptr::addr_of_mut!(CONTEXTS).cast::<Context>().add(cpu) } }
fn code_phys(cpu: usize) -> u64 { unsafe { ptr::addr_of!(CODE_PAGES).cast::<Page>().add(cpu) as u64 } }
fn stack_phys(cpu: usize) -> u64 { unsafe { ptr::addr_of!(STACK_PAGES).cast::<Page>().add(cpu) as u64 } }
fn trap_start(cpu: usize) -> u64 { unsafe { ptr::addr_of!(TRAP_STACKS).cast::<Stack>().add(cpu) as u64 } }
fn fault_start(cpu: usize) -> u64 { unsafe { ptr::addr_of!(FAULT_STACKS).cast::<Stack>().add(cpu) as u64 } }
fn heartbeat(cpu: usize) -> u64 { DATA_PAGES[cpu].0[0].load(Ordering::Acquire) }
fn marker(cpu: usize) -> u64 { DATA_PAGES[cpu].0[1].load(Ordering::Acquire) }
fn user_address(symbol: *const u8) -> u64 { let offset = (symbol as u64).checked_sub(ptr::addr_of!(smp_user_program_start) as u64); ensure(offset.is_some_and(|n| n < 4096)); CODE + offset.unwrap() }
fn wait(value: &AtomicU64, expected: u64) { let start = clock(); for _ in 0..200_000_000 { if value.load(Ordering::Acquire) == expected { return; } ensure(elapsed(start, clock()) < TIMEOUT); core::hint::spin_loop(); } ensure(false); }
fn progress(cpu: usize, before: u64) -> u64 { let start = clock(); for _ in 0..200_000_000 { let now = heartbeat(cpu); if now > before { return now; } ensure(elapsed(start, clock()) < TIMEOUT); core::hint::spin_loop(); } ensure(false); 0 }
fn hash_page(address: u64) -> [u8; 32] { let mut bytes = [0; 4096]; for (i, b) in bytes.iter_mut().enumerate() { *b = unsafe { (address as *const u8).add(i).read_volatile() }; } crate::k02_sha256::digest(&bytes) }
fn print_payload(cpu: usize, phase: &str) { let template = hash_page(ptr::addr_of!(smp_user_program_start) as u64); let digest = hash_page(code_phys(cpu)); ensure(digest == template); print(format_args!("TESSRYN_K03_SMP_USER_PAYLOAD cpu={cpu} phase={phase} sha256=")); for b in digest { print(format_args!("{b:02x}")); } print(format_args!("\n")); }

/// Sole BSP writer, before any SIPI. No mapping/reference crosses AP release.
pub fn prepare(handoff: &crate::uefi::Handoff, bsp: u64, ap: u64) {
    ensure(case_id() < 3 && ptr::addr_of!(smp_user_program_end) as u64 - ptr::addr_of!(smp_user_program_start) as u64 == 4096);
    ensure(handoff.physical_bits == 48);
    for cpu in 0..2 {
        IDS[cpu].store(if cpu == 0 { bsp } else { ap }, Ordering::Relaxed);
        let code = code_phys(cpu); let stack = stack_phys(cpu);
        ensure(code % 4096 == 0 && stack % 4096 == 0 && code >= handoff.image.start && code + 4096 <= handoff.image.end);
        unsafe { ptr::copy_nonoverlapping(ptr::addr_of!(smp_user_program_start), code as *mut u8, 4096); }
        DATA_PAGES[cpu].0[1].store(SEED + cpu as u64, Ordering::Relaxed);
        let tables = unsafe { &mut *ptr::addr_of_mut!(ROOTS).cast::<Tables<16>>().add(cpu) };
        let table_base = tables as *mut _ as u64;
        tables.reset(handoff.physical_bits, table_base).unwrap_or_else(|_| { ensure(false); unreachable!() });
        tables.map_supervisor_range(crate::paging::Range { start: 0, end: crate::paging::LOW_LIMIT }).unwrap_or_else(|_| { ensure(false); });
        for range in [handoff.image, handoff.stack, handoff.map_allocation] { tables.map_supervisor_range(range).unwrap_or_else(|_| { ensure(false); }); }
        if let Some(range) = handoff.framebuffer { tables.map_supervisor_range(range).unwrap_or_else(|_| { ensure(false); }); }
        for index in 0..handoff.descriptors() { let d = handoff.descriptor(index); if d.attributes & crate::uefi::RUNTIME != 0 { tables.map_supervisor_range(crate::paging::Range::checked(d.start, d.pages * 4096).unwrap()).unwrap_or_else(|_| { ensure(false); }); } }
        tables.set_hpet_uncached().unwrap_or_else(|_| { ensure(false); });
        tables.set_lapic_uncached().unwrap_or_else(|_| { ensure(false); });
        tables.map_trusted_code(CODE, code).unwrap_or_else(|_| { ensure(false); });
        tables.map_data(STACK, stack, UserAccess::ReadWrite).unwrap_or_else(|_| { ensure(false); });
        tables.map_data(DATA, &DATA_PAGES[cpu] as *const Data as u64, UserAccess::ReadWrite).unwrap_or_else(|_| { ensure(false); });
        if cpu == 0 { tables.map_data(PEER, ptr::addr_of!(PEER_PAGE) as u64, UserAccess::ReadOnly).unwrap_or_else(|_| { ensure(false); }); }
        tables.validate().unwrap_or_else(|_| { ensure(false); });
        ensure(tables.user_leaf_count() == if cpu == 0 { 4 } else { 3 });
        for (address, physical, writable, executable) in [(CODE, code, false, true), (STACK, stack, true, false), (DATA, &DATA_PAGES[cpu] as *const Data as u64, true, false)] {
            let t = tables.user_translation(address).unwrap(); ensure(t.physical == physical && t.writable == writable && t.executable == executable && t.page_bytes == 4096);
        }
        if cpu == 1 { ensure(tables.translation(PEER).is_none()); }
        let mut saved = initial();
        saved.rip = if cpu == 0 { user_address(ptr::addr_of!(smp_user_bsp_start)) } else { match case_id() { 0 => user_address(ptr::addr_of!(smp_user_warmup_start)), 1 => user_address(ptr::addr_of!(smp_user_peer_fault)), _ => user_address(ptr::addr_of!(smp_user_forged_fault)) } };
        saved.registers[2] = SEED + cpu as u64; saved.registers[3] = SENTINEL + cpu as u64;
        saved.registers[8] = DATA; saved.registers[9] = PEER; saved.registers[13] = ITERATIONS;
        saved.fp[160..168].copy_from_slice(&(SENTINEL + cpu as u64).to_le_bytes());
        saved.fp[168..176].copy_from_slice(&(SEED + cpu as u64).to_le_bytes());
        unsafe { context(cpu).write(Context { own: context(cpu) as u64, kernel_rsp: 0, kernel_root: 0, index: cpu as u64, saved, root: tables.root(), apic: if cpu == 0 { bsp } else { ap } }); }
    }
    ensure(unsafe { (*context(0)).root != (*context(1)).root });
    unsafe { (ptr::addr_of_mut!(PEER_PAGE).cast::<u64>()).write(SEED); }
    fence(Ordering::Release);
}

/// Each CPU writes only its own static state, with interrupts masked.
pub fn install(cpu: usize) {
    ensure(id() == IDS[cpu].load(Ordering::Acquire));
    let top = trap_start(cpu) + size_of::<Stack>() as u64;
    unsafe {
        asm!("cli", options(nostack));
        let tss = ptr::addr_of_mut!(TSS).cast::<Tss>().add(cpu);
        ptr::write_unaligned(ptr::addr_of_mut!((*tss).rsp).cast::<u64>(), top);
        ptr::write_unaligned(ptr::addr_of_mut!((*tss).ist).cast::<u64>(), fault_start(cpu) + size_of::<Stack>() as u64);
        let base = tss as u64; let gdt = ptr::addr_of_mut!(GDT).cast::<[u64; 7]>().add(cpu).cast::<u64>();
        gdt.write(0); gdt.add(1).write(0x00af_9a00_0000_ffff); gdt.add(2).write(0x00cf_9200_0000_ffff);
        gdt.add(3).write(103 | ((base & 0xff_ffff) << 16) | (0x89 << 40) | ((base & 0xff00_0000) << 32)); gdt.add(4).write(base >> 32);
        gdt.add(5).write(0x00cf_f200_0000_ffff); gdt.add(6).write(0x00af_fa00_0000_ffff);
        smp_load_gdt(&Pointer { limit: 55, base: gdt as u64 });
        let idt = ptr::addr_of_mut!(IDT).cast::<[Gate; 256]>().add(cpu).cast::<Gate>();
        for vector in 0..256 { idt.add(vector).write(Gate::new(smp_user_unexpected as *const () as usize, if vector == 8 { 1 } else { 0 }, false)); }
        for (vector, address, dpl3) in [(13, smp_user_fault_13 as *const () as usize, false), (14, smp_user_fault_14 as *const () as usize, false), (66, smp_user_ipi_66 as *const () as usize, false), (128, smp_user_yield_128 as *const () as usize, true), (255, smp_spurious as *const () as usize, false)] { idt.add(vector).write(Gate::new(address, 0, dpl3)); }
        asm!("lidt [{}]", in(reg) &Pointer { limit: 4095, base: idt as u64 }, options(readonly, nostack));
        // No user-controlled GS value can select the privileged continuation.
        asm!("xor eax, eax", "mov fs, ax", "mov gs, ax", out("eax") _, options(nostack));
        set_msr(0xc000_0100, 0); set_msr(0xc000_0101, context(cpu) as u64); set_msr(0xc000_0102, 0);
        let efer = msr(0xc000_0080) & !1; set_msr(0xc000_0080, efer | (1 << 11));
        set_msr(0x174, 0); set_msr(0x175, 0); set_msr(0x176, 0);
        let (cr0, cr4): (u64, u64); asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack)); asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        ensure(cr0 & ((1 << 2) | (1 << 3)) == 0 && cr0 & (1 << 16) != 0);
        ensure(cr4 & ((1 << 7) | (1 << 8) | (1 << 12) | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 22) | (1 << 23) | (1 << 24)) == 0 && cr4 & 0x600 == 0x600);
        let mut actual_gdt = Pointer { limit: 0, base: 0 }; let mut actual_idt = Pointer { limit: 0, base: 0 };
        let (tr, ldt): (u16, u16); let dr7: u64;
        asm!("sgdt [{}]", in(reg) &mut actual_gdt, options(nostack));
        asm!("sidt [{}]", in(reg) &mut actual_idt, options(nostack));
        asm!("str {0:x}", out(reg) tr, options(nomem, nostack));
        asm!("xor eax, eax", "lldt ax", "mov dr7, rax", out("eax") _, options(nostack));
        asm!("sldt {0:x}", out(reg) ldt, options(nomem, nostack)); asm!("mov {}, dr7", out(reg) dr7, options(nomem, nostack));
        ensure(actual_gdt.limit == 55 && actual_gdt.base == gdt as u64 && actual_idt.limit == 4095 && actual_idt.base == idt as u64 && tr == 24 && ldt == 0 && dr7 & 0xffff_2fff == 0x400);
        let low = gdt.add(3).read(); let high = gdt.add(4).read();
        let actual_tss = ((low >> 16) & 0xff_ffff) | ((low >> 32) & 0xff00_0000) | (high << 32);
        ensure(actual_tss == tss as u64 && ptr::addr_of!((*tss).rsp).cast::<u64>().read_unaligned() == top);
        for (index, value) in [cr0, cr4, msr(0xc000_0080), msr(0xc000_0101), msr(0xc000_0102), actual_gdt.base, actual_idt.base, actual_tss, tr as u64, ldt as u64, dr7].into_iter().enumerate() { CPU_STATE[cpu][index].store(value, Ordering::Relaxed); }
    }
    ensure(msr(0xc000_0100) == 0 && msr(0xc000_0101) == context(cpu) as u64 && msr(0xc000_0102) == 0);
    for word in 0..8 { ensure(read(0xfee0_0000, 0x100 + word * 16) == 0); }
}
fn enter(cpu: usize) {
    // The callback writes these fields. Only raw pointers cross the boundary.
    let c = context(cpu); let root = unsafe { ptr::addr_of!((*c).root).read() };
    ensure(id() == IDS[cpu].load(Ordering::Relaxed) && msr(0xc000_0101) == c as u64);
    unsafe { set_msr(0xc000_0102, 0); smp_user_enter(root, ptr::addr_of!((*c).saved), c); }
    let actual: u64; unsafe { asm!("mov {}, cr3", out(reg) actual, options(nomem, nostack)); }
    ensure(actual == unsafe { (*c).kernel_root } && msr(0xc000_0101) == c as u64);
}

#[unsafe(no_mangle)]
extern "sysv64" fn smp_user_capture(frame: *const Saved, fp: *const u8, c: *mut Context) {
    let cpu = if id() == IDS[0].load(Ordering::Relaxed) { 0 } else { 1 };
    ensure(c == context(cpu));
    let (root, cr2): (u64, u64); unsafe { asm!("mov {}, cr3", out(reg) root, options(nomem, nostack)); asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)); }
    ensure(id() == IDS[cpu].load(Ordering::Relaxed) && root == unsafe { (*c).root });
    let start = trap_start(cpu); let end = start + size_of::<Stack>() as u64;
    ensure(frame as u64 >= start && frame as u64 + 176 == end && fp as u64 == (frame as u64 & !15) - 512 && fp as u64 >= start);
    let mut saved = initial();
    unsafe { ptr::copy_nonoverlapping(frame.cast::<u8>(), ptr::addr_of_mut!(saved).cast::<u8>(), 176); ptr::copy_nonoverlapping(fp, saved.fp.as_mut_ptr(), 512); }
    ensure(saved.cs == 0x33 && saved.ss == 0x2b && saved.rflags & 0x200 != 0 && saved.rflags & ((3 << 12) | (1 << 8) | (1 << 10) | (1 << 14) | (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20)) == 0 && saved.rsp == STACK + 4096 - 16);
    let mut expected_registers = [0u64; 15];
    expected_registers[2] = SEED + cpu as u64; expected_registers[3] = SENTINEL + cpu as u64;
    expected_registers[8] = DATA; expected_registers[9] = PEER;
    expected_registers[13] = if cpu == 1 && case_id() == 0 { 0 } else { ITERATIONS };
    expected_registers[14] = if cpu == 0 || case_id() == 0 { 0x2b } else { 0 };
    // Normalized order: R15..R8, RDI, RSI, RBP, RBX, RDX, RCX, RAX.
    ensure(saved.registers == expected_registers);
    ensure(saved.registers[3] == SENTINEL + cpu as u64 && saved.registers[2] == SEED + cpu as u64 && saved.registers[8] == DATA && saved.registers[9] == PEER);
    ensure(u64::from_le_bytes(saved.fp[160..168].try_into().unwrap()) == SENTINEL + cpu as u64 && u64::from_le_bytes(saved.fp[168..176].try_into().unwrap()) == SEED + cpu as u64);
    let mut expected_fp = initial().fp;
    expected_fp[160..168].copy_from_slice(&(SENTINEL + cpu as u64).to_le_bytes());
    expected_fp[168..176].copy_from_slice(&(SEED + cpu as u64).to_le_bytes());
    // MXCSR_MASK is a hardware output, not loaded by FXRSTOR.
    let mask = u32::from_le_bytes(saved.fp[28..32].try_into().unwrap());
    ensure(mask != 0 && mask & 0x1f80 == 0x1f80);
    expected_fp[28..32].copy_from_slice(&mask.to_le_bytes());
    ensure(saved.fp == expected_fp);
    ensure(saved.fp[0..2] == [0x7f, 3] && saved.fp[24..28] == [0x80, 0x1f, 0, 0] && marker(cpu) == SEED + cpu as u64);
    let (mut before, mut after, mut generation) = (0, 0, 0);
    let slot = if cpu == 0 { 0 } else if saved.vector == 66 { 2 } else { 1 };
    if saved.vector == 66 {
        let offset = saved.rip.checked_sub(user_address(ptr::addr_of!(smp_user_loop_start)));
        ensure(offset.is_some_and(|n| matches!(n, 0 | 4 | 6)) && saved.rip < user_address(ptr::addr_of!(smp_user_loop_end)) && saved.error == 0);
        generation = REQUEST[cpu].load(Ordering::Acquire); ensure(generation == 1 && ACK[cpu].load(Ordering::Relaxed) == 0);
        for word in 0..8 { ensure(read(0xfee0_0000, 0x100 + word * 16) == if word == 2 { 4 } else { 0 }); }
        before = read(0xfee0_0000, 0x120) as u64; write(0xb0, 0);
        for word in 0..8 { ensure(read(0xfee0_0000, 0x100 + word * 16) == 0); }
        after = read(0xfee0_0000, 0x120) as u64;
    } else if saved.vector == 128 {
        ensure(cpu == 1 && case_id() == 0 && saved.error == 0 && saved.rip == user_address(ptr::addr_of!(smp_user_after_yield)) && saved.registers[13] == 0 && heartbeat(1) == ITERATIONS);
    } else if case_id() == 1 {
        ensure(cpu == 1 && saved.vector == 14 && saved.error == 4 && saved.rip == user_address(ptr::addr_of!(smp_user_peer_fault)) && cr2 == PEER);
    } else {
        ensure(cpu == 1 && case_id() == 2 && saved.vector == 13 && saved.error == 0x212 && saved.rip == user_address(ptr::addr_of!(smp_user_forged_fault)));
        for word in 0..8 { ensure(read(0xfee0_0000, 0x100 + word * 16) == 0); }
    }
    unsafe {
        ptr::addr_of_mut!((*c).saved).write(saved);
        ptr::addr_of_mut!(CAPTURES).cast::<Capture>().add(slot).write(Capture { saved, cr2, frame: frame as u64, fp: fp as u64, root, apic: id(), before, after, generation, heartbeat: heartbeat(cpu), kernel_rsp: (*c).kernel_rsp, kernel_cr3: (*c).kernel_root });
    }
    if saved.vector == 66 { ACK[cpu].store(1, Ordering::Release); }
}

pub fn ap_run() -> ! {
    wait(&COMMAND, 1);
    let bsp_before = progress(0, 0); let ap_before = heartbeat(1); let start = clock();
    enter(1);
    let end = clock(); let bsp_after = progress(0, bsp_before); let ap_after = heartbeat(1);
    for (i, v) in [bsp_before, bsp_after, ap_before, ap_after, start, end].into_iter().enumerate() { OVERLAP[i].store(v, Ordering::Relaxed); }
    if case_id() != 0 {
        let before = heartbeat(0); let start = clock(); wait_ns(WINDOW); let end = clock(); let after = heartbeat(0); ensure(after > before);
        for (i, v) in [before, after, start, end].into_iter().enumerate() { FAULT_PROGRESS[i].store(v, Ordering::Relaxed); }
    }
    REQUEST[0].store(1, Ordering::Release); send(IDS[0].load(Ordering::Relaxed), 66);
    if case_id() == 0 { wait(&COMMAND, 2); enter(1); ensure(ACK[1].load(Ordering::Acquire) == 1); }
    // No RAM write follows this Release acknowledgment, including epilogues.
    fence(Ordering::Release);
    unsafe { asm!("mov qword ptr [{done}], 1", "2: cli", "hlt", "jmp 2b", done = in(reg) &DONE, options(noreturn)); }
}
fn print_space(cpu: usize) {
    let c = context(cpu); let root = unsafe { (*c).root }; let peer = if cpu == 0 { ptr::addr_of!(PEER_PAGE) as u64 } else { 0 };
    print(format_args!("TESSRYN_K03_SMP_USER_SPACE cpu={cpu} apic={} root={root:#x} root_end={:#x} code_phys={:#x} stack_phys={:#x} data_phys={:#x} peer_phys={peer:#x} code={CODE:#x} stack={STACK:#x} data={DATA:#x} peer={PEER:#x} leaves={} gdt={:#x} idt={:#x} tss={:#x} trap_start={:#x} trap_end={:#x} fault_start={:#x} fault_end={:#x} context={:#x} marker={:#x}\n",
        IDS[cpu].load(Ordering::Relaxed), root + Tables::<16>::object_bytes(), code_phys(cpu), stack_phys(cpu), &DATA_PAGES[cpu] as *const Data as u64, if cpu == 0 { 4 } else { 3 },
        unsafe { ptr::addr_of!(GDT).cast::<[u64; 7]>().add(cpu) as u64 }, unsafe { ptr::addr_of!(IDT).cast::<[Gate; 256]>().add(cpu) as u64 }, unsafe { ptr::addr_of!(TSS).cast::<Tss>().add(cpu) as u64 }, trap_start(cpu), trap_start(cpu) + size_of::<Stack>() as u64, fault_start(cpu), fault_start(cpu) + size_of::<Stack>() as u64, c as u64, marker(cpu)));
    let s: [u64; 11] = core::array::from_fn(|i| CPU_STATE[cpu][i].load(Ordering::Relaxed));
    print(format_args!("TESSRYN_K03_SMP_USER_STATE cpu={cpu} cr0={:#x} cr4={:#x} efer={:#x} gsbase={:#x} user_gsbase={:#x} gdt={:#x} idt={:#x} tss={:#x} tr={} ldtr={} dr7={:#x}\n", s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10]));
}
fn print_walks(cpu: usize) {
    // No mutation or mutable references: mappings were sealed before SIPI.
    let tables = unsafe { &*ptr::addr_of!(ROOTS).cast::<Tables<16>>().add(cpu) };
    for (kind, va) in [("code", CODE), ("stack", STACK), ("data", DATA), ("peer", PEER), ("code_alias", code_phys(cpu)), ("stack_alias", stack_phys(cpu)), ("data_alias", &DATA_PAGES[cpu] as *const Data as u64), ("hpet", 0xfed0_0000), ("lapic", 0xfee0_0000)] {
        let (t, e) = tables.raw_walk(va).unwrap_or_else(|_| { ensure(false); unreachable!() });
        print(format_args!("TESSRYN_K03_SMP_USER_WALK cpu={cpu} kind={kind} va={va:#x} t0={:#x} t1={:#x} t2={:#x} t3={:#x} e0={:#x} e1={:#x} e2={:#x} e3={:#x}\n", t[0], t[1], t[2], t[3], e[0], e[1], e[2], e[3]));
    }
}
fn print_capture(cpu: usize, stage: &str, slot: usize) {
    let c = unsafe { ptr::addr_of!(CAPTURES).cast::<Capture>().add(slot).read() }; let s = c.saved;
    print(format_args!("TESSRYN_K03_SMP_USER_TRAP cpu={cpu} stage={stage} vector={} error={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x} cr2={:#x} frame={:#x} fp={:#x} root={:#x} apic={} r12={:#x} r13={:#x} xmm0lo={:#x} xmm0hi={:#x} isr_before={} isr_after={} generation={} marker={:#x} heartbeat={} kernel_rsp={:#x} kernel_cr3={:#x}", s.vector, s.error, s.rip, s.cs, s.rflags, s.rsp, s.ss, c.cr2, c.frame, c.fp, c.root, c.apic, s.registers[3], s.registers[2], u64::from_le_bytes(s.fp[160..168].try_into().unwrap()), u64::from_le_bytes(s.fp[168..176].try_into().unwrap()), c.before, c.after, c.generation, marker(cpu), c.heartbeat, c.kernel_rsp, c.kernel_cr3));
    print(format_args!(" gpr=")); for register in s.registers { for byte in register.to_le_bytes() { print(format_args!("{byte:02x}")); } }
    print(format_args!(" fp_image=")); for byte in s.fp { print(format_args!("{byte:02x}")); } print(format_args!("\n"));
}
pub fn run(_handoff: &crate::uefi::Handoff) -> ! {
    install(0);
    print(format_args!("TESSRYN_K03_SMP_USER_BEGIN case={} cpus=2 vector=66\n", case_name()));
    for cpu in 0..2 { print_space(cpu); print_walks(cpu); print_payload(cpu, "before"); }
    COMMAND.store(1, Ordering::Release);
    enter(0); ensure(ACK[0].load(Ordering::Acquire) == 1);
    if case_id() == 0 {
        COMMAND.store(2, Ordering::Release); progress(1, ITERATIONS); wait_ns(WINDOW);
        REQUEST[1].store(1, Ordering::Release); send(IDS[1].load(Ordering::Relaxed), 66);
    }
    wait(&DONE, 1);
    let hb = heartbeat(1); let start = clock(); wait_ns(WINDOW); let end = clock(); let stable = heartbeat(1); ensure(hb == stable);
    let o: [u64; 6] = core::array::from_fn(|i| OVERLAP[i].load(Ordering::Relaxed));
    ensure(o[1] > o[0] && if case_id() == 0 { o[3] == ITERATIONS && o[2] == 0 } else { o[2] == 0 && o[3] == 0 });
    print(format_args!("TESSRYN_K03_SMP_USER_OVERLAP bsp_before={} bsp_after={} ap_before={} ap_after={} start={} end={}\n", o[0], o[1], o[2], o[3], o[4], o[5]));
    print_capture(1, if case_id() == 0 { "warmup" } else { "fault" }, 1); print_capture(0, "ipi", 0);
    if case_id() == 0 { print_capture(1, "ipi", 2); } else { let p: [u64; 4] = core::array::from_fn(|i| FAULT_PROGRESS[i].load(Ordering::Relaxed)); print(format_args!("TESSRYN_K03_SMP_USER_FAULT_PROGRESS before={} after={} start={} end={}\n", p[0], p[1], p[2], p[3])); }
    print(format_args!("TESSRYN_K03_SMP_USER_STOP cpu=1 generation=1 heartbeat={hb} stable={stable} start={start} end={end}\n"));
    for cpu in 0..2 { print_payload(cpu, "after"); ensure(marker(cpu) == SEED + cpu as u64); }
    print(format_args!("TESSRYN_K03_SMP_USER_PASS cpus=2 ipis={} faults={} retained=all\n", if case_id() == 0 { 2 } else { 1 }, if case_id() == 0 { 0 } else { 1 }));
    finish(true)
}
