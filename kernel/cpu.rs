// Original x86-64 descriptor tables, exception boundary and initial paging.
use core::arch::{asm, global_asm, x86_64::__cpuid};
use core::mem::{size_of, offset_of};
use core::ptr;
use crate::diagnostics::{fail, print, finish};

global_asm!(include_str!("entry.S"));

unsafe extern "efiapi" {
    pub fn kernel_enter(stack: u64, handoff: *const core::ffi::c_void) -> !;
}
unsafe extern "sysv64" {
    fn load_gdt(pointer: *const TablePointer);
    fn exception_unexpected();
    pub fn probe_int3() -> u64;
    fn smash_probe_fp();
    static exception_addresses: [usize; 32];
}

#[repr(C, packed)]
struct TablePointer { limit: u16, base: u64 }

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
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap: u16,
}
#[repr(C, align(16))]
struct FaultStack([u8; 16 * 1024]);

static mut GDT: [u64; 5] = [0, 0x00af_9a00_0000_ffff, 0x00cf_9200_0000_ffff, 0, 0];
static mut IDT: [Gate; 256] = [EMPTY; 256];
static mut TSS: Tss = Tss { reserved0: 0, rsp: [0; 3], reserved1: 0, ist: [0; 7], reserved2: 0, reserved3: 0, iomap: 104 };
static mut FAULT_STACK: FaultStack = FaultStack([0; 16 * 1024]);
static mut TABLES: crate::paging::Tables = crate::paging::Tables::empty();
#[cfg(k02_native)]
static mut K02_GDT: [u64; 7] = [0; 7];

pub struct PagingInfo { pub root: u64, pub tables: usize, pub leaves: usize }

pub fn physical_profile() -> Result<u8, &'static str> {
    // UEFI x64 enters with identity paging. This implementation deliberately
    // handles four levels only; changing an active LA57 mode requires a separate
    // transition and must not be attempted after firmware ownership is lost.
    let cr4: u64;
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack)); }
    if cr4 & (1 << 12) != 0 { return Err("five-level-paging-unavailable"); }
    let maximum = __cpuid(0x8000_0000).eax;
    let bits = if maximum >= 0x8000_0008 { (__cpuid(0x8000_0008).eax & 0xff) as u8 } else { 36 };
    if !(32..=52).contains(&bits) { return Err("physical-address-width"); }
    Ok(bits)
}

pub unsafe fn prepare_mappings(handoff: &crate::uefi::Handoff) -> Result<PagingInfo, crate::paging::Error> {
    use crate::paging::{Range, LOW_LIMIT};
    // SAFETY: one boot CPU, before EBS. The pool belongs to the loaded image;
    // retries only rewrite its contents and never allocate firmware memory.
    let tables = unsafe { &mut *ptr::addr_of_mut!(TABLES) };
    let base = ptr::addr_of!(TABLES) as u64;
    let pool = Range::checked(base, size_of::<crate::paging::Tables>() as u64)?;
    if pool.start < handoff.image.start || pool.end > handoff.image.end {
        return Err(crate::paging::Error::TableLink);
    }
    tables.reset(handoff.physical_bits, base)?;
    tables.map_range(Range { start: 0, end: LOW_LIMIT })?;
    for range in [handoff.image, handoff.stack, handoff.map_allocation] { tables.map_range(range)?; }
    if let Some(range) = handoff.high_scratch { tables.map_range(range)?; }
    if let Some(range) = handoff.framebuffer { tables.map_range(range)?; }
    for index in 0..handoff.descriptors() {
        let d = handoff.descriptor(index);
        if d.attributes & crate::uefi::RUNTIME != 0 {
            tables.map_range(Range::checked(d.start, d.pages * 4096)?)?;
        }
    }
    if tables.translation(crate::paging::GUARD).is_some() { return Err(crate::paging::Error::Guard); }
    Ok(PagingInfo { root: tables.root(), tables: tables.table_count(), leaves: tables.leaf_count() })
}

#[repr(C)]
pub struct ExceptionFrame {
    pub(crate) registers: [u64; 15],
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}
const _: () = {
    assert!(size_of::<Gate>() == 16);
    assert!(size_of::<TablePointer>() == 10);
    assert!(size_of::<Tss>() == 104);
    assert!(offset_of!(ExceptionFrame, vector) == 120);
    assert!(offset_of!(ExceptionFrame, rip) == 136);
};

pub unsafe fn take_ownership(handoff: &crate::uefi::Handoff) {
    let stack_top = handoff.stack.end;
    // SAFETY: boot CPU is single threaded with interrupts masked. The tables
    // are image-owned memory excluded from allocator ownership and stay live.
    unsafe {
        let tss = ptr::addr_of_mut!(TSS);
        ptr::write_unaligned(ptr::addr_of_mut!((*tss).rsp).cast::<u64>(), stack_top);
        ptr::write_unaligned(ptr::addr_of_mut!((*tss).ist).cast::<u64>(),
            ptr::addr_of!(FAULT_STACK) as u64 + size_of::<FaultStack>() as u64);
        let base = tss as u64;
        let limit = size_of::<Tss>() as u64 - 1;
        let gdt = ptr::addr_of_mut!(GDT).cast::<u64>();
        gdt.add(3).write((limit & 0xffff) | ((base & 0xff_ffff) << 16)
            | (0x89 << 40) | ((limit & 0xf_0000) << 32) | ((base & 0xff00_0000) << 32));
        gdt.add(4).write(base >> 32);
        load_gdt(&TablePointer { limit: (size_of::<[u64; 5]>() - 1) as u16, base: gdt as u64 });
        let idt = ptr::addr_of_mut!(IDT).cast::<Gate>();
        for vector in 0..256 {
            let address = if vector < 32 { ptr::addr_of!(exception_addresses).cast::<usize>().add(vector).read() }
                else { exception_unexpected as *const () as usize };
            idt.add(vector).write(Gate::new(address, if vector == 8 { 1 } else { 0 }));
        }
        let descriptor = TablePointer { limit: (size_of::<[Gate; 256]>() - 1) as u16, base: idt as u64 };
        asm!("lidt [{}]", in(reg) &descriptor, options(readonly, nostack));

        // Table capacity, address width, live ranges and guard exclusion were
        // checked before EBS. Low RAM and only admitted high live regions use
        // coarse supervisor mappings; K02 supplies protection and isolation.
        // Clear PGE first to invalidate any global firmware translations;
        // reloading CR3 alone does not invalidate those entries. The kernel's
        // own leaves are non-global and its guard must have no stale alias.
        let cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        asm!("mov cr4, {}", in(reg) cr4 & !(1u64 << 7), options(nostack));
        asm!("mov cr3, {}", in(reg) handoff.cr3, options(nostack));
        let actual_cr3: u64;
        let rsp: u64;
        let rip: u64;
        asm!("mov {}, cr3", out(reg) actual_cr3, options(nomem, nostack));
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
        asm!("lea {}, [rip]", out(reg) rip, options(nomem, nostack));
        if actual_cr3 != handoff.cr3 || rsp >= stack_top
            || rsp < stack_top - crate::uefi::STACK_PAGES as u64 * 4096 { fail("cpu-ownership"); }
        if rip < handoff.image.start || rip >= handoff.image.end { fail("executing-image-range"); }
        print(format_args!("TESSRYN_K01_CPU_OWNED cr3={actual_cr3:#x} rsp={rsp:#x} rip={rip:#x} gdt=owned idt=owned tss=owned\n"));
    }
}

#[cfg(k02_native)]
pub unsafe fn install_user_test_boundary(stack_top: u64, return_gate: usize) {
    // SAFETY: one boot CPU, interrupts masked, before any user instruction.
    // Preserve K01's original descriptor table; this separate table adds only
    // the declared test segments. LTR requires a fresh available TSS type.
    unsafe {
        let base = ptr::addr_of!(TSS) as u64;
        let limit = size_of::<Tss>() as u64 - 1;
        let gdt = ptr::addr_of_mut!(K02_GDT).cast::<u64>();
        gdt.write(0);
        gdt.add(1).write(0x00af_9a00_0000_ffff);
        gdt.add(2).write(0x00cf_9200_0000_ffff);
        gdt.add(3).write((limit & 0xffff) | ((base & 0xff_ffff) << 16)
            | (0x89 << 40) | ((limit & 0xf_0000) << 32) | ((base & 0xff00_0000) << 32));
        gdt.add(4).write(base >> 32);
        gdt.add(5).write(0x00cf_f200_0000_ffff);
        gdt.add(6).write(0x00af_fa00_0000_ffff);
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr::addr_of_mut!(TSS)).rsp).cast::<u64>(), stack_top);
        load_gdt(&TablePointer { limit: (size_of::<[u64; 7]>() - 1) as u16, base: gdt as u64 });
        let mut gate = Gate::new(return_gate, 0);
        gate.flags = 0xee; // present, DPL3, 64-bit interrupt gate
        ptr::addr_of_mut!(IDT).cast::<Gate>().add(128).write(gate);
    }
}

#[unsafe(no_mangle)]
pub extern "sysv64" fn exception_handler(frame: &ExceptionFrame) {
    let cr2: u64;
    // SAFETY: entry stubs supply a live normalized frame in privileged mode.
    unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)) };
    print(format_args!("TESSRYN_K01_EXCEPTION vector={} error={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} cr2={:#x}\n",
        frame.vector, frame.error, frame.rip, frame.cs, frame.rflags, frame.rsp, cr2));
    #[cfg(k02_native)]
    crate::k02::handle_exception(frame, cr2);
    if cfg!(k01_case = "int3") && frame.vector == 3 && frame.error == 0 {
        // Deliberately clobber caller-saved FP registers; the returning trap
        // wrapper must restore the interrupted context's sentinels.
        unsafe { smash_probe_fp() };
        return;
    }
    let expected = (cfg!(k01_case = "invalid_opcode") && frame.vector == 6 && frame.error == 0)
        || (cfg!(k01_case = "page_fault") && frame.vector == 14 && frame.error == 0 && cr2 == crate::paging::GUARD);
    if expected {
        print(format_args!("TESSRYN_K01_EXPECTED_FAULT\n"));
        finish(true);
    }
    fail("unexpected-exception")
}
