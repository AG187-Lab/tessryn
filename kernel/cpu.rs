// Original x86-64 descriptor tables, exception boundary and initial paging.
use core::arch::{asm, global_asm, x86_64::__cpuid};
use core::mem::{size_of, offset_of};
use core::ptr;
use crate::diagnostics::{fail, print, finish};

global_asm!(include_str!("entry.S"), region_service = const cfg!(k02_region_service) as u8,
    timer_profile = const cfg!(k03_timer) as u8);

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

#[cfg(io02_nvme_registers)]
const EFER: u32 = 0xc000_0080;
#[cfg(io02_nvme_registers)]
const NXE: u64 = 1 << 11;
#[cfg(io02_nvme_registers)]
const WP: u64 = 1 << 16;

#[cfg(io02_nvme_registers)]
fn mmio_cpu_features() -> bool {
    const MSR_AND_PAT: u32 = (1 << 5) | (1 << 16);
    __cpuid(0).eax >= 1 && __cpuid(1).edx & MSR_AND_PAT == MSR_AND_PAT
        && __cpuid(0x8000_0000).eax >= 0x8000_0001 && __cpuid(0x8000_0001).edx & (1 << 20) != 0
}

#[cfg(io02_nvme_registers)]
unsafe fn mmio_cpu_owner(handoff: &crate::uefi::Handoff) -> Option<(u64, u64)> {
    let (cr0, cr3, cr4, rflags): (u64, u64, u64, u64);
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
    }
    // A single non-global, non-PCID four-level root admits a full CR3 fence.
    (cr3 == handoff.cr3 && cr4 & ((1 << 7) | (1 << 12) | (1 << 17)) == 0 && rflags & (1 << 9) == 0)
        .then_some((cr0, cr3))
}

#[cfg(io02_nvme_registers)]
unsafe fn read_msr(index: u32) -> u64 {
    let (low, high): (u32, u32);
    unsafe {
        asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Admit one fixed QEMU NVMe register page after K01 CPU ownership.
///
/// The caller must be the sole BSP with interrupts masked. BAR identity and
/// memory decoding must already have been verified without touching MMIO.
#[cfg(io02_nvme_registers)]
pub unsafe fn prepare_nvme_mmio(handoff: &crate::uefi::Handoff, bar: u64) -> Result<(), &'static str> {
    use crate::paging::{nvme_aperture, Range};

    let aperture = nvme_aperture(bar, handoff.physical_bits).map_err(|error| error.label())?;
    let scratch = Range::checked(handoff.scratch, 4096).map_err(|error| error.label())?;
    if [handoff.image, handoff.stack, handoff.map_allocation, scratch]
        .into_iter().any(|range| aperture.overlaps(range))
        || handoff.framebuffer.is_some_and(|range| aperture.overlaps(range))
        || handoff.high_scratch.is_some_and(|range| aperture.overlaps(range))
    {
        return Err("nvme-bar-overlaps-live-range");
    }
    for index in 0..handoff.descriptors() {
        let descriptor = handoff.descriptor(index);
        let bytes = descriptor.pages.checked_mul(4096).ok_or("nvme-descriptor-overflow")?;
        let range = Range::checked(descriptor.start, bytes).map_err(|error| error.label())?;
        if aperture.overlaps(range) { return Err("nvme-bar-overlaps-memory-map"); }
    }

    if !mmio_cpu_features() { return Err("nvme-mmio-cpu-features"); }
    let (cr0, cr3) = unsafe { mmio_cpu_owner(handoff) }.ok_or("nvme-mmio-cpu-ownership")?;

    // The chosen PTE uses PWT and PCD with PAT=0, selecting UC index 3.
    if unsafe { read_msr(0x277) } >> 24 & 0xff != 0 { return Err("nvme-mmio-pat-not-uc"); }
    let efer = unsafe { read_msr(EFER) } | NXE;
    let cr0_after: u64;
    unsafe {
        asm!("wrmsr", in("ecx") EFER, in("eax") efer as u32, in("edx") (efer >> 32) as u32,
            options(nostack, preserves_flags));
        asm!("mov cr0, {}", in(reg) cr0 | WP, options(nostack, preserves_flags));
        asm!("mov {}, cr0", out(reg) cr0_after, options(nomem, nostack, preserves_flags));
    }
    if unsafe { read_msr(EFER) } & NXE == 0 || cr0_after & WP == 0 {
        return Err("nvme-mmio-cpu-protection");
    }

    // SAFETY: K01 installed the image-owned root and no other CPU can use it.
    let tables = unsafe { &mut *ptr::addr_of_mut!(TABLES) };
    if tables.root() != cr3 { return Err("nvme-mmio-root"); }
    tables.set_nvme_register_page(bar).map_err(|error| error.label())?;
    unsafe { asm!("wbinvd", "mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags)); }
    Ok(())
}

/// Admit the pinned VT-d register page after the NVMe page established
/// NXE, CR0.WP and PAT[3]=UC. The caller remains the sole masked BSP.
#[cfg(io02_nvme_dma_isolation)]
pub unsafe fn prepare_vtd_mmio(handoff: &crate::uefi::Handoff, base: u64) -> Result<(), &'static str> {
    use crate::paging::{Range, VTD_MMIO_BASE, validate_range};

    if base != VTD_MMIO_BASE || handoff.vtd_base != Some(base) {
        return Err("vtd-mmio-not-admitted");
    }
    let aperture = Range::checked(base, 4096).map_err(|error| error.label())?;
    validate_range(aperture, handoff.physical_bits).map_err(|error| error.label())?;
    let scratch = Range::checked(handoff.scratch, 4096).map_err(|error| error.label())?;
    if [handoff.image, handoff.stack, handoff.map_allocation, scratch]
        .into_iter().any(|range| aperture.overlaps(range))
        || handoff.framebuffer.is_some_and(|range| aperture.overlaps(range))
        || handoff.high_scratch.is_some_and(|range| aperture.overlaps(range))
    {
        return Err("vtd-mmio-overlaps-live-range");
    }
    for index in 0..handoff.descriptors() {
        let descriptor = handoff.descriptor(index);
        let bytes = descriptor.pages.checked_mul(4096).ok_or("vtd-descriptor-overflow")?;
        let range = Range::checked(descriptor.start, bytes).map_err(|error| error.label())?;
        // A disjoint descriptor or an explicit non-runtime MMIO descriptor
        // may coexist with the exact DMAR-admitted register aperture.
        if aperture.overlaps(range) && (descriptor.kind != 11 || descriptor.attributes & crate::uefi::RUNTIME != 0) {
            return Err("vtd-mmio-overlaps-memory-map");
        }
    }

    if !mmio_cpu_features() { return Err("vtd-mmio-cpu-features"); }
    let (cr0, cr3) = unsafe { mmio_cpu_owner(handoff) }.ok_or("vtd-mmio-cpu-ownership")?;
    if cr0 & WP == 0 || unsafe { read_msr(EFER) } & NXE == 0 || unsafe { read_msr(0x277) } >> 24 & 0xff != 0 {
        return Err("vtd-mmio-cpu-protection");
    }
    // SAFETY: the live image-owned root is private to the masked BSP.
    let tables = unsafe { &mut *ptr::addr_of_mut!(TABLES) };
    if tables.root() != cr3 { return Err("vtd-mmio-root"); }
    tables.set_vtd_register_page(base).map_err(|error| error.label())?;
    unsafe { asm!("wbinvd", "mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags)); }
    Ok(())
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

/// The timer profile owns exactly one DPL0 hardware gate. CPL3 INT32 must #GP.
#[cfg(k03_timer)]
pub unsafe fn install_timer_boundary() {
    unsafe extern "sysv64" { fn timer_interrupt_32(); }
    unsafe {
        ptr::addr_of_mut!(IDT).cast::<Gate>().add(32)
            .write(Gate::new(timer_interrupt_32 as *const () as usize, 0));
    }
}

/// Change the admitted HPET identity leaf before its first MMIO access.
#[cfg(k03_timer)]
pub unsafe fn prepare_timer_mmio() {
    let tables = unsafe { &mut *ptr::addr_of_mut!(TABLES) };
    tables.set_hpet_uncached().unwrap_or_else(|_| fail("timer-kernel-mmio-map"));
    if !tables.hpet_uncached().unwrap_or(false) { fail("timer-kernel-mmio-flags"); }
    unsafe { asm!("wbinvd", "mov cr3, {}", in(reg) tables.root(), options(nostack)); }
}

/// Sole BSP mutation, before SIPI. The common root is immutable afterward.
#[cfg(k03_smp)]
pub unsafe fn prepare_smp_mmio() {
    let tables = unsafe { &mut *ptr::addr_of_mut!(TABLES) };
    tables.set_hpet_uncached().unwrap_or_else(|_| fail("smp-hpet-map"));
    tables.set_lapic_uncached().unwrap_or_else(|_| fail("smp-lapic-map"));
    if !tables.hpet_uncached().unwrap_or(false) { fail("smp-mmio-flags"); }
    unsafe { asm!("wbinvd", "mov cr3, {}", in(reg) tables.root(), options(nostack)); }
}

#[unsafe(no_mangle)]
pub extern "sysv64" fn exception_handler(frame: &ExceptionFrame, _fp: *const u8) {
    let cr2: u64;
    // SAFETY: entry stubs supply a live normalized frame in privileged mode.
    unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)) };
    #[cfg(not(k03_timer))]
    print(format_args!("TESSRYN_K01_EXCEPTION vector={} error={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} cr2={:#x}\n",
        frame.vector, frame.error, frame.rip, frame.cs, frame.rflags, frame.rsp, cr2));
    #[cfg(k02_region_service)]
    crate::region_runtime::capture(frame, _fp, cr2);
    #[cfg(all(k02_native, not(any(k02_matrix, k02_region_service))))]
    crate::k02::handle_exception(frame, cr2);
    #[cfg(k02_matrix)]
    crate::k02_matrix::handle_exception(frame, cr2);
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
