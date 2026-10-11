// Original x86-64 descriptor tables, exception boundary and initial paging.
use core::arch::{asm, global_asm};
use core::mem::{size_of, offset_of};
use core::ptr;
use crate::diagnostics::{fail, print, finish};

global_asm!(include_str!("entry.S"));

unsafe extern "efiapi" {
    pub fn kernel_enter(stack: u64, handoff: *const crate::uefi::Handoff) -> !;
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
#[repr(C, align(4096))]
struct PageTable([u64; 512]);

static mut GDT: [u64; 5] = [0, 0x00af_9a00_0000_ffff, 0x00cf_9200_0000_ffff, 0, 0];
static mut IDT: [Gate; 256] = [EMPTY; 256];
static mut TSS: Tss = Tss { reserved0: 0, rsp: [0; 3], reserved1: 0, ist: [0; 7], reserved2: 0, reserved3: 0, iomap: 104 };
static mut FAULT_STACK: FaultStack = FaultStack([0; 16 * 1024]);
static mut PML4: PageTable = PageTable([0; 512]);
static mut PDPT: PageTable = PageTable([0; 512]);
static mut DIRECTORIES: [PageTable; 4] = [const { PageTable([0; 512]) }; 4];

#[repr(C)]
pub struct ExceptionFrame {
    registers: [u64; 15],
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

pub unsafe fn take_ownership(stack_top: u64) {
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

        let root = ptr::addr_of_mut!(PML4).cast::<u64>();
        let pdpt = ptr::addr_of_mut!(PDPT).cast::<u64>();
        let directories = ptr::addr_of_mut!(DIRECTORIES).cast::<PageTable>();
        root.write(pdpt as u64 | 3);
        for gigabyte in 0..4 {
            let directory = directories.add(gigabyte).cast::<u64>();
            pdpt.add(gigabyte).write(directory as u64 | 3);
            for entry in 0..512 {
                let physical = ((gigabyte * 512 + entry) as u64) << 21;
                directory.add(entry).write(physical | 0x83);
            }
        }
        // The initial supervisor-only 4 GiB identity mapping deliberately has
        // no isolation/protection claim; K02 supplies granular mappings.
        asm!("mov cr3, {}", in(reg) root as u64, options(nostack));
        let actual_cr3: u64;
        let rsp: u64;
        asm!("mov {}, cr3", out(reg) actual_cr3, options(nomem, nostack));
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
        if actual_cr3 != root as u64 || rsp >= stack_top
            || rsp < stack_top - crate::uefi::STACK_PAGES as u64 * 4096 { fail("cpu-ownership"); }
        print(format_args!("TESSRYN_K01_CPU_OWNED cr3={actual_cr3:#x} rsp={rsp:#x} gdt=owned idt=owned tss=owned\n"));
    }
}

#[unsafe(no_mangle)]
pub extern "sysv64" fn exception_handler(frame: &ExceptionFrame) {
    let cr2: u64;
    // SAFETY: entry stubs supply a live normalized frame in privileged mode.
    unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)) };
    print(format_args!("TESSRYN_K01_EXCEPTION vector={} error={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} cr2={:#x}\n",
        frame.vector, frame.error, frame.rip, frame.cs, frame.rflags, frame.rsp, cr2));
    if cfg!(k01_case = "int3") && frame.vector == 3 && frame.error == 0 {
        // Deliberately clobber caller-saved FP registers; the returning trap
        // wrapper must restore the interrupted context's sentinels.
        unsafe { smash_probe_fp() };
        return;
    }
    let expected = (cfg!(k01_case = "invalid_opcode") && frame.vector == 6 && frame.error == 0)
        || (cfg!(k01_case = "page_fault") && frame.vector == 14 && frame.error == 0 && cr2 == crate::uefi::LIMIT);
    if expected {
        print(format_args!("TESSRYN_K01_EXPECTED_FAULT\n"));
        finish(true);
    }
    fail("unexpected-exception")
}
