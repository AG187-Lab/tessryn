// Original single-CPU test boundary. No untrusted syscall dispatcher or SMP.
use core::arch::{asm, global_asm, x86_64::__cpuid};
use core::mem::size_of;
use core::ptr;
use crate::diagnostics::{fail, print};

global_asm!(include_str!("k02_entry.S"));

pub const USER_CS: u64 = 0x33;
pub const USER_SS: u64 = 0x2b;

#[repr(C, align(16))]
struct TrapStack([u8; 32 * 1024]);
static mut TRAP_STACK: TrapStack = TrapStack([0; 32 * 1024]);

#[unsafe(no_mangle)]
static mut k02_saved_kernel_rsp: u64 = 0;
#[unsafe(no_mangle)]
static mut k02_saved_kernel_cr3: u64 = 0;

unsafe extern "sysv64" {
    fn k02_enter_user(root: u64, instruction: u64, stack: u64, target: u64, value: u64) -> u64;
    fn k02_return_kernel() -> !;
    pub fn exception_k02_return();
    pub static k02_user_code_start: u8;
    pub static k02_user_code_end: u8;
    pub static k02_probe_own_write: u8;
    pub static k02_probe_own_read: u8;
    pub static k02_probe_own_return: u8;
    pub static k02_probe_foreign_read: u8;
    pub static k02_probe_kernel_read: u8;
    pub static k02_probe_readonly_write: u8;
}

pub fn trap_stack() -> crate::paging::Range {
    let start = ptr::addr_of!(TRAP_STACK) as u64;
    crate::paging::Range { start, end: start + size_of::<TrapStack>() as u64 }
}

pub fn code_page() -> u64 { ptr::addr_of!(k02_user_code_start) as u64 }
pub fn probe_offset(symbol: *const u8) -> u64 {
    (symbol as u64).checked_sub(code_page()).filter(|offset| *offset < 4096)
        .unwrap_or_else(|| fail("k02-probe-offset"))
}

/// Admit the narrow profile before installing any NX-marked user PTE.
pub fn initialize(handoff: &crate::uefi::Handoff) {
    if handoff.physical_bits != 48 || __cpuid(0x8000_0000).eax < 0x8000_0008
        || __cpuid(0x8000_0001).edx & (1 << 20) == 0 { fail("k02-cpu-profile"); }
    let cr4: u64;
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack)); }
    if cr4 & (1 << 12) != 0 { fail("k02-five-level-profile"); }
    // K01 has already installed an aligned, non-PCID root and removed PGE.
    // Keep that profile explicit; no PCID or global translations survive.
    unsafe {
        asm!("mov cr4, {}", in(reg) cr4 & !((1u64 << 7) | (1u64 << 17)), options(nostack));
        let low: u32;
        let high: u32;
        asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") low, out("edx") high, options(nostack));
        asm!("wrmsr", in("ecx") 0xc000_0080u32, in("eax") low | (1 << 11), in("edx") high, options(nostack));
        let cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        asm!("mov cr0, {}", in(reg) cr0 | (1u64 << 16), options(nostack));
    }
    let stack = trap_stack();
    if stack.start < handoff.image.start || stack.end > handoff.image.end
        || code_page() % 4096 != 0 || code_page() < handoff.image.start
        || code_page() + 4096 > handoff.image.end
        || ptr::addr_of!(k02_user_code_end) as u64 != code_page() + 4096
    { fail("k02-protected-boundary-range"); }
    // A dedicated privilege-transition stack never overwrites the active Rust
    // boot stack. This stack and all boundary state remain image-owned.
    unsafe { crate::cpu::install_user_test_boundary(stack.end, exception_k02_return as *const () as usize); }
    let actual_cr4: u64;
    let low: u32;
    let high: u32;
    unsafe {
        asm!("mov {}, cr4", out(reg) actual_cr4, options(nomem, nostack));
        asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") low, out("edx") high, options(nostack));
    }
    let _ = high;
    if actual_cr4 & ((1 << 7) | (1 << 12) | (1 << 17)) != 0 || low & (1 << 11) == 0 {
        fail("k02-cpu-profile-readback");
    }
    print(format_args!("TESSRYN_K02_PROFILE physical_bits={} cpu_count=1 paging_levels=4 nx_supported=1 nx_enabled=1 pcid_enabled=0 global_translations=0 la57_enabled=0 cr4={actual_cr4:#x} efer_low={low:#x}\n", handoff.physical_bits));
}

/// SAFETY: validated private root, trusted code and stack maps, one active
/// protected probe context; no IRQ or concurrent owner can access the maps.
pub unsafe fn enter(root: u64, instruction: u64, stack: u64, target: u64, value: u64) {
    let result = unsafe { k02_enter_user(root, instruction, stack, target, value) };
    if result != 1 { fail("k02-user-return-status"); }
}

/// SAFETY: only the exact admitted CPL3 test return/fault can call this. The
/// original kernel stack/root/FP state were saved by the active entry routine.
pub unsafe fn return_to_kernel() -> ! { unsafe { k02_return_kernel() } }

/// SAFETY: interrupts masked, caller owns both roots, no user code is running.
/// A real CR3 reload completes the declared no-PCID/non-global TLB fence.
pub unsafe fn reload(root: u64) {
    unsafe { asm!("mov cr3, {}", in(reg) root, options(nostack)); }
    let actual: u64;
    unsafe { asm!("mov {}, cr3", out(reg) actual, options(nomem, nostack)); }
    if actual != root { fail("k02-cr3-reload"); }
}
