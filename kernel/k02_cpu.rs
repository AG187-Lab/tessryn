// Original single-CPU test boundary. Matrix requests use image-bound controlled
// probes and protected caller context; this is not a production syscall ABI.
use core::arch::{asm, global_asm, x86_64::__cpuid};
use core::mem::size_of;
use core::ptr;
use crate::diagnostics::{fail, print};

global_asm!(include_str!("k02_entry.S"),matrix_test=const cfg!(k02_matrix) as u8);

pub const USER_CS: u64 = 0x33;
pub const USER_SS: u64 = 0x2b;

#[repr(C, align(16))]
struct TrapStack([u8; 32 * 1024]);
static mut TRAP_STACK: TrapStack = TrapStack([0; 32 * 1024]);

// Intel's 64-bit FXSAVE layout: FCW at 0, MXCSR at 24, eight 16-byte
// x87/MMX slots at 32 and sixteen 16-byte XMM slots at 160. Loading the
// complete reset image clears the data registers as well as their tags.
// FNINIT alone would leave prior register contents physically observable.
#[repr(C, align(16))]
struct ResetFp([u8;512]);
const fn reset_fp() -> ResetFp {
    let mut bytes=[0;512];
    bytes[0]=0x7f;bytes[1]=0x03;
    bytes[24]=0x80;bytes[25]=0x1f;
    ResetFp(bytes)
}
#[used]
#[unsafe(no_mangle)]
static k02_reset_fp:ResetFp=reset_fp();
#[unsafe(no_mangle)]
static mut k02_restored_fp:ResetFp=ResetFp([0;512]);
#[unsafe(no_mangle)]
static mut k02_kernel_fp_restored:u64=0;
static mut MXCSR_MASK:u32=0;

pub fn mxcsr_mask() -> u32 {unsafe{ptr::addr_of!(MXCSR_MASK).read()}}

#[unsafe(no_mangle)]
pub extern "sysv64" fn k02_fp_restore_failure(offset:u64)->! {
    print(format_args!("TESSRYN_K02_FP_RESTORE_MISMATCH first_offset={offset}\n"));
    fail("k02-kernel-fp-restore-mismatch")
}

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
    pub static k02_probe_read: u8;
    pub static k02_probe_read_return: u8;
    pub static k02_probe_write: u8;
    pub static k02_probe_write_return: u8;
    pub static k02_probe_request: u8;
    pub static k02_probe_request_trap: u8;
    pub static k02_probe_kernel_read_return: u8;
    pub static k02_probe_readonly_write_return: u8;
    pub static k02_probe_unauthorized_read: u8;
    pub static k02_probe_unauthorized_read_return: u8;
    pub static k02_probe_guard_read: u8;
    pub static k02_probe_guard_read_return: u8;
    pub static k02_probe_kernel_write: u8;
    pub static k02_probe_kernel_write_return: u8;
    pub static k02_probe_policy_read: u8;
    pub static k02_probe_policy_read_return: u8;
    pub static k02_probe_policy_write: u8;
    pub static k02_probe_policy_write_return: u8;
    pub static k02_probe_page_table_read: u8;
    pub static k02_probe_page_table_read_return: u8;
    pub static k02_probe_page_table_write: u8;
    pub static k02_probe_page_table_write_return: u8;
    pub static k02_probe_recursive_B_read: u8;
    pub static k02_probe_recursive_B_read_return: u8;
    pub static k02_probe_recursive_B_write: u8;
    pub static k02_probe_recursive_B_write_return: u8;
    pub static k02_probe_recursive_D_read: u8;
    pub static k02_probe_recursive_D_read_return: u8;
    pub static k02_probe_recursive_D_write: u8;
    pub static k02_probe_recursive_D_write_return: u8;
    pub static k02_probe_reuse_B_read: u8;
    pub static k02_probe_reuse_B_read_return: u8;
    pub static k02_probe_reuse_B_write: u8;
    pub static k02_probe_reuse_B_write_return: u8;
    pub static k02_probe_boundary_snapshot: u8;
    pub static k02_probe_boundary_snapshot_return: u8;
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
    let cr0:u64;
    unsafe { asm!("mov {}, cr0",out(reg)cr0,options(nomem,nostack)); }
    let features=__cpuid(1).edx;
    // This boundary saves/sanitizes the legacy x87/MMX/SSE state with FXSAVE.
    // Extended-state execution needs a separately reviewed XSAVE profile.
    // Reject active OSXSAVE instead of silently dropping YMM/ZMM/other state.
    if features & ((1<<24)|(1<<25)|(1<<26)) != ((1<<24)|(1<<25)|(1<<26))
        || cr4 & (1<<18) != 0 || cr4 & ((1<<9)|(1<<10)) != ((1<<9)|(1<<10))
        || cr0 & ((1<<2)|(1<<3)) != 0 { fail("k02-legacy-fp-profile"); }
    // The supported MXCSR mask is hardware-defined and is not restored from
    // the software reset image. Capture it independently before any user entry.
    let mut supported=ResetFp([0;512]);
    unsafe{asm!("fxsave64 [{}]",in(reg)ptr::addr_of_mut!(supported),options(nostack));}
    let mask=u32::from_le_bytes(supported.0[28..32].try_into().unwrap());
    if mask==0 || mask & 0x1f80 != 0x1f80 {fail("k02-fxsave-mxcsr-mask");}
    unsafe{ptr::addr_of_mut!(MXCSR_MASK).write(mask);}
    #[cfg(any(k02_matrix, k02_region_service))]
    {
        // This matrix admits ordinary four-level page permissions only. Do not
        // dismantle a live CET/shadow-stack context or reinterpret PKRU/PKRS.
        // Reject those active modes before changing any control state.
        if cr4 & ((1u64 << 22) | (1u64 << 23) | (1u64 << 24)) != 0 {
            fail("k02-matrix-extra-protection-mode");
        }
        // SGX is a capability/firmware feature, not a CR4 enable bit. Exclude
        // processors exposing it instead of modifying locked firmware MSRs.
        if __cpuid(0).eax >= 7
            && core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 2) != 0
        { fail("k02-matrix-enclave-profile"); }
    }
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
        || ptr::addr_of!(k02_reset_fp) as u64 % 16 != 0
        || (ptr::addr_of!(k02_reset_fp) as u64) < handoff.image.start
        || ptr::addr_of!(k02_reset_fp) as u64 + size_of::<ResetFp>() as u64 > handoff.image.end
        || (ptr::addr_of!(k02_restored_fp) as u64) < handoff.image.start
        || ptr::addr_of!(k02_restored_fp) as u64 + size_of::<ResetFp>() as u64 > handoff.image.end
    { fail("k02-protected-boundary-range"); }
    // A dedicated privilege-transition stack never overwrites the active Rust
    // boot stack. This stack and all boundary state remain image-owned.
    unsafe { crate::cpu::install_user_test_boundary(stack.end, exception_k02_return as *const () as usize); }
    let actual_cr0: u64;
    let actual_cr4: u64;
    let low: u32;
    let high: u32;
    unsafe {
        asm!("mov {}, cr0", out(reg) actual_cr0, options(nomem, nostack));
        asm!("mov {}, cr4", out(reg) actual_cr4, options(nomem, nostack));
        asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") low, out("edx") high, options(nostack));
    }
    let _ = high;
    if actual_cr0 & (1 << 16) == 0
        || actual_cr4 & ((1 << 7) | (1 << 12) | (1 << 17) | (1<<18)) != 0
        || actual_cr4 & ((1<<9)|(1<<10)) != ((1<<9)|(1<<10))
        || actual_cr0 & ((1<<2)|(1<<3)) != 0 || low & (1 << 11) == 0 {
        fail("k02-cpu-profile-readback");
    }
    print(format_args!("TESSRYN_K02_PROFILE physical_bits={} cpu_count=1 paging_levels=4 nx_supported=1 nx_enabled=1 pcid_enabled=0 global_translations=0 la57_enabled=0 cr4={actual_cr4:#x} efer_low={low:#x}\n", handoff.physical_bits));
    #[cfg(any(k02_matrix, k02_region_service))]
    {
        if actual_cr4 & ((1u64 << 22) | (1u64 << 23) | (1u64 << 24)) != 0 {
            fail("k02-matrix-protection-readback");
        }
        #[cfg(k02_matrix)]
        print(format_args!("TESSRYN_K02_MATRIX_CPU cr0={actual_cr0:#x} wp_enabled=1 pke_enabled=0 pks_enabled=0 cet_enabled=0 sgx_supported=0 osxsave_enabled=0 fxsave_mxcsr_mask={mask:#x}\n"));
    }
}

/// SAFETY: validated private root, trusted code and stack maps, one active
/// protected probe context; no IRQ or concurrent owner can access the maps.
pub unsafe fn enter(root: u64, instruction: u64, stack: u64, target: u64, value: u64) {
    let result = unsafe { k02_enter_user(root, instruction, stack, target, value) };
    if result != 1 || unsafe{ptr::addr_of!(k02_kernel_fp_restored).read()}!=1 {
        fail("k02-user-return-status");
    }
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
