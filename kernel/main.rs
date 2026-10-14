// Tessryn's original first kernel. Apache-2.0; no Cargo or third-party crates.
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg_attr(native_benchmarks, allow(dead_code))]
mod cpu;
mod diagnostics;
mod framebuffer;
mod paging;
mod uefi;
#[cfg(all(native_benchmarks, k02_native))]
compile_error!("native_benchmarks and k02_native are separate opt-in images");
#[cfg(all(native_benchmarks, any(k01_aws, not(k01_emulator))))]
compile_error!("the first native benchmark profile requires k01_emulator only");
#[cfg(native_benchmarks)]
mod benchmark_clock;
#[cfg(native_benchmarks)]
mod native_benchmarks;
#[cfg(native_benchmarks)]
extern crate tessryn_scheduler;
#[cfg(any(k02_native, native_benchmarks))]
extern crate tessryn_owned_memory;
#[cfg(k02_native)]
mod k02;
#[cfg(k02_native)]
mod k02_cpu;
#[cfg(k02_native)]
mod k02_memory;
#[cfg(k02_native)]
mod k02_paging;

#[cfg(not(native_benchmarks))]
use core::arch::asm;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::ptr;
#[cfg(not(native_benchmarks))]
use diagnostics::fail;
use diagnostics::{finish, print};

static mut HANDOFF: MaybeUninit<uefi::Handoff> = MaybeUninit::uninit();

#[unsafe(no_mangle)]
pub unsafe extern "efiapi" fn efi_main(image: uefi::Handle, system: *const uefi::SystemTable) -> usize {
    diagnostics::init();
    print(format_args!("TESSRYN_K01_ENTRY\n"));
    // SAFETY: firmware supplied the documented x64 entry parameters. No pointer
    // to firmware boot services is retained in the kernel handoff.
    let handoff = match unsafe { uefi::leave_firmware(image, system) } {
        Ok(handoff) => handoff,
        Err(status) => return status,
    };
    let stack_top = handoff.stack.end;
    // SAFETY: loader image data belongs to this kernel and is reserved by its
    // memory inventory. The assembly changes stack and never returns.
    unsafe {
        let destination = ptr::addr_of_mut!(HANDOFF).cast::<uefi::Handoff>();
        destination.write(handoff);
        cpu::kernel_enter(stack_top, destination.cast())
    }
}

#[unsafe(no_mangle)]
pub extern "sysv64" fn kernel_main(handoff: &uefi::Handoff) -> ! {
    // SAFETY: firmware has exited; kernel owns its loaded image and stack.
    unsafe { cpu::take_ownership(handoff) };
    #[cfg(native_benchmarks)]
    native_benchmarks::run(handoff);
    #[cfg(not(native_benchmarks))]
    {
    #[cfg(k02_native)]
    k02::run(handoff);
    // Read/write one page from conventional RAM only. Every live allocation,
    // runtime, ACPI and reserved descriptor has been excluded by validation.
    let scratch = handoff.scratch as *mut u64;
    let pattern = 0x5445_5353_5259_4e01u64;
    unsafe {
        scratch.write_volatile(pattern);
        if scratch.read_volatile() != pattern { fail("owned-memory-readback"); }
        scratch.write_volatile(0);
    }
    print(format_args!("TESSRYN_K01_MEMORY_OWNERSHIP_OK scratch={:#x} free_pages={} loader=reserved runtime=reserved firmware=quarantined\n",
        handoff.scratch, handoff.free_pages));
    if cfg!(k01_high_handoff) {
        print(format_args!("TESSRYN_K01_HIGH_OWNERSHIP_OK scratch={:#x} pattern={pattern:#x}\n", handoff.scratch));
    }
    if cfg!(k01_case = "int3") {
        // SAFETY: vector 3 is installed with a returning normalized trap stub.
        if unsafe { cpu::probe_int3() } != 1 { fail("trap-fp-state-preservation"); }
        print(format_args!("TESSRYN_K01_INT3_RECOVERED fp_state=preserved\n"));
    } else if cfg!(k01_case = "invalid_opcode") {
        // SAFETY: this intentionally tests the terminal #UD diagnostic path.
        unsafe { asm!("ud2", options(noreturn)) };
    } else if cfg!(k01_case = "page_fault") {
        // SAFETY: intentional supervisor read from the reserved, unmapped,
        // canonical guard. High live mappings never consume this region.
        unsafe { asm!("mov rax, qword ptr [rcx]", in("rcx") paging::GUARD, out("rax") _, options(nostack)) };
        fail("page-fault-did-not-trap");
    } else if cfg!(k01_case = "panic") {
        panic!("intentional K01 panic");
    } else if cfg!(k01_case = "reboot") {
        print(format_args!("TESSRYN_K01_REBOOT_REQUEST method=uefi-runtime-cold-reset\n"));
        // SAFETY: runtime code/data are preserved and identity mapped, flat
        // selectors and ABI alignment are restored, and CPU FP state remains
        // the UEFI entry state. Runtime reset remains legal after firmware exit.
        unsafe { (handoff.reset)(0, 0, 0, ptr::null()) };
    }
    print(format_args!("TESSRYN_K01_PASS\n"));
    finish(true)
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // No allocator, locks, firmware console or stack unwinding on this path.
    print(format_args!("TESSRYN_K01_PANIC {info}\n"));
    finish(cfg!(k01_case = "panic"))
}
