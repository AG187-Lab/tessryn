// Tessryn's original first kernel. Apache-2.0; no Cargo or third-party crates.
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg_attr(any(native_benchmarks, k03_smp), allow(dead_code))]
mod cpu;
mod diagnostics;
mod framebuffer;
mod paging;
mod uefi;
#[cfg(k03_smp)]
mod smp;
#[cfg(k03_smp)]
mod smp_acpi;
#[cfg(smp_benchmarks)]
mod contention_benchmarks;
#[cfg(all(smp_benchmarks, any(not(k03_smp), not(k01_emulator), k01_aws,
    k02_native, k02_matrix, k02_region_service, native_benchmarks, k03_timer, k03_smp_user,
    not(smp_case = "rendezvous"))))]
compile_error!("contention benchmarks require the separate two-CPU rendezvous emulator image");
#[cfg(all(k03_smp, any(not(k01_emulator), k01_aws, k02_native, native_benchmarks, k03_timer)))]
compile_error!("SMP bootstrap is a separate emulator-only image");
#[cfg(all(native_benchmarks, any(k02_native, k02_matrix, k02_region_service)))]
compile_error!("native_benchmarks and k02_native are separate opt-in images");
#[cfg(all(native_benchmarks, any(k01_aws, not(k01_emulator))))]
compile_error!("the first native benchmark profile requires k01_emulator only");
#[cfg(native_benchmarks)]
mod benchmark_clock;
#[cfg(native_benchmarks)]
mod native_benchmarks;
#[cfg(any(native_benchmarks, k03_timer))]
extern crate tessryn_scheduler;
#[cfg(k03_timer)]
mod preempt_timer;
#[cfg(k03_timer)]
mod preempt_policy;
#[cfg(all(k03_timer, any(not(k02_region_service), k02_matrix, native_benchmarks)))]
compile_error!("timer preemption requires the separate region-service emulator profile");
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
#[cfg(k02_matrix)]
mod k02_matrix;
#[cfg(k02_matrix)]
mod k02_sha256;
#[cfg(all(k02_region_service, k02_matrix))]
compile_error!("region service and fixed matrix are separate profiles");
#[cfg(all(k02_region_service, any(k01_aws, not(k01_emulator), not(k02_native))))]
compile_error!("the first region service profile requires K02 native emulator only");
#[cfg(k02_region_service)]
mod region_service;
#[cfg(k02_region_service)]
mod region_runtime;
#[cfg(all(k02_region_service, not(k02_matrix)))]
mod k02_sha256;

#[cfg(not(any(native_benchmarks, k03_smp)))]
use core::arch::asm;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::ptr;
#[cfg(not(any(native_benchmarks, k03_smp)))]
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
    #[cfg(k03_smp)]
    smp::run(handoff);
    #[cfg(native_benchmarks)]
    native_benchmarks::run(handoff);
    #[cfg(not(any(native_benchmarks, k03_smp)))]
    {
    #[cfg(k02_matrix)]
    k02_matrix::run(handoff);
    #[cfg(k02_region_service)]
    region_runtime::run(handoff);
    #[cfg(all(k02_native, not(any(k02_matrix, k02_region_service))))]
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
    #[cfg(k03_smp)]
    smp::panic_park_if_ap();
    // No allocator, locks, firmware console or stack unwinding on this path.
    print(format_args!("TESSRYN_K01_PANIC {info}\n"));
    finish(cfg!(k01_case = "panic"))
}
