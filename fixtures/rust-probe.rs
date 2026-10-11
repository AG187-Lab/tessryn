// Original Apache-2.0 compiler/linker probe. Never executed by the ROM harness.
#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

#[unsafe(no_mangle)]
pub extern "C" fn fixture_entry() -> ! {
    loop {
        // SAFETY: this probe is freestanding x86 code; hlt has no memory operands.
        // Executing it requires privileged x86 state, which this issue does not set up.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fixture_entry()
}
