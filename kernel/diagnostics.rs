// Original Apache-2.0 early x86 diagnostics. No firmware console dependency.
use core::arch::asm;
use core::fmt::{self, Write};

pub unsafe fn out8(port: u16, value: u8) {
    // SAFETY: the caller has privileged x86 I/O authority for this port.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack)) };
}

unsafe fn in8(port: u16) -> u8 {
    let value: u8;
    // SAFETY: this module owns the declared emulator COM1 device.
    unsafe { asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack)) };
    value
}

pub fn init() {
    if !cfg!(k01_emulator) { return; }
    // SAFETY: the K01 machine profile assigns COM1 to this kernel.
    unsafe {
        out8(0x3f9, 0);
        out8(0x3fb, 0x80);
        out8(0x3f8, 1);
        out8(0x3f9, 0);
        out8(0x3fb, 3);
        out8(0x3fa, 0xc7);
        out8(0x3fc, 0x0b);
    }
}

struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            crate::framebuffer::write(byte);
            if !cfg!(k01_emulator) { continue; }
            // SAFETY: debugcon and COM1 are fixed devices in the K01 profile.
            // Bounded polling ensures a broken UART cannot suppress debugcon.
            unsafe {
                out8(0xe9, byte);
                for _ in 0..1024 {
                    if in8(0x3fd) & 0x20 != 0 {
                        out8(0x3f8, byte);
                        break;
                    }
                    core::hint::spin_loop();
                }
            }
        }
        Ok(())
    }
}

pub fn print(arguments: fmt::Arguments<'_>) {
    // Single boot CPU, interrupts disabled after handoff, no locks or allocation.
    let _ = Console.write_fmt(arguments);
}

pub fn finish(success: bool) -> ! {
    // SAFETY: isa-debug-exit is evaluator-controlled and present only in QEMU.
    // Physical boot simply reaches the terminal halt if that device is absent.
    if cfg!(k01_emulator) {
        unsafe {
            asm!("out dx, eax", in("dx") 0xf4u16,
                 in("eax") if success { 0x10u32 } else { 0x11u32 },
                 options(nomem, nostack));
        }
    }
    halt()
}

pub fn halt() -> ! {
    loop {
        // SAFETY: terminal privileged kernel state; no task remains runnable.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

pub fn fail(reason: &str) -> ! {
    print(format_args!("TESSRYN_K01_FAIL reason={reason}\n"));
    finish(false)
}
