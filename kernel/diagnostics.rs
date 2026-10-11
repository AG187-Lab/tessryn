// Original Apache-2.0 early x86 diagnostics. No firmware console dependency.
use core::arch::asm;
use core::fmt::{self, Write};

fn serial_enabled() -> bool { cfg!(k01_emulator) || cfg!(k01_aws) }
fn emulator_ports() -> bool { cfg!(k01_emulator) && !cfg!(k01_aws) }

pub unsafe fn out8(port: u16, value: u8) {
    // SAFETY: the caller has privileged x86 I/O authority for this port.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack)) };
}

unsafe fn in8(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the selected early serial profile grants COM1 port authority.
    unsafe { asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack)) };
    value
}

pub fn init() {
    if !serial_enabled() { return; }
    // SAFETY: emulator COM1 is assigned by its evaluator. The explicit AWS
    // profile assumes an x86 16550-compatible COM1 at 0x3f8, 115200n8. AWS
    // documents serial port 0/COM1, but this I/O address must be qualified on
    // the delivered instance. Generic physical deployment grants no UART I/O.
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
            if !serial_enabled() { continue; }
            // SAFETY: selected profile owns COM1; QEMU-only ports are never
            // used by an AWS artifact, even if both cfg flags are supplied.
            // Bounded polling ensures a broken UART cannot suppress debugcon.
            unsafe {
                if emulator_ports() { out8(0xe9, byte); }
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
    if emulator_ports() {
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
