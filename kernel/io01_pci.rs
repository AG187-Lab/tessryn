//! Original Apache-2.0 PCI configuration discovery for one q35 emulator profile.
//!
//! Segment zero, buses 0–7 and the conventional configuration header only.
//! This profile leaves firmware assignments untouched and grants no BAR, MMIO,
//! interrupt, DMA or driver authority.

#[cfg(not(test))]
use crate::diagnostics::{halt, print};

const MAX_FUNCTIONS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bdf {
    bus: u8,
    slot: u8,
    function: u8,
}

#[derive(Clone, Copy)]
#[repr(u32)]
enum Register {
    Id = 0x00,
    ClassRevision = 0x08,
    Header = 0x0c,
}

impl Bdf {
    fn selector(self, register: Register) -> u32 {
        0x8000_0000
            | (u32::from(self.bus) << 16)
            | (u32::from(self.slot) << 11)
            | (u32::from(self.function) << 8)
            | register as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Function {
    bdf: Bdf,
    id: u32,
    class_rev: u32,
    header: u32,
}

impl Function {
    const EMPTY: Self = Self {
        bdf: Bdf {
            bus: 0,
            slot: 0,
            function: 0,
        },
        id: 0,
        class_rev: 0,
        header: 0,
    };
}

struct Inventory {
    functions: [Function; MAX_FUNCTIONS],
    len: usize,
}

impl Inventory {
    fn admitted(&self) -> &[Function] {
        &self.functions[..self.len]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanError {
    ZeroVendor,
    UnsupportedHeader,
    Capacity,
}

fn scan(mut read: impl FnMut(u32) -> u32) -> Result<Inventory, ScanError> {
    let mut inventory = Inventory {
        functions: [Function::EMPTY; MAX_FUNCTIONS],
        len: 0,
    };
    // Probe every admitted BDF, including nonzero functions. The order of the
    // fixed loops is also the order of the resulting inventory.
    for bus in 0..8 {
        for slot in 0..32 {
            for function in 0..8 {
                let bdf = Bdf {
                    bus,
                    slot,
                    function,
                };
                let id = read(bdf.selector(Register::Id));
                match id as u16 {
                    0xffff => continue,
                    0 => return Err(ScanError::ZeroVendor),
                    _ => {}
                }
                if inventory.len == MAX_FUNCTIONS {
                    return Err(ScanError::Capacity);
                }
                let class_rev = read(bdf.selector(Register::ClassRevision));
                let header = read(bdf.selector(Register::Header));
                // Header type is byte 0x0e; bit 7 of that byte is multifunction.
                if ((header >> 16) & 0x7f) > 2 {
                    return Err(ScanError::UnsupportedHeader);
                }
                inventory.functions[inventory.len] = Function {
                    bdf,
                    id,
                    class_rev,
                    header,
                };
                inventory.len += 1;
            }
        }
    }
    Ok(inventory)
}

#[cfg(not(test))]
unsafe fn read_config(selector: u32) -> u32 {
    let value: u32;
    // SAFETY: the dedicated q35 profile owns this selector/data pair on a
    // single privileged CPU with interrupts disabled. Only the address port
    // receives a write. The data port is only read, and no pointer is used.
    unsafe {
        core::arch::asm!(
            "mov dx, 0xcf8",
            "out dx, eax",
            "mov dx, 0xcfc",
            "in eax, dx",
            inout("eax") selector => value,
            out("dx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

#[cfg(not(test))]
pub fn run() -> ! {
    print(format_args!(
        "TESSRYN_IO01_PCI_BEGIN segment=0 buses=0-7 mechanism=cf8-cfc\n"
    ));
    // SAFETY: this entry is reachable only after K01 handoff in the dedicated
    // single-CPU emulator profile. Selectors are constructed solely by scan.
    match scan(|selector| unsafe { read_config(selector) }) {
        Ok(inventory) => {
            for record in inventory.admitted() {
                let Function {
                    bdf:
                        Bdf {
                            bus,
                            slot,
                            function,
                        },
                    id,
                    class_rev,
                    header,
                } = *record;
                print(format_args!(
                    "TESSRYN_IO01_PCI_FUNCTION bdf={bus:02x}:{slot:02x}.{function:x} id=0x{id:08x} class_rev=0x{class_rev:08x} header=0x{header:08x}\n"
                ));
            }
            print(format_args!(
                "TESSRYN_IO01_PCI_DONE count={}\n",
                inventory.len
            ));
        }
        Err(error) => {
            let reason = match error {
                ScanError::ZeroVendor => "zero-vendor",
                ScanError::UnsupportedHeader => "unsupported-header",
                ScanError::Capacity => "capacity",
            };
            print(format_args!("TESSRYN_IO01_PCI_FAIL reason={reason}\n"));
        }
    }
    // The host collects the final topology via QMP before it quits QEMU.
    halt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_encodes_address_and_only_the_admitted_dwords() {
        let bdf = Bdf {
            bus: 7,
            slot: 31,
            function: 7,
        };
        assert_eq!(bdf.selector(Register::Id), 0x8007_ff00);
        assert_eq!(bdf.selector(Register::ClassRevision), 0x8007_ff08);
        assert_eq!(bdf.selector(Register::Header), 0x8007_ff0c);
    }

    #[test]
    fn absent_functions_still_probe_every_bdf_but_no_other_dword() {
        let mut probes = 0;
        let inventory = scan(|selector| {
            assert_eq!(selector, 0x8000_0000 | (probes << 8));
            probes += 1;
            0x0123_ffff // Only the low (vendor) half determines absence.
        })
        .expect("empty profile");
        assert_eq!(probes, 2048);
        assert!(inventory.admitted().is_empty());
    }

    #[test]
    fn records_are_sorted_and_preserve_little_endian_header_dwords() {
        let inventory = scan(|selector| match selector {
            0x8000_0100 => 0xffff_8086, // Device half is not the presence field.
            0x8000_0108 => 0x0600_0001,
            0x8000_010c => 0x0080_0000,
            0x8007_ff00 => 0x0010_1b36,
            0x8007_ff08 => 0x0108_0202,
            0x8007_ff0c => 0x0082_0000,
            _ => 0xffff_ffff,
        })
        .expect("two valid functions");
        assert_eq!(
            inventory.admitted(),
            &[
                Function {
                    bdf: Bdf {
                        bus: 0,
                        slot: 0,
                        function: 1
                    },
                    id: 0xffff_8086,
                    class_rev: 0x0600_0001,
                    header: 0x0080_0000,
                },
                Function {
                    bdf: Bdf {
                        bus: 7,
                        slot: 31,
                        function: 7
                    },
                    id: 0x0010_1b36,
                    class_rev: 0x0108_0202,
                    header: 0x0082_0000,
                },
            ]
        );
    }

    #[test]
    fn invalid_vendor_and_unsupported_header_fail_closed() {
        assert_eq!(
            scan(|selector| {
                assert_eq!(selector, 0x8000_0000);
                0x1234_0000
            })
            .err(),
            Some(ScanError::ZeroVendor)
        );
        assert_eq!(
            scan(|selector| match selector {
                0x8000_0000 => 0x1234_8086,
                0x8000_0008 => 0x0600_0000,
                0x8000_000c => 0x0083_0000,
                _ => panic!("must stop at the unsupported header"),
            })
            .err(),
            Some(ScanError::UnsupportedHeader)
        );
    }

    #[test]
    fn capacity_accepts_64_and_rejects_65_before_any_extra_header_reads() {
        let read = |count: u32, selector: u32| {
            if ((selector >> 8) & 0x7ff) >= count {
                return 0xffff_ffff;
            }
            match selector & 0xff {
                0 => 0x1234_8086,
                8 | 12 => 0,
                _ => panic!("unadmitted register read"),
            }
        };
        assert_eq!(
            scan(|selector| read(64, selector))
                .expect("at capacity")
                .admitted()
                .len(),
            64
        );
        let mut probes = 0;
        assert_eq!(
            scan(|selector| {
                probes += 1;
                read(65, selector)
            })
            .err(),
            Some(ScanError::Capacity)
        );
        assert_eq!(probes, 64 * 3 + 1);
    }
}
