//! Original read-only register probe for one namespace-less q35 NVMe model.

use super::{Bdf, Function, Register};

#[cfg(io02_nvme_admin_queues)]
#[path = "io02_nvme_admin.rs"]
mod admin;

const CONTROLLER: Bdf = Bdf {
    bus: 1,
    slot: 0,
    function: 0,
};
const ID: u32 = 0x0010_1b36;
const CLASS: u32 = 0x0108_02;
#[cfg(not(test))]
const BAR: u64 = crate::paging::NVME_MMIO_BASE;
#[cfg(test)]
const BAR: u64 = 0x8100_0000;
const CAP: u64 = 0x0040_0820_0f01_07ff;
const VS: u32 = 0x0001_0400;

#[derive(Debug, PartialEq, Eq)]
struct Registers {
    bar: u64,
    cap: u64,
    vs: u32,
}

fn probe(
    functions: &[Function],
    mut config: impl FnMut(u32) -> u32,
    prepare_mmio: impl FnOnce(u64) -> Result<(), &'static str>,
    mut mmio: impl FnMut(u64) -> u32,
) -> Result<Option<Registers>, &'static str> {
    let mut candidates = functions
        .iter()
        .filter(|row| row.bdf == CONTROLLER || row.id == ID || row.class_rev >> 16 == CLASS >> 8);
    let Some(row) = candidates.next() else {
        return Ok(None);
    };
    // Each of these signals is enough to refuse a lookalike, even if the
    // expected function is present elsewhere in the same inventory.
    if row.bdf != CONTROLLER
        || row.id != ID
        || row.class_rev >> 8 != CLASS
        || ((row.header >> 16) & 0xff) != 0
        || candidates.next().is_some()
    {
        return Err("unexpected-controller");
    }
    let command = config(row.bdf.selector(Register::CommandStatus)) as u16;
    if command == u16::MAX || command & 2 == 0 {
        return Err("invalid-memory-decode");
    }
    let low = config(row.bdf.selector(Register::Bar0));
    let high = config(row.bdf.selector(Register::Bar1));
    let bar = (u64::from(high) << 32) | u64::from(low & !0xf);
    // The low nibble must describe 64-bit, non-prefetchable memory. The
    // firmware assignment must match the one admitted q35 profile.
    if low & 0xf != 4 || bar != BAR {
        return Err("unexpected-bar");
    }
    prepare_mmio(bar)?;
    let cap = u64::from(mmio(bar)) | (u64::from(mmio(bar + 4)) << 32);
    let vs = mmio(bar + 8);
    if cap != CAP || vs != VS {
        return Err("unexpected-registers");
    }
    Ok(Some(Registers { bar, cap, vs }))
}

#[cfg(not(test))]
pub(super) fn run(handoff: &crate::uefi::Handoff, functions: &[Function]) {
    use crate::diagnostics::{halt, print};

    let result = probe(
        functions,
        // SAFETY: this profile owns the selector/data ports on the masked BSP.
        |selector| unsafe { super::read_config(selector) },
        // SAFETY: K01 owns CR3 and has validated the final firmware handoff.
        |bar| unsafe { crate::cpu::prepare_nvme_mmio(handoff, bar) },
        // SAFETY: probe admits the single uncached BAR page before invoking
        // this closure at only the three aligned register offsets.
        |address| unsafe { core::ptr::without_provenance::<u32>(address as usize).read_volatile() },
    );
    match result {
        Ok(None) => {
            print(format_args!("TESSRYN_IO02_NVME_ABSENT reads=0\n"));
            #[cfg(io02_nvme_admin_queues)]
            print(format_args!("TESSRYN_IO02_NVME_ADMIN_ABSENT writes=0\n"));
        }
        Ok(Some(Registers { bar, cap, vs })) => {
            print(format_args!(
                "TESSRYN_IO02_NVME_REGISTERS bdf=01:00.0 bar={bar:#010x} cap={cap:#018x} vs={vs:#010x} reads=3\n"
            ));
            #[cfg(io02_nvme_admin_queues)]
            match queue_io::run(handoff, bar) {
                Ok((asq, acq, firmware_reset)) => {
                    let firmware = if firmware_reset { "reset" } else { "inactive" };
                    print(format_args!(
                        "TESSRYN_IO02_NVME_ADMIN bdf=01:00.0 asq={asq:#018x} acq={acq:#018x} aqa=0x00010001 cc_ready=0x00460001 csts_ready=0x00000001 cc_final=0x00000000 csts_final=0x00000000 bme=0 doorbells=0 firmware={firmware}\n"
                    ));
                }
                Err(reason) => {
                    print(format_args!("TESSRYN_IO02_NVME_ADMIN_FAIL reason={reason}\n"));
                    halt();
                }
            }
        }
        Err(reason) => {
            print(format_args!("TESSRYN_IO02_NVME_FAIL reason={reason}\n"));
            halt();
        }
    }
}

#[cfg(all(io02_nvme_admin_queues, not(test)))]
mod queue_io {
    use core::ptr;
    use core::sync::atomic::{Ordering, fence};

    use crate::paging::{LOW_LIMIT, Range, validate_range};
    use crate::uefi::Handoff;

    use super::{CONTROLLER, Register as PciRegister, admin};

    const PAGE_BYTES: usize = 4096;
    const PAGE_WORDS: usize = PAGE_BYTES / size_of::<u64>();

    #[repr(C, align(4096))]
    struct QueuePage([u64; PAGE_WORDS]);

    static mut SUBMISSION: QueuePage = QueuePage([0; PAGE_WORDS]);
    static mut COMPLETION: QueuePage = QueuePage([0; PAGE_WORDS]);

    struct Device {
        bar: u64,
        submission: *mut u64,
        completion: *mut u64,
    }

    impl admin::AdminIo for Device {
        fn pci_command(&mut self) -> u16 {
            // SAFETY: the exact endpoint is admitted on the sole masked BSP.
            unsafe { super::super::read_config(CONTROLLER.selector(PciRegister::CommandStatus)) as u16 }
        }

        fn set_pci_command(&mut self, value: u16) {
            // SAFETY: the state machine changes BME on this endpoint only.
            unsafe { super::super::write_config_command(CONTROLLER, value) };
        }

        fn read(&mut self, register: admin::Register) -> u32 {
            // SAFETY: the admitted UC register page contains every typed offset.
            unsafe { ptr::without_provenance::<u32>((self.bar + register as u64) as usize).read_volatile() }
        }

        fn write(&mut self, register: admin::Register, value: u32) {
            // SAFETY: only this profile gets a writable register page, and
            // the typed offsets exclude the doorbell aperture.
            unsafe { ptr::without_provenance_mut::<u32>((self.bar + register as u64) as usize).write_volatile(value) };
        }

        fn zero_pages(&mut self) {
            // SAFETY: the distinct static pages are image-owned and the
            // state machine calls this with device bus mastering stopped.
            for page in [self.submission, self.completion] {
                for index in 0..PAGE_WORDS {
                    unsafe { page.add(index).write_volatile(0) };
                }
            }
            fence(Ordering::SeqCst);
        }
    }

    fn queue_page(handoff: &Handoff, address: u64) -> Result<Range, &'static str> {
        if address == 0 || address % PAGE_BYTES as u64 != 0 {
            return Err("admin-page-alignment");
        }
        let page = Range::checked(address, PAGE_BYTES as u64).map_err(|error| error.label())?;
        validate_range(page, handoff.physical_bits).map_err(|error| error.label())?;
        if page.start < handoff.image.start || page.end > handoff.image.end || page.end > LOW_LIMIT {
            return Err("admin-page-ownership");
        }
        Ok(page)
    }

    pub(super) fn run(handoff: &Handoff, bar: u64) -> Result<(u64, u64, bool), &'static str> {
        // K01 already identity maps the image in the live root. Keep the raw
        // pointers for CPU stores and admit their whole pages as DMA addresses.
        let submission = ptr::addr_of_mut!(SUBMISSION).cast::<u64>();
        let completion = ptr::addr_of_mut!(COMPLETION).cast::<u64>();
        let asq = queue_page(handoff, submission.addr() as u64)?;
        let acq = queue_page(handoff, completion.addr() as u64)?;
        if asq.overlaps(acq) {
            return Err("admin-page-overlap");
        }
        let firmware_reset = admin::cycle(&mut Device { bar, submission, completion }, asq.start, acq.start)?;
        Ok((asq.start, acq.start, firmware_reset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    const VALID: Function = Function {
        bdf: CONTROLLER,
        id: ID,
        class_rev: CLASS << 8 | 2,
        header: 0,
    };

    fn config(selector: u32) -> u32 {
        match selector {
            0x8001_0004 => 0x0010_0006,
            0x8001_0010 => 0x8100_0004,
            0x8001_0014 => 0,
            _ => panic!("unadmitted configuration selector"),
        }
    }

    #[test]
    fn absent_ignores_other_classes_and_never_accesses_the_device() {
        let sata = Function {
            bdf: Bdf {
                bus: 0,
                slot: 31,
                function: 2,
            },
            id: 0x2922_8086,
            class_rev: 0x0106_0100,
            header: 0,
        };
        assert_eq!(
            probe(
                &[sata],
                |_| panic!("no extra configuration reads"),
                |_| panic!("no MMIO mapping"),
                |_| panic!("no MMIO reads"),
            ),
            Ok(None)
        );
    }

    #[test]
    fn lookalikes_and_duplicate_candidates_fail_before_extra_configuration_reads() {
        let invalid = [
            Function {
                bdf: Bdf {
                    bus: 2,
                    ..CONTROLLER
                },
                ..VALID
            },
            Function {
                id: 0x0010_1234,
                ..VALID
            },
            Function {
                class_rev: 0x0108_0102,
                ..VALID
            },
            Function {
                class_rev: 0x0106_0202,
                ..VALID
            },
            Function {
                header: 0x0080_0000,
                ..VALID
            },
            Function {
                header: 0x0001_0000,
                ..VALID
            },
        ];
        let reject = |functions: &[Function]| {
            assert_eq!(
                probe(
                    functions,
                    |_| panic!("no extra configuration reads"),
                    |_| panic!("no MMIO mapping"),
                    |_| panic!("no MMIO reads"),
                ),
                Err("unexpected-controller")
            );
        };
        for row in invalid {
            reject(&[row]);
        }
        reject(&[VALID, invalid[0]]);
    }

    #[test]
    fn decoding_must_be_enabled_before_reading_bar() {
        for command in [0, 4, u32::MAX] {
            assert_eq!(
                probe(
                    &[VALID],
                    |selector| {
                        assert_eq!(selector, 0x8001_0004);
                        command
                    },
                    |_| panic!("no MMIO mapping"),
                    |_| panic!("no MMIO reads"),
                ),
                Err("invalid-memory-decode")
            );
        }
    }

    #[test]
    fn incorrect_bar_geometry_never_reaches_the_mapper() {
        for (low, high) in [
            (0x8100_0005, 0), // I/O BAR.
            (0x8100_0000, 0), // 32-bit BAR.
            (0x8100_000c, 0), // Prefetchable memory.
            (0x0000_0004, 0), // Unassigned.
            (0x8100_1004, 0), // Different page.
            (0x8100_0004, 1), // Above the admitted low identity window.
            (u32::MAX, u32::MAX),
        ] {
            assert_eq!(
                probe(
                    &[VALID],
                    |selector| match selector {
                        0x8001_0010 => low,
                        0x8001_0014 => high,
                        _ => config(selector),
                    },
                    |_| panic!("no MMIO mapping"),
                    |_| panic!("no MMIO reads"),
                ),
                Err("unexpected-bar")
            );
        }
    }

    #[test]
    fn mapping_failure_prevents_register_reads() {
        assert_eq!(
            probe(
                &[VALID],
                config,
                |bar| {
                    assert_eq!(bar, BAR);
                    Err("mapping-rejected")
                },
                |_| panic!("no MMIO reads"),
            ),
            Err("mapping-rejected")
        );
    }

    #[test]
    fn positive_reads_exactly_three_dwords_after_admission() {
        let mapped = Cell::new(false);
        let mut config_reads = [0x8001_0004, 0x8001_0010, 0x8001_0014].into_iter();
        let mut mmio_reads = [
            (BAR, CAP as u32),
            (BAR + 4, (CAP >> 32) as u32),
            (BAR + 8, VS),
        ]
        .into_iter();
        assert_eq!(
            probe(
                &[VALID],
                |selector| {
                    assert_eq!(Some(selector), config_reads.next());
                    config(selector)
                },
                |bar| {
                    assert_eq!(bar, BAR);
                    mapped.set(true);
                    Ok(())
                },
                |address| {
                    assert!(mapped.get());
                    let (expected, value) = mmio_reads.next().expect("no extra MMIO reads");
                    assert_eq!(address, expected);
                    value
                },
            ),
            Ok(Some(Registers {
                bar: BAR,
                cap: CAP,
                vs: VS
            }))
        );
        assert_eq!(config_reads.next(), None);
        assert_eq!(mmio_reads.next(), None);
    }

    #[test]
    fn incorrect_model_values_fail() {
        for changed in [BAR, BAR + 4, BAR + 8] {
            assert_eq!(
                probe(
                    &[VALID],
                    config,
                    |_| Ok(()),
                    |address| {
                        let expected = match address - BAR {
                            0 => CAP as u32,
                            4 => (CAP >> 32) as u32,
                            8 => VS,
                            _ => panic!("unadmitted MMIO offset"),
                        };
                        expected ^ u32::from(address == changed)
                    },
                ),
                Err("unexpected-registers")
            );
        }
    }
}
