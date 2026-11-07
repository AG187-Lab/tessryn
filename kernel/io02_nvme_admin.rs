//! Empty Admin SQ/CQ lifecycle for the admitted namespace-less QEMU model.

const PAGE_BYTES: u64 = 4096;
const MEMORY_SPACE: u16 = 1 << 1;
const BUS_MASTER: u16 = 1 << 2;
const ENABLE: u32 = 1;
const READY: u32 = 1;
const CC_CONFIGURATION: u32 = (6 << 16) | (4 << 20);
const CC_ENABLED: u32 = CC_CONFIGURATION | ENABLE;
const ADMIN_TWO_ENTRIES: u32 = (1 << 16) | 1;
const POLL_LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub(super) enum Register {
    Cc = 0x14,
    Csts = 0x1c,
    Aqa = 0x24,
    AsqLow = 0x28,
    AsqHigh = 0x2c,
    AcqLow = 0x30,
    AcqHigh = 0x34,
}
use Register::{AcqHigh, AcqLow, Aqa, AsqHigh, AsqLow, Cc, Csts};

pub(super) trait AdminIo {
    fn pci_command(&mut self) -> u16;
    fn set_pci_command(&mut self, value: u16);
    fn read(&mut self, register: Register) -> u32;
    fn write(&mut self, register: Register, value: u32);

    // Zero exactly the two admitted pages and finish the memory fence before
    // the controller sees either queue address.
    fn zero_pages(&mut self);
}

fn quiescent(io: &mut impl AdminIo) -> bool {
    io.read(Cc) == 0 && io.read(Csts) == 0
}

fn write_queues(io: &mut impl AdminIo, attributes: u32, asq: u64, acq: u64) {
    io.write(Aqa, attributes);
    io.write(AsqLow, asq as u32);
    io.write(AsqHigh, (asq >> 32) as u32);
    io.write(AcqLow, acq as u32);
    io.write(AcqHigh, (acq >> 32) as u32);
}

fn queues_match(io: &mut impl AdminIo, attributes: u32, asq: u64, acq: u64) -> bool {
    io.read(Aqa) == attributes
        && io.read(AsqLow) == asq as u32
        && io.read(AsqHigh) == (asq >> 32) as u32
        && io.read(AcqLow) == acq as u32
        && io.read(AcqHigh) == (acq >> 32) as u32
}

fn clear_queues(io: &mut impl AdminIo) -> Result<(), &'static str> {
    write_queues(io, 0, 0, 0);
    if !queues_match(io, 0, 0, 0) {
        return Err("admin-queue-clear-readback");
    }
    Ok(())
}

fn wait_status(io: &mut impl AdminIo, expected: u32) -> Result<(), &'static str> {
    for _ in 0..POLL_LIMIT {
        let status = io.read(Csts);
        if status == expected {
            return Ok(());
        }
        if status & !READY != 0 {
            return Err("admin-controller-status");
        }
        core::hint::spin_loop();
    }
    Err(if expected == READY {
        "admin-ready-timeout"
    } else {
        "admin-disable-timeout"
    })
}

/// Configure two empty, dedicated pages and verify controller teardown.
/// Returns whether the exact modeled firmware controller state needed reset.
///
/// The adapter has sole access to the admitted controller after firmware exit
/// and must keep both pages reserved until emulator termination, even on error.
pub(super) fn cycle(io: &mut impl AdminIo, asq: u64, acq: u64) -> Result<bool, &'static str> {
    if asq == acq
        || [asq, acq].into_iter().any(|base| {
            base == 0 || base % PAGE_BYTES != 0 || base.checked_add(PAGE_BYTES).is_none()
        })
    {
        return Err("admin-queue-page-range");
    }
    let inherited = (io.read(Cc), io.read(Csts));
    let reset_firmware = match inherited {
        (0, 0) => false,
        (CC_ENABLED, READY) => true,
        _ => return Err("admin-unknown-firmware-state"),
    };

    let original_command = io.pci_command();
    if original_command == u16::MAX || original_command & MEMORY_SPACE == 0 {
        return Err("admin-pci-memory-decode");
    }
    let command = original_command & !BUS_MASTER;
    if command != original_command {
        io.set_pci_command(command);
    }
    if io.pci_command() != command {
        return Err("admin-pci-command-readback");
    }
    if (io.read(Cc), io.read(Csts)) != inherited {
        return Err("admin-firmware-state-changed");
    }
    if reset_firmware {
        // Only the exact ready state is reset. QEMU cancels old requests on
        // CC.EN clear. We revoke bus mastering first and never access firmware
        // queue memory or reprogram its registers until the model is disabled.
        io.write(Cc, CC_CONFIGURATION);
        wait_status(io, 0)?;
        if io.read(Cc) != 0 || io.pci_command() != command {
            return Err("admin-firmware-reset-readback");
        }
    }

    io.zero_pages();
    write_queues(io, ADMIN_TWO_ENTRIES, asq, acq);
    let configured = queues_match(io, ADMIN_TWO_ENTRIES, asq, acq);
    if !quiescent(io) || io.pci_command() != command {
        return Err("admin-setup-state-changed");
    }
    if !configured {
        clear_queues(io)?;
        return Err("admin-queue-setup-readback");
    }

    io.write(Cc, CC_ENABLED);
    // If readiness was never established, clearing EN could hit the undefined
    // EN=1/RDY=0 transition. Stop touching the controller and retain the pages.
    wait_status(io, READY)?;
    if io.read(Cc) != CC_ENABLED || io.pci_command() != command {
        return Err("admin-ready-readback");
    }
    let ready_queues_match = queues_match(io, ADMIN_TWO_ENTRIES, asq, acq);

    io.write(Cc, CC_CONFIGURATION);
    wait_status(io, 0)?;
    if io.read(Cc) != 0 || io.pci_command() != command {
        return Err("admin-disabled-readback");
    }
    clear_queues(io)?;
    if io.read(Cc) != 0 || io.read(Csts) != 0 || io.pci_command() != command {
        return Err("admin-final-readback");
    }
    if !ready_queues_match {
        return Err("admin-ready-queue-readback");
    }
    Ok(reset_firmware)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASQ: u64 = 0x0000_0001_0020_0000;
    const ACQ: u64 = ASQ + PAGE_BYTES;
    const ORIGINAL_COMMAND: u16 = 0x0406;
    const SAFE_COMMAND: u16 = 0x0402;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mutation {
        Command(u16),
        ZeroPages,
        Write(Register, u32),
    }
    use Mutation::{Command, Write, ZeroPages};

    #[derive(Default)]
    struct Model {
        command: u16,
        registers: [u32; 7],
        mutations: Vec<Mutation>,
        status_reads: usize,
        ignore_command: bool,
        change_status_on_revoke: bool,
        corrupt_setup: bool,
        retain_queue_on_clear: bool,
        lose_queue_on_enable: bool,
        enable_status: u32,
        stall_disable: bool,
    }

    impl Model {
        fn new() -> Self {
            Self {
                command: ORIGINAL_COMMAND,
                enable_status: 1,
                ..Self::default()
            }
        }

        fn firmware_active() -> Self {
            Self {
                registers: [0x0046_0001, 1, 0x0001_0001, 0x1000, 0, 0x2000, 0],
                ..Self::new()
            }
        }
    }

    fn index(register: Register) -> usize {
        match register {
            Cc => 0,
            Csts => 1,
            Aqa => 2,
            AsqLow => 3,
            AsqHigh => 4,
            AcqLow => 5,
            AcqHigh => 6,
        }
    }

    impl AdminIo for Model {
        fn pci_command(&mut self) -> u16 {
            self.command
        }

        fn set_pci_command(&mut self, value: u16) {
            self.mutations.push(Command(value));
            if !self.ignore_command {
                self.command = value;
            }
            if self.change_status_on_revoke {
                self.registers[index(Csts)] = 0;
            }
        }

        fn read(&mut self, register: Register) -> u32 {
            if register == Csts {
                self.status_reads += 1;
            }
            self.registers[index(register)]
        }

        fn write(&mut self, register: Register, value: u32) {
            assert_eq!(self.command, SAFE_COMMAND);
            self.mutations.push(Write(register, value));
            self.registers[index(register)] = match register {
                Aqa if value != 0 && self.corrupt_setup => 0,
                Aqa if value == 0 && self.retain_queue_on_clear => ADMIN_TWO_ENTRIES,
                Cc if value & ENABLE != 0 => {
                    self.registers[index(Csts)] = self.enable_status;
                    if self.lose_queue_on_enable {
                        self.registers[index(Aqa)] = 0;
                    }
                    value
                }
                Cc if !self.stall_disable => {
                    self.registers[index(Csts)] = 0;
                    0
                }
                _ => value,
            };
        }

        fn zero_pages(&mut self) {
            assert_eq!(self.command, SAFE_COMMAND);
            self.mutations.push(ZeroPages);
        }
    }

    #[test]
    fn clears_bus_master_then_programs_and_tears_down_two_empty_queues() {
        let mut io = Model::new();
        assert_eq!(cycle(&mut io, ASQ, ACQ), Ok(false));
        assert_eq!(
            io.mutations,
            [
                Command(0x0402),
                ZeroPages,
                Write(Aqa, 0x0001_0001),
                Write(AsqLow, 0x0020_0000),
                Write(AsqHigh, 1),
                Write(AcqLow, 0x0020_1000),
                Write(AcqHigh, 1),
                Write(Cc, 0x0046_0001),
                Write(Cc, 0x0046_0000),
                Write(Aqa, 0),
                Write(AsqLow, 0),
                Write(AsqHigh, 0),
                Write(AcqLow, 0),
                Write(AcqHigh, 0),
            ],
        );
        assert_eq!(io.registers, [0; 7]);
        assert_eq!(io.command, SAFE_COMMAND);
    }

    #[test]
    fn revokes_bus_master_and_resets_known_firmware_before_using_new_pages() {
        let mut io = Model::firmware_active();
        assert_eq!(cycle(&mut io, ASQ, ACQ), Ok(true));
        assert_eq!(
            io.mutations[..4],
            [
                Command(0x0402),
                Write(Cc, 0x0046_0000),
                ZeroPages,
                Write(Aqa, 0x0001_0001)
            ],
        );
        assert_eq!(io.registers, [0; 7]);
        assert_eq!(io.command, SAFE_COMMAND);
    }

    #[test]
    fn failed_firmware_reset_never_touches_any_queue() {
        let mut io = Model {
            stall_disable: true,
            ..Model::firmware_active()
        };
        assert_eq!(cycle(&mut io, ASQ, ACQ), Err("admin-disable-timeout"));
        assert_eq!(io.mutations, [Command(0x0402), Write(Cc, 0x0046_0000)]);
        assert_eq!(
            io.registers[index(Aqa)..],
            [0x0001_0001, 0x1000, 0, 0x2000, 0]
        );
        assert_eq!(io.command, SAFE_COMMAND);
    }

    #[test]
    fn changing_firmware_state_after_revocation_blocks_reset() {
        let mut io = Model {
            change_status_on_revoke: true,
            ..Model::firmware_active()
        };
        assert_eq!(
            cycle(&mut io, ASQ, ACQ),
            Err("admin-firmware-state-changed")
        );
        assert_eq!(io.mutations, [Command(0x0402)]);
    }

    #[test]
    fn rejects_bad_pages_before_any_device_access() {
        for (asq, acq) in [
            (0, ACQ),
            (ASQ + 1, ACQ),
            (ASQ, ASQ),
            (ASQ, u64::MAX & !4095),
        ] {
            let mut io = Model::new();
            assert_eq!(cycle(&mut io, asq, acq), Err("admin-queue-page-range"));
            assert!(io.mutations.is_empty());
            assert_eq!(io.status_reads, 0);
        }
    }

    #[test]
    fn refuses_unknown_active_transition_and_fatal_controller_without_writes() {
        for (cc, csts) in [(1, 1), (CC_ENABLED, 0), (CC_ENABLED, 3), (0, 1), (0, 2)] {
            let mut io = Model::new();
            io.registers[index(Cc)] = cc;
            io.registers[index(Csts)] = csts;
            assert_eq!(
                cycle(&mut io, ASQ, ACQ),
                Err("admin-unknown-firmware-state")
            );
            assert!(io.mutations.is_empty());
        }
    }

    #[test]
    fn refuses_disabled_memory_decoding_or_unverified_bus_master_clear() {
        for command in [BUS_MASTER, u16::MAX] {
            let mut io = Model {
                command,
                ..Model::new()
            };
            assert_eq!(cycle(&mut io, ASQ, ACQ), Err("admin-pci-memory-decode"));
            assert!(io.mutations.is_empty());
        }

        let mut io = Model {
            ignore_command: true,
            ..Model::new()
        };
        assert_eq!(cycle(&mut io, ASQ, ACQ), Err("admin-pci-command-readback"));
        assert_eq!(io.mutations, [Command(SAFE_COMMAND)]);
    }

    #[test]
    fn bad_setup_readback_scrubs_quiescent_queues_without_enabling() {
        let mut io = Model {
            corrupt_setup: true,
            ..Model::new()
        };
        assert_eq!(cycle(&mut io, ASQ, ACQ), Err("admin-queue-setup-readback"));
        assert!(
            !io.mutations
                .iter()
                .any(|mutation| matches!(mutation, Write(Cc, _)))
        );
        assert_eq!(io.registers, [0; 7]);
        assert_eq!(io.command, SAFE_COMMAND);
    }

    #[test]
    fn bad_ready_queue_readback_still_tears_down_known_ready_controller() {
        let mut io = Model {
            lose_queue_on_enable: true,
            command: SAFE_COMMAND,
            ..Model::new()
        };
        assert_eq!(cycle(&mut io, ASQ, ACQ), Err("admin-ready-queue-readback"));
        assert_eq!(io.registers, [0; 7]);
        assert!(
            !io.mutations
                .iter()
                .any(|mutation| matches!(mutation, Command(_)))
        );
        assert_eq!(io.command, SAFE_COMMAND);
    }

    #[test]
    fn readiness_timeout_or_fatal_status_leaves_queue_pages_reserved() {
        for (status, error, reads) in [
            (0, "admin-ready-timeout", POLL_LIMIT),
            (2, "admin-controller-status", 1),
        ] {
            let mut io = Model {
                enable_status: status,
                ..Model::new()
            };
            assert_eq!(cycle(&mut io, ASQ, ACQ), Err(error));
            assert_eq!(io.status_reads, reads + 3);
            assert_eq!(io.mutations.last(), Some(&Write(Cc, 0x0046_0001)));
            assert_eq!(io.registers[index(Aqa)], 0x0001_0001);
            assert_eq!(io.command, SAFE_COMMAND);
        }
    }

    #[test]
    fn disable_timeout_does_not_scrub_active_queues() {
        let mut io = Model {
            stall_disable: true,
            ..Model::new()
        };
        assert_eq!(cycle(&mut io, ASQ, ACQ), Err("admin-disable-timeout"));
        assert_eq!(io.status_reads, POLL_LIMIT + 4);
        assert_eq!(io.mutations.last(), Some(&Write(Cc, 0x0046_0000)));
        assert_eq!(io.registers[index(Aqa)], 0x0001_0001);
        assert_eq!(io.command, SAFE_COMMAND);
    }

    #[test]
    fn incomplete_clear_is_not_a_successful_teardown() {
        let mut io = Model {
            retain_queue_on_clear: true,
            ..Model::new()
        };
        assert_eq!(cycle(&mut io, ASQ, ACQ), Err("admin-queue-clear-readback"));
        assert_eq!(io.registers[index(Csts)], 0);
        assert_eq!(io.command, SAFE_COMMAND);
    }
}
