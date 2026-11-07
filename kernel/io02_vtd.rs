//! One legacy VT-d domain in the pinned q35 profile. No device DMA is issued.

const BASE: u64 = 0xfed9_0000;
const PAGE_BYTES: u64 = 4096;
const PAGE_WORDS: usize = 512;
const TABLE_PAGES: usize = 5;
const LOW_LIMIT: u64 = 1 << 32;
const POLL_LIMIT: usize = 1024;

const VER: usize = 0x00;
const CAP: usize = 0x08;
const ECAP: usize = 0x10;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const RTADDR: usize = 0x20;
const CCMD: usize = 0x28;
const FSTS: usize = 0x34;
const FECTL: usize = 0x38;
const IOTLB: usize = 0xf8;

const TE: u32 = 1 << 31;
const SRTP: u32 = 1 << 30;
const READY: u32 = TE | SRTP;
const INV: u64 = 1 << 63;
const CONTEXT_GLOBAL: u64 = 1 << 61;
const CONTEXT_ACTUAL_MASK: u64 = 3 << 59;
const CONTEXT_ACTUAL_GLOBAL: u64 = 1 << 59;
const IOTLB_GLOBAL: u64 = 1 << 60;
const IOTLB_ACTUAL_MASK: u64 = 3 << 57;
const IOTLB_ACTUAL_GLOBAL: u64 = 1 << 57;

// VT-d legacy root and context entries occupy two qwords each. The three
// second-level paging structures use one qword per entry.
#[repr(C, align(4096))]
struct Tables([u64; PAGE_WORDS * TABLE_PAGES]);

impl Tables {
    const fn empty() -> Self {
        Self([0; PAGE_WORDS * TABLE_PAGES])
    }

    fn build(
        &mut self,
        root: u64,
        asq: u64,
        acq: u64,
        image: core::ops::Range<u64>,
    ) -> Result<(), &'static str> {
        let table_end = owned_end(root, TABLE_PAGES as u64 * PAGE_BYTES, &image)?;
        let asq_end = owned_end(asq, PAGE_BYTES, &image)?;
        let acq_end = owned_end(acq, PAGE_BYTES, &image)?;
        if asq == acq || (asq < table_end && root < asq_end) || (acq < table_end && root < acq_end) {
            return Err("vtd-page-alias");
        }

        self.0.fill(0);
        self.0[2] = (root + PAGE_BYTES) | 1; // Bus 1 only.
        self.0[PAGE_WORDS] = (root + 2 * PAGE_BYTES) | 1; // Devfn 0, multilevel translation.
        self.0[PAGE_WORDS + 1] = 0x101; // Domain 1, adjusted width encoding 1.
        self.0[2 * PAGE_WORDS] = (root + 3 * PAGE_BYTES) | 3;
        self.0[3 * PAGE_WORDS + 8] = (root + 4 * PAGE_BYTES) | 3;
        self.0[4 * PAGE_WORDS] = asq | 1; // IOVA 0x01000000, device read only.
        self.0[4 * PAGE_WORDS + 1] = acq | 2; // IOVA 0x01001000, device write only.
        Ok(())
    }
}

fn owned_end(
    start: u64,
    bytes: u64,
    image: &core::ops::Range<u64>,
) -> Result<u64, &'static str> {
    let end = start.checked_add(bytes).ok_or("vtd-page-overflow")?;
    if start == 0 || start & (PAGE_BYTES - 1) != 0 || start < image.start
        || end > image.end || end > LOW_LIMIT
    {
        return Err("vtd-page-ownership");
    }
    Ok(end)
}

trait Registers {
    fn read32(&self, offset: usize) -> u32;
    fn read64(&self, offset: usize) -> u64;
    fn write32(&mut self, offset: usize, value: u32);
    fn write64(&mut self, offset: usize, value: u64);
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    active: bool,
    root: u64,
    gsts: u32,
}

fn wait_for(
    mut observed: impl FnMut() -> bool,
    reason: &'static str,
) -> Result<(), &'static str> {
    for _ in 0..POLL_LIMIT {
        if observed() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(reason)
}

fn configure(
    registers: &mut impl Registers,
    prepare_tables: impl FnOnce() -> Result<u64, &'static str>,
) -> Result<Observation, &'static str> {
    let cap = registers.read64(CAP);
    let sagaw = (cap >> 8) & 0x1f;
    // Pin VER and the q35 legacy register layout. ECAP advertises queued
    // invalidation and passthrough capability, neither of which is enabled.
    // Require no write-buffer-flush requirement and one primary fault record.
    if registers.read32(VER) != 0x10 || registers.read64(ECAP) != 0xf42
        || (cap >> 16) & 0x3f != 38 || (cap >> 24) & 0x3ff != 0x22
        || (cap >> 40) & 0xff != 0 || cap & (1 << 4) != 0
        || !matches!(sagaw, 0 | 2)
    {
        return Err("vtd-capability-profile");
    }
    let gsts = registers.read32(GSTS);
    let root = registers.read64(RTADDR);
    if gsts != 0 || root != 0 || registers.read32(FSTS) != 0
        || registers.read32(FECTL) != 1 << 31
        || registers.read64(CCMD) & INV != 0 || registers.read64(IOTLB) & INV != 0
    {
        return Err("vtd-initial-state");
    }
    // QEMU with dma-translation=off advertises no second-level widths. This
    // control must refuse before building tables or programming registers.
    if sagaw == 0 {
        return Ok(Observation { active: false, root, gsts });
    }

    let root = prepare_tables()?;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    registers.write64(RTADDR, root);
    if registers.read64(RTADDR) != root {
        return Err("vtd-root-readback");
    }
    registers.write32(GCMD, SRTP);
    wait_for(|| registers.read32(GSTS) == SRTP, "vtd-root-latch")?;

    registers.write64(CCMD, INV | CONTEXT_GLOBAL);
    wait_for(|| registers.read64(CCMD) & INV == 0, "vtd-context-invalidate-timeout")?;
    if registers.read64(CCMD) & CONTEXT_ACTUAL_MASK != CONTEXT_ACTUAL_GLOBAL {
        return Err("vtd-context-invalidate-result");
    }
    registers.write64(IOTLB, INV | IOTLB_GLOBAL);
    wait_for(|| registers.read64(IOTLB) & INV == 0, "vtd-iotlb-invalidate-timeout")?;
    if registers.read64(IOTLB) & IOTLB_ACTUAL_MASK != IOTLB_ACTUAL_GLOBAL {
        return Err("vtd-iotlb-invalidate-result");
    }

    registers.write32(GCMD, TE);
    wait_for(|| registers.read32(GSTS) == READY, "vtd-enable-timeout")?;
    let gsts = registers.read32(GSTS);
    if gsts != READY || registers.read64(RTADDR) != root || registers.read32(FSTS) != 0 {
        return Err("vtd-final-readback");
    }
    // Keep the live tables and translation until the VM exits. If any wait
    // failed, the caller halts with BME still off and the pages retained.
    Ok(Observation { active: true, root, gsts })
}

#[cfg(not(test))]
struct Mmio(usize);

#[cfg(not(test))]
impl Registers for Mmio {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: run admitted and mapped the sole pinned register page.
        unsafe { core::ptr::without_provenance::<u32>(self.0 + offset).read_volatile() }
    }

    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: the whitelisted qword offsets are aligned in that page.
        unsafe { core::ptr::without_provenance::<u64>(self.0 + offset).read_volatile() }
    }

    fn write32(&mut self, offset: usize, value: u32) {
        // SAFETY: this image owns the admitted remapper after firmware exit.
        unsafe { core::ptr::without_provenance_mut::<u32>(self.0 + offset).write_volatile(value) }
    }

    fn write64(&mut self, offset: usize, value: u64) {
        // SAFETY: the whitelisted qword offsets are aligned in that page.
        unsafe { core::ptr::without_provenance_mut::<u64>(self.0 + offset).write_volatile(value) }
    }
}

#[cfg(not(test))]
pub fn run(handoff: &crate::uefi::Handoff, asq: u64, acq: u64) -> Result<(), &'static str> {
    static mut TABLES: Tables = Tables::empty();
    let base = handoff.vtd_base.filter(|base| *base == BASE).ok_or("vtd-mmio-profile")?;
    // SAFETY: the sole BSP already owns CR3 and validated the handoff.
    unsafe { crate::cpu::prepare_vtd_mmio(handoff, base) }?;
    let result = configure(&mut Mmio(base as usize), || {
        let tables = core::ptr::addr_of_mut!(TABLES);
        let root = tables.addr() as u64;
        // SAFETY: called once on the sole BSP, before publishing RTADDR.
        let tables = unsafe { &mut *tables };
        tables.build(root, asq, acq, handoff.image.start..handoff.image.end)?;
        Ok(root)
    })?;
    let status = if result.active { "ready" } else { "blocked" };
    let Observation { root, gsts, .. } = result;
    crate::diagnostics::print(format_args!(
        "TESSRYN_IO02_VTD status={status} base={base:#010x} sid=0x0100 root={root:#018x} gsts={gsts:#010x} bme=0\n"
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: u64 = 0x120_000;
    const ASQ: u64 = 0x130_000;
    const ACQ: u64 = 0x131_000;

    #[test]
    fn only_one_requester_and_two_least_privilege_leaves_are_present() {
        assert_eq!(BASE, 0xfed9_0000);
        assert_eq!(core::mem::size_of::<Tables>(), 5 * 4096);
        assert_eq!(core::mem::align_of::<Tables>(), 4096);
        let mut tables = Tables::empty();
        tables.0.fill(u64::MAX);
        tables.build(ROOT, ASQ, ACQ, 0x100_000..0x200_000).unwrap();
        let populated: Vec<_> = tables.0.into_iter().enumerate().filter(|(_, value)| *value != 0).collect();
        assert_eq!(populated, [
            (2, 0x121_001),
            (512, 0x122_001),
            (513, 0x101),
            (1024, 0x123_003),
            (1544, 0x124_003),
            (2048, 0x130_001),
            (2049, 0x131_002),
        ]);
    }

    #[test]
    fn rejects_aliases_bad_alignment_and_non_image_pages_before_table_changes() {
        let mut tables = Tables::empty();
        let image = 0x100_000..0x200_000;
        for (root, asq, acq) in [
            (0, ASQ, ACQ),
            (ROOT + 1, ASQ, ACQ),
            (ROOT, ASQ, ACQ - 1),
            (ROOT, ASQ, ASQ),
            (ROOT, ROOT + 4096, ACQ),
            (ROOT, ASQ, ROOT + 4 * 4096),
            (0x1fc_000, ASQ, ACQ),
            (ROOT, ASQ, image.end),
            (u64::MAX & !0xfff, ASQ, ACQ),
        ] {
            assert!(tables.build(root, asq, acq, image.clone()).is_err());
            assert!(tables.0.iter().all(|entry| *entry == 0));
        }
        assert!(tables.build(LOW_LIMIT, ASQ, ACQ, 0x100_000..LOW_LIMIT + 0x5000).is_err());
    }

    #[derive(Default)]
    struct Fake {
        sagaw: u64,
        root: u64,
        gsts: u32,
        fault: u32,
        context: u64,
        iotlb: u64,
        writes: Vec<(usize, u64)>,
        stall: Option<usize>,
    }

    impl Registers for Fake {
        fn read32(&self, offset: usize) -> u32 {
            match offset {
                VER => 0x10,
                GSTS => self.gsts,
                FSTS => self.fault,
                FECTL => 1 << 31,
                _ => panic!("unexpected dword read"),
            }
        }

        fn read64(&self, offset: usize) -> u64 {
            match offset {
                CAP => (0x22 << 24) | (38 << 16) | (self.sagaw << 8),
                ECAP => 0xf42,
                RTADDR => self.root,
                CCMD => self.context,
                IOTLB => self.iotlb,
                _ => panic!("unexpected qword read"),
            }
        }

        fn write32(&mut self, offset: usize, value: u32) {
            assert_eq!(offset, GCMD);
            self.writes.push((offset, value.into()));
            self.gsts |= match value {
                SRTP => SRTP,
                TE if self.stall == Some(GCMD) => 0,
                TE => TE,
                _ => panic!("unexpected global command"),
            };
        }

        fn write64(&mut self, offset: usize, value: u64) {
            self.writes.push((offset, value));
            match offset {
                RTADDR if self.stall == Some(RTADDR) => (),
                RTADDR => self.root = value,
                CCMD => self.context = if self.stall == Some(CCMD) { value } else { CONTEXT_ACTUAL_GLOBAL },
                IOTLB => self.iotlb = if self.stall == Some(IOTLB) { value } else { IOTLB_ACTUAL_GLOBAL },
                _ => panic!("unexpected qword write"),
            }
        }
    }

    #[test]
    fn unsupported_profile_refuses_without_preparing_tables_or_writing() {
        let mut registers = Fake::default();
        assert_eq!(
            configure(&mut registers, || panic!("blocked path must not prepare tables")),
            Ok(Observation { active: false, root: 0, gsts: 0 }),
        );
        assert!(registers.writes.is_empty());
    }

    #[test]
    fn ready_latches_root_and_invalidates_before_enabling() {
        let mut registers = Fake { sagaw: 2, ..Fake::default() };
        assert_eq!(
            configure(&mut registers, || Ok(ROOT)),
            Ok(Observation { active: true, root: ROOT, gsts: 0xc000_0000 }),
        );
        assert_eq!(registers.writes, [
            (0x20, ROOT),
            (0x18, 0x4000_0000),
            (0x28, 0xa000_0000_0000_0000),
            (0xf8, 0x9000_0000_0000_0000),
            (0x18, 0x8000_0000),
        ]);
    }

    #[test]
    fn inherited_state_and_unknown_width_refuse_before_any_writes() {
        for mut registers in [
            Fake { sagaw: 2, root: ROOT, ..Fake::default() },
            Fake { gsts: TE, ..Fake::default() },
            Fake { fault: 1, ..Fake::default() },
            Fake { sagaw: 4, ..Fake::default() },
        ] {
            assert!(configure(&mut registers, || panic!("unadmitted profile")).is_err());
            assert!(registers.writes.is_empty());
        }
    }

    #[test]
    fn failing_readbacks_and_timeouts_stop_at_the_failed_stage() {
        for (offset, error, writes) in [
            (RTADDR, "vtd-root-readback", 1),
            (CCMD, "vtd-context-invalidate-timeout", 3),
            (IOTLB, "vtd-iotlb-invalidate-timeout", 4),
            (GCMD, "vtd-enable-timeout", 5),
        ] {
            let mut registers = Fake { sagaw: 2, stall: Some(offset), ..Fake::default() };
            assert_eq!(configure(&mut registers, || Ok(ROOT)), Err(error));
            assert_eq!(registers.writes.len(), writes);
        }
    }
}
