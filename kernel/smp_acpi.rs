//! Bounded, allocation-free ACPI metadata parsing for the two-CPU profile.
//!
//! Every input is an exact bounded byte slice. The native caller must validate
//! physical address/range authority BEFORE viewing any firmware table; none of
//! these routines dereferences a physical address or establishes its ownership.
//! ACPI checksums establish format consistency, not firmware authenticity.
#![forbid(unsafe_code)]

pub const SDT_HEADER_BYTES: usize = 36;
pub const MAX_SDT_BYTES: usize = 64 * 1024;
pub const LAPIC_BASE: u64 = 0xfee0_0000;
pub const HPET_BASE: u64 = 0xfed0_0000;
const MAX_PROCESSOR_ENTRIES: usize = 256;
const HPET_BLOCK_ID: u32 = 0x8086_a201;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Signature,
    Revision,
    Checksum,
    Reserved,
    Address,
    Structure,
    Duplicate,
    Capacity,
    ProcessorCount,
    UnsupportedX2Apic,
    LapicOverride,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rsdp {
    pub xsdt: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Topology {
    pub lapic: u64,
    /// Ascending enabled xAPIC IDs, not an assumption that BSP has ID zero.
    /// The runtime locates BSP using its actual CPU/APIC identity.
    pub ids: [u8; 2],
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}
fn checksum(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}
fn table_address(address: u64) -> bool {
    address != 0 && address.checked_add(SDT_HEADER_BYTES as u64).is_some()
}

/// This deliberately admits the 36-byte ACPI 2+ RSDP layout only. The loader
/// bounds those bytes before calling; both legacy and extended sums must
/// validate. Physical width, mapped memory kind and the XSDT's full span remain
/// the native caller's separate responsibility.
pub fn parse_rsdp(bytes: &[u8]) -> Result<Rsdp, Error> {
    if bytes.len() != 36 { return Err(Error::Length); }
    if &bytes[..8] != b"RSD PTR " { return Err(Error::Signature); }
    if bytes[15] < 2 { return Err(Error::Revision); }
    if u32_at(bytes, 20) != 36 { return Err(Error::Length); }
    if !checksum(&bytes[..20]) || !checksum(bytes) { return Err(Error::Checksum); }
    if bytes[33..36] != [0; 3] { return Err(Error::Reserved); }
    let xsdt = u64_at(bytes, 24);
    if !table_address(xsdt) { return Err(Error::Address); }
    Ok(Rsdp { xsdt })
}

/// Return the full validated SDT, including its header. Extra trailing bytes are
/// rejected, so the returned slice has precisely the declared length. All data
/// access uses byte slices; SDT payloads need not be naturally aligned.
pub fn validate_sdt(bytes: &[u8], signature: [u8; 4]) -> Result<&[u8], Error> {
    if bytes.len() < SDT_HEADER_BYTES || bytes.len() > MAX_SDT_BYTES { return Err(Error::Length); }
    if bytes[..4] != signature { return Err(Error::Signature); }
    if u32_at(bytes, 4) as usize != bytes.len() { return Err(Error::Length); }
    if bytes[8] == 0 { return Err(Error::Revision); }
    if !checksum(bytes) { return Err(Error::Checksum); }
    Ok(bytes)
}

/// Validated XSDT iterator. Entry addresses are format values only, not readable
/// pointers. Every consumer must check their physical spans before viewing.
#[derive(Clone, Debug)]
pub struct Xsdt<'a> {
    payload: &'a [u8],
    offset: usize,
}
impl Iterator for Xsdt<'_> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.offset == self.payload.len() { return None; }
        let address = u64_at(self.payload, self.offset);
        self.offset += 8;
        Some(address)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.payload.len() - self.offset) / 8;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for Xsdt<'_> {}
impl core::iter::FusedIterator for Xsdt<'_> {}

pub fn xsdt_entries(bytes: &[u8]) -> Result<Xsdt<'_>, Error> {
    let table = validate_sdt(bytes, *b"XSDT")?;
    let payload = &table[SDT_HEADER_BYTES..];
    if payload.is_empty() || payload.len() % 8 != 0 { return Err(Error::Structure); }
    for entry in payload.chunks_exact(8) {
        if !table_address(u64_at(entry, 0)) { return Err(Error::Address); }
    }
    // The loader must reject duplicate selected MADT/HPET tables while resolving
    // these addresses; iteration itself grants no choice of authoritative table.
    Ok(Xsdt { payload, offset: 0 })
}

/// Require exactly two enabled legacy xAPIC processors and the fixed LAPIC.
/// Disabled processor entries are not started, but their APIC IDs still take
/// part in duplicate detection (also across disabled x2APIC structures).
/// Other well-framed MADT structures describe devices unused by this profile.
pub fn parse_madt(bytes: &[u8]) -> Result<Topology, Error> {
    let table = validate_sdt(bytes, *b"APIC")?;
    if table.len() < 44 { return Err(Error::Length); }
    let lapic = u32_at(table, 36) as u64;
    if lapic != LAPIC_BASE { return Err(Error::Address); }
    if u32_at(table, 40) & !1 != 0 { return Err(Error::Reserved); }
    let mut seen = [0u32; MAX_PROCESSOR_ENTRIES];
    let mut seen_count = 0usize;
    let mut enabled = [0u8; 2];
    let mut count = 0usize;
    let mut offset = 44usize;
    while offset < table.len() {
        if table.len() - offset < 2 { return Err(Error::Structure); }
        let kind = table[offset];
        let length = table[offset + 1] as usize;
        if length < 2 || length > table.len() - offset { return Err(Error::Structure); }
        let entry = &table[offset..offset + length];
        let processor = match kind {
            0 => {
                if length != 8 { return Err(Error::Structure); }
                Some((entry[3] as u32, u32_at(entry, 4), false))
            }
            5 => {
                if length != 12 { return Err(Error::Structure); }
                return Err(Error::LapicOverride);
            }
            9 => {
                if length != 16 { return Err(Error::Structure); }
                if entry[2..4] != [0; 2] { return Err(Error::Reserved); }
                Some((u32_at(entry, 4), u32_at(entry, 8), true))
            }
            _ => None,
        };
        if let Some((id, flags, x2apic)) = processor {
            // Online Capable is reserved when Enabled is set (ACPI 6.6,
            // processor Local APIC/x2APIC flags).
            if flags & !3 != 0 || flags & 3 == 3 { return Err(Error::Reserved); }
            if seen[..seen_count].contains(&id) { return Err(Error::Duplicate); }
            if seen_count == MAX_PROCESSOR_ENTRIES { return Err(Error::Capacity); }
            seen[seen_count] = id;
            seen_count += 1;
            if flags & 1 != 0 {
                if x2apic { return Err(Error::UnsupportedX2Apic); }
                if id == 255 { return Err(Error::Address); }
                if count == enabled.len() { return Err(Error::ProcessorCount); }
                enabled[count] = id as u8;
                count += 1;
            }
        }
        offset += length;
    }
    if count != 2 { return Err(Error::ProcessorCount); }
    if enabled[0] > enabled[1] { enabled.swap(0, 1); }
    Ok(Topology { lapic, ids: enabled })
}

/// Corroborate the bounded q35 HPET descriptor, without touching MMIO, timer
/// comparators or interrupt routing. Runtime admission independently checks the
/// actual capability/period registers before using this advertised address.
pub fn parse_hpet(bytes: &[u8]) -> Result<u64, Error> {
    let table = validate_sdt(bytes, *b"HPET")?;
    if table.len() != 56 { return Err(Error::Length); }
    if u32_at(table, 36) != HPET_BLOCK_ID { return Err(Error::Structure); }
    // Pinned QEMU advertises GAS width0 (unspecified); explicit64 is also
    // consistent with this profile. Actual counter width is checked from MMIO
    // by the runtime, never inferred from this metadata. No interrupts are used.
    if table[40] != 0 || !matches!(table[41], 0 | 64) || table[42..44] != [0; 2] {
        return Err(Error::Structure);
    }
    let address = u64_at(table, 44);
    if address != HPET_BASE { return Err(Error::Address); }
    if table[52] != 0 || table[55] & !0x0f != 0 { return Err(Error::Reserved); }
    Ok(address)
}
