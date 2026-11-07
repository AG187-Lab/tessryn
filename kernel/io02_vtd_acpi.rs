//! Bounded admission of the pinned q35 Intel IOMMU's DMAR description.
#![forbid(unsafe_code)]

#[cfg(not(test))]
use crate::smp_acpi;
#[cfg(test)]
#[path = "smp_acpi.rs"]
#[allow(dead_code)]
mod smp_acpi;

const DMAR_HEADER_BYTES: usize = 48;
const DRHD_HEADER_BYTES: usize = 16;
const SCOPE_BYTES: usize = 8;
const MAX_DMAR_BYTES: usize = 256;

/// Accept only the legacy, single segment-0 unit and its exact root-port
/// scope. Checksums bound the description but do not establish authenticity.
pub fn admit_dmar(bytes: &[u8], register_base: u64) -> Result<u64, &'static str> {
    let prefix = DMAR_HEADER_BYTES + DRHD_HEADER_BYTES;
    if !(prefix + SCOPE_BYTES..=MAX_DMAR_BYTES).contains(&bytes.len()) {
        return Err("dmar-length");
    }
    smp_acpi::validate_sdt(bytes, *b"DMAR").map_err(|_| "dmar-checksum")?;
    // Table revision 1, aw-bits=39, interrupt remapping disabled.
    if bytes[8] != 1 || bytes[36] != 38 || bytes[37..48] != [0; 11] {
        return Err("dmar-header");
    }

    let unit = &bytes[DMAR_HEADER_BYTES..];
    let length = u16::from_le_bytes([unit[2], unit[3]]) as usize;
    let base = u64::from_le_bytes(unit[8..16].try_into().unwrap());
    // Type 0 DRHD, clear INCLUDE_PCI_ALL, reserved byte zero, segment 0.
    // The single structure must consume the entire payload.
    if unit[..2] != [0; 2] || length != unit.len() || unit[4..8] != [0; 4]
        || base != register_base || (unit.len() - DRHD_HEADER_BYTES) % SCOPE_BYTES != 0
    {
        return Err("dmar-drhd");
    }

    let mut root_port = false;
    let mut ioapic = false;
    for scope in unit[DRHD_HEADER_BYTES..].chunks_exact(SCOPE_BYTES) {
        if scope[1] as usize != SCOPE_BYTES || scope[2..4] != [0; 2]
            || scope[6] > 31 || scope[7] > 7
        {
            return Err("dmar-scope-shape");
        }
        match scope[0] {
            // Other root-bus endpoints do not confer translation authority.
            1 if scope[4..6] == [0, 0] && scope[6..8] != [2, 0] => (),
            2 if scope[4..8] == [0, 0, 2, 0] && !root_port => root_port = true,
            // QEMU describes the integrated IOAPIC using its pseudo bus.
            3 if scope[5..8] == [0xff, 0, 0] && !ioapic => ioapic = true,
            _ => return Err("dmar-scope-profile"),
        }
    }
    if !root_port { return Err("dmar-root-port-missing"); }
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0xfed9_0000;
    const ROOT_PORT: [u8; 8] = [2, 8, 0, 0, 0, 0, 2, 0];
    const IOAPIC: [u8; 8] = [3, 8, 0, 0, 0, 0xff, 0, 0];
    const ENDPOINT: [u8; 8] = [1, 8, 0, 0, 0, 0, 31, 2];

    fn checksum(bytes: &mut [u8]) {
        bytes[9] = 0;
        bytes[9] = 0u8.wrapping_sub(bytes.iter().copied().fold(0u8, u8::wrapping_add));
    }

    fn fixture(scopes: &[[u8; 8]]) -> Vec<u8> {
        let length = DMAR_HEADER_BYTES + DRHD_HEADER_BYTES + scopes.len() * SCOPE_BYTES;
        let mut bytes = vec![0; length];
        bytes[..4].copy_from_slice(b"DMAR");
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[8] = 1;
        bytes[36] = 38;
        bytes[50..52].copy_from_slice(&((length - DMAR_HEADER_BYTES) as u16).to_le_bytes());
        bytes[56..64].copy_from_slice(&BASE.to_le_bytes());
        for (output, scope) in bytes[64..].chunks_exact_mut(8).zip(scopes) {
            output.copy_from_slice(scope);
        }
        checksum(&mut bytes);
        bytes
    }

    #[test]
    fn admits_the_exact_root_port_with_or_without_other_valid_qemu_scopes() {
        assert_eq!(admit_dmar(&fixture(&[ROOT_PORT]), BASE), Ok(BASE));
        assert_eq!(admit_dmar(&fixture(&[IOAPIC, ENDPOINT, ROOT_PORT]), BASE), Ok(BASE));
    }

    #[test]
    fn refuses_wrong_unit_or_unsupported_header_even_with_valid_checksum() {
        for (offset, value) in [(36, 47), (37, 1), (38, 1), (48, 1), (50, 16),
            (52, 1), (53, 1), (54, 1), (57, 1)]
        {
            let mut bytes = fixture(&[ROOT_PORT]);
            bytes[offset] = value;
            checksum(&mut bytes);
            assert!(admit_dmar(&bytes, BASE).is_err(), "accepted byte {offset}");
        }
        let mut bytes = fixture(&[ROOT_PORT]);
        bytes[9] ^= 1;
        assert_eq!(admit_dmar(&bytes, BASE), Err("dmar-checksum"));
        assert_eq!(admit_dmar(&bytes[..71], BASE), Err("dmar-length"));
    }

    #[test]
    fn refuses_missing_duplicate_or_lookalike_bridge_scope() {
        assert_eq!(admit_dmar(&fixture(&[IOAPIC, ENDPOINT]), BASE), Err("dmar-root-port-missing"));
        for scopes in [[ROOT_PORT, ROOT_PORT], [ROOT_PORT, [1, 8, 0, 0, 0, 0, 2, 0]],
            [ROOT_PORT, [2, 8, 0, 0, 0, 1, 2, 0]], [ROOT_PORT, [2, 7, 0, 0, 0, 0, 2, 0]]]
        {
            assert!(admit_dmar(&fixture(&scopes), BASE).is_err());
        }
    }
}
