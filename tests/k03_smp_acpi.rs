//! Execute the real safe ACPI parser on owned host bytes only. No firmware
//! pointer dereference, AP startup, MMIO or native CPU claim comes from this.
#[path = "../kernel/smp_acpi.rs"]
mod smp_acpi;
use smp_acpi::*;

fn sum(bytes: &mut [u8], index: usize) {
    bytes[index] = 0;
    bytes[index] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
}
fn sdt(signature: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; SDT_HEADER_BYTES];
    bytes[..4].copy_from_slice(&signature);
    bytes[8] = 1;
    bytes[10..16].copy_from_slice(b"TESSRY");
    bytes.extend_from_slice(payload);
    let length = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&length.to_le_bytes());
    sum(&mut bytes, 9);
    bytes
}
fn repair(bytes: &mut [u8]) { sum(bytes, 9); }
fn rsdp(address: u64) -> Vec<u8> {
    let mut bytes = vec![0; 36];
    bytes[..8].copy_from_slice(b"RSD PTR ");
    bytes[15] = 2;
    bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&address.to_le_bytes());
    sum(&mut bytes[..20], 8);
    sum(&mut bytes, 32);
    bytes
}
fn local(id: u8, flags: u32) -> Vec<u8> {
    let mut bytes = vec![0, 8, id, id];
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes
}
fn x2(id: u32, flags: u32) -> Vec<u8> {
    let mut bytes = vec![9, 16, 0, 0];
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes
}
fn madt(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = (LAPIC_BASE as u32).to_le_bytes().to_vec();
    payload.extend_from_slice(&1u32.to_le_bytes());
    for entry in entries { payload.extend_from_slice(entry); }
    sdt(*b"APIC", &payload)
}
fn two() -> Vec<u8> { madt(&[local(0, 1), local(1, 1)]) }
fn hpet() -> Vec<u8> {
    let mut payload = 0x8086_a201u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0, 0, 0, 0]); // actual pinned QEMU GAS metadata
    payload.extend_from_slice(&HPET_BASE.to_le_bytes());
    payload.extend_from_slice(&[0; 4]);
    sdt(*b"HPET", &payload)
}

#[test]
fn rsdp_requires_exact_36_byte_layout_and_returns_owned_address_value() {
    assert_eq!(parse_rsdp(&rsdp(0x1234_5000)), Ok(Rsdp { xsdt: 0x1234_5000 }));
    let mut future = rsdp(0x1234_5000); future[15] = 3;
    sum(&mut future[..20], 8); sum(&mut future, 32);
    assert_eq!(parse_rsdp(&future), Ok(Rsdp { xsdt: 0x1234_5000 }));
    for length in 0..36 { assert_eq!(parse_rsdp(&rsdp(0x1000)[..length]), Err(Error::Length)); }
    let mut extra = rsdp(0x1000); extra.push(0);
    assert_eq!(parse_rsdp(&extra), Err(Error::Length));
}
#[test]
fn rsdp_signature_revision_and_both_checksums_are_independent() {
    let mut b = rsdp(0x1000); b[7] = 0;
    assert_eq!(parse_rsdp(&b), Err(Error::Signature));
    let mut b = rsdp(0x1000); b[15] = 1;
    assert_eq!(parse_rsdp(&b), Err(Error::Revision));
    // Repair extended checksum while leaving the legacy 20-byte sum corrupt.
    let mut b = rsdp(0x1000); b[8] ^= 1; sum(&mut b, 32);
    assert_eq!(parse_rsdp(&b), Err(Error::Checksum));
    let mut b = rsdp(0x1000); b[32] ^= 1;
    assert_eq!(parse_rsdp(&b), Err(Error::Checksum));
}
#[test]
fn rsdp_declared_length_reserved_and_pointer_overflow_are_rejected() {
    let mut b = rsdp(0x1000); b[20..24].copy_from_slice(&40u32.to_le_bytes()); sum(&mut b, 32);
    assert_eq!(parse_rsdp(&b), Err(Error::Length));
    let mut b = rsdp(0x1000); b[33] = 1; sum(&mut b, 32);
    assert_eq!(parse_rsdp(&b), Err(Error::Reserved));
    for address in [0, u64::MAX, u64::MAX - 34] {
        assert_eq!(parse_rsdp(&rsdp(address)), Err(Error::Address));
    }
}
#[test]
fn sdt_exact_header_and_64_kib_limit_accept_owned_unaligned_bytes() {
    let b = sdt(*b"TEST", &[]);
    assert_eq!(validate_sdt(&b, *b"TEST"), Ok(b.as_slice()));
    let mut storage = vec![0xee]; storage.extend_from_slice(&b);
    assert!(validate_sdt(&storage[1..], *b"TEST").is_ok());
    let max = sdt(*b"TEST", &vec![0; MAX_SDT_BYTES - SDT_HEADER_BYTES]);
    assert_eq!(max.len(), 65536);
    assert!(validate_sdt(&max, *b"TEST").is_ok());
    let larger = sdt(*b"TEST", &vec![0; MAX_SDT_BYTES + 1 - SDT_HEADER_BYTES]);
    assert_eq!(validate_sdt(&larger, *b"TEST"), Err(Error::Length));
}
#[test]
fn sdt_rejects_truncation_trailing_or_self_inconsistent_lengths() {
    let b = sdt(*b"TEST", &[1, 2, 3]);
    for length in 0..b.len() { assert_eq!(validate_sdt(&b[..length], *b"TEST"), Err(Error::Length)); }
    let mut extra = b.clone(); extra.push(0);
    assert_eq!(validate_sdt(&extra, *b"TEST"), Err(Error::Length));
    let mut bad = b; bad[4..8].copy_from_slice(&u32::MAX.to_le_bytes()); repair(&mut bad);
    assert_eq!(validate_sdt(&bad, *b"TEST"), Err(Error::Length));
}
#[test]
fn sdt_signature_revision_and_checksum_cannot_be_self_asserted() {
    let b = sdt(*b"TEST", &[1]);
    assert_eq!(validate_sdt(&b, *b"APIC"), Err(Error::Signature));
    let mut bad = b.clone(); bad[8] = 0; repair(&mut bad);
    assert_eq!(validate_sdt(&bad, *b"TEST"), Err(Error::Revision));
    let mut bad = b; bad[10] ^= 1;
    assert_eq!(validate_sdt(&bad, *b"TEST"), Err(Error::Checksum));
}
#[test]
fn xsdt_walks_little_endian_u64_entries_with_exact_remaining_count() {
    let addresses = [0x1003u64, 0x1_0000_2000, 0x4000];
    let payload: Vec<u8> = addresses.iter().flat_map(|a| a.to_le_bytes()).collect();
    let b = sdt(*b"XSDT", &payload);
    let mut walker = xsdt_entries(&b).unwrap();
    assert_eq!(walker.size_hint(), (3, Some(3)));
    assert_eq!(walker.next(), Some(addresses[0]));
    assert_eq!(walker.len(), 2);
    assert_eq!(walker.next(), Some(addresses[1]));
    assert_eq!(walker.next(), Some(addresses[2]));
    assert_eq!(walker.next(), None); assert_eq!(walker.next(), None);
    assert_eq!(walker.size_hint(), (0, Some(0)));
}
#[test]
fn xsdt_rejects_empty_partial_zero_and_overflowing_entries() {
    assert_eq!(xsdt_entries(&sdt(*b"XSDT", &[])).unwrap_err(), Error::Structure);
    for length in 1..8 { assert_eq!(xsdt_entries(&sdt(*b"XSDT", &vec![0; length])).unwrap_err(), Error::Structure); }
    for address in [0u64, u64::MAX, u64::MAX - 34] {
        assert_eq!(xsdt_entries(&sdt(*b"XSDT", &address.to_le_bytes())).unwrap_err(), Error::Address);
    }
}
#[test]
fn xsdt_validates_entire_table_before_publishing_any_iterator() {
    let b = sdt(*b"XSDT", &[0x10; 16]);
    let mut bad = b.clone(); bad[9] ^= 1;
    assert_eq!(xsdt_entries(&bad).unwrap_err(), Error::Checksum);
    assert_eq!(xsdt_entries(&sdt(*b"APIC", &[0x10; 16])).unwrap_err(), Error::Signature);
    let mut payload = 0x1000u64.to_le_bytes().to_vec(); payload.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(xsdt_entries(&sdt(*b"XSDT", &payload)).unwrap_err(), Error::Address);
}
#[test]
fn madt_returns_exactly_two_sorted_enabled_xapic_ids() {
    assert_eq!(parse_madt(&two()), Ok(Topology { lapic: LAPIC_BASE, ids: [0, 1] }));
    assert_eq!(parse_madt(&madt(&[local(7, 1), local(2, 1)])), Ok(Topology { lapic: LAPIC_BASE, ids: [2, 7] }));
}
#[test]
fn madt_disabled_and_online_capable_processors_are_not_boot_targets() {
    let b = madt(&[local(8, 0), local(7, 1), local(5, 2), local(2, 1), x2(1000, 0)]);
    assert_eq!(parse_madt(&b), Ok(Topology { lapic: LAPIC_BASE, ids: [2, 7] }));
}
#[test]
fn madt_rejects_zero_one_or_three_enabled_processors() {
    for entries in [vec![], vec![local(0, 0)], vec![local(0, 1)], vec![local(0, 1), local(1, 1), local(2, 1)]] {
        assert_eq!(parse_madt(&madt(&entries)), Err(Error::ProcessorCount));
    }
}
#[test]
fn madt_rejects_duplicate_ids_even_when_disabled_or_after_two_valid_targets() {
    for entries in [vec![local(0, 1), local(0, 1)],
                    vec![local(0, 0), local(0, 1), local(1, 1)],
                    vec![local(0, 1), local(1, 1), local(0, 0)],
                    vec![local(0, 1), local(1, 1), local(9, 0), local(9, 2)]] {
        assert_eq!(parse_madt(&madt(&entries)), Err(Error::Duplicate));
    }
}
#[test]
fn madt_duplicate_ids_cross_legacy_and_disabled_x2apic_entries() {
    for entries in [vec![local(0, 1), local(1, 1), x2(0, 0)],
                    vec![x2(1, 0), local(0, 1), local(1, 1)],
                    vec![local(0, 1), local(1, 1), x2(1000, 0), x2(1000, 0)]] {
        assert_eq!(parse_madt(&madt(&entries)), Err(Error::Duplicate));
    }
}
#[test]
fn madt_enabled_x2apic_is_explicitly_unsupported() {
    assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 1), x2(300, 1)])), Err(Error::UnsupportedX2Apic));
}
#[test]
fn madt_rejects_all_lapic_overrides_even_to_the_same_address() {
    for address in [LAPIC_BASE, 0xfee1_0000] {
        let mut override_entry = vec![5, 12, 0, 0]; override_entry.extend_from_slice(&address.to_le_bytes());
        assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 1), override_entry])), Err(Error::LapicOverride));
    }
}
#[test]
fn madt_header_lapic_flags_and_broadcast_target_are_bounded() {
    let mut bad = two(); bad[36..40].copy_from_slice(&0xfee1_0000u32.to_le_bytes()); repair(&mut bad);
    assert_eq!(parse_madt(&bad), Err(Error::Address));
    let mut bad = two(); bad[40..44].copy_from_slice(&2u32.to_le_bytes()); repair(&mut bad);
    assert_eq!(parse_madt(&bad), Err(Error::Reserved));
    assert_eq!(parse_madt(&madt(&[local(0, 1), local(255, 1)])), Err(Error::Address));
}
#[test]
fn madt_rejects_reserved_processor_flags_and_x2apic_reserved_bytes() {
    assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 3)])), Err(Error::Reserved));
    assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 1), x2(300, 3)])), Err(Error::Reserved));
    assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 5)])), Err(Error::Reserved));
    assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 1), x2(300, 4)])), Err(Error::Reserved));
    let mut bad = x2(300, 0); bad[2] = 1;
    assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 1), bad])), Err(Error::Reserved));
}
#[test]
fn madt_every_subtable_must_advance_and_fit_the_declared_table() {
    for tail in [vec![0], vec![0, 0], vec![0, 1], vec![0, 8, 1], vec![99, 8, 1]] {
        assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 1), tail])), Err(Error::Structure));
    }
}
#[test]
fn madt_fixed_cpu_structure_lengths_and_table_header_are_enforced() {
    for (kind, length) in [(0u8, 7u8), (0, 9), (9, 15), (9, 17), (5, 11), (5, 13)] {
        let mut bad = vec![0; length as usize]; bad[0] = kind; bad[1] = length;
        assert_eq!(parse_madt(&madt(&[local(0, 1), local(1, 1), bad])), Err(Error::Structure));
    }
    assert_eq!(parse_madt(&sdt(*b"APIC", &[0; 7])), Err(Error::Length));
    assert_eq!(parse_madt(&sdt(*b"TEST", &[0; 8])), Err(Error::Signature));
    let mut bad = two(); bad[9] ^= 1;
    assert_eq!(parse_madt(&bad), Err(Error::Checksum));
}
#[test]
fn madt_well_framed_unneeded_structures_are_skipped_without_authority() {
    let b = madt(&[vec![127, 4, 0xaa, 0xbb], local(2, 1), vec![128, 2], local(7, 1)]);
    assert_eq!(parse_madt(&b), Ok(Topology { lapic: LAPIC_BASE, ids: [2, 7] }));
}
#[test]
fn madt_processor_tracking_has_a_fixed_nonallocating_bound() {
    let mut entries = vec![local(0, 1), local(1, 1)];
    entries.extend((1000..1254).map(|id| x2(id, 0)));
    assert_eq!(parse_madt(&madt(&entries)), Ok(Topology { lapic: LAPIC_BASE, ids: [0, 1] }));
    entries.push(x2(1254, 0));
    assert_eq!(parse_madt(&madt(&entries)), Err(Error::Capacity));
}
#[test]
fn hpet_matches_actual_qemu_table_and_explicit_64_bit_gas() {
    assert_eq!(parse_hpet(&hpet()), Ok(HPET_BASE));
    let mut explicit = hpet(); explicit[41] = 64; repair(&mut explicit);
    assert_eq!(parse_hpet(&explicit), Ok(HPET_BASE));
}
#[test]
fn hpet_rejects_wrong_signature_size_checksum_and_capability_metadata() {
    assert_eq!(parse_hpet(&sdt(*b"TEST", &[0; 20])), Err(Error::Signature));
    assert_eq!(parse_hpet(&sdt(*b"HPET", &[0; 19])), Err(Error::Length));
    assert_eq!(parse_hpet(&sdt(*b"HPET", &[0; 21])), Err(Error::Length));
    let mut bad = hpet(); bad[9] ^= 1;
    assert_eq!(parse_hpet(&bad), Err(Error::Checksum));
    let mut bad = hpet(); bad[36] ^= 1; repair(&mut bad);
    assert_eq!(parse_hpet(&bad), Err(Error::Structure));
}
#[test]
fn hpet_requires_system_memory_fixed_base_and_zero_gas_offset() {
    for (offset, value) in [(40, 1), (41, 32), (42, 1), (43, 4)] {
        let mut bad = hpet(); bad[offset] = value; repair(&mut bad);
        assert_eq!(parse_hpet(&bad), Err(Error::Structure));
    }
    for address in [0u64, 0xfed0_1000, u64::MAX] {
        let mut bad = hpet(); bad[44..52].copy_from_slice(&address.to_le_bytes()); repair(&mut bad);
        assert_eq!(parse_hpet(&bad), Err(Error::Address));
    }
}
#[test]
fn hpet_rejects_unknown_block_or_reserved_profile_metadata() {
    let mut bad = hpet(); bad[52] = 1; repair(&mut bad);
    assert_eq!(parse_hpet(&bad), Err(Error::Reserved));
    let mut bad = hpet(); bad[55] = 0x80; repair(&mut bad);
    assert_eq!(parse_hpet(&bad), Err(Error::Reserved));
}
