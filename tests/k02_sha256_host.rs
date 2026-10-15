// Pure host checks of the original no_std digest. They do not qualify memory
// ownership or CPU enforcement. Nonstandard expected digests were independently
// calculated with Python hashlib, never with the implementation under test.
#[path = "../kernel/k02_sha256.rs"]
mod k02_sha256;

fn expected(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    let mut value = [0u8; 32];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    value
}

fn page() -> [u8; 4096] {
    let mut bytes = [0u8; 4096];
    for index in 0..512 {
        bytes[index * 8..index * 8 + 8]
            .copy_from_slice(&(0x5445_5353_5049_5045u64 ^ index as u64).to_le_bytes());
    }
    bytes
}

#[test]
fn empty_known_vector() {
    assert_eq!(k02_sha256::digest(b""), expected("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

#[test]
fn abc_known_vector() {
    assert_eq!(k02_sha256::digest(b"abc"), expected("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

#[test]
fn long_56_byte_known_vector() {
    assert_eq!(k02_sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        expected("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

#[test]
fn long_112_byte_known_vector() {
    let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(input.len(), 112);
    assert_eq!(k02_sha256::digest(input), expected("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"));
}

#[test]
fn million_a_known_vector() {
    assert_eq!(k02_sha256::digest(&vec![b'a'; 1_000_000]),
        expected("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

#[test]
fn padding_and_complete_block_boundaries() {
    let mut input = [0u8; 128];
    for (index, byte) in input.iter_mut().enumerate() { *byte = (index * 73 + 19) as u8; }
    for (length, hash) in [
        (55, "0c43a30970ee9525a6603d5656803c325bded148fa65bbd363df54cb3ac3dee5"),
        (56, "f4dcdc09c846d1b3621701516b300055c1e7875e216ba019dd4423f5a420f2d0"),
        (63, "ba3bb62c4369fe74e7b94392d0f04ed284a7b5d7295bfa48fabdb25c01d85ab7"),
        (64, "cb6862268ca7c02e7b6af558f0e3d236ce9ec7ff41cc746b2848c04c582da94e"),
        (65, "b68af55df9ce8ee60870e45d10e36b2e8363c9896f6e62478dcb6f593a4d7133"),
        (119, "175624f0f95b0a47a1b3b52f5b149f88802d3822b184325d0c20a1a7c132a687"),
        (120, "0598a3d8b5a82710dda54f05c4aa11fdd1c0aa5fafb216840fccbae323f07520"),
        (127, "a8365b6e6ed1daf56c41bae89ab089c03b671240ae103070480a7f271bdbad57"),
        (128, "d399f065c9f21e2fd51e2aeadb7768eab7e6e45e5150f31227c9711934a4d1d3"),
    ] { assert_eq!(k02_sha256::digest(&input[..length]), expected(hash), "length {length}"); }
}

#[test]
fn zero_page_multiblock_vector() {
    assert_eq!(k02_sha256::digest(&[0; 4096]),
        expected("ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7"));
}

#[test]
fn little_endian_page_pattern_vector() {
    assert_eq!(k02_sha256::digest(&page()),
        expected("1fef44dd5b9b2bfa748003eb47563f7065c1c5db50bc2670f7383003e91225e2"));
}

#[test]
fn unaligned_slice_hashes_only_the_requested_bytes() {
    let mut input = [0u8; 4105];
    for (index, byte) in input.iter_mut().enumerate() { *byte = (index * 7 + 3) as u8; }
    assert_eq!(k02_sha256::digest(&input[5..4101]),
        expected("8908ab0df1ffb1c7ce0fc96a99f7f5307459e368c9debfbda93e0e45a4bbe8a5"));
}

#[test]
fn exact_middle_byte_mutation_has_independent_digest() {
    let original = page();
    let original_hash = k02_sha256::digest(&original);
    let mut changed = original;
    changed[2048] ^= 0x80;
    assert_eq!(k02_sha256::digest(&changed),
        expected("c00cfae4153c54d2a8276ef60b4fcd394c740281c623aa169f3ee0397a687914"));
    assert_ne!(k02_sha256::digest(&changed), original_hash);
    assert_eq!(original, page());
    assert_eq!(k02_sha256::digest(&original), original_hash);
}
