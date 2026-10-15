//! Original, allocation-free SHA-256 for checked byte slices.
//!
//! Algorithm, initial words and round constants: NIST FIPS 180-4, sections
//! 4.1.2, 4.2.2, 5.1.1, 5.3.3 and 6.2.2 (not copied implementation code).
//! https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//! This is a digest implementation, not a FIPS validation claim.

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const ROUND: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut schedule = [0u32; 64];
    for (index, word) in schedule[..16].iter_mut().enumerate() {
        let at = index * 4;
        *word = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
    }
    for index in 16..64 {
        let left = schedule[index - 15];
        let right = schedule[index - 2];
        let small0 = left.rotate_right(7) ^ left.rotate_right(18) ^ (left >> 3);
        let small1 = right.rotate_right(17) ^ right.rotate_right(19) ^ (right >> 10);
        schedule[index] = schedule[index - 16].wrapping_add(small0)
            .wrapping_add(schedule[index - 7]).wrapping_add(small1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let first = h.wrapping_add(big1).wrapping_add(choose)
            .wrapping_add(ROUND[index]).wrapping_add(schedule[index]);
        let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let second = big0.wrapping_add(majority);
        h = g; g = f; f = e; e = d.wrapping_add(first);
        d = c; c = b; b = a; a = first.wrapping_add(second);
    }
    for (word, addend) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(addend);
    }
}

/// Hash bytes without allocating or dereferencing caller-supplied addresses.
/// Working storage has fixed size independent of input length. As required by
/// SHA-256, the byte length must fit a strictly less than 2^64-bit message.
pub fn digest(input: &[u8]) -> [u8; 32] {
    let bit_length = u64::try_from(input.len()).ok().and_then(|length| length.checked_mul(8))
        .expect("SHA-256 message exceeds its bit-length format");
    let mut state = INITIAL;
    let mut blocks = input.chunks_exact(64);
    for block in &mut blocks { compress(&mut state, block); }
    let remaining = blocks.remainder();
    let mut final_block = [0u8; 64];
    final_block[..remaining.len()].copy_from_slice(remaining);
    final_block[remaining.len()] = 0x80;
    if remaining.len() >= 56 {
        compress(&mut state, &final_block);
        final_block.fill(0);
    }
    final_block[56..].copy_from_slice(&bit_length.to_be_bytes());
    compress(&mut state, &final_block);
    let mut output = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}
