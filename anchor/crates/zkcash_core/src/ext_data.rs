//! Mirrors `utils::calculate_complete_ext_data_hash`.
//!
//! Upstream builds a `#[derive(AnchorSerialize)]` struct and serializes it with
//! Borsh; Borsh cannot be extracted, so this writes the same bytes explicitly.
//! Equivalence with Borsh is checked by the differential tests.

use alloc::vec::Vec;

/// SHA-256 (the `sol_sha256` syscall on-chain, via `solana_program::hash::hash`).
/// The Lean model treats it as an abstract function.
pub trait Sha256 {
    fn hash(data: &[u8]) -> [u8; 32];
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let mut i = 0;
    while i < bytes.len() {
        out.push(bytes[i]);
        i += 1;
    }
}

/// Little-endian bytes of `x` (Borsh's encoding of u64, and of i64 via `as u64`).
fn push_u64_le(out: &mut Vec<u8>, x: u64) {
    let mut i = 0;
    while i < 8 {
        out.push((x >> (8 * i)) as u8);
        i += 1;
    }
}

/// Borsh's encoding of a `Vec<u8>`: a little-endian u32 length, then the bytes.
/// Returns false (writing nothing) when the length does not fit in a u32,
/// where Borsh fails.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> bool {
    if bytes.len() > 0xffff_ffff {
        return false;
    }
    let len = bytes.len() as u32;
    let mut i = 0;
    while i < 4 {
        out.push((len >> (8 * i)) as u8);
        i += 1;
    }
    push_bytes(out, bytes);
    true
}

/// Borsh serialization of upstream's `CompleteExtData`, field by field in
/// declaration order. `None` exactly when Borsh's `serialize` would fail.
pub fn serialize_complete_ext_data(
    recipient: [u8; 32],
    ext_amount: i64,
    encrypted_output1: &[u8],
    encrypted_output2: &[u8],
    fee: u64,
    fee_recipient: [u8; 32],
    mint_address: [u8; 32],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_bytes(&mut out, &recipient);
    push_u64_le(&mut out, ext_amount as u64);
    // (Aeneas does not support `?` on `Option`, hence the explicit checks.)
    if !push_len_prefixed(&mut out, encrypted_output1) {
        return None;
    }
    if !push_len_prefixed(&mut out, encrypted_output2) {
        return None;
    }
    push_u64_le(&mut out, fee);
    push_bytes(&mut out, &fee_recipient);
    push_bytes(&mut out, &mint_address);
    Some(out)
}

/// Mirrors `utils::calculate_complete_ext_data_hash`: SHA-256 of the
/// serialization. `None` exactly when upstream's `serialize(..)?` fails.
pub fn calculate_complete_ext_data_hash<S: Sha256>(
    recipient: [u8; 32],
    ext_amount: i64,
    encrypted_output1: &[u8],
    encrypted_output2: &[u8],
    fee: u64,
    fee_recipient: [u8; 32],
    mint_address: [u8; 32],
) -> Option<[u8; 32]> {
    match serialize_complete_ext_data(
        recipient,
        ext_amount,
        encrypted_output1,
        encrypted_output2,
        fee,
        fee_recipient,
        mint_address,
    ) {
        Some(serialized_ext_data) => Some(S::hash(&serialized_ext_data)),
        None => None,
    }
}
