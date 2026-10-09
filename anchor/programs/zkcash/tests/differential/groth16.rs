//! Differential test of Groth16 verification: upstream `verify_proof` (which
//! drives upstream's `Groth16Verifier`, still in groth16.rs) against the
//! program's `verify_proof`, now backed by `zkcash_core::groth16`. Both use
//! the real `alt_bn128` implementations and arkworks.
//!
//! Inputs start from a real valid proof and are then corrupted: bit flips in
//! each proof element and public input, public inputs at or above the field
//! size, random or malformed points, the non-negated proof, and altered
//! verifying keys (including a wrong number of `vk_ic` entries).

use ark_bn254::g1::G1Affine as G1;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use num_bigint::BigUint;
use proptest::prelude::*;
use std::ops::Neg;
use zkcash::groth16::Groth16Verifyingkey;
use zkcash::utils::{change_endianness, VERIFYING_KEY};
use zkcash::Proof;

mod upstream {
    use super::*;
    use zkcash::groth16::Groth16Verifier;

    // Verbatim from upstream `utils::verify_proof` (utils.rs:214-268).
    pub fn verify_proof(proof: Proof, verifying_key: Groth16Verifyingkey) -> bool {
        let mut public_inputs_vec: [[u8; 32]; 7] = [[0u8; 32]; 7];

        public_inputs_vec[0] = proof.root;
        public_inputs_vec[1] = proof.public_amount;
        public_inputs_vec[2] = proof.ext_data_hash;
        public_inputs_vec[3] = proof.input_nullifiers[0];
        public_inputs_vec[4] = proof.input_nullifiers[1];
        public_inputs_vec[5] = proof.output_commitments[0];
        public_inputs_vec[6] = proof.output_commitments[1];

         // First deserialize PROOF_A into a G1 point
         let g1_point = match G1::deserialize_with_mode(
            &*[&change_endianness(&proof.proof_a[0..64]), &[0u8][..]].concat(),
            Compress::No,
            Validate::Yes,
        ) {
            Ok(point) => point,
            Err(_) => return false,
        };
        
        let mut proof_a_neg = [0u8; 65];
        if g1_point
            .neg()
            .x
            .serialize_with_mode(&mut proof_a_neg[..32], Compress::No)
            .is_err() {
            return false;
        }
        if g1_point
            .neg()
            .y
            .serialize_with_mode(&mut proof_a_neg[32..], Compress::No)
            .is_err() {
            return false;
        }

        let proof_a: [u8; 64] = match change_endianness(&proof_a_neg[..64]).try_into() {
            Ok(array) => array,
            Err(_) => return false,
        };

        let mut verifier = match Groth16Verifier::new(
            &proof_a,
            &proof.proof_b,
            &proof.proof_c,
            &public_inputs_vec,
            &verifying_key
        ) {
            Ok(v) => v,
            Err(_) => return false,
        };

        verifier.verify().unwrap_or(false)
    }
}

// Copied from tests/unit/utils_test.rs: a valid proof for these public inputs.
const PROOF_A: [u8; 64] = [33, 176, 101, 34, 69, 225, 121, 7, 75, 118, 155, 230, 240, 148, 177, 70, 99, 90, 162, 126, 87, 113, 101, 157, 129, 98, 119, 140, 178, 220, 223, 122, 42, 93, 51, 152, 119, 241, 116, 56, 93, 200, 108, 194, 135, 57, 47, 7, 74, 149, 72, 215, 103, 26, 163, 253, 6, 50, 9, 231, 148, 41, 211, 13];

const PROOF_B: [u8; 128] = [28, 69, 92, 80, 191, 61, 65, 166, 65, 16, 144, 119, 255, 160, 145, 2, 30, 88, 182, 169, 63, 180, 68, 166, 105, 176, 38, 156, 166, 97, 222, 156, 5, 234, 80, 151, 207, 227, 105, 13, 16, 198, 227, 11, 68, 95, 221, 154, 8, 182, 177, 87, 153, 67, 253, 4, 156, 48, 177, 155, 30, 88, 178, 98, 32, 167, 163, 62, 173, 34, 110, 201, 42, 191, 119, 199, 125, 58, 227, 36, 66, 55, 152, 156, 185, 137, 154, 2, 41, 216, 225, 156, 81, 200, 80, 251, 41, 67, 206, 85, 6, 214, 224, 15, 88, 73, 79, 202, 181, 35, 139, 77, 253, 193, 117, 165, 85, 234, 148, 18, 251, 156, 15, 11, 131, 100, 88, 217];

const PROOF_C: [u8; 64] = [9, 98, 181, 114, 139, 22, 71, 4, 210, 99, 210, 2, 209, 196, 194, 133, 94, 114, 55, 225, 10, 171, 202, 249, 174, 228, 199, 10, 100, 115, 119, 40, 36, 73, 23, 170, 47, 236, 126, 81, 98, 255, 93, 225, 55, 13, 14, 63, 18, 66, 64, 204, 154, 139, 54, 91, 85, 62, 65, 20, 120, 78, 45, 195];

const PUBLIC_INPUTS: [[u8; 32]; 7] = [
    [
      35,  32, 33, 165,  51,  76, 83,  64,  62,
      43, 144, 45,  80,   2, 148, 32, 201,   8,
       9, 187, 65,  43, 198, 110, 43,  70, 151,
      29, 126, 19,  55,  86
    ],
    [
       48, 100,  78, 114, 225,  49, 160,  41,
      184,  80,  69, 182, 129, 129,  88,  93,
       40,  51, 232,  72, 121, 185, 112, 145,
       67, 225, 245, 147, 180, 101,  54,   1
    ],
    [
      10,  72, 121, 237,  87,  62,  14, 224,
       3, 149, 108, 134, 203, 123,  20, 155,
      22, 150, 213, 175, 200, 250, 183, 227,
      27, 146,  56, 232, 215, 174,  24, 211
    ],
    [
       47,  33, 196, 198,   7, 143, 191, 249,
      108, 187, 250, 115, 104,  59,  79, 209,
       49,  53, 243,  59, 169,  49,  63, 242,
      187, 239, 231, 229, 241, 202, 230, 214
    ],
    [
       25, 194, 167, 199, 121, 112,  72, 102,
       77,  28,   9,  25, 134, 178, 128,  76,
      206, 219, 227,  88,  58,  76,  27, 133,
      168, 194,  12, 187,  16, 146, 229, 117
    ],
    [
       15, 228, 113,  58,  51, 201, 233,  28,
       56, 160, 107, 159,  70,  46, 119,  72,
       70, 108, 196, 189,  71, 204,  89, 173,
      136, 147, 174, 215, 106,  61,  35, 201
    ],
    [
       13, 107, 132,  53, 242, 134,  45,  10,
      102,  33,  59,  68,  61,  13, 210, 252,
      230,  78, 219, 201, 232, 238, 149, 197,
       58,  64, 125, 223, 202,   1, 185, 194
    ]
];

fn valid_proof() -> Proof {
    Proof {
        root: PUBLIC_INPUTS[0],
        public_amount: PUBLIC_INPUTS[1],
        ext_data_hash: PUBLIC_INPUTS[2],
        input_nullifiers: [PUBLIC_INPUTS[3], PUBLIC_INPUTS[4]],
        output_commitments: [PUBLIC_INPUTS[5], PUBLIC_INPUTS[6]],
        proof_a: PROOF_A,
        proof_b: PROOF_B,
        proof_c: PROOF_C,
    }
}

/// The 32 bytes of each public input, in circuit order.
fn public_input_mut(p: &mut Proof, i: usize) -> &mut [u8; 32] {
    match i {
        0 => &mut p.root,
        1 => &mut p.public_amount,
        2 => &mut p.ext_data_hash,
        3 => &mut p.input_nullifiers[0],
        4 => &mut p.input_nullifiers[1],
        5 => &mut p.output_commitments[0],
        _ => &mut p.output_commitments[1],
    }
}

fn modulus_plus(delta: u32) -> [u8; 32] {
    let x = BigUint::from_bytes_be(&ark_bn254::Fr::MODULUS.to_bytes_be()) + delta;
    let b = x.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

#[derive(Clone, Debug)]
enum Corruption {
    None,
    FlipProofA(usize, u8),
    FlipProofB(usize, u8),
    FlipProofC(usize, u8),
    FlipInput(usize, usize, u8),
    InputAtLeastModulus(usize, u32),
    /// The valid input plus p: the same field element with different bytes.
    /// Only the field-size check rejects it (without it the proof verifies,
    /// letting the same proof be replayed with a different encoding).
    InputPlusModulus(usize),
    RandomProofA([u8; 32], [u8; 32]),
    ZeroProofA,
    NonNegatedProofA,
    FlipKeyAlpha(usize, u8),
    FlipKeyIc(usize, usize, u8),
    KeyIcLength(usize),
}

fn corruption() -> impl Strategy<Value = Corruption> {
    prop_oneof![
        Just(Corruption::None),
        (0usize..64, 0u8..8).prop_map(|(i, b)| Corruption::FlipProofA(i, b)),
        (0usize..128, 0u8..8).prop_map(|(i, b)| Corruption::FlipProofB(i, b)),
        (0usize..64, 0u8..8).prop_map(|(i, b)| Corruption::FlipProofC(i, b)),
        (0usize..7, 0usize..32, 0u8..8).prop_map(|(k, i, b)| Corruption::FlipInput(k, i, b)),
        (0usize..7, 0u32..3).prop_map(|(k, d)| Corruption::InputAtLeastModulus(k, d)),
        (0usize..7).prop_map(Corruption::InputPlusModulus),
        any::<([u8; 32], [u8; 32])>().prop_map(|(x, y)| Corruption::RandomProofA(x, y)),
        Just(Corruption::ZeroProofA),
        Just(Corruption::NonNegatedProofA),
        (0usize..64, 0u8..8).prop_map(|(i, b)| Corruption::FlipKeyAlpha(i, b)),
        (0usize..8, 0usize..64, 0u8..8).prop_map(|(k, i, b)| Corruption::FlipKeyIc(k, i, b)),
        prop::sample::select(vec![0usize, 1, 7, 9]).prop_map(Corruption::KeyIcLength),
    ]
}

/// Applies the corruption and returns the proof and `vk_ic` to verify with.
fn apply(c: &Corruption) -> (Proof, [u8; 64], Vec<[u8; 64]>) {
    let mut p = valid_proof();
    let mut alpha = VERIFYING_KEY.vk_alpha_g1;
    let mut ic = VERIFYING_KEY.vk_ic.to_vec();
    match *c {
        Corruption::None => {}
        Corruption::FlipProofA(i, b) => p.proof_a[i] ^= 1 << b,
        Corruption::FlipProofB(i, b) => p.proof_b[i] ^= 1 << b,
        Corruption::FlipProofC(i, b) => p.proof_c[i] ^= 1 << b,
        Corruption::FlipInput(k, i, b) => public_input_mut(&mut p, k)[i] ^= 1 << b,
        Corruption::InputAtLeastModulus(k, d) => *public_input_mut(&mut p, k) = modulus_plus(d),
        Corruption::InputPlusModulus(k) => {
            let x = BigUint::from_bytes_be(public_input_mut(&mut p, k))
                + BigUint::from_bytes_be(&ark_bn254::Fr::MODULUS.to_bytes_be());
            let b = x.to_bytes_be();
            if b.len() <= 32 {
                let mut out = [0u8; 32];
                out[32 - b.len()..].copy_from_slice(&b);
                *public_input_mut(&mut p, k) = out;
            }
        }
        Corruption::RandomProofA(x, y) => {
            p.proof_a[..32].copy_from_slice(&x);
            p.proof_a[32..].copy_from_slice(&y);
        }
        Corruption::ZeroProofA => p.proof_a = [0; 64],
        Corruption::NonNegatedProofA => {
            // What a client that forgot to negate would send: -proof_a.
            let g = G1::deserialize_with_mode(
                &*[&change_endianness(&PROOF_A), &[0u8][..]].concat(), Compress::No, Validate::Yes,
            ).unwrap();
            let mut neg = [0u8; 65];
            g.neg().x.serialize_with_mode(&mut neg[..32], Compress::No).unwrap();
            g.neg().y.serialize_with_mode(&mut neg[32..], Compress::No).unwrap();
            p.proof_a = change_endianness(&neg[..64]).try_into().unwrap();
        }
        Corruption::FlipKeyAlpha(i, b) => alpha[i] ^= 1 << b,
        Corruption::FlipKeyIc(k, i, b) => ic[k][i] ^= 1 << b,
        Corruption::KeyIcLength(n) => ic.resize(n, VERIFYING_KEY.vk_ic[0]),
    }
    (p, alpha, ic)
}

#[test]
fn valid_proof_verifies_on_both() {
    assert!(zkcash::utils::verify_proof(valid_proof(), VERIFYING_KEY));
    assert!(upstream::verify_proof(valid_proof(), VERIFYING_KEY));
}

/// Every public input of the fixture is small enough that adding p still fits
/// in 32 bytes, so `InputPlusModulus` really produces the aliased encoding.
#[test]
fn every_fixture_input_has_an_aliased_encoding() {
    for k in 0..7 {
        let (p, _, _) = apply(&Corruption::InputPlusModulus(k));
        assert_ne!(*public_input_mut(&mut p.clone(), k), PUBLIC_INPUTS[k], "input {k}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn verify_proof_matches_upstream(c in corruption()) {
        let (proof, alpha, ic) = apply(&c);
        // Groth16Verifyingkey is not Copy, so build it once per side.
        let key = || Groth16Verifyingkey { vk_alpha_g1: alpha, vk_ic: &ic, ..VERIFYING_KEY };
        prop_assert_eq!(
            zkcash::utils::verify_proof(proof.clone(), key()),
            upstream::verify_proof(proof, key()),
        );
    }
}
