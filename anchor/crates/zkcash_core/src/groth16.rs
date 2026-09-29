//! Mirrors the Groth16 verifier: `utils::verify_proof` and
//! `groth16::Groth16Verifier` (with 7 public inputs, as the program uses it).
//!
//! The elliptic-curve work is a boundary: the `alt_bn128` add / scalar
//! multiplication / pairing syscalls, and deserializing, validating and
//! negating the proof's G1 point (arkworks), go through the `Bn254` trait. What
//! stays here is everything the verifier decides: which public inputs, in which
//! order, the field-size checks, how the pairing input is laid out, and how the
//! pairing result is read.

use crate::transact::Proof;
use crate::utils::is_less_than_bn254_field_size_be;

/// Number of public inputs of the transaction circuit.
pub const NR_PUBLIC_INPUTS: usize = 7;

/// Mirrors the program's `Groth16Verifyingkey` for 7 public inputs.
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamme_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: [[u8; 64]; NR_PUBLIC_INPUTS + 1],
}

/// Mirrors the program's `Groth16Error`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Groth16Error {
    InvalidG1Length,
    InvalidG2Length,
    InvalidPublicInputsLength,
    PublicInputGreaterThanFieldSize,
    PreparingInputsG1MulFailed,
    PreparingInputsG1AdditionFailed,
    ProofVerificationFailed,
}

/// BN254 curve operations. `None` means the operation failed.
pub trait Bn254 {
    /// `alt_bn128_multiplication(point || scalar)`: 64-byte G1 point times a
    /// 32-byte big-endian scalar.
    fn g1_mul(point: &[u8; 64], scalar: &[u8; 32]) -> Option<[u8; 64]>;
    /// `alt_bn128_addition(a || b)`: sum of two 64-byte G1 points.
    fn g1_add(a: &[u8; 64], b: &[u8; 64]) -> Option<[u8; 64]>;
    /// `alt_bn128_pairing(input)` on four (G1, G2) pairs.
    fn pairing(input: &[u8; 768]) -> Option<[u8; 32]>;
    /// Deserializes `proof_a` (64 big-endian bytes, x || y), checks it is a
    /// valid G1 point, and returns its negation in the same encoding.
    fn negate_g1(proof_a: &[u8; 64]) -> Option<[u8; 64]>;
}

fn copy_into<const N: usize>(out: &mut [u8; 768], at: usize, bytes: &[u8; N]) {
    let mut i = 0;
    while i < N {
        out[at + i] = bytes[i];
        i += 1;
    }
}

/// Mirrors `Groth16Verifier::prepare_inputs::<true>`: vk_ic[0] + sum of
/// input_i * vk_ic[i + 1], rejecting inputs that are not below the field size.
fn prepare_inputs<C: Bn254>(
    public_inputs: &[[u8; 32]; NR_PUBLIC_INPUTS],
    verifyingkey: &VerifyingKey,
) -> Result<[u8; 64], Groth16Error> {
    let mut prepared_public_inputs = verifyingkey.vk_ic[0];

    let mut i = 0;
    while i < NR_PUBLIC_INPUTS {
        let input = &public_inputs[i];
        if !is_less_than_bn254_field_size_be(input) {
            return Err(Groth16Error::PublicInputGreaterThanFieldSize);
        }
        let mul_res = match C::g1_mul(&verifyingkey.vk_ic[i + 1], input) {
            Some(p) => p,
            None => return Err(Groth16Error::PreparingInputsG1MulFailed),
        };
        prepared_public_inputs = match C::g1_add(&mul_res, &prepared_public_inputs) {
            Some(p) => p,
            None => return Err(Groth16Error::PreparingInputsG1AdditionFailed),
        };
        i += 1;
    }

    Ok(prepared_public_inputs)
}

/// Mirrors `Groth16Verifier::new(..)` followed by `verify()`, for 7 public inputs.
/// (`new`'s length checks always pass for these fixed-size arrays.)
pub fn verify<C: Bn254>(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    public_inputs: &[[u8; 32]; NR_PUBLIC_INPUTS],
    verifyingkey: &VerifyingKey,
) -> Result<bool, Groth16Error> {
    let prepared_public_inputs = match prepare_inputs::<C>(public_inputs, verifyingkey) {
        Ok(p) => p,
        Err(e) => return Err(e),
    };

    // proof_a || proof_b || prepared_inputs || gamma || proof_c || delta || alpha || beta
    let mut pairing_input = [0u8; 768];
    copy_into(&mut pairing_input, 0, proof_a);
    copy_into(&mut pairing_input, 64, proof_b);
    copy_into(&mut pairing_input, 192, &prepared_public_inputs);
    copy_into(&mut pairing_input, 256, &verifyingkey.vk_gamme_g2);
    copy_into(&mut pairing_input, 384, proof_c);
    copy_into(&mut pairing_input, 448, &verifyingkey.vk_delta_g2);
    copy_into(&mut pairing_input, 576, &verifyingkey.vk_alpha_g1);
    copy_into(&mut pairing_input, 640, &verifyingkey.vk_beta_g2);

    let pairing_res = match C::pairing(&pairing_input) {
        Some(r) => r,
        None => return Err(Groth16Error::ProofVerificationFailed),
    };

    if pairing_res[31] != 1 {
        return Err(Groth16Error::ProofVerificationFailed);
    }
    Ok(true)
}

/// Mirrors `utils::verify_proof`: the proof's public inputs in circuit order,
/// proof_a negated, then `verify`. Any failure means "not verified".
pub fn verify_proof<C: Bn254>(proof: &Proof, verifying_key: &VerifyingKey) -> bool {
    let public_inputs_vec: [[u8; 32]; NR_PUBLIC_INPUTS] = [
        proof.root,
        proof.public_amount,
        proof.ext_data_hash,
        proof.input_nullifiers[0],
        proof.input_nullifiers[1],
        proof.output_commitments[0],
        proof.output_commitments[1],
    ];

    let proof_a = match C::negate_g1(&proof.proof_a) {
        Some(p) => p,
        None => return false,
    };

    match verify::<C>(&proof_a, &proof.proof_b, &proof.proof_c, &public_inputs_vec, verifying_key) {
        Ok(v) => v,
        Err(_) => false,
    }
}
