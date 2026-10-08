use crate::Proof;
use crate::groth16::Groth16Verifyingkey;
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};
use crate::ErrorCode;
use ark_bn254;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use std::ops::Neg;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;

type G1 = ark_bn254::g1::G1Affine;

pub const SOL_ADDRESS: Pubkey = anchor_lang::pubkey!("11111111111111111111111111111112");

/// The program's verifying key, in the upstream type. The bytes are defined
/// once, in `zkcash_core::verifying_key`, so the verified model and the
/// program cannot disagree on them.
pub const VERIFYING_KEY: Groth16Verifyingkey = Groth16Verifyingkey {
	nr_pubinputs: zkcash_core::groth16::NR_PUBLIC_INPUTS,
	vk_alpha_g1: zkcash_core::verifying_key::VERIFYING_KEY.vk_alpha_g1,
	vk_beta_g2: zkcash_core::verifying_key::VERIFYING_KEY.vk_beta_g2,
	vk_gamme_g2: zkcash_core::verifying_key::VERIFYING_KEY.vk_gamme_g2,
	vk_delta_g2: zkcash_core::verifying_key::VERIFYING_KEY.vk_delta_g2,
	vk_ic: &zkcash_core::verifying_key::VERIFYING_KEY.vk_ic,
};

/**
 * Calculates the expected public amount from ext_amount and fee, then verifies if it matches
 * the provided public_amount_bytes.
 *
 * @param ext_amount The external amount (can be positive or negative), as i64.
 * @param fee The fee (non-negative), as u64.
 * @param public_amount_bytes The public amount to verify against, as a 32-byte array (big-endian).
 * @return Returns `true` if the calculated public amount matches public_amount_bytes AND 
 *         the input ext_amount and fee are valid according to predefined limits. 
 *         Returns `false` otherwise (either due to mismatch or invalid inputs for calculation).
 */
pub fn check_public_amount(ext_amount: i64, fee: u64, public_amount_bytes: [u8; 32]) -> bool {
    if ext_amount == i64::MIN {
        msg!("can't use i64::MIN as ext_amount"); 
    }
    zkcash_core::utils::check_public_amount::<ArkFr>(ext_amount, fee, public_amount_bytes)
}

/// Implements the core crate's `PrimeField` with arkworks' BN254 scalar field.
#[derive(Clone, Copy)]
pub struct ArkFr(pub Fr);

impl zkcash_core::field::PrimeField for ArkFr {
    fn from_u64(x: u64) -> Self {
        ArkFr(Fr::from(x))
    }

    fn from_be_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        ArkFr(Fr::from_be_bytes_mod_order(bytes))
    }

    fn from_le_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        ArkFr(Fr::from_le_bytes_mod_order(bytes))
    }

    fn add(a: Self, b: Self) -> Self {
        ArkFr(a.0 + b.0)
    }

    fn sub(a: Self, b: Self) -> Self {
        ArkFr(a.0 - b.0)
    }

    fn neg(a: Self) -> Self {
        ArkFr(-a.0)
    }

    fn le(a: Self, b: Self) -> bool {
        a.0 <= b.0
    }

    fn eq(a: Self, b: Self) -> bool {
        a.0 == b.0
    }
}

/**
 * Validates that the provided fee meets the minimum required fee based on global configuration.
 * 
 * For deposits (ext_amount > 0):
 * - expected_fee = (ext_amount * deposit_fee_rate) / 10000
 * - minimum_fee = expected_fee * (1 - fee_error_margin/10000)
 * 
 * For withdrawals (ext_amount < 0):
 * - expected_fee = (abs(ext_amount) * withdrawal_fee_rate) / 10000
 * - minimum_fee = expected_fee * (1 - fee_error_margin/10000)
 * 
 * @param ext_amount The external amount (positive for deposits, negative for withdrawals)
 * @param provided_fee The fee provided by the user
 * @param deposit_fee_rate Fee rate for deposits (in basis points, 0-10000)
 * @param withdrawal_fee_rate Fee rate for withdrawals (in basis points, 0-10000)
 * @param fee_error_margin Tolerance rate (in basis points, 0-10000)
 * @return Ok(()) if fee is valid, Err(ErrorCode) if invalid
 */
pub fn validate_fee(
    ext_amount: i64,
    provided_fee: u64,
    deposit_fee_rate: u16,
    withdrawal_fee_rate: u16,
    fee_error_margin: u16,
) -> Result<()> {
    zkcash_core::utils::validate_fee(
        ext_amount,
        provided_fee,
        deposit_fee_rate,
        withdrawal_fee_rate,
        fee_error_margin,
    )
    .map_err(|e| ErrorCode::from(e).into())
}

pub fn verify_proof(proof: Proof, verifying_key: Groth16Verifyingkey) -> bool {
    // Upstream's `Groth16Verifier::new` rejects a key whose `vk_ic` does not
    // have one entry per public input plus one.
    let vk_ic = match verifying_key.vk_ic.try_into() {
        Ok(vk_ic) => vk_ic,
        Err(_) => return false,
    };
    let verifying_key = zkcash_core::groth16::VerifyingKey {
        vk_alpha_g1: verifying_key.vk_alpha_g1,
        vk_beta_g2: verifying_key.vk_beta_g2,
        vk_gamme_g2: verifying_key.vk_gamme_g2,
        vk_delta_g2: verifying_key.vk_delta_g2,
        vk_ic,
    };
    zkcash_core::groth16::verify_proof::<SolanaBn254>(&proof.to_core(), &verifying_key)
}

/// Implements the core crate's `Bn254` with the `alt_bn128` syscalls and, for
/// negating proof_a, arkworks (each body is the code upstream used).
pub struct SolanaBn254;

impl zkcash_core::groth16::Bn254 for SolanaBn254 {
    fn g1_mul(point: &[u8; 64], scalar: &[u8; 32]) -> Option<[u8; 64]> {
        alt_bn128_multiplication(&[&point[..], &scalar[..]].concat()).ok()?.try_into().ok()
    }

    fn g1_add(a: &[u8; 64], b: &[u8; 64]) -> Option<[u8; 64]> {
        alt_bn128_addition(&[&a[..], &b[..]].concat()).ok()?.try_into().ok()
    }

    fn pairing(input: &[u8; 768]) -> Option<[u8; 32]> {
        alt_bn128_pairing(input.as_slice()).ok()?.try_into().ok()
    }

    fn negate_g1(proof_a: &[u8; 64]) -> Option<[u8; 64]> {
        // First deserialize PROOF_A into a G1 point
        let g1_point = match G1::deserialize_with_mode(
            &*[&change_endianness(&proof_a[0..64]), &[0u8][..]].concat(),
            Compress::No,
            Validate::Yes,
        ) {
            Ok(point) => point,
            Err(_) => return None,
        };

        let mut proof_a_neg = [0u8; 65];
        if g1_point
            .neg()
            .x
            .serialize_with_mode(&mut proof_a_neg[..32], Compress::No)
            .is_err() {
            return None;
        }
        if g1_point
            .neg()
            .y
            .serialize_with_mode(&mut proof_a_neg[32..], Compress::No)
            .is_err() {
            return None;
        }

        change_endianness(&proof_a_neg[..64]).try_into().ok()
    }
}

/**
 * Calculate ExtData hash with encrypted outputs included
 * This matches the client-side calculation for hash verification
 * 
 * This is for SOL mint address only
 */
pub fn calculate_complete_ext_data_hash(
    recipient: Pubkey,
    ext_amount: i64,
    encrypted_output1: &[u8],
    encrypted_output2: &[u8],
    fee: u64,
    fee_recipient: Pubkey,
    mint_address: Pubkey,
) -> Result<[u8; 32]> {
    zkcash_core::ext_data::calculate_complete_ext_data_hash::<SolanaSha256>(
        recipient.to_bytes(),
        ext_amount,
        encrypted_output1,
        encrypted_output2,
        fee,
        fee_recipient.to_bytes(),
        mint_address.to_bytes(),
    )
    // Upstream's Borsh `serialize(..)?` fails only for an encrypted output
    // longer than u32::MAX bytes, with a Borsh I/O error.
    .ok_or_else(|| Error::from(ProgramError::BorshIoError("Overflow".to_string())))
}

/// Implements the core crate's `Sha256` with `solana_program::hash::hash`
/// (the `sol_sha256` syscall on-chain).
pub struct SolanaSha256;

impl zkcash_core::ext_data::Sha256 for SolanaSha256 {
    fn hash(data: &[u8]) -> [u8; 32] {
        hash(data).to_bytes()
    }
}

pub fn change_endianness(bytes: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for b in bytes.chunks(32) {
        for byte in b.iter().rev() {
            vec.push(*byte);
        }
    }
    vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_fee_deposit_exact_minimum() {
        // Test deposit with exact minimum fee
        // 1000 * 25 / 10000 = 2.5 -> 2 (rounded down)
        // minimum = 2 * 95% = 1.9 -> 1 (rounded down)
        let result = validate_fee(
            1000,  // ext_amount (deposit)
            1,     // provided_fee (exact minimum)
            0,     // deposit_fee_rate (0% - free deposits)
            25,    // withdrawal_fee_rate (0.25%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_deposit_above_minimum() {
        // Test deposit with fee above minimum
        let result = validate_fee(
            1000,  // ext_amount (deposit)
            10,    // provided_fee (well above minimum)
            0,     // deposit_fee_rate (0% - free deposits)
            25,    // withdrawal_fee_rate (0.25%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_deposit_below_minimum() {
        // Test that deposits with 0% fee rate accept any fee >= 0
        // Since deposits are free, any fee should be acceptable
        // 10000 * 0 / 10000 = 0 (expected fee)
        // minimum = 0 * 95% = 0 (minimum acceptable fee)
        let result = validate_fee(
            10000, // ext_amount (deposit)
            0,     // provided_fee (even 0 is acceptable for free deposits)
            0,     // deposit_fee_rate (0% - free deposits)
            25,    // withdrawal_fee_rate (0.25%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok()); // Should pass since deposits are free
    }

    #[test]
    fn test_validate_fee_withdrawal_zero_rate() {
        // Test withdrawal with 0% fee rate
        let result = validate_fee(
            -1000, // ext_amount (withdrawal)
            5,     // provided_fee (any amount is fine since expected is 0)
            25,    // deposit_fee_rate
            0,     // withdrawal_fee_rate (0%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_withdrawal_with_rate() {
        // Test withdrawal with non-zero fee rate
        // 1000 * 50 / 10000 = 5
        // minimum = 5 * 95% = 4.75 -> 4 (rounded down)
        let result = validate_fee(
            -1000, // ext_amount (withdrawal)
            4,     // provided_fee (exact minimum)
            25,    // deposit_fee_rate
            50,    // withdrawal_fee_rate (0.5%)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_withdrawal_below_minimum() {
        // Test withdrawal with fee below minimum
        // 1000 * 100 / 10000 = 10
        // minimum = 10 * 95% = 9.5 -> 9 (rounded down)
        let result = validate_fee(
            -1000, // ext_amount (withdrawal)
            8,     // provided_fee (below minimum of 9)
            25,    // deposit_fee_rate
            100,   // withdrawal_fee_rate (1%)
            500,   // error_rate (5%)
        );
        assert!(result.is_err());
        // In anchor, the error is wrapped, so we need to check the error differently
        match result {
            Err(e) => {
                // Check that it contains our error code
                assert!(e.to_string().contains("InvalidFeeAmount") || format!("{:?}", e).contains("InvalidFeeAmount"));
            },
            Ok(_) => panic!("Expected error but got Ok"),
        }
    }

    #[test]
    fn test_validate_fee_zero_amount() {
        // Test with zero ext_amount (should always pass)
        let result = validate_fee(
            0,     // ext_amount (neither deposit nor withdrawal)
            100,   // provided_fee
            25,    // deposit_fee_rate
            50,    // withdrawal_fee_rate
            500,   // error_rate
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_small_deposit_zero_expected() {
        // Test very small deposit that results in 0 expected fee
        // 1 * 25 / 10000 = 0.0025 -> 0 (rounded down)
        let result = validate_fee(
            1,     // ext_amount (very small deposit)
            0,     // provided_fee (0 is acceptable when expected is 0)
            25,    // deposit_fee_rate (0.25%)
            0,     // withdrawal_fee_rate
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_high_fee_error_margin() {
        // Test with high fee error margin (50%)
        // 1000 * 25 / 10000 = 2.5 -> 2
        // minimum = 2 * 50% = 1
        let result = validate_fee(
            1000,  // ext_amount (deposit)
            1,     // provided_fee (minimum with 50% fee error margin)
            25,    // deposit_fee_rate (0.25%)
            0,     // withdrawal_fee_rate
            5000,  // fee_error_margin (50%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_overflow_protection() {
        // Test that we don't overflow with large amounts
        // Use a large but safe value that won't cause overflow during multiplication
        let result = validate_fee(
            1_000_000_000, // ext_amount (1 billion, large but safe)
            1000000,       // provided_fee
            1,             // deposit_fee_rate (small rate to avoid overflow)
            0,             // withdrawal_fee_rate
            500,           // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_edge_case_min_withdrawal() {
        // Test edge case with minimum negative value (but not i64::MIN)
        let result = validate_fee(
            -1,    // ext_amount (smallest withdrawal)
            0,     // provided_fee
            25,    // deposit_fee_rate
            0,     // withdrawal_fee_rate (0%, so any fee is fine)
            500,   // error_rate (5%)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fee_arithmetic_overflow_detection() {
        // Test that arithmetic overflow is properly detected and handled
        // Using maximum values that would cause overflow in the multiplication
        let result = validate_fee(
            i64::MAX,  // ext_amount (maximum positive value)
            0,         // provided_fee
            10000,     // deposit_fee_rate (100% - maximum rate)
            0,         // withdrawal_fee_rate
            0,         // fee_error_margin (0% to test exact calculation)
        );
        // This should return an error (either arithmetic overflow or invalid fee amount)
        assert!(result.is_err());
        // We don't need to check the specific error type since overflow protection
        // may result in different error conditions depending on implementation
    }
}