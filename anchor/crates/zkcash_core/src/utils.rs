use crate::error::{ErrorCode, Result};
use crate::field::PrimeField;

/// Mirrors `utils::validate_fee`.
pub fn validate_fee(
    ext_amount: i64,
    provided_fee: u64,
    deposit_fee_rate: u16,
    withdrawal_fee_rate: u16,
    fee_error_margin: u16,
) -> Result<()> {
    if ext_amount > 0 {
        // Deposit: check fee against deposit rate
        let expected_fee = (ext_amount as u128)
            .checked_mul(deposit_fee_rate as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(10000)
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        // Calculate minimum acceptable fee: expected_fee * (1 - fee_error_margin/10000)
        let min_acceptable_fee = if expected_fee > 0 {
            let error_multiplier = 10000u128.checked_sub(fee_error_margin as u128)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            (expected_fee as u128)
                .checked_mul(error_multiplier)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_div(10000)
                .ok_or(ErrorCode::ArithmeticOverflow)? as u64
        } else {
            0 // If expected fee is 0, minimum is also 0
        };
        
        if !(provided_fee >= min_acceptable_fee) {
            return Err(ErrorCode::InvalidFeeAmount);
        }
    } else if ext_amount < 0 {
        // Withdrawal: check fee against withdrawal rate
        let withdrawal_amount = ext_amount.checked_neg()
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        let expected_fee = (withdrawal_amount as u128)
            .checked_mul(withdrawal_fee_rate as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(10000)
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        // Calculate minimum acceptable fee: expected_fee * (1 - fee_error_margin/10000)
        let min_acceptable_fee = if expected_fee > 0 {
            let error_multiplier = 10000u128.checked_sub(fee_error_margin as u128)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            (expected_fee as u128)
                .checked_mul(error_multiplier)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_div(10000)
                .ok_or(ErrorCode::ArithmeticOverflow)? as u64
        } else {
            0 // If expected fee is 0, minimum is also 0
        };
        
        if !(provided_fee >= min_acceptable_fee) {
            return Err(ErrorCode::InvalidFeeAmount);
        }
    }
    // For ext_amount == 0, no fee validation needed
    
    Ok(())
}

/// Mirrors `utils::check_public_amount`. The upstream `msg!` log for
/// `i64::MIN` stays in the program wrapper (logging is a syscall).
pub fn check_public_amount<F: PrimeField>(
    ext_amount: i64,
    fee: u64,
    public_amount_bytes: [u8; 32],
) -> bool {
    if ext_amount == i64::MIN {
        return false;
    }

    // Convert to field elements for proper BN254 arithmetic
    let fee_fr = F::from_u64(fee);
    let ext_amount_fr = if ext_amount >= 0 {
        F::from_u64(ext_amount as u64)
    } else {
        let abs_ext_amount = match ext_amount.checked_neg() {
            Some(val) => val,
            None => return false,
        };
        F::from_u64(abs_ext_amount as u64)
    };

    // return false if the deposit amount is barely enough to cover the fee
    if ext_amount >= 0 && F::le(ext_amount_fr, fee_fr) {
        return false;
    }

    let result_public_amount = if ext_amount >= 0 {
        // For positive amounts: public_amount = ext_amount - fee
        F::sub(ext_amount_fr, fee_fr)
    } else {
        // For negative amounts: public_amount = -abs(ext_amount) - fee
        // In field arithmetic, this becomes: FIELD_SIZE - (abs(ext_amount) + fee)
        F::neg(F::add(ext_amount_fr, fee_fr))
    };

    // Convert provided bytes to field element for comparison
    let provided_amount = F::from_be_bytes_mod_order(&public_amount_bytes);
    
    F::eq(result_public_amount, provided_amount)
}
