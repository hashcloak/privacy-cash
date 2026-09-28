use super::outcome;
use proptest::prelude::*;

mod upstream {
    use anchor_lang::prelude::*;
    use zkcash::ErrorCode;

    // Verbatim from upstream `utils::validate_fee` (utils.rs:148-212).
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
            
            require!(
                provided_fee >= min_acceptable_fee,
                ErrorCode::InvalidFeeAmount
            );
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
            
            require!(
                provided_fee >= min_acceptable_fee,
                ErrorCode::InvalidFeeAmount
            );
        }
        // For ext_amount == 0, no fee validation needed
        
        Ok(())
    }
}

/// Amounts biased towards the boundaries where behavior changes.
fn ext_amount() -> impl Strategy<Value = i64> {
    prop_oneof![
        prop::sample::select(vec![i64::MIN, i64::MIN + 1, -10_000, -1, 0, 1, 10_000, i64::MAX]),
        -1_000_000_000_000i64..1_000_000_000_000,
        any::<i64>(),
    ]
}

/// Rates mostly in the valid 0..=10000 basis-point range, sometimes above it
/// (which makes `10000 - fee_error_margin` underflow).
fn rate() -> impl Strategy<Value = u16> {
    prop_oneof![
        prop::sample::select(vec![0u16, 1, 25, 500, 9_999, 10_000, 10_001, u16::MAX]),
        0u16..=10_000,
        any::<u16>(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn validate_fee_matches_upstream(
        ext_amount in ext_amount(),
        fee in prop_oneof![0u64..1_000_000, any::<u64>()],
        deposit_fee_rate in rate(),
        withdrawal_fee_rate in rate(),
        fee_error_margin in rate(),
    ) {
        let new = outcome(zkcash::utils::validate_fee(
            ext_amount, fee, deposit_fee_rate, withdrawal_fee_rate, fee_error_margin,
        ));
        let old = outcome(upstream::validate_fee(
            ext_amount, fee, deposit_fee_rate, withdrawal_fee_rate, fee_error_margin,
        ));
        prop_assert_eq!(new, old);
    }

    /// Fees right at the acceptance threshold, where an off-by-one would show.
    #[test]
    fn validate_fee_matches_upstream_near_threshold(
        ext_amount in -1_000_000_000_000i64..1_000_000_000_000,
        rates in (0u16..=10_000, 0u16..=10_000, 0u16..=10_000),
        delta in -3i64..=3,
    ) {
        let (deposit_fee_rate, withdrawal_fee_rate, fee_error_margin) = rates;
        let rate = if ext_amount > 0 { deposit_fee_rate } else { withdrawal_fee_rate };
        let expected = (ext_amount.unsigned_abs() as u128 * rate as u128 / 10_000) as u64;
        let min = (expected as u128 * (10_000 - fee_error_margin as u128) / 10_000) as i64;
        let fee = (min + delta).max(0) as u64;
        let new = outcome(zkcash::utils::validate_fee(
            ext_amount, fee, deposit_fee_rate, withdrawal_fee_rate, fee_error_margin,
        ));
        let old = outcome(upstream::validate_fee(
            ext_amount, fee, deposit_fee_rate, withdrawal_fee_rate, fee_error_margin,
        ));
        prop_assert_eq!(new, old);
    }
}
