use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use proptest::prelude::*;

mod upstream {
    use anchor_lang::prelude::*;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    // Verbatim from upstream `utils::check_public_amount` (utils.rs:92-129).
    pub fn check_public_amount(ext_amount: i64, fee: u64, public_amount_bytes: [u8; 32]) -> bool {
        if ext_amount == i64::MIN {
            msg!("can't use i64::MIN as ext_amount"); 
            return false;
        }

        // Convert to field elements for proper BN254 arithmetic
        let fee_fr = Fr::from(fee);
        let ext_amount_fr = if ext_amount >= 0 {
            Fr::from(ext_amount as u64)
        } else {
            let abs_ext_amount = match ext_amount.checked_neg() {
                Some(val) => val,
                None => return false,
            };
            Fr::from(abs_ext_amount as u64)
        };

        // return false if the deposit amount is barely enough to cover the fee
        if ext_amount >= 0 && ext_amount_fr <= fee_fr {
            return false;
        }

        let result_public_amount = if ext_amount >= 0 {
            // For positive amounts: public_amount = ext_amount - fee
            ext_amount_fr - fee_fr
        } else {
            // For negative amounts: public_amount = -abs(ext_amount) - fee
            // In field arithmetic, this becomes: FIELD_SIZE - (abs(ext_amount) + fee)
            -(ext_amount_fr + fee_fr)
        };

        // Convert provided bytes to field element for comparison
        let provided_amount = Fr::from_be_bytes_mod_order(&public_amount_bytes);
        
        result_public_amount == provided_amount
    }
}

fn to_bytes(x: &BigUint) -> Option<[u8; 32]> {
    let b = x.to_bytes_be();
    (b.len() <= 32).then(|| {
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(&b);
        out
    })
}

/// The public amount a correct client would send, as a canonical big-endian
/// field element, so that `true` results are as common as `false` ones.
fn expected(ext_amount: i64, fee: u64) -> BigUint {
    let abs = Fr::from(ext_amount.unsigned_abs());
    let v = if ext_amount >= 0 { abs - Fr::from(fee) } else { -(abs + Fr::from(fee)) };
    BigUint::from_bytes_be(&v.into_bigint().to_bytes_be())
}

fn ext_amount() -> impl Strategy<Value = i64> {
    prop_oneof![
        prop::sample::select(vec![i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX]),
        -1_000_000i64..1_000_000,
        any::<i64>(),
    ]
}

fn fee() -> impl Strategy<Value = u64> {
    prop_oneof![
        prop::sample::select(vec![0u64, 1, u64::MAX]),
        0u64..1_000_000,
        any::<u64>(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50_000))]

    #[test]
    fn check_public_amount_matches_upstream(
        ext_amount in ext_amount(),
        fee in fee(),
        variant in 0u8..4,
        random in any::<[u8; 32]>(),
        offset in -2i64..=2,
    ) {
        let p = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
        let e = expected(ext_amount, fee);
        let bytes = match variant {
            // The correct value, or off by a small amount.
            0 => to_bytes(&((&e + &p + BigUint::from((offset + 2) as u64) - 2u32) % &p)).unwrap(),
            // The correct value plus p: same field element, non-canonical bytes.
            1 => to_bytes(&(&e + &p)).unwrap_or(random),
            2 => [0xff; 32],
            _ => random,
        };
        prop_assert_eq!(
            zkcash::utils::check_public_amount(ext_amount, fee, bytes),
            upstream::check_public_amount(ext_amount, fee, bytes),
        );
    }
}
