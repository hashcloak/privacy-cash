use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use proptest::prelude::*;

mod upstream {
    use ark_ff::PrimeField;
    use num_bigint::BigUint;

    // Verbatim from upstream `utils::change_endianness` (utils.rs:313-321).
    pub fn change_endianness(bytes: &[u8]) -> Vec<u8> {
        let mut vec = Vec::new();
        for b in bytes.chunks(32) {
            for byte in b.iter().rev() {
                vec.push(*byte);
            }
        }
        vec
    }

    // Verbatim from upstream `groth16::is_less_than_bn254_field_size_be` (groth16.rs:149-152).
    pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
        let bigint = BigUint::from_bytes_be(bytes);
        bigint < ark_bn254::Fr::MODULUS.into()
    }
}

fn modulus() -> BigUint {
    BigUint::from_bytes_be(&ark_bn254::Fr::MODULUS.to_bytes_be())
}

/// `p + delta` as 32 big-endian bytes (p is far from 0 and 2^256).
fn near_modulus(delta: i32) -> [u8; 32] {
    let p = modulus();
    let x = if delta >= 0 { p + BigUint::from(delta as u32) } else { p - BigUint::from((-delta) as u32) };
    let b = x.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

#[test]
fn modulus_constant_matches_arkworks() {
    assert_eq!(
        zkcash_core::utils::BN254_FR_MODULUS_BE.to_vec(),
        ark_bn254::Fr::MODULUS.to_bytes_be(),
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    /// Any length, including 0 and lengths that are not a multiple of 32.
    #[test]
    fn change_endianness_matches_upstream(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        prop_assert_eq!(
            zkcash::utils::change_endianness(&bytes),
            upstream::change_endianness(&bytes),
        );
    }

    #[test]
    fn is_less_than_field_size_matches_upstream(
        bytes in prop_oneof![
            any::<[u8; 32]>(),
            (-300i32..=300).prop_map(near_modulus),
            // Same leading bytes as p, random tail.
            (any::<[u8; 32]>(), 0usize..32).prop_map(|(mut b, k)| {
                b[..k].copy_from_slice(&near_modulus(0)[..k]);
                b
            }),
        ],
    ) {
        prop_assert_eq!(
            zkcash::groth16::is_less_than_bn254_field_size_be(&bytes),
            upstream::is_less_than_bn254_field_size_be(&bytes),
        );
    }
}
