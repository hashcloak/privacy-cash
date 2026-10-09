//! Test vectors for the Lean model's hand-written parts.
//!
//! Each `print_*` generator runs the program's real arkworks code on fixed
//! inputs and prints them as Lean, between GENERATED markers in a file under
//! `formal-verification/core-model/Tests/`, whose `#guard`s check that the
//! Lean model gives the same answers:
//! - `print_negate_g1_vectors`: `SolanaBn254::negate_g1` (`Bn254Vectors.lean`);
//! - `print_field_vectors`: `ArkFr` (`FieldVectors.lean`);
//! - `print_account_spaces`: the `space` of each `init` account
//!   (`AccountSpaces.lean`).
//! `formal-verification/core-model/scripts/check_vectors.sh` regenerates the
//! files and fails if they changed.
//!
//! `zero_bytes_are_empty_subtree_roots` (a normal test) checks the model's
//! `ZeroBytesConsistent` hypothesis on the program's real Poseidon.

use ark_ff::PrimeField as _;
use num_bigint::BigUint;
use light_hasher::Poseidon;
use zkcash::merkle_tree::LightHasher;
use zkcash::utils::{ArkFr, SolanaBn254, VERIFYING_KEY};
use zkcash::{GlobalConfig, MerkleTreeAccount, NullifierAccount, TreeTokenAccount};
use zkcash_core::field::PrimeField;
use zkcash_core::groth16::Bn254;
use zkcash_core::merkle_tree::{Hasher, ZERO_BYTES_LEN};

/// Deterministic xorshift, so the vectors are the same on every run.
struct Xorshift(u64);
impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.next() as u8;
        }
        out
    }
}

/// A big-endian G1 encoding from two big-endian 32-byte coordinates.
fn point(x: [u8; 32], y: [u8; 32]) -> [u8; 64] {
    let mut p = [0u8; 64];
    p[..32].copy_from_slice(&x);
    p[32..].copy_from_slice(&y);
    p
}

fn be_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// BN254 base field modulus q, big-endian.
const Q: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// `x + k` for a big-endian `x` whose last byte does not overflow.
fn add_small(mut x: [u8; 32], k: u8) -> [u8; 32] {
    x[31] = x[31].checked_add(k).expect("no carry");
    x
}

fn inputs() -> Vec<(&'static str, [u8; 64])> {
    let g = point(be_u64(1), be_u64(2));
    let mut v: Vec<(&'static str, [u8; 64])> = vec![("generator", g)];
    v.push(("vk alpha", VERIFYING_KEY.vk_alpha_g1));
    for ic in VERIFYING_KEY.vk_ic {
        v.push(("vk ic", *ic));
    }
    // Multiples of the generator, through the multiplication syscall.
    let mut rng = Xorshift(0x5eed_cafe_f00d_d00d);
    for _ in 0..8 {
        let k: [u8; 32] = rng.bytes();
        if let Some(p) = SolanaBn254::g1_mul(&g, &k) {
            v.push(("k * generator", p));
        }
    }
    // Flags live in the top bits of y's most significant byte (byte 32 big-endian).
    let mut inf = [0u8; 64];
    inf[32] = 0x40;
    v.push(("infinity flag", inf));
    let mut inf_x = point(be_u64(5), [0u8; 32]);
    inf_x[32] = 0x40;
    v.push(("infinity flag, nonzero x", inf_x));
    let mut both = g;
    both[32] |= 0xc0;
    v.push(("both flags", both));
    let mut neg_flag = g;
    neg_flag[32] |= 0x80;
    v.push(("y-negative flag on generator", neg_flag));
    v.push(("all zero", [0u8; 64]));
    v.push(("x = q", point(Q, be_u64(2))));
    let mut q_minus_1 = Q;
    q_minus_1[31] -= 1;
    v.push(("y = q - 1 (not on curve)", point(be_u64(1), q_minus_1)));
    v.push(("y = q", point(be_u64(1), Q)));
    v.push(("(1, 3), not on curve", point(be_u64(1), be_u64(3))));
    // Non-canonical encodings of the generator: a coordinate plus q.
    v.push(("generator with x + q", point(add_small(Q, 1), be_u64(2))));
    v.push(("generator with y + q", point(be_u64(1), add_small(Q, 2))));
    // Range checks run before the infinity check, so these must be rejected.
    let mut inf_y_q = point([0u8; 32], Q);
    inf_y_q[32] |= 0x40;
    v.push(("infinity flag, y = q", inf_y_q));
    let mut inf_x_q = point(Q, [0u8; 32]);
    inf_x_q[32] |= 0x40;
    v.push(("infinity flag, x = q", inf_x_q));
    for _ in 0..8 {
        v.push(("random bytes", rng.bytes()));
    }
    v
}

fn lean_bytes(b: &[u8]) -> String {
    let s: Vec<String> = b.iter().map(|x| x.to_string()).collect();
    format!("[{}]", s.join(", "))
}

#[test]
#[ignore = "generator: run with --ignored --nocapture"]
fn print_negate_g1_vectors() {
    println!("-- BEGIN GENERATED");
    println!("/-- (description, input, `SolanaBn254::negate_g1(input)`) -/");
    println!("def negateG1Vectors : List (String × List Nat × Option (List Nat)) := [");
    let all = inputs();
    for (i, (name, input)) in all.iter().enumerate() {
        let out = match SolanaBn254::negate_g1(input) {
            Some(o) => format!("some {}", lean_bytes(&o)),
            None => "none".to_string(),
        };
        let sep = if i + 1 == all.len() { "" } else { "," };
        println!("  (\"{}\", {},\n    {}){}", name, lean_bytes(input), out, sep);
    }
    println!("]");
    println!("-- END GENERATED");
}

/// BN254 scalar field modulus r.
fn modulus_r() -> BigUint {
    ark_bn254::Fr::MODULUS.into()
}

/// The canonical value in `0..r` of a field element, in decimal.
fn fr_value(a: ArkFr) -> String {
    let v: BigUint = a.0.into_bigint().into();
    v.to_string()
}

/// `n` as 32 big-endian bytes (`n < 2^256`).
fn be32(n: &BigUint) -> [u8; 32] {
    let b = n.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

#[test]
#[ignore = "generator: run with --ignored --nocapture"]
fn print_field_vectors() {
    let r = modulus_r();
    let one = BigUint::from(1u8);
    let two_256 = BigUint::from(1u8) << 256;
    let mut rng = Xorshift(0xf1e1_d5ca_1a12_0001);

    // u64 inputs.
    let mut u64s = vec![0u64, 1, 2, u64::MAX, u64::MAX - 1];
    for _ in 0..5 {
        u64s.push(rng.next());
    }

    // 32-byte inputs, each read both big- and little-endian.
    let mut bytes: Vec<[u8; 32]> = [
        BigUint::from(0u8),
        one.clone(),
        &r - &one,
        r.clone(),
        &r + &one,
        &r * 2u8,
        &r * 5u8,
        &two_256 - &one,
        BigUint::from(1u8) << 255,
        BigUint::from(u64::MAX),
    ]
    .iter()
    .map(be32)
    .collect();
    for _ in 0..8 {
        bytes.push(rng.bytes());
    }

    // Field elements for the binary operations, given by their canonical values.
    let mut elems: Vec<BigUint> = vec![
        BigUint::from(0u8),
        one.clone(),
        BigUint::from(2u8),
        &r - &one,
        &r - BigUint::from(2u8),
        (&r - &one) / 2u8,
        (&r + &one) / 2u8,
    ];
    for _ in 0..5 {
        let b: [u8; 32] = rng.bytes();
        elems.push(BigUint::from_bytes_be(&b) % &r);
    }
    let fr = |n: &BigUint| ArkFr::from_be_bytes_mod_order(&be32(n));

    println!("-- BEGIN GENERATED");
    println!("/-- (x, `ArkFr::from_u64(x)`) -/");
    println!("def fromU64Vectors : List (Nat × Nat) := [");
    for (i, x) in u64s.iter().enumerate() {
        let sep = if i + 1 == u64s.len() { "" } else { "," };
        println!("  ({}, {}){}", x, fr_value(ArkFr::from_u64(*x)), sep);
    }
    println!("]");
    println!();
    println!("/-- (bytes, `from_be_bytes_mod_order(bytes)`, `from_le_bytes_mod_order(bytes)`) -/");
    println!("def fromBytesVectors : List (List Nat × Nat × Nat) := [");
    for (i, b) in bytes.iter().enumerate() {
        let sep = if i + 1 == bytes.len() { "" } else { "," };
        println!(
            "  ({}, {}, {}){}",
            lean_bytes(b),
            fr_value(ArkFr::from_be_bytes_mod_order(b)),
            fr_value(ArkFr::from_le_bytes_mod_order(b)),
            sep
        );
    }
    println!("]");
    println!();
    println!("/-- (a, b, `add(a, b)`, `sub(a, b)`, `neg(a)`, `le(a, b)`, `eq(a, b)`) -/");
    println!("def opVectors : List (Nat × Nat × Nat × Nat × Nat × Bool × Bool) := [");
    let n = elems.len() * elems.len();
    let mut k = 0;
    for a in &elems {
        for b in &elems {
            k += 1;
            let sep = if k == n { "" } else { "," };
            let (fa, fb) = (fr(a), fr(b));
            println!(
                "  ({}, {}, {}, {}, {}, {}, {}){}",
                a,
                b,
                fr_value(ArkFr::add(fa, fb)),
                fr_value(ArkFr::sub(fa, fb)),
                fr_value(ArkFr::neg(fa)),
                ArkFr::le(fa, fb),
                ArkFr::eq(fa, fb),
                sep
            );
        }
    }
    println!("]");
    println!("-- END GENERATED");
}

/// The model's `ZeroBytesConsistent`: entry `i + 1` of the program's
/// `zero_bytes` is the Poseidon hash of two copies of entry `i`, so each entry
/// is the root of an empty subtree one level higher.
#[test]
fn zero_bytes_are_empty_subtree_roots() {
    let z = <LightHasher<Poseidon> as Hasher>::zero_bytes();
    for i in 0..ZERO_BYTES_LEN - 1 {
        assert_eq!(
            <LightHasher<Poseidon> as Hasher>::hash_pair(&z[i], &z[i]),
            z[i + 1],
            "zero_bytes[{}] is not hash(zero_bytes[{}], zero_bytes[{}])",
            i + 1,
            i,
            i
        );
    }
}

#[test]
#[ignore = "generator: run with --ignored --nocapture"]
fn print_account_spaces() {
    // `space = 8 + std::mem::size_of::<T>()` in lib.rs (8 = Anchor discriminator).
    let spaces = [
        ("MerkleTreeAccount", 8 + std::mem::size_of::<MerkleTreeAccount>()),
        ("TreeTokenAccount", 8 + std::mem::size_of::<TreeTokenAccount>()),
        ("GlobalConfig", 8 + std::mem::size_of::<GlobalConfig>()),
        ("NullifierAccount", 8 + std::mem::size_of::<NullifierAccount>()),
    ];
    println!("-- BEGIN GENERATED");
    println!("/-- (account type, `8 + size_of::<T>()`) -/");
    println!("def accountSpaces : List (String × Nat) := [");
    for (i, (name, space)) in spaces.iter().enumerate() {
        let sep = if i + 1 == spaces.len() { "" } else { "," };
        println!("  (\"{}\", {}){}", name, space, sep);
    }
    println!("]");
    println!("-- END GENERATED");
}
