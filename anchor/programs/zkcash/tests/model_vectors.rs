//! Test vectors for the Lean model's hand-written parts.
//!
//! `print_negate_g1_vectors` runs the program's real `SolanaBn254::negate_g1`
//! (arkworks) on fixed inputs and prints them as the Lean file
//! `formal-verification/core-model/PrivacyCash/Tests/Bn254Vectors.lean`, whose
//! `#guard`s check that the Lean `negateG1` gives the same answers.
//! `formal-verification/core-model/scripts/check_vectors.sh` regenerates the
//! file and fails if it changed.

use zkcash::utils::{SolanaBn254, VERIFYING_KEY};
use zkcash_core::groth16::Bn254;

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
