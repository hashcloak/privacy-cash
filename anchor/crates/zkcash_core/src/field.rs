/// Arithmetic in the BN254 scalar field (`ark_bn254::Fr` in the program).
///
/// The program implements this with arkworks; the Lean model treats the field
/// as abstract, so every property the proofs rely on is an explicit assumption.
pub trait PrimeField: Copy {
    /// `x mod p`, like `Fr::from(x)`.
    fn from_u64(x: u64) -> Self;
    /// Big-endian bytes reduced mod p, like `Fr::from_be_bytes_mod_order`.
    fn from_be_bytes_mod_order(bytes: &[u8; 32]) -> Self;
    /// Little-endian bytes reduced mod p, like `Fr::from_le_bytes_mod_order`.
    fn from_le_bytes_mod_order(bytes: &[u8; 32]) -> Self;
    fn add(a: Self, b: Self) -> Self;
    fn sub(a: Self, b: Self) -> Self;
    fn neg(a: Self) -> Self;
    /// `a <= b` on canonical representatives in `0..p`, like arkworks' `Ord`.
    fn le(a: Self, b: Self) -> bool;
    fn eq(a: Self, b: Self) -> bool;
}
