// Adapted from https://github.com/Lightprotocol/light-protocol/blob/b2a236409bb7797615d217fbf4fff498c852d25e/sparse-merkle-tree/src/merkle_tree.rs
use core::marker::PhantomData;
use light_hasher::Hasher;
use zkcash_core::merkle_tree::ZERO_BYTES_LEN;
use crate::{MerkleTreeAccount, ErrorCode};
use anchor_lang::prelude::*;

pub struct MerkleTree;

/// Implements the core crate's `Hasher` with a `light_hasher` hasher
/// (Poseidon: the `sol_poseidon` syscall on-chain).
pub struct LightHasher<H>(PhantomData<H>);

impl<H: Hasher> zkcash_core::merkle_tree::Hasher for LightHasher<H> {
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        H::hashv(&[left.as_slice(), right.as_slice()]).unwrap()
    }

    fn zero_bytes() -> [[u8; 32]; ZERO_BYTES_LEN] {
        H::zero_bytes()
    }
}

impl MerkleTree {
    pub fn initialize<H: Hasher>(tree_account: &mut MerkleTreeAccount) -> Result<()> {
        zkcash_core::merkle_tree::initialize::<LightHasher<H>>(tree_account.as_core_mut())
            .map_err(|e| ErrorCode::from(e).into())
    }

    pub fn append<H: Hasher>(
        leaf: [u8; 32],
        tree_account: &mut MerkleTreeAccount,
    ) -> Result<Vec<[u8; 32]>> {
        zkcash_core::merkle_tree::append::<LightHasher<H>>(leaf, tree_account.as_core_mut())
            .map_err(|e| ErrorCode::from(e).into())
    }

    pub fn is_known_root(tree_account: &MerkleTreeAccount, root: [u8; 32]) -> bool {
        zkcash_core::merkle_tree::is_known_root(tree_account.as_core(), root)
    }
}
