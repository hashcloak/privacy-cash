use alloc::{vec, vec::Vec};

use crate::error::{ErrorCode, Result};

pub const MERKLE_TREE_HEIGHT: usize = 26;
/// Number of roots kept in  `MerkleTreeAccount::root_history`.
pub const ROOT_HISTORY_CAPACITY: usize = 100;

/// Byte-for-byte identical to the program's `#[account(zero_copy)] MerkleTreeAccount`.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "bytemuck", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct MerkleTreeAccount {
    pub authority: [u8; 32],
    pub next_index: u64,
    pub subtrees: [[u8; 32]; MERKLE_TREE_HEIGHT],
    pub root: [u8; 32],
    pub root_history: [[u8; 32]; ROOT_HISTORY_CAPACITY],
    pub root_index: u64,
    pub max_deposit_amount: u64,
    pub height: u8,
    pub root_history_size: u8,
    pub bump: u8,
    pub _padding: [u8; 5],
}

pub fn is_known_root(tree_account: &MerkleTreeAccount,
root: [u8; 32]) -> bool {
    if root == [0u8; 32] {
        return false;
    }

    let root_history_size = tree_account.root_history_size as usize;
    let current_root_index = tree_account.root_index as usize;
    let mut i = current_root_index;

    loop {
        if root == tree_account.root_history[i] {
            return true;
        }

        if i == 0 {
            i = root_history_size - 1;
        } else {
            i -= 1;
        }

        if i == current_root_index {
            break;
        }
    }

    false
}

/// Number of precomputed empty-subtree hashes (light_hasher's `MAX_HEIGHT + 1`).
pub const ZERO_BYTES_LEN: usize = 41;

/// The hash function of the tree. The program implements it with
/// `light_hasher::Poseidon` (the `sol_poseidon` syscall on-chain); the Lean
/// model treats it as an abstract function.
pub trait Hasher {
    /// Hash of two 32-byte nodes. Panics if the underlying hasher fails,
    /// like the `.unwrap()` in the original code.
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
    /// `zero_bytes()[i]` is the root of an empty subtree of height `i`.
    fn zero_bytes() -> [[u8; 32]; ZERO_BYTES_LEN];
}

/// Mirrors `MerkleTree::initialize`.
pub fn initialize<H: Hasher>(tree_account: &mut MerkleTreeAccount) -> Result<()> {
    let height = tree_account.height as usize;

    // Initialize empty subtrees
    let zero_bytes = H::zero_bytes();
    for i in 0..height {
        tree_account.subtrees[i] = zero_bytes[i];
    }

    // Set initial root
    let initial_root = H::zero_bytes()[height];
    tree_account.root = initial_root;
    tree_account.root_history[0] = initial_root;

    Ok(())
}

/// Mirrors `MerkleTree::append`.
pub fn append<H: Hasher>(
    leaf: [u8; 32],
    tree_account: &mut MerkleTreeAccount,
) -> Result<Vec<[u8; 32]>> {
    let height = tree_account.height as usize;
    let root_history_size = tree_account.root_history_size as usize;

    // Check if tree is full before appending
    // Maximum capacity is 2^height leaves
    let max_capacity = 1u64 << height; // 2^height
    if !(tree_account.next_index < max_capacity) {
        return Err(ErrorCode::MerkleTreeFull);
    }

    let mut current_index = tree_account.next_index as usize;
    let mut current_level_hash = leaf;
    let mut left;
    let mut right;
    let mut proof: Vec<[u8; 32]> = vec![[0u8; 32]; height];

    for i in 0..height {
        let subtree = &mut tree_account.subtrees[i];
        let zero_byte = H::zero_bytes()[i];

        if current_index % 2 == 0 {
            left = current_level_hash;
            right = zero_byte;
            *subtree = current_level_hash;
            proof[i] = right;
        } else {
            left = *subtree;
            right = current_level_hash;
            proof[i] = left;
        }
        current_level_hash = H::hash_pair(&left, &right);
        current_index /= 2;
    }

    tree_account.root = current_level_hash;
    tree_account.next_index = tree_account.next_index
        .checked_add(1)
        .ok_or(ErrorCode::ArithmeticOverflow)?;

    let new_root_index = (tree_account.root_index as usize)
        .checked_add(1)
        .ok_or(ErrorCode::ArithmeticOverflow)? % root_history_size;
    tree_account.root_index = new_root_index as u64;
    tree_account.root_history[new_root_index] = current_level_hash;

    Ok(proof)
}
