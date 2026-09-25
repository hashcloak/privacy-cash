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