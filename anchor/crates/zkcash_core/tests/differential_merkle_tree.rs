//! Differential tests: `zkcash_core` must behave exactly like the upstream
//! program code it replaced, including panicking on the same inputs.
//!
//! Each `upstream::*` function is the upstream function body copied verbatim
//! from privacy-cash `main` (anchor/programs/zkcash/src/merkle_tree.rs) and
//! must never be edited: it is the frozen reference behavior.

use proptest::prelude::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use zkcash_core::merkle_tree::{
    self, MerkleTreeAccount, MERKLE_TREE_HEIGHT, ROOT_HISTORY_CAPACITY,
};

mod upstream {
    use super::MerkleTreeAccount;

    // Verbatim from upstream `MerkleTree::is_known_root` (merkle_tree.rs:79-104).
    pub fn is_known_root(tree_account: &MerkleTreeAccount, root: [u8; 32]) -> bool {
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
}

/// `Some(result)` if `f` returned, `None` if it panicked.
fn outcome<T>(f: impl FnOnce() -> T) -> Option<T> {
    // Expected panics would otherwise print thousands of messages.
    static SILENCE_PANICS: std::sync::Once = std::sync::Once::new();
    SILENCE_PANICS.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    catch_unwind(AssertUnwindSafe(f)).ok()
}

fn tree(root_history: Vec<[u8; 32]>, root_index: u64, root_history_size: u8) -> MerkleTreeAccount {
    MerkleTreeAccount {
        authority: [0; 32],
        next_index: 0,
        subtrees: [[0; 32]; MERKLE_TREE_HEIGHT],
        root: [0; 32],
        root_history: root_history.try_into().unwrap(),
        root_index,
        max_deposit_amount: 0,
        height: MERKLE_TREE_HEIGHT as u8,
        root_history_size,
        bump: 0,
        _padding: [0; 5],
    }
}

/// Roots drawn from a small pool (including the zero root) so that hits,
/// misses and duplicates are all common.
fn root() -> impl Strategy<Value = [u8; 32]> {
    prop_oneof![
        Just([0u8; 32]),
        (1u8..=4).prop_map(|b| [b; 32]),
        any::<[u8; 32]>(),
    ]
}

fn root_history() -> impl Strategy<Value = Vec<[u8; 32]>> {
    prop::collection::vec(root(), ROOT_HISTORY_CAPACITY)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// States the program can actually reach: 1 <= size <= 100, index < size.
    #[test]
    fn is_known_root_matches_upstream_on_valid_states(
        history in root_history(),
        (size, index) in (1u8..=100).prop_flat_map(|s| (Just(s), 0..s as u64)),
        query in root(),
    ) {
        let t = tree(history, index, size);
        prop_assert_eq!(
            outcome(|| merkle_tree::is_known_root(&t, query)),
            outcome(|| upstream::is_known_root(&t, query)),
        );
    }

    /// Invalid states (unreachable on-chain) where upstream panics:
    /// size 0 (underflow in `size - 1`) or index >= 100 (out-of-bounds read).
    /// The core must panic on exactly the same inputs.
    ///
    /// Not covered: 0 < size <= index < 100. There upstream loops forever when
    /// `root` is absent (`i` cycles through 0..size and never returns to index),
    /// so no result can be compared. The Lean proof must assume index < size.
    #[test]
    fn is_known_root_matches_upstream_on_invalid_states(
        history in root_history(),
        (size, index) in prop_oneof![
            (Just(0u8), any::<u64>()),
            (any::<u8>(), (ROOT_HISTORY_CAPACITY as u64)..),
        ],
        query in root(),
    ) {
        let t = tree(history, index, size);
        prop_assert_eq!(
            outcome(|| merkle_tree::is_known_root(&t, query)),
            outcome(|| upstream::is_known_root(&t, query)),
        );
    }
}
