use super::outcome;
use light_hasher::Poseidon;
use proptest::prelude::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use zkcash::{merkle_tree::MerkleTree, MerkleTreeAccount};

mod upstream {
    use anchor_lang::prelude::*;
    use light_hasher::Hasher;
    use zkcash::{ErrorCode, MerkleTreeAccount};

    pub struct MerkleTree;

    // Verbatim from upstream `MerkleTree::initialize` and `MerkleTree::append`
    // (merkle_tree.rs:9-77).
    impl MerkleTree {
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

        pub fn append<H: Hasher>(
            leaf: [u8; 32],
            tree_account: &mut MerkleTreeAccount,
        ) -> Result<Vec<[u8; 32]>> {
            let height = tree_account.height as usize;
            let root_history_size = tree_account.root_history_size as usize;
            
            // Check if tree is full before appending
            // Maximum capacity is 2^height leaves
            let max_capacity = 1u64 << height; // 2^height
            require!(
                tree_account.next_index < max_capacity,
                ErrorCode::MerkleTreeFull
            );

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
                current_level_hash = H::hashv(&[&left, &right]).unwrap();
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
    }
}

/// `None` if `f` panicked, otherwise its outcome with the error code number.
fn run<T>(f: impl FnOnce() -> anchor_lang::Result<T>) -> Option<Result<T, u32>> {
    static SILENCE_PANICS: std::sync::Once = std::sync::Once::new();
    SILENCE_PANICS.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    catch_unwind(AssertUnwindSafe(|| outcome(f()))).ok()
}

fn account(height: u8, root_history_size: u8) -> MerkleTreeAccount {
    let mut a: MerkleTreeAccount = bytemuck::Zeroable::zeroed();
    a.height = height;
    a.root_history_size = root_history_size;
    a
}

/// Mostly valid field elements (top bits cleared), sometimes arbitrary bytes,
/// which can exceed the BN254 modulus and make Poseidon fail.
fn leaf() -> impl Strategy<Value = [u8; 32]> {
    prop_oneof![
        9 => any::<[u8; 32]>().prop_map(|mut l| { l[0] &= 0x1f; l }),
        1 => any::<[u8; 32]>(),
    ]
}

/// Runs `initialize` and then every append on both implementations, checking
/// after each operation that results (value, error code or panic) and the
/// full account bytes are identical.
fn check(height: u8, root_history_size: u8, leaves: Vec<[u8; 32]>) -> Result<(), TestCaseError> {
    let mut new = account(height, root_history_size);
    let mut old = new;
    prop_assert_eq!(
        run(|| MerkleTree::initialize::<Poseidon>(&mut new)),
        run(|| upstream::MerkleTree::initialize::<Poseidon>(&mut old)),
    );
    prop_assert_eq!(bytemuck::bytes_of(&new), bytemuck::bytes_of(&old));
    for leaf in leaves {
        prop_assert_eq!(
            run(|| MerkleTree::append::<Poseidon>(leaf, &mut new)),
            run(|| upstream::MerkleTree::append::<Poseidon>(leaf, &mut old)),
        );
        prop_assert_eq!(bytemuck::bytes_of(&new), bytemuck::bytes_of(&old));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Small trees: fill them up (MerkleTreeFull) and wrap the root history.
    #[test]
    fn small_trees_match_upstream(
        height in 1u8..=6,
        root_history_size in prop_oneof![Just(100u8), 1u8..=100],
        leaves in prop::collection::vec(leaf(), 0..=80),
    ) {
        check(height, root_history_size, leaves)?;
    }

    /// Invalid configurations the program never creates (height 0, heights
    /// beyond the 26 stored subtrees, root_history_size 0 or > 100): both
    /// sides must fail in the same way.
    #[test]
    fn invalid_configurations_match_upstream(
        height in prop_oneof![Just(0u8), 27u8..=45, any::<u8>()],
        root_history_size in prop_oneof![Just(0u8), 101u8..=255],
        leaves in prop::collection::vec(leaf(), 0..=3),
    ) {
        check(height, root_history_size, leaves)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    /// The production configuration: height 26, 100 roots, past the wrap-around.
    #[test]
    fn production_tree_matches_upstream(
        leaves in prop::collection::vec(leaf(), 101..=105),
    ) {
        check(26, 100, leaves)?;
    }
}
