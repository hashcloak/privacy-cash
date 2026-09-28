use super::outcome;
use anchor_lang::prelude::*;
use proptest::prelude::*;
use zkcash::{admin, GlobalConfig, MerkleTreeAccount, TreeTokenAccount};

/// Bodies of the upstream admin instruction handlers (lib.rs), verbatim except
/// that `ctx.accounts.*`, `ctx.bumps.*` and the feature-gated constants
/// (`ADMIN_PUBKEY`, `ALLOW_ALL_SPL_TOKENS`, `ALLOWED_TOKENS`) are parameters,
/// and `msg!` logging is omitted. `MerkleTree::initialize` is the program's,
/// already checked against upstream in `differential::merkle_tree`.
mod upstream {
    use anchor_lang::prelude::*;
    use light_hasher::Poseidon;
    use zkcash::{merkle_tree::MerkleTree, ErrorCode, GlobalConfig, MerkleTreeAccount, TreeTokenAccount};

    const MERKLE_TREE_HEIGHT: u8 = 26;

    // lib.rs:70-101 (`initialize`)
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        admin_pubkey: Option<Pubkey>,
        authority: Pubkey,
        tree_account: &mut MerkleTreeAccount,
        token_account: &mut TreeTokenAccount,
        global_config: &mut GlobalConfig,
        tree_account_bump: u8,
        tree_token_account_bump: u8,
        global_config_bump: u8,
    ) -> Result<()> {
        if let Some(admin_key) = admin_pubkey {
            require!(authority.eq(&admin_key), ErrorCode::Unauthorized);
        }
        
        tree_account.authority = authority;
        tree_account.next_index = 0;
        tree_account.root_index = 0;
        tree_account.bump = tree_account_bump;
        tree_account.max_deposit_amount = 1_000_000_000_000; // 1000 SOL default limit
        tree_account.height = MERKLE_TREE_HEIGHT; // Hardcoded height
        tree_account.root_history_size = 100; // Hardcoded root history size

        MerkleTree::initialize::<Poseidon>(tree_account)?;
        
        token_account.authority = authority;
        token_account.bump = tree_token_account_bump;
        
        // Initialize global config
        global_config.authority = authority;
        global_config.deposit_fee_rate = 0; // 0% - Free deposits
        global_config.withdrawal_fee_rate = 25; // 0.25% (25 basis points)
        global_config.fee_error_margin = 500; // 5% (500 basis points)
        global_config.bump = global_config_bump;
        
        Ok(())
    }

    // lib.rs:119-150 (`update_global_config`)
    pub fn update_global_config(
        global_config: &mut GlobalConfig,
        deposit_fee_rate: Option<u16>,
        withdrawal_fee_rate: Option<u16>,
        fee_error_margin: Option<u16>
    ) -> Result<()> {
        if let Some(deposit_rate) = deposit_fee_rate {
            require!(deposit_rate <= 10000, ErrorCode::InvalidFeeRate);
            global_config.deposit_fee_rate = deposit_rate;
        }
        
        if let Some(withdrawal_rate) = withdrawal_fee_rate {
            require!(withdrawal_rate <= 10000, ErrorCode::InvalidFeeRate);
            global_config.withdrawal_fee_rate = withdrawal_rate;
        }
        
        if let Some(fee_error_margin_val) = fee_error_margin {
            require!(fee_error_margin_val <= 10000, ErrorCode::InvalidFeeRate);
            global_config.fee_error_margin = fee_error_margin_val;
        }
        
        Ok(())
    }

    // lib.rs:153-190 (`initialize_tree_account_for_spl_token`)
    pub fn initialize_tree_account_for_spl_token(
        admin_pubkey: Option<Pubkey>,
        allow_all_spl_tokens: bool,
        allowed_tokens: &[Pubkey],
        authority: Pubkey,
        mint: Pubkey,
        tree_account: &mut MerkleTreeAccount,
        tree_account_bump: u8,
        max_deposit_amount: u64
    ) -> Result<()> {
        if let Some(admin_key) = admin_pubkey {
            require!(authority.eq(&admin_key), ErrorCode::Unauthorized);
        }
        
        // Validate that the mint is in the allowed tokens list
        require!(
            allow_all_spl_tokens || allowed_tokens.contains(&mint),
            ErrorCode::InvalidMintAddress
        );
        
        tree_account.authority = authority;
        tree_account.next_index = 0;
        tree_account.root_index = 0;
        tree_account.bump = tree_account_bump;
        tree_account.max_deposit_amount = max_deposit_amount;
        tree_account.height = MERKLE_TREE_HEIGHT;
        tree_account.root_history_size = 100;

        MerkleTree::initialize::<Poseidon>(tree_account)?;
        
        Ok(())
    }

    // lib.rs:107-117 and 193-212 (`update_deposit_limit[_for_spl_token]`)
    pub fn update_deposit_limit(tree_account: &mut MerkleTreeAccount, new_limit: u64) {
        tree_account.max_deposit_amount = new_limit;
    }
}

fn pubkey() -> impl Strategy<Value = Pubkey> {
    any::<[u8; 32]>().prop_map(Pubkey::new_from_array)
}

/// Arbitrary account contents, so a missed write shows up as a diff. (The
/// account types are built inside each test because proptest needs `Debug`,
/// which they do not implement.)
fn tree_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), std::mem::size_of::<MerkleTreeAccount>())
}

fn tree_account(bytes: &[u8]) -> MerkleTreeAccount {
    bytemuck::pod_read_unaligned(bytes)
}

fn tree_token_account((authority, bump): ([u8; 32], u8)) -> TreeTokenAccount {
    TreeTokenAccount { authority: Pubkey::new_from_array(authority), bump }
}

fn global_config((authority, deposit_fee_rate, withdrawal_fee_rate, fee_error_margin, bump): ([u8; 32], u16, u16, u16, u8)) -> GlobalConfig {
    GlobalConfig {
        authority: Pubkey::new_from_array(authority),
        deposit_fee_rate, withdrawal_fee_rate, fee_error_margin, bump,
    }
}

/// None, the signer itself, or someone else.
fn admin_for(authority: Pubkey) -> impl Strategy<Value = Option<Pubkey>> {
    prop_oneof![Just(None), Just(Some(authority)), pubkey().prop_map(Some)]
}

/// Rates on both sides of the 10000 basis-point limit.
fn rate() -> impl Strategy<Value = Option<u16>> {
    prop::option::of(prop_oneof![0u16..=10_000, Just(10_000u16), Just(10_001u16), any::<u16>()])
}

fn bytes<T: AnchorSerialize>(x: &T) -> Vec<u8> {
    x.try_to_vec().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn initialize_matches_upstream(
        (authority, admin_pubkey) in pubkey().prop_flat_map(|a| (Just(a), admin_for(a))),
        tree in tree_bytes(),
        token in any::<([u8; 32], u8)>(),
        config in any::<([u8; 32], u16, u16, u16, u8)>(),
        bumps in any::<(u8, u8, u8)>(),
    ) {
        let (mut new_tree, mut new_token, mut new_config) = (tree_account(&tree), tree_token_account(token), global_config(config));
        let (mut old_tree, mut old_token, mut old_config) = (tree_account(&tree), tree_token_account(token), global_config(config));

        let new = outcome(admin::check_admin(&authority, admin_pubkey).and_then(|()| {
            admin::initialize(
                &mut new_tree, &mut new_token, &mut new_config,
                &authority, bumps.0, bumps.1, bumps.2,
            )
        }));
        let old = outcome(upstream::initialize(
            admin_pubkey, authority, &mut old_tree, &mut old_token, &mut old_config,
            bumps.0, bumps.1, bumps.2,
        ));

        prop_assert_eq!(new, old);
        prop_assert_eq!(bytemuck::bytes_of(&new_tree), bytemuck::bytes_of(&old_tree));
        prop_assert_eq!(bytes(&new_token), bytes(&old_token));
        prop_assert_eq!(bytes(&new_config), bytes(&old_config));
    }

    #[test]
    fn initialize_tree_account_for_spl_token_matches_upstream(
        (authority, admin_pubkey) in pubkey().prop_flat_map(|a| (Just(a), admin_for(a))),
        allow_all_spl_tokens in any::<bool>(),
        (mint, allowed_tokens) in (pubkey(), prop::collection::vec(pubkey(), 0..5), any::<bool>())
            .prop_map(|(mint, mut list, include)| {
                if include && !list.is_empty() {
                    let i = mint.to_bytes()[0] as usize % list.len();
                    list[i] = mint;
                }
                (mint, list)
            }),
        tree in tree_bytes(),
        bump in any::<u8>(),
        max_deposit_amount in any::<u64>(),
    ) {
        let (mut new_tree, mut old_tree) = (tree_account(&tree), tree_account(&tree));

        let new = outcome(
            admin::check_admin(&authority, admin_pubkey)
                .and_then(|()| admin::check_allowed_mint(&mint, allow_all_spl_tokens, &allowed_tokens))
                .and_then(|()| admin::initialize_tree_account_for_spl_token(
                    &mut new_tree, &authority, bump, max_deposit_amount,
                )),
        );
        let old = outcome(upstream::initialize_tree_account_for_spl_token(
            admin_pubkey, allow_all_spl_tokens, &allowed_tokens, authority, mint,
            &mut old_tree, bump, max_deposit_amount,
        ));

        prop_assert_eq!(new, old);
        prop_assert_eq!(bytemuck::bytes_of(&new_tree), bytemuck::bytes_of(&old_tree));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    #[test]
    fn update_global_config_matches_upstream(
        config in any::<([u8; 32], u16, u16, u16, u8)>(),
        deposit_fee_rate in rate(),
        withdrawal_fee_rate in rate(),
        fee_error_margin in rate(),
    ) {
        let (mut new_config, mut old_config) = (global_config(config), global_config(config));
        let new = outcome(admin::update_global_config(
            &mut new_config, deposit_fee_rate, withdrawal_fee_rate, fee_error_margin,
        ));
        let old = outcome(upstream::update_global_config(
            &mut old_config, deposit_fee_rate, withdrawal_fee_rate, fee_error_margin,
        ));
        prop_assert_eq!(new, old);
        // On error the transaction reverts, so only a successful update's state matters.
        if new.is_ok() {
            prop_assert_eq!(bytes(&new_config), bytes(&old_config));
        }
    }

    #[test]
    fn update_deposit_limit_matches_upstream(tree in tree_bytes(), new_limit in any::<u64>()) {
        let (mut new_tree, mut old_tree) = (tree_account(&tree), tree_account(&tree));
        admin::update_deposit_limit(&mut new_tree, new_limit);
        upstream::update_deposit_limit(&mut old_tree, new_limit);
        prop_assert_eq!(bytemuck::bytes_of(&new_tree), bytemuck::bytes_of(&old_tree));
    }
}
