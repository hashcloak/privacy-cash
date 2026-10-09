//! Moved from upstream: the state changes of the admin instructions in lib.rs:
//! `initialize`, `update_deposit_limit`, `update_global_config`,
//! `initialize_tree_account_for_spl_token` and
//! `update_deposit_limit_for_spl_token`.
//!
//! Account validation (PDAs, `init`, `has_one = authority`, signers) stays in
//! Anchor, and logging (`msg!`) stays in the program.

use crate::error::{ErrorCode, Result};
use crate::merkle_tree::{self, Hasher, MerkleTreeAccount};

pub const MERKLE_TREE_HEIGHT: u8 = 26;
pub const ROOT_HISTORY_SIZE: u8 = 100;
/// 1000 SOL, the default limit set by `initialize`.
pub const DEFAULT_MAX_DEPOSIT_AMOUNT: u64 = 1_000_000_000_000;
/// 100% in basis points: the upper bound of every fee rate.
pub const MAX_BASIS_POINTS: u16 = 10000;

/// Mirrors the program's `#[account] TreeTokenAccount` (Pubkey as [u8; 32]).
#[derive(Clone, Copy)]
pub struct TreeTokenAccount {
    pub authority: [u8; 32],
    pub bump: u8,
}

/// Mirrors the program's `#[account] GlobalConfig` (Pubkey as [u8; 32]).
#[derive(Clone, Copy)]
pub struct GlobalConfig {
    pub authority: [u8; 32],
    pub deposit_fee_rate: u16,
    pub withdrawal_fee_rate: u16,
    pub fee_error_margin: u16,
    pub bump: u8,
}

/// `if let Some(admin_key) = ADMIN_PUBKEY { require!(authority == admin_key, Unauthorized) }`
pub fn check_admin(authority: [u8; 32], admin_pubkey: Option<[u8; 32]>) -> Result<()> {
    if let Some(admin_key) = admin_pubkey {
        if !(authority == admin_key) {
            return Err(ErrorCode::Unauthorized);
        }
    }
    Ok(())
}

/// `require!(ALLOW_ALL_SPL_TOKENS || ALLOWED_TOKENS.contains(&mint), InvalidMintAddress)`
pub fn check_allowed_mint(
    mint: [u8; 32],
    allow_all_spl_tokens: bool,
    allowed_tokens: &[[u8; 32]],
) -> Result<()> {
    if allow_all_spl_tokens {
        return Ok(());
    }
    let mut i = 0;
    while i < allowed_tokens.len() {
        if allowed_tokens[i] == mint {
            return Ok(());
        }
        i += 1;
    }
    Err(ErrorCode::InvalidMintAddress)
}

/// The field writes shared by `initialize` and
/// `initialize_tree_account_for_spl_token`, followed by `MerkleTree::initialize`.
fn init_tree<H: Hasher>(
    tree_account: &mut MerkleTreeAccount,
    authority: [u8; 32],
    bump: u8,
    max_deposit_amount: u64,
) -> Result<()> {
    tree_account.authority = authority;
    tree_account.next_index = 0;
    tree_account.root_index = 0;
    tree_account.bump = bump;
    tree_account.max_deposit_amount = max_deposit_amount;
    tree_account.height = MERKLE_TREE_HEIGHT; // Hardcoded height
    tree_account.root_history_size = ROOT_HISTORY_SIZE; // Hardcoded root history size

    merkle_tree::initialize::<H>(tree_account)
}

/// `initialize`, after the admin check (see `check_admin`).
pub fn initialize<H: Hasher>(
    tree_account: &mut MerkleTreeAccount,
    tree_token_account: &mut TreeTokenAccount,
    global_config: &mut GlobalConfig,
    authority: [u8; 32],
    tree_account_bump: u8,
    tree_token_account_bump: u8,
    global_config_bump: u8,
) -> Result<()> {
    init_tree::<H>(tree_account, authority, tree_account_bump, DEFAULT_MAX_DEPOSIT_AMOUNT)?;

    tree_token_account.authority = authority;
    tree_token_account.bump = tree_token_account_bump;

    global_config.authority = authority;
    global_config.deposit_fee_rate = 0; // 0% - Free deposits
    global_config.withdrawal_fee_rate = 25; // 0.25% (25 basis points)
    global_config.fee_error_margin = 500; // 5% (500 basis points)
    global_config.bump = global_config_bump;

    Ok(())
}

/// `initialize_tree_account_for_spl_token`, after the admin and mint checks
/// (see `check_admin` and `is_allowed_mint`).
pub fn initialize_tree_account_for_spl_token<H: Hasher>(
    tree_account: &mut MerkleTreeAccount,
    authority: [u8; 32],
    tree_account_bump: u8,
    max_deposit_amount: u64,
) -> Result<()> {
    init_tree::<H>(tree_account, authority, tree_account_bump, max_deposit_amount)
}

/// `update_deposit_limit` and `update_deposit_limit_for_spl_token`.
pub fn update_deposit_limit(tree_account: &mut MerkleTreeAccount, new_limit: u64) {
    tree_account.max_deposit_amount = new_limit;
}

/// `update_global_config`: each provided rate must be at most 10000 basis points.
pub fn update_global_config(
    global_config: &mut GlobalConfig,
    deposit_fee_rate: Option<u16>,
    withdrawal_fee_rate: Option<u16>,
    fee_error_margin: Option<u16>,
) -> Result<()> {
    if let Some(deposit_rate) = deposit_fee_rate {
        if !(deposit_rate <= MAX_BASIS_POINTS) {
            return Err(ErrorCode::InvalidFeeRate);
        }
        global_config.deposit_fee_rate = deposit_rate;
    }

    if let Some(withdrawal_rate) = withdrawal_fee_rate {
        if !(withdrawal_rate <= MAX_BASIS_POINTS) {
            return Err(ErrorCode::InvalidFeeRate);
        }
        global_config.withdrawal_fee_rate = withdrawal_rate;
    }

    if let Some(fee_error_margin_val) = fee_error_margin {
        if !(fee_error_margin_val <= MAX_BASIS_POINTS) {
            return Err(ErrorCode::InvalidFeeRate);
        }
        global_config.fee_error_margin = fee_error_margin_val;
    }

    Ok(())
}
