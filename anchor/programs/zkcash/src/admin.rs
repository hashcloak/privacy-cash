//! Adapters between the program's Anchor account types and the extracted
//! `zkcash_core::admin` functions. The instruction handlers in lib.rs call
//! these; the differential tests call them too.

use anchor_lang::prelude::*;
use light_hasher::Poseidon;
use zkcash_core::admin as core;

use crate::merkle_tree::LightHasher;
use crate::{ErrorCode, GlobalConfig, MerkleTreeAccount, TreeTokenAccount};

fn core_err(e: zkcash_core::error::ErrorCode) -> Error {
    ErrorCode::from(e).into()
}

impl TreeTokenAccount {
    fn to_core(&self) -> core::TreeTokenAccount {
        core::TreeTokenAccount { authority: self.authority.to_bytes(), bump: self.bump }
    }

    fn set_from_core(&mut self, c: &core::TreeTokenAccount) {
        self.authority = Pubkey::new_from_array(c.authority);
        self.bump = c.bump;
    }
}

impl GlobalConfig {
    pub fn to_core(&self) -> core::GlobalConfig {
        core::GlobalConfig {
            authority: self.authority.to_bytes(),
            deposit_fee_rate: self.deposit_fee_rate,
            withdrawal_fee_rate: self.withdrawal_fee_rate,
            fee_error_margin: self.fee_error_margin,
            bump: self.bump,
        }
    }

    fn set_from_core(&mut self, c: &core::GlobalConfig) {
        self.authority = Pubkey::new_from_array(c.authority);
        self.deposit_fee_rate = c.deposit_fee_rate;
        self.withdrawal_fee_rate = c.withdrawal_fee_rate;
        self.fee_error_margin = c.fee_error_margin;
        self.bump = c.bump;
    }
}

/// Called with `ADMIN_PUBKEY` by the handlers.
pub fn check_admin(authority: &Pubkey, admin_pubkey: Option<Pubkey>) -> Result<()> {
    core::check_admin(authority.to_bytes(), admin_pubkey.map(|k| k.to_bytes())).map_err(core_err)
}

/// Called with `ALLOW_ALL_SPL_TOKENS` and `ALLOWED_TOKENS` by the handlers.
pub fn check_allowed_mint(mint: &Pubkey, allow_all_spl_tokens: bool, allowed_tokens: &[Pubkey]) -> Result<()> {
    core::check_allowed_mint(
        mint.to_bytes(),
        allow_all_spl_tokens,
        bytemuck::cast_slice::<Pubkey, [u8; 32]>(allowed_tokens),
    )
    .map_err(core_err)
}

pub fn initialize(
    tree_account: &mut MerkleTreeAccount,
    tree_token_account: &mut TreeTokenAccount,
    global_config: &mut GlobalConfig,
    authority: &Pubkey,
    tree_account_bump: u8,
    tree_token_account_bump: u8,
    global_config_bump: u8,
) -> Result<()> {
    let mut token = tree_token_account.to_core();
    let mut config = global_config.to_core();
    core::initialize::<LightHasher<Poseidon>>(
        tree_account.as_core_mut(),
        &mut token,
        &mut config,
        authority.to_bytes(),
        tree_account_bump,
        tree_token_account_bump,
        global_config_bump,
    )
    .map_err(core_err)?;
    tree_token_account.set_from_core(&token);
    global_config.set_from_core(&config);
    Ok(())
}

pub fn initialize_tree_account_for_spl_token(
    tree_account: &mut MerkleTreeAccount,
    authority: &Pubkey,
    tree_account_bump: u8,
    max_deposit_amount: u64,
) -> Result<()> {
    core::initialize_tree_account_for_spl_token::<LightHasher<Poseidon>>(
        tree_account.as_core_mut(),
        authority.to_bytes(),
        tree_account_bump,
        max_deposit_amount,
    )
    .map_err(core_err)
}

pub fn update_deposit_limit(tree_account: &mut MerkleTreeAccount, new_limit: u64) {
    core::update_deposit_limit(tree_account.as_core_mut(), new_limit);
}

pub fn update_global_config(
    global_config: &mut GlobalConfig,
    deposit_fee_rate: Option<u16>,
    withdrawal_fee_rate: Option<u16>,
    fee_error_margin: Option<u16>,
) -> Result<()> {
    let mut config = global_config.to_core();
    core::update_global_config(&mut config, deposit_fee_rate, withdrawal_fee_rate, fee_error_margin)
        .map_err(core_err)?;
    global_config.set_from_core(&config);
    Ok(())
}
