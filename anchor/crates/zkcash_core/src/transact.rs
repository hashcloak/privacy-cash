//! Mirrors the `transact` instruction (SOL deposits and withdrawals).
//!
//! Everything the instruction decides happens here. What needs the Solana
//! runtime (reading and writing lamports, the system-program transfer CPI, the
//! `Rent` sysvar) goes through the `SolRuntime` trait, and Groth16 verification
//! through `ProofVerifier`; the Lean model treats both as abstract.
//! Account validation (PDAs, nullifier `init`) stays in Anchor and events
//! (`emit!`) stay in the program.
//!
//! Aeneas supports `?` only on `Result` values of the same error type and has
//! no model of `Option::ok_or` chains or `Result::is_err`, so the checked
//! arithmetic below uses explicit `match`es.

use crate::admin::GlobalConfig;
use crate::error::ErrorCode;
use crate::ext_data::{calculate_complete_ext_data_hash, Sha256};
use crate::field::PrimeField;
use crate::merkle_tree::{append, is_known_root, Hasher, MerkleTreeAccount};
use crate::utils::{check_public_amount, validate_fee};

/// `utils::SOL_ADDRESS` (11111111111111111111111111111112): the mint address
/// hashed into the ext data of SOL transactions.
pub const SOL_ADDRESS: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

/// Mirrors the program's `Proof` instruction argument.
#[derive(Clone, Copy)]
pub struct Proof {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub root: [u8; 32],
    pub public_amount: [u8; 32],
    pub ext_data_hash: [u8; 32],
    pub input_nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
}

/// Why `transact` failed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// One of the program's own error codes.
    Program(ErrorCode),
    /// Serializing the ext data failed (upstream: a Borsh I/O error).
    Serialization,
    /// The runtime failed (a CPI, sysvar read or account borrow); the
    /// `SolRuntime` implementation holds the actual error.
    Runtime,
}

/// Groth16 verification of `proof` against the program's verifying key.
pub trait ProofVerifier {
    fn verify(proof: &Proof) -> bool;
}

/// The Solana runtime as seen by `transact`. `Err(())` means the runtime
/// failed; the implementation keeps the actual error.
pub trait SolRuntime {
    /// `Rent::get()?.minimum_balance(tree_token_account.data_len())`
    fn rent_exempt_minimum(&mut self) -> Result<u64, ()>;
    /// System-program transfer of `amount` lamports from the signer to the
    /// tree token account.
    fn transfer_from_signer_to_tree_token(&mut self, amount: u64) -> Result<(), ()>;
    fn tree_token_lamports(&self) -> u64;
    fn recipient_lamports(&self) -> u64;
    fn fee_recipient_lamports(&self) -> u64;
    fn set_tree_token_lamports(&mut self, lamports: u64) -> Result<(), ()>;
    fn set_recipient_lamports(&mut self, lamports: u64) -> Result<(), ()>;
    fn set_fee_recipient_lamports(&mut self, lamports: u64) -> Result<(), ()>;
}

/// Indices of the two commitments appended to the tree (for the events).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    pub first_index: u64,
    pub second_index: u64,
}

fn program_err<T>(e: ErrorCode) -> Result<T, Error> {
    Err(Error::Program(e))
}

/// Mirrors the body of `transact` after the accounts are loaded.
#[allow(clippy::too_many_arguments)]
pub fn transact<H: Hasher, F: PrimeField, S: Sha256, V: ProofVerifier, R: SolRuntime>(
    runtime: &mut R,
    tree_account: &mut MerkleTreeAccount,
    global_config: &GlobalConfig,
    proof: &Proof,
    ext_amount: i64,
    fee: u64,
    recipient: [u8; 32],
    fee_recipient: [u8; 32],
    encrypted_output1: &[u8],
    encrypted_output2: &[u8],
) -> Result<Appended, Error> {
    // check if proof.root is in the tree_account's proof history
    if !is_known_root(tree_account, proof.root) {
        return program_err(ErrorCode::UnknownRoot);
    }

    // check if the ext_data hashes to the same ext_data in the proof
    let calculated_ext_data_hash = match calculate_complete_ext_data_hash::<S>(
        recipient,
        ext_amount,
        encrypted_output1,
        encrypted_output2,
        fee,
        fee_recipient,
        SOL_ADDRESS,
    ) {
        Some(hash) => hash,
        None => return Err(Error::Serialization),
    };

    if !F::eq(
        F::from_le_bytes_mod_order(&calculated_ext_data_hash),
        F::from_be_bytes_mod_order(&proof.ext_data_hash),
    ) {
        return program_err(ErrorCode::ExtDataHashMismatch);
    }

    if !check_public_amount::<F>(ext_amount, fee, proof.public_amount) {
        return program_err(ErrorCode::InvalidPublicAmountData);
    }

    // Validate fee calculation using utility function
    if let Err(e) = validate_fee(
        ext_amount,
        fee,
        global_config.deposit_fee_rate,
        global_config.withdrawal_fee_rate,
        global_config.fee_error_margin,
    ) {
        return program_err(e);
    }

    // verify the proof
    if !V::verify(proof) {
        return program_err(ErrorCode::InvalidProof);
    }

    let rent_exempt_minimum = match runtime.rent_exempt_minimum() {
        Ok(v) => v,
        Err(()) => return Err(Error::Runtime),
    };

    if ext_amount > 0 {
        // Check deposit limit for deposits
        let deposit_amount = ext_amount as u64;
        if !(deposit_amount <= tree_account.max_deposit_amount) {
            return program_err(ErrorCode::DepositLimitExceeded);
        }

        // If it's a deposit, transfer the SOL to the tree token account.
        if let Err(()) = runtime.transfer_from_signer_to_tree_token(ext_amount as u64) {
            return Err(Error::Runtime);
        }
    } else if ext_amount < 0 {
        // PDA can't directly sign transactions, so we need to transfer SOL via try_borrow_mut_lamports
        // No limit on withdrawals
        // (Upstream: `.checked_neg().ok_or(ArithmeticOverflow)?.try_into().map_err(|_| InvalidExtAmount)?`.)
        let negated = match ext_amount.checked_neg() {
            Some(v) => v,
            None => return program_err(ErrorCode::ArithmeticOverflow),
        };
        if negated < 0 {
            return program_err(ErrorCode::InvalidExtAmount);
        }
        let ext_amount_abs = negated as u64;

        let total_required = match ext_amount_abs.checked_add(fee) {
            Some(v) => match v.checked_add(rent_exempt_minimum) {
                Some(v) => v,
                None => return program_err(ErrorCode::ArithmeticOverflow),
            },
            None => return program_err(ErrorCode::ArithmeticOverflow),
        };

        if !(runtime.tree_token_lamports() >= total_required) {
            return program_err(ErrorCode::InsufficientFundsForWithdrawal);
        }

        let tree_token_balance = runtime.tree_token_lamports();
        let recipient_balance = runtime.recipient_lamports();

        let new_tree_token_balance = match tree_token_balance.checked_sub(ext_amount_abs) {
            Some(v) => v,
            None => return program_err(ErrorCode::ArithmeticOverflow),
        };
        let new_recipient_balance = match recipient_balance.checked_add(ext_amount_abs) {
            Some(v) => v,
            None => return program_err(ErrorCode::ArithmeticOverflow),
        };

        if let Err(()) = runtime.set_tree_token_lamports(new_tree_token_balance) {
            return Err(Error::Runtime);
        }
        if let Err(()) = runtime.set_recipient_lamports(new_recipient_balance) {
            return Err(Error::Runtime);
        }
    }

    if fee > 0 {
        if ext_amount >= 0 {
            let total_required = match fee.checked_add(rent_exempt_minimum) {
                Some(v) => v,
                None => return program_err(ErrorCode::ArithmeticOverflow),
            };

            if !(runtime.tree_token_lamports() >= total_required) {
                return program_err(ErrorCode::InsufficientFundsForFee);
            }
        }

        let tree_token_balance = runtime.tree_token_lamports();
        let fee_recipient_balance = runtime.fee_recipient_lamports();

        let new_tree_token_balance = match tree_token_balance.checked_sub(fee) {
            Some(v) => v,
            None => return program_err(ErrorCode::ArithmeticOverflow),
        };
        let new_fee_recipient_balance = match fee_recipient_balance.checked_add(fee) {
            Some(v) => v,
            None => return program_err(ErrorCode::ArithmeticOverflow),
        };

        if let Err(()) = runtime.set_tree_token_lamports(new_tree_token_balance) {
            return Err(Error::Runtime);
        }
        if let Err(()) = runtime.set_fee_recipient_lamports(new_fee_recipient_balance) {
            return Err(Error::Runtime);
        }
    }

    let next_index_to_insert = tree_account.next_index;
    if let Err(e) = append::<H>(proof.output_commitments[0], tree_account) {
        return program_err(e);
    }
    if let Err(e) = append::<H>(proof.output_commitments[1], tree_account) {
        return program_err(e);
    }

    let second_index = match next_index_to_insert.checked_add(1) {
        Some(v) => v,
        None => return program_err(ErrorCode::ArithmeticOverflow),
    };

    Ok(Appended { first_index: next_index_to_insert, second_index })
}
