//! The Solana side of the extracted `zkcash_core::transact`: its `SolRuntime`
//! (lamports, the system-program transfer CPI, the `Rent` sysvar) and
//! `ProofVerifier` (Groth16) implementations, and error conversion.

use anchor_lang::prelude::*;
use zkcash_core::transact as core;

use crate::utils::{verify_proof, VERIFYING_KEY};
use crate::{ErrorCode, Proof};

impl Proof {
    pub fn to_core(&self) -> core::Proof {
        core::Proof {
            proof_a: self.proof_a,
            proof_b: self.proof_b,
            proof_c: self.proof_c,
            root: self.root,
            public_amount: self.public_amount,
            ext_data_hash: self.ext_data_hash,
            input_nullifiers: self.input_nullifiers,
            output_commitments: self.output_commitments,
        }
    }

    fn from_core(p: &core::Proof) -> Self {
        Proof {
            proof_a: p.proof_a,
            proof_b: p.proof_b,
            proof_c: p.proof_c,
            root: p.root,
            public_amount: p.public_amount,
            ext_data_hash: p.ext_data_hash,
            input_nullifiers: p.input_nullifiers,
            output_commitments: p.output_commitments,
        }
    }
}

/// Groth16 verification with the program's verifying key.
pub struct ProgramVerifier;

impl core::ProofVerifier for ProgramVerifier {
    fn verify(proof: &core::Proof) -> bool {
        verify_proof(Proof::from_core(proof), VERIFYING_KEY)
    }
}

/// `SolRuntime` over the accounts of a `transact` instruction. A failing
/// runtime call stores its error here, so `into_error` can return it unchanged.
pub struct SolTransactRuntime<'info> {
    pub signer: AccountInfo<'info>,
    pub tree_token_account: AccountInfo<'info>,
    pub recipient: AccountInfo<'info>,
    pub fee_recipient_account: AccountInfo<'info>,
    pub system_program: AccountInfo<'info>,
    error: Option<Error>,
}

impl<'info> SolTransactRuntime<'info> {
    pub fn new(
        signer: AccountInfo<'info>,
        tree_token_account: AccountInfo<'info>,
        recipient: AccountInfo<'info>,
        fee_recipient_account: AccountInfo<'info>,
        system_program: AccountInfo<'info>,
    ) -> Self {
        Self { signer, tree_token_account, recipient, fee_recipient_account, system_program, error: None }
    }

    /// The Anchor error the upstream handler would have returned.
    pub fn into_error(self, e: core::Error) -> Error {
        match e {
            core::Error::Program(code) => ErrorCode::from(code).into(),
            core::Error::Serialization => ProgramError::BorshIoError("Overflow".to_string()).into(),
            core::Error::Runtime => self.error.expect("SolRuntime failed without recording an error"),
        }
    }

    fn record<T>(&mut self, r: Result<T>) -> std::result::Result<T, ()> {
        r.map_err(|e| self.error = Some(e))
    }

    fn set_lamports(&mut self, account: fn(&Self) -> &AccountInfo<'info>, lamports: u64) -> std::result::Result<(), ()> {
        let r = account(self).try_borrow_mut_lamports().map(|mut l| **l = lamports).map_err(Error::from);
        self.record(r)
    }
}

impl<'info> core::SolRuntime for SolTransactRuntime<'info> {
    fn rent_exempt_minimum(&mut self) -> std::result::Result<u64, ()> {
        let data_len = self.tree_token_account.data_len();
        let r = Rent::get().map(|rent| rent.minimum_balance(data_len)).map_err(Error::from);
        self.record(r)
    }

    fn transfer_from_signer_to_tree_token(&mut self, amount: u64) -> std::result::Result<(), ()> {
        let r = anchor_lang::system_program::transfer(
            CpiContext::new(
                self.system_program.clone(),
                anchor_lang::system_program::Transfer {
                    from: self.signer.clone(),
                    to: self.tree_token_account.clone(),
                },
            ),
            amount,
        );
        self.record(r)
    }

    fn tree_token_lamports(&self) -> u64 {
        self.tree_token_account.lamports()
    }

    fn recipient_lamports(&self) -> u64 {
        self.recipient.lamports()
    }

    fn fee_recipient_lamports(&self) -> u64 {
        self.fee_recipient_account.lamports()
    }

    fn set_tree_token_lamports(&mut self, lamports: u64) -> std::result::Result<(), ()> {
        self.set_lamports(|s| &s.tree_token_account, lamports)
    }

    fn set_recipient_lamports(&mut self, lamports: u64) -> std::result::Result<(), ()> {
        self.set_lamports(|s| &s.recipient, lamports)
    }

    fn set_fee_recipient_lamports(&mut self, lamports: u64) -> std::result::Result<(), ()> {
        self.set_lamports(|s| &s.fee_recipient_account, lamports)
    }
}
