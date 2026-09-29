//! Differential test of `transact`: the upstream handler body against the
//! verified core, on a mock Solana runtime.
//!
//! scripts/e2e.sh runs upstream's integration suites against the real programs,
//! but their negative tests accept any failure ("Transaction simulation
//! failed"), so they cannot tell error codes apart. This test compares exact
//! error codes, every balance and the whole tree account.
//!
//! The upstream body is copied from lib.rs:215-370 with only the runtime
//! plumbing replaced: `ctx.accounts.*` lamports and `try_borrow_mut_lamports`
//! become `Mock` reads/writes, the system-program CPI and `Rent::get()` become
//! `Mock` calls, `verify_proof(..)` becomes the mock verifier, and events are
//! omitted. The helpers it calls (`is_known_root`, `check_public_amount`, ...)
//! are the program's, each checked against upstream in its own test module.

use super::outcome;
use anchor_lang::prelude::*;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_hasher::Poseidon;
use proptest::prelude::*;
use std::cell::Cell;
use zkcash::{merkle_tree::LightHasher, merkle_tree::MerkleTree, utils, GlobalConfig, MerkleTreeAccount, Proof};
use zkcash_core::transact as core;

/// The accounts `transact` touches. Several roles may be the same account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role { Signer, TreeToken, Recipient, FeeRecipient }

#[derive(Clone, Debug, PartialEq, Eq)]
struct Mock {
    /// Balances of up to four distinct accounts.
    lamports: [u64; 4],
    /// Which account each role is (so the recipient can alias the fee recipient, etc.).
    slot: [usize; 4],
    rent_exempt_minimum: Option<u64>,
    transfer_fails: bool,
}

/// Distinct errors for the runtime failures, standing in for the real ones.
const RENT_ERROR: u32 = 900_001;
const TRANSFER_ERROR: u32 = 900_002;

impl Mock {
    fn get(&self, r: Role) -> u64 { self.lamports[self.slot[r as usize]] }
    fn set(&mut self, r: Role, v: u64) { self.lamports[self.slot[r as usize]] = v; }

    fn rent(&self) -> std::result::Result<u64, u32> { self.rent_exempt_minimum.ok_or(RENT_ERROR) }

    /// A system-program transfer: fails if asked to, or like the system
    /// program when the signer cannot pay.
    fn transfer(&mut self, amount: u64) -> std::result::Result<(), u32> {
        if self.transfer_fails || self.get(Role::Signer) < amount { return Err(TRANSFER_ERROR); }
        let from = self.get(Role::Signer) - amount;
        self.set(Role::Signer, from);
        let to = self.get(Role::TreeToken).checked_add(amount).ok_or(TRANSFER_ERROR)?;
        self.set(Role::TreeToken, to);
        Ok(())
    }
}

thread_local! {
    static PROOF_IS_VALID: Cell<bool> = const { Cell::new(true) };
}

struct MockVerifier;
impl core::ProofVerifier for MockVerifier {
    fn verify(_: &core::Proof) -> bool { PROOF_IS_VALID.with(Cell::get) }
}

/// The core's view of the mock; runtime failures are recorded like the
/// program's `SolTransactRuntime` does.
struct CoreRuntime { mock: Mock, error: Option<u32> }

impl core::SolRuntime for CoreRuntime {
    fn rent_exempt_minimum(&mut self) -> std::result::Result<u64, ()> {
        self.mock.rent().map_err(|e| self.error = Some(e))
    }
    fn transfer_from_signer_to_tree_token(&mut self, amount: u64) -> std::result::Result<(), ()> {
        self.mock.transfer(amount).map_err(|e| self.error = Some(e))
    }
    fn tree_token_lamports(&self) -> u64 { self.mock.get(Role::TreeToken) }
    fn recipient_lamports(&self) -> u64 { self.mock.get(Role::Recipient) }
    fn fee_recipient_lamports(&self) -> u64 { self.mock.get(Role::FeeRecipient) }
    fn set_tree_token_lamports(&mut self, v: u64) -> std::result::Result<(), ()> { self.mock.set(Role::TreeToken, v); Ok(()) }
    fn set_recipient_lamports(&mut self, v: u64) -> std::result::Result<(), ()> { self.mock.set(Role::Recipient, v); Ok(()) }
    fn set_fee_recipient_lamports(&mut self, v: u64) -> std::result::Result<(), ()> { self.mock.set(Role::FeeRecipient, v); Ok(()) }
}

type Outcome = std::result::Result<(u64, u64), u32>;

fn code(e: zkcash::ErrorCode) -> u32 { anchor_lang::error::ERROR_CODE_OFFSET + e as u32 }

mod upstream {
    use super::*;
    use zkcash::ErrorCode;

    /// Upstream `transact` body (lib.rs:215-370), runtime plumbing replaced.
    #[allow(clippy::too_many_arguments)]
    pub fn transact(
        m: &mut Mock,
        tree_account: &mut MerkleTreeAccount,
        global_config: &GlobalConfig,
        proof: Proof,
        ext_amount: i64,
        fee: u64,
        recipient: Pubkey,
        fee_recipient: Pubkey,
        encrypted_output1: &[u8],
        encrypted_output2: &[u8],
    ) -> Outcome {
        let r = (|| -> Result<std::result::Result<(u64, u64), u32>> {
        // check if proof.root is in the tree_account's proof history
        require!(
            MerkleTree::is_known_root(&tree_account, proof.root),
            ErrorCode::UnknownRoot
        );

        // check if the ext_data hashes to the same ext_data in the proof
        let calculated_ext_data_hash = utils::calculate_complete_ext_data_hash(
            recipient,
            ext_amount,
            &encrypted_output1,
            &encrypted_output2,
            fee,
            fee_recipient,
            utils::SOL_ADDRESS,
        )?;

        require!(
            Fr::from_le_bytes_mod_order(&calculated_ext_data_hash) == Fr::from_be_bytes_mod_order(&proof.ext_data_hash),
            ErrorCode::ExtDataHashMismatch
        );

        require!(
            utils::check_public_amount(ext_amount, fee, proof.public_amount),
            ErrorCode::InvalidPublicAmountData
        );

        // Validate fee calculation using utility function
        utils::validate_fee(
            ext_amount,
            fee,
            global_config.deposit_fee_rate,
            global_config.withdrawal_fee_rate,
            global_config.fee_error_margin,
        )?;

        // verify the proof
        require!(PROOF_IS_VALID.with(Cell::get), ErrorCode::InvalidProof);

        let rent_exempt_minimum = match m.rent() { Ok(v) => v, Err(e) => return Ok(Err(e)) };

        if ext_amount > 0 {
            // Check deposit limit for deposits
            let deposit_amount = ext_amount as u64;
            require!(
                deposit_amount <= tree_account.max_deposit_amount,
                ErrorCode::DepositLimitExceeded
            );
            
            // If it's a deposit, transfer the SOL to the tree token account.
            if let Err(e) = m.transfer(ext_amount as u64) { return Ok(Err(e)); }
        } else if ext_amount < 0 {
            let ext_amount_abs: u64 = ext_amount.checked_neg()
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .try_into()
                .map_err(|_| ErrorCode::InvalidExtAmount)?;
            
            let total_required = ext_amount_abs
                .checked_add(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_add(rent_exempt_minimum)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            
            require!(
                m.get(Role::TreeToken) >= total_required,
                ErrorCode::InsufficientFundsForWithdrawal
            );

            let tree_token_balance = m.get(Role::TreeToken);
            let recipient_balance = m.get(Role::Recipient);
            
            let new_tree_token_balance = tree_token_balance.checked_sub(ext_amount_abs)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            let new_recipient_balance = recipient_balance.checked_add(ext_amount_abs)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
                
            m.set(Role::TreeToken, new_tree_token_balance);
            m.set(Role::Recipient, new_recipient_balance);
        }
        
        if fee > 0 {
            if ext_amount >= 0 {
                let total_required = fee
                    .checked_add(rent_exempt_minimum)
                    .ok_or(ErrorCode::ArithmeticOverflow)?;
                
                require!(
                    m.get(Role::TreeToken) >= total_required,
                    ErrorCode::InsufficientFundsForFee
                );
            }

            let tree_token_balance = m.get(Role::TreeToken);
            let fee_recipient_balance = m.get(Role::FeeRecipient);
            
            let new_tree_token_balance = tree_token_balance.checked_sub(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            let new_fee_recipient_balance = fee_recipient_balance.checked_add(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
                
            m.set(Role::TreeToken, new_tree_token_balance);
            m.set(Role::FeeRecipient, new_fee_recipient_balance);
        }

        let next_index_to_insert = tree_account.next_index;
        MerkleTree::append::<Poseidon>(proof.output_commitments[0], tree_account)?;
        MerkleTree::append::<Poseidon>(proof.output_commitments[1], tree_account)?;

        let second_index = next_index_to_insert.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        Ok(Ok((next_index_to_insert, second_index)))
        })();
        match outcome(r) { Ok(inner) => inner, Err(code) => Err(code) }
    }
}

/// The new path: exactly what the program's `transact` handler does around
/// the core call.
#[allow(clippy::too_many_arguments)]
fn new_transact(
    m: &mut Mock,
    tree_account: &mut MerkleTreeAccount,
    global_config: &GlobalConfig,
    proof: Proof,
    ext_amount: i64,
    fee: u64,
    recipient: Pubkey,
    fee_recipient: Pubkey,
    encrypted_output1: &[u8],
    encrypted_output2: &[u8],
) -> Outcome {
    let mut runtime = CoreRuntime { mock: m.clone(), error: None };
    let r = core::transact::<LightHasher<Poseidon>, utils::ArkFr, utils::SolanaSha256, MockVerifier, _>(
        &mut runtime,
        tree_account.as_core_mut(),
        &global_config.to_core(),
        &proof.to_core(),
        ext_amount,
        fee,
        recipient.to_bytes(),
        fee_recipient.to_bytes(),
        encrypted_output1,
        encrypted_output2,
    );
    *m = runtime.mock;
    match r {
        Ok(a) => Ok((a.first_index, a.second_index)),
        Err(core::Error::Program(c)) => Err(code(zkcash::ErrorCode::from(c))),
        Err(core::Error::Serialization) => Err(u32::MAX),
        Err(core::Error::Runtime) => Err(runtime.error.expect("runtime error recorded")),
    }
}

/// A valid transaction for the given amounts, before any corruption.
struct Case {
    tree: MerkleTreeAccount,
    config: GlobalConfig,
    proof: Proof,
    ext_amount: i64,
    fee: u64,
    recipient: Pubkey,
    fee_recipient: Pubkey,
    out1: Vec<u8>,
    out2: Vec<u8>,
}

fn fr_be(x: Fr) -> [u8; 32] {
    x.into_bigint().to_bytes_be().try_into().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn valid_case(
    history: u8, ext_amount: i64, fee: u64, rates: (u16, u16, u16), max_deposit: u64,
    keys: ([u8; 32], [u8; 32]), outs: (Vec<u8>, Vec<u8>), commitments: [[u8; 32]; 2], next_index: u64,
) -> Case {
    let mut tree: MerkleTreeAccount = bytemuck::Zeroable::zeroed();
    tree.height = 26;
    tree.root_history_size = 100;
    MerkleTree::initialize::<Poseidon>(&mut tree).unwrap();
    for i in 0..history {
        MerkleTree::append::<Poseidon>([i + 1; 32], &mut tree).unwrap();
    }
    tree.next_index = next_index.max(tree.next_index);
    tree.max_deposit_amount = max_deposit;

    let (recipient, fee_recipient) = (Pubkey::new_from_array(keys.0), Pubkey::new_from_array(keys.1));
    let hash = utils::calculate_complete_ext_data_hash(
        recipient, ext_amount, &outs.0, &outs.1, fee, fee_recipient, utils::SOL_ADDRESS,
    ).unwrap();
    let abs = Fr::from(ext_amount.unsigned_abs());
    let public_amount = if ext_amount >= 0 { abs - Fr::from(fee) } else { -(abs + Fr::from(fee)) };

    Case {
        config: GlobalConfig {
            authority: Pubkey::default(),
            deposit_fee_rate: rates.0, withdrawal_fee_rate: rates.1, fee_error_margin: rates.2, bump: 0,
        },
        proof: Proof {
            proof_a: [0; 64], proof_b: [0; 128], proof_c: [0; 64],
            root: tree.root_history[(history as usize) % 100.max(1)],
            public_amount: fr_be(public_amount),
            ext_data_hash: fr_be(Fr::from_le_bytes_mod_order(&hash)),
            input_nullifiers: [[7; 32], [8; 32]],
            output_commitments: commitments,
        },
        tree, ext_amount, fee, recipient, fee_recipient, out1: outs.0, out2: outs.1,
    }
}

/// Amounts and balances concentrated around the thresholds that matter.
fn ext_amount() -> impl Strategy<Value = i64> {
    prop_oneof![
        prop::sample::select(vec![i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX]),
        -10_000_000i64..10_000_000,
        -3_000_000_000i64..3_000_000_000,
        any::<i64>(),
    ]
}

fn lamports() -> impl Strategy<Value = u64> {
    prop_oneof![0u64..10_000_000_000, prop::sample::select(vec![0, 1, u64::MAX - 1, u64::MAX]), any::<u64>()]
}

/// Which account each role is: distinct, or with aliases between roles.
fn slots() -> impl Strategy<Value = [usize; 4]> {
    prop_oneof![
        4 => Just([0, 1, 2, 3]),
        1 => Just([0, 1, 2, 2]),  // recipient is the fee recipient
        1 => Just([0, 1, 1, 3]),  // recipient is the tree token account
        1 => Just([0, 1, 2, 1]),  // fee recipient is the tree token account
        1 => Just([0, 1, 0, 3]),  // recipient is the signer
        1 => prop::array::uniform4(0usize..4),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    #[test]
    fn transact_matches_upstream(
        history in 0u8..3,
        ext_amount in ext_amount(),
        // Mostly the minimum fee the rates require plus a small delta, so the
        // fee check passes and later checks are reached; sometimes arbitrary.
        fee_choice in prop_oneof![3 => (0u64..4).prop_map(Ok), 1 => prop_oneof![0u64..10_000_000, Just(0u64), any::<u64>()].prop_map(Err)],
        rates in (0u16..=10_000, 0u16..=10_000, 0u16..=10_000),
        max_deposit in prop_oneof![Just(1_000_000_000_000u64), lamports()],
        keys in any::<([u8; 32], [u8; 32])>(),
        outs in (prop::collection::vec(any::<u8>(), 0..100), prop::collection::vec(any::<u8>(), 0..100)),
        commitments in prop::array::uniform2(any::<[u8; 32]>().prop_map(|mut c| { c[0] &= 0x1f; c })),
        next_index in prop_oneof![9 => Just(0u64), 1 => (1u64 << 26) - 2..=(1u64 << 26)],
        mock in (prop::array::uniform4(lamports()), slots(), prop::option::weighted(0.95, 0u64..5_000_000), prop::bool::weighted(0.05)),
        proof_is_valid in prop::bool::weighted(0.9),
        // 0 = leave valid; otherwise break one condition.
        corruption in prop_oneof![6 => Just(0u8), 1 => 1u8..=4],
    ) {
        let fee = match fee_choice {
            Ok(delta) => {
                let rate = if ext_amount > 0 { rates.0 } else { rates.1 };
                let expected = (ext_amount.unsigned_abs() as u128 * rate as u128 / 10_000) as u64;
                let min = (expected as u128 * (10_000 - rates.2 as u128) / 10_000) as u64;
                min.saturating_add(delta)
            }
            Err(fee) => fee,
        };
        let mut c = valid_case(history, ext_amount, fee, rates, max_deposit, keys, outs, commitments, next_index);
        match corruption {
            1 => c.proof.root = [9; 32],
            2 => c.proof.ext_data_hash[31] ^= 1,
            3 => c.proof.public_amount[31] ^= 1,
            4 => c.fee = c.fee.wrapping_add(1),
            _ => {}
        }
        let (lamports, slot, rent_exempt_minimum, transfer_fails) = mock;
        compare(&c, Mock { lamports, slot, rent_exempt_minimum, transfer_fails }, proof_is_valid)?;
    }

    /// Deposits whose fee cannot be paid while keeping the tree token account
    /// rent exempt (InsufficientFundsForFee), which random inputs rarely reach.
    /// The fee must stay below the amount (`check_public_amount` rejects
    /// deposits that do not exceed their fee), so this needs a pool that is
    /// nearly empty relative to the rent-exempt minimum.
    #[test]
    fn deposit_fee_funding_matches_upstream(
        ext_amount in 100i64..100_000,
        below_amount in 1u64..4,
        tree_token_lamports in 0u64..20_000,
        // Mostly right at the boundary, where the pool after the deposit holds
        // exactly fee + rent (+/- 2); sometimes anywhere.
        rent_choice in prop_oneof![3 => (-2i64..=2).prop_map(Ok), 1 => (0u64..200_000).prop_map(Err)],
        keys in any::<([u8; 32], [u8; 32])>(),
    ) {
        // After the deposit the pool holds tree_token_lamports + ext_amount and
        // must keep fee + rent = ext_amount - below_amount + rent.
        let rent = match rent_choice {
            Ok(offset) => (tree_token_lamports as i64 + below_amount as i64 + offset).max(0) as u64,
            Err(rent) => rent,
        };
        // 100% deposit fee with a 5% margin: any fee in [0.95, 1) x amount is valid.
        let fee = ext_amount as u64 - below_amount;
        let c = valid_case(0, ext_amount, fee, (10_000, 0, 500), u64::MAX, keys,
            (vec![1], vec![2]), [[1; 32], [2; 32]], 0);
        let mock = Mock {
            lamports: [u64::MAX / 2, tree_token_lamports, 0, 0],
            slot: [0, 1, 2, 3],
            rent_exempt_minimum: Some(rent),
            transfer_fails: false,
        };
        compare(&c, mock, true)?;
    }
}

/// Runs both implementations on the same inputs; they must agree on the
/// result and, when it succeeds, on every balance and the whole tree account.
fn compare(c: &Case, mock: Mock, proof_is_valid: bool) -> std::result::Result<(), TestCaseError> {
    PROOF_IS_VALID.with(|v| v.set(proof_is_valid));
    let (mut new_mock, mut new_tree) = (mock.clone(), c.tree);
    let (mut old_mock, mut old_tree) = (mock, c.tree);
    let new = new_transact(&mut new_mock, &mut new_tree, &c.config, c.proof.clone(),
        c.ext_amount, c.fee, c.recipient, c.fee_recipient, &c.out1, &c.out2);
    let old = upstream::transact(&mut old_mock, &mut old_tree, &c.config, c.proof.clone(),
        c.ext_amount, c.fee, c.recipient, c.fee_recipient, &c.out1, &c.out2);

    prop_assert_eq!(new, old);
    // A failed transaction reverts all writes, so state only matters on success.
    if new.is_ok() {
        prop_assert_eq!(new_mock, old_mock);
        prop_assert_eq!(bytemuck::bytes_of(&new_tree), bytemuck::bytes_of(&old_tree));
    }
    Ok(())
}

#[test]
fn sol_address_matches_upstream() {
    assert_eq!(zkcash_core::transact::SOL_ADDRESS, utils::SOL_ADDRESS.to_bytes());
}

proptest! {
    /// `Proof::to_core` copies every field (a swapped or stale field would
    /// silently change what is verified).
    #[test]
    fn proof_to_core_copies_every_field(
        a in prop::collection::vec(any::<u8>(), 64),
        b in prop::collection::vec(any::<u8>(), 128),
        c in prop::collection::vec(any::<u8>(), 64),
        fields in any::<([u8; 32], [u8; 32], [u8; 32], [[u8; 32]; 2], [[u8; 32]; 2])>(),
    ) {
        let (root, public_amount, ext_data_hash, input_nullifiers, output_commitments) = fields;
        let proof = Proof {
            proof_a: a.clone().try_into().unwrap(),
            proof_b: b.clone().try_into().unwrap(),
            proof_c: c.clone().try_into().unwrap(),
            root, public_amount, ext_data_hash, input_nullifiers, output_commitments,
        };
        let core = proof.to_core();
        prop_assert_eq!(core.proof_a.to_vec(), a);
        prop_assert_eq!(core.proof_b.to_vec(), b);
        prop_assert_eq!(core.proof_c.to_vec(), c);
        prop_assert_eq!(core.root, root);
        prop_assert_eq!(core.public_amount, public_amount);
        prop_assert_eq!(core.ext_data_hash, ext_data_hash);
        prop_assert_eq!(core.input_nullifiers, input_nullifiers);
        prop_assert_eq!(core.output_commitments, output_commitments);
    }
}
