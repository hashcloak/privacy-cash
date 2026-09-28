use super::outcome;
use anchor_lang::prelude::*;
use proptest::prelude::*;

mod upstream {
    use anchor_lang::prelude::*;
    use anchor_lang::solana_program::hash::hash;

    // Verbatim from upstream `utils::calculate_complete_ext_data_hash` (utils.rs:276-311).
    pub fn calculate_complete_ext_data_hash(
        recipient: Pubkey,
        ext_amount: i64,
        encrypted_output1: &[u8],
        encrypted_output2: &[u8],
        fee: u64,
        fee_recipient: Pubkey,
        mint_address: Pubkey,
    ) -> Result<[u8; 32]> {
        #[derive(AnchorSerialize)]
        struct CompleteExtData {
            pub recipient: Pubkey,
            pub ext_amount: i64,
            pub encrypted_output1: Vec<u8>,
            pub encrypted_output2: Vec<u8>,
            pub fee: u64,
            pub fee_recipient: Pubkey,
            pub mint_address: Pubkey,
        }

        let complete_ext_data = CompleteExtData {
            recipient,
            ext_amount,
            encrypted_output1: encrypted_output1.to_vec(),
            encrypted_output2: encrypted_output2.to_vec(),
            fee,
            fee_recipient,
            mint_address
        };

        let mut serialized_ext_data = Vec::new();
        complete_ext_data.serialize(&mut serialized_ext_data)?;
        let calculated_ext_data_hash = hash(&serialized_ext_data).to_bytes();

        Ok(calculated_ext_data_hash)
    }

    /// The same struct, to compare raw bytes with the core serializer.
    #[derive(AnchorSerialize)]
    pub struct CompleteExtData {
        pub recipient: Pubkey,
        pub ext_amount: i64,
        pub encrypted_output1: Vec<u8>,
        pub encrypted_output2: Vec<u8>,
        pub fee: u64,
        pub fee_recipient: Pubkey,
        pub mint_address: Pubkey,
    }
}

fn pubkey() -> impl Strategy<Value = Pubkey> {
    any::<[u8; 32]>().prop_map(Pubkey::new_from_array)
}

fn ext_amount() -> impl Strategy<Value = i64> {
    prop_oneof![
        prop::sample::select(vec![i64::MIN, -1, 0, 1, i64::MAX]),
        any::<i64>(),
    ]
}

fn fee() -> impl Strategy<Value = u64> {
    prop_oneof![prop::sample::select(vec![0u64, 1, u64::MAX]), any::<u64>()]
}

/// Encrypted outputs of any size a transaction can carry (and empty ones).
fn output() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1300)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    /// The core serializer produces exactly Borsh's bytes.
    #[test]
    fn serialization_matches_borsh(
        recipient in pubkey(), ext_amount in ext_amount(),
        out1 in output(), out2 in output(),
        fee in fee(), fee_recipient in pubkey(), mint_address in pubkey(),
    ) {
        let borsh = upstream::CompleteExtData {
            recipient, ext_amount,
            encrypted_output1: out1.clone(), encrypted_output2: out2.clone(),
            fee, fee_recipient, mint_address,
        }
        .try_to_vec()
        .unwrap();
        let core = zkcash_core::ext_data::serialize_complete_ext_data(
            recipient.to_bytes(), ext_amount, &out1, &out2,
            fee, fee_recipient.to_bytes(), mint_address.to_bytes(),
        );
        prop_assert_eq!(core, Some(borsh));
    }

    #[test]
    fn ext_data_hash_matches_upstream(
        recipient in pubkey(), ext_amount in ext_amount(),
        out1 in output(), out2 in output(),
        fee in fee(), fee_recipient in pubkey(), mint_address in pubkey(),
    ) {
        prop_assert_eq!(
            outcome(zkcash::utils::calculate_complete_ext_data_hash(
                recipient, ext_amount, &out1, &out2, fee, fee_recipient, mint_address,
            )),
            outcome(upstream::calculate_complete_ext_data_hash(
                recipient, ext_amount, &out1, &out2, fee, fee_recipient, mint_address,
            )),
        );
    }
}
