//! BIP-174 test vector executor.
//!
//! Parses `bip174.json` and runs each case through a single dispatcher
//! keyed on the `task` field. One `#[test]` per vector, named after its
//! `description`, so `cargo test` output maps 1-to-1 with the JSON document.

#![cfg(all(feature = "std", feature = "base64", feature = "serde", feature = "miniscript"))]

mod vectors;

use vectors::bip174;

mod invalid {
    use super::bip174;

    #[test]
    fn network_transaction_not_psbt_format() { bip174(0); }

    #[test]
    fn missing_outputs() { bip174(1); }

    #[test]
    fn unsigned_tx_has_signatures() { bip174(2); }

    #[test]
    fn missing_unsigned_tx() { bip174(3); }

    #[test]
    fn missing_inputs() { bip174(4); }

    #[test]
    fn non_witness_utxo() { bip174(5); }

    #[test]
    fn witness_utxo_provided_for_non_witness_input() { bip174(6); }

    #[test]
    fn redeemscript_with_non_witness_utxo_does_not_match_the_scriptpubkey() { bip174(7); }

    #[test]
    fn redeemscript_with_witness_utxo_does_not_match_the_scriptpubkey() { bip174(8); }

    #[test]
    fn witness_script_with_witness_utxo_does_not_match_the_redeemscript() { bip174(9); }

    #[test]
    fn witness_script() { bip174(10); }

    #[test]
    fn pubkey_in_input_bip_32_derivation_paths() { bip174(11); }

    #[test]
    fn pubkey_in_output_bip_32_derivation_paths() { bip174(12); }

    #[test]
    fn duplicate_keys_in_input() { bip174(13); }

    #[test]
    fn pubkey_length_for_input_partial_signature() { bip174(14); }

    #[test]
    fn input_sighash_type() { bip174(15); }

    #[test]
    fn output_redeemscript() { bip174(16); }

    #[test]
    fn output_witness_script() { bip174(17); }

    #[test]
    fn global_transaction() { bip174(18); }

    #[test]
    fn unsigned_tx_serialized_with_witness_serialization_format() { bip174(19); }

    #[test]
    fn final_scriptsig() { bip174(24); }

    #[test]
    fn final_script_witness() { bip174(25); }

    #[test]
    fn value_data_size_does_not_match_value_len() { bip174(26); }

    #[test]
    fn redeemscript() { bip174(27); }
}

mod valid {
    use super::bip174;

    #[test]
    fn no_inputs_nor_outputs_in_global_unsigned_tx() { bip174(20); }

    #[test]
    fn no_outputs_one_p2pkh_input() { bip174(21); }

    #[test]
    fn no_outputs_and_a_p2pkh_input_without_final_scriptsig_and_sighash_type_set() { bip174(22); }

    #[test]
    fn no_inputs() { bip174(23); }

    #[test]
    fn outputs_filled_with_p2pkh_input_and_p2sh_p2wpkh_input_with_reedem_script_both_with_non_final_scriptsigs(
    ) {
        bip174(28);
    }

    #[test]
    fn outputs_filled_one_p2wsh_2_of_2_multisig_input_witness_script_keypaths_and_global_xpubs_available_no_signatures(
    ) {
        bip174(29);
    }

    #[test]
    fn psbt_global_xpub() { bip174(31); }

    #[test]
    fn unknown_types_in_the_inputs() { bip174(32); }

    #[test]
    fn combiner_combines_keys_lexicographically() { bip174(33); }

    #[test]
    fn one_p2sh_p2wsh_2_of_2_multisig_input_with_redeemscript_witness_script_and_keypaths_one_signature_available(
    ) {
        bip174(39);
    }
}

mod workflow {
    use super::bip174;

    #[test]
    fn step_1_creator_creates_psbt() { bip174(34); }

    #[test]
    fn step_2_updater_updates_keys() { bip174(35); }

    #[test]
    fn step_3_updater_updates_sighash() { bip174(36); }

    #[test]
    fn step_4_signer_that_supports_sighash_all_for_p2pkh_and_p2wpkh_spends_and_uses_rfc6979_for_nonce_generation_provides_first_signature(
    ) {
        bip174(37);
    }

    #[test]
    fn step_5_signer_provides_second_signature() { bip174(38); }

    #[test]
    fn step_6_combiner_combines() { bip174(40); }

    #[test]
    fn step_7_input_finalizer_finalizes() { bip174(40); }

    #[test]
    fn step_8_extractor_extracts() { bip174(41); }
}
