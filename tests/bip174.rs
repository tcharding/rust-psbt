//! BIP-174 test vector executor.
//!
//! Parses `bip174.json` and runs each case through a single dispatcher
//! keyed on the `task` field. One `#[test]` per vector, named after its
//! `description`, so `cargo test` output maps 1-to-1 with the JSON document.

#![cfg(all(feature = "std", feature = "base64", feature = "serde"))]

mod vectors;

use vectors::check_case;

mod invalid {
    use super::check_case;

    #[test]
    fn network_transaction_not_psbt_format() { check_case(0); }

    #[test]
    fn missing_outputs() { check_case(1); }

    #[test]
    fn unsigned_tx_has_signatures() { check_case(2); }

    #[test]
    fn missing_unsigned_tx() { check_case(3); }

    #[test]
    fn missing_inputs() { check_case(4); }

    #[test]
    fn non_witness_utxo() { check_case(5); }

    #[test]
    fn witness_utxo_provided_for_non_witness_input() { check_case(6); }

    #[test]
    fn redeemscript_with_non_witness_utxo_does_not_match_the_scriptpubkey() { check_case(7); }

    #[test]
    fn redeemscript_with_witness_utxo_does_not_match_the_scriptpubkey() { check_case(8); }

    #[test]
    fn witness_script_with_witness_utxo_does_not_match_the_redeemscript() { check_case(9); }

    #[test]
    fn witness_script() { check_case(10); }

    #[test]
    fn pubkey_in_input_bip_32_derivation_paths() { check_case(11); }

    #[test]
    fn pubkey_in_output_bip_32_derivation_paths() { check_case(12); }

    #[test]
    fn duplicate_keys_in_input() { check_case(13); }

    #[test]
    fn pubkey_length_for_input_partial_signature() { check_case(14); }

    #[test]
    fn input_sighash_type() { check_case(15); }

    #[test]
    fn output_redeemscript() { check_case(16); }

    #[test]
    fn output_witness_script() { check_case(17); }

    #[test]
    fn global_transaction() { check_case(18); }

    #[test]
    fn unsigned_tx_serialized_with_witness_serialization_format() { check_case(19); }

    #[test]
    fn final_scriptsig() { check_case(24); }

    #[test]
    fn final_script_witness() { check_case(25); }

    #[test]
    fn value_data_size_does_not_match_value_len() { check_case(26); }

    #[test]
    fn redeemscript() { check_case(27); }
}

mod valid {
    use super::check_case;

    #[test]
    fn no_inputs_nor_outputs_in_global_unsigned_tx() { check_case(20); }

    #[test]
    fn no_outputs_one_p2pkh_input() { check_case(21); }

    #[test]
    fn no_outputs_and_a_p2pkh_input_without_final_scriptsig_and_sighash_type_set() {
        check_case(22);
    }

    #[test]
    fn no_inputs() { check_case(23); }

    #[test]
    fn outputs_filled_with_p2pkh_input_and_p2sh_p2wpkh_input_with_reedem_script_both_with_non_final_scriptsigs(
    ) {
        check_case(28);
    }

    #[test]
    fn outputs_filled_one_p2wsh_2_of_2_multisig_input_witness_script_keypaths_and_global_xpubs_available_no_signatures(
    ) {
        check_case(29);
    }

    #[test]
    fn psbt_global_xpub() { check_case(31); }

    #[test]
    fn unknown_types_in_the_inputs() { check_case(32); }

    #[test]
    fn combiner_combines_keys_lexicographically() { check_case(33); }

    #[test]
    fn one_p2sh_p2wsh_2_of_2_multisig_input_with_redeemscript_witness_script_and_keypaths_one_signature_available(
    ) {
        check_case(39);
    }
}

mod workflow {
    use super::check_case;

    #[test]
    fn step_1_creator_creates_psbt() { check_case(34); }

    #[test]
    fn step_2_updater_updates_keys() { check_case(35); }

    #[test]
    fn step_3_updater_updates_sighash() { check_case(36); }

    #[test]
    fn step_4_signer_that_supports_sighash_all_for_p2pkh_and_p2wpkh_spends_and_uses_rfc6979_for_nonce_generation_provides_first_signature(
    ) {
        check_case(37);
    }

    #[test]
    fn step_5_signer_provides_second_signature() { check_case(38); }

    #[test]
    fn step_6_combiner_combines() { check_case(40); }

    #[test]
    fn step_7_input_finalizer_finalizes() { check_case(40); }

    #[test]
    fn step_8_extractor_extracts() { check_case(41); }
}
