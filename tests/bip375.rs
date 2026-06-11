//! [BIP-375 Test Vectors](https://github.com/bitcoin/bips/blob/master/bip-0375/bip375_test_vectors.json).

#![cfg(all(
    feature = "std",
    feature = "base64",
    feature = "serde",
    feature = "miniscript",
    feature = "silent-payments"
))]

mod vectors;

use vectors::bip375;

mod valid {
    use super::bip375;

    #[test]
    fn can_finalize_one_p2pkh_input_single_signer() { bip375(0); }

    #[test]
    fn can_finalize_one_p2wpkh_input_single_signer() { bip375(1); }

    #[test]
    fn can_finalize_two_inputs_both_eligible() { bip375(2); }

    #[test]
    fn can_finalize_two_inputs_one_ineligible() { bip375(3); }

    #[test]
    fn can_finalize_many_eligible_inputs_no_dups() { bip375(4); }

    #[test]
    fn can_finalize_many_eligible_inputs_with_dups() { bip375(5); }

    #[test]
    fn handles_many_sp_outputs_correct_matching() { bip375(6); }

    #[test]
    fn handles_many_non_sp_outputs() { bip375(7); }

    #[test]
    fn output_is_sp_when_sp_info_present() { bip375(8); }

    #[test]
    fn outputs_not_sp_when_no_sp_info() { bip375(9); }

    #[test]
    fn label_zero_is_valid() { bip375(10); }

    #[test]
    fn label_with_long_bytes_is_valid() { bip375(11); }

    #[test]
    fn dleq_proof_correct_for_inputs() { bip375(12); }

    #[test]
    fn dleq_proof_with_different_values_per_input() { bip375(13); }

    #[test]
    fn global_shares_only_one_share_per_key() { bip375(14); }

    #[test]
    fn global_shares_many_keys_different_values() { bip375(15); }

    #[test]
    fn input_shares_one_per_input() { bip375(16); }

    #[test]
    fn input_shares_different_values_per_input() { bip375(17); }

    #[test]
    fn mixed_global_and_input_shares() { bip375(18); }
}

mod invalid {
    use super::bip375;

    #[test]
    fn psbt_structure_missing_out_sp_v0_info_field_when_out_sp_v0_label_set() { bip375(19); }

    #[test]
    fn psbt_structure_incorrect_byte_length_for_out_sp_v0_info_field() { bip375(20); }

    #[test]
    fn psbt_structure_incorrect_byte_length_for_in_sp_ecdh_share_field() { bip375(21); }

    #[test]
    fn psbt_structure_incorrect_byte_length_for_in_sp_dleq_field() { bip375(22); }

    // TODO: Validate that global tx modifiable field must be zero for SP outputs
    #[ignore]
    #[test]
    fn psbt_structure_global_tx_modifiable_field_is_nonzero_when_out_script_set_for_sp_output() {
        bip375(23);
    }

    #[test]
    fn psbt_structure_missing_out_script_field_when_sending_to_non_sp_output() { bip375(24); }

    // TODO: Validate ECDH share coverage for eligible inputs
    #[ignore]
    #[test]
    fn ecdh_coverage_only_one_ineligible_p2sh_multisig_input_when_out_script_set_for_sp_output() {
        bip375(25);
    }

    // TODO: Validate that all eligible inputs must have ECDH shares
    #[ignore]
    #[test]
    fn ecdh_coverage_missing_in_sp_ecdh_share_field_for_input_0_when_out_script_set_for_sp_output()
    {
        bip375(26);
    }

    #[test]
    fn ecdh_coverage_no_ecdh_shares_present_when_out_script_set_for_sp_output() { bip375(27); }

    #[test]
    fn ecdh_coverage_incomplete_ecdh_shares_missing_input_1() { bip375(28); }

    // TODO: Validate that scan keys must be unique across fields
    #[ignore]
    #[test]
    fn duplicate_keys_global_ecdh_duplicate_scan_key() { bip375(29); }

    // TODO: Validate that scan keys must be unique across fields
    #[ignore]
    #[test]
    fn duplicate_keys_global_dleq_duplicate_scan_key() { bip375(30); }

    // TODO: Validate that scan keys must be unique across fields
    #[ignore]
    #[test]
    fn duplicate_keys_per_input_ecdh_duplicate_scan_key() { bip375(31); }

    // TODO: Validate that scan keys must be unique across fields
    #[ignore]
    #[test]
    fn duplicate_keys_per_input_dleq_duplicate_scan_key() { bip375(32); }

    // TODO: Validate that ECDH and DLEQ proofs must both be present or both absent
    #[ignore]
    #[test]
    fn field_mismatch_global_dleq_only_no_ecdh() { bip375(33); }

    // TODO: Validate that ECDH and DLEQ proofs must both be present or both absent
    #[ignore]
    #[test]
    fn field_mismatch_global_ecdh_only_no_dleq() { bip375(34); }

    // TODO: Validate that ECDH and DLEQ proofs must both be present or both absent
    #[ignore]
    #[test]
    fn field_mismatch_per_input_dleq_only_no_ecdh() { bip375(35); }

    // TODO: Validate that ECDH and DLEQ proofs must both be present or both absent
    #[ignore]
    #[test]
    fn field_mismatch_per_input_ecdh_only_no_dleq() { bip375(36); }

    // TODO: Validate consistency between global and per-input field presence
    #[ignore]
    #[test]
    fn field_mismatch_global_and_per_input_imbalance() { bip375(37); }

    // TODO: Reject unknown PSBT output fields
    #[ignore]
    #[test]
    fn psbt_output_unknown_field_non_bip375_field() { bip375(38); }

    // TODO: Reject unknown PSBT input fields
    #[ignore]
    #[test]
    fn psbt_input_unknown_field_non_bip375_field() { bip375(39); }

    // TODO: Validate that finalization should fail for certain field combinations
    #[ignore]
    #[test]
    fn can_finalize_should_fail_check() { bip375(40); }
}
