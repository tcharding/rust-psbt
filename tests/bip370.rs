//! BIP-370 Test Vectors.

#![cfg(all(feature = "std", feature = "base64", feature = "serde"))]

mod vectors;

use vectors::bip370;

mod valid {
    use super::bip370;

    #[test]
    fn required_fields_only() { bip370(0); }

    #[test]
    fn updated() { bip370(1); }

    #[test]
    fn with_psbt_in_sequence() { bip370(2); }

    #[test]
    fn with_psbt_in_sequence_and_all_locktime_fields() { bip370(3); }

    #[test]
    fn with_inputs_modifiable_flag() { bip370(4); }

    #[test]
    fn with_outputs_modifiable_flag() { bip370(5); }

    #[test]
    fn with_has_sighash_single_flag() { bip370(6); }

    #[test]
    fn with_an_undefined_flag() { bip370(7); }

    #[test]
    fn with_both_inputs_and_outputs_modifiable_flags() { bip370(8); }

    #[test]
    fn with_inputs_modifiable_and_sighash_single_flags() { bip370(9); }

    #[test]
    fn with_outputs_modifiable_and_sighash_single_flags() { bip370(10); }

    #[test]
    fn with_all_defined_modifiable_flags() { bip370(11); }

    #[test]
    fn with_all_possible_modifiable_flags() { bip370(12); }

    #[test]
    fn with_all_psbtv2_fields() { bip370(13); }
}

mod invalid {
    use super::bip370;

    #[test]
    fn psbtv0_with_global_version_set_to_2() { bip370(14); }

    #[test]
    fn psbtv0_with_global_tx_version() { bip370(15); }

    #[test]
    fn psbtv0_with_global_fallback_locktime() { bip370(16); }

    #[test]
    fn psbtv0_with_global_input_count() { bip370(17); }

    #[test]
    fn psbtv0_with_global_output_count() { bip370(18); }

    #[test]
    fn psbtv0_with_global_tx_modifiable() { bip370(19); }

    #[test]
    fn psbtv0_with_psbt_in_previous_txid() { bip370(20); }

    #[test]
    fn psbtv0_with_psbt_in_output_index() { bip370(21); }

    #[test]
    fn psbtv0_with_psbt_in_sequence() { bip370(22); }

    #[test]
    fn psbtv0_with_psbt_in_required_time_locktime() { bip370(23); }

    #[test]
    fn psbtv0_with_psbt_in_required_height_locktime() { bip370(24); }

    #[test]
    fn psbtv0_with_psbt_out_amount() { bip370(25); }

    #[test]
    fn psbtv0_with_psbt_out_script() { bip370(26); }

    #[test]
    fn psbtv2_missing_psbt_global_input_count() { bip370(27); }

    #[test]
    fn psbtv2_missing_psbt_global_output_count() { bip370(28); }

    #[test]
    fn psbtv2_missing_psbt_in_previous_txid() { bip370(29); }

    #[test]
    fn psbtv2_missing_psbt_in_output_index() { bip370(30); }

    #[test]
    fn psbtv2_missing_psbt_out_amount() { bip370(31); }

    #[test]
    fn psbtv2_missing_psbt_out_script() { bip370(32); }

    #[test]
    fn psbtv2_with_required_time_locktime_less_than_500000000() { bip370(33); }

    #[test]
    fn psbtv2_with_required_height_locktime_greater_than_or_equal_to_500000000() { bip370(34); }
}

mod determine_lock_time {
    use super::bip370;

    #[test]
    fn no_locktimes_specified() { bip370(35); }

    #[test]
    fn fallback_locktime_of_0() { bip370(36); }

    #[test]
    fn input_1_has_height_locktime_of_10000_input_2_has_no_locktime_fields() { bip370(37); }

    #[test]
    fn input_1_has_height_locktime_of_10000_input_2_has_height_locktime_of_9000() { bip370(38); }

    #[test]
    fn input_1_has_height_locktime_of_10000_input_2_has_both_time_and_height_locktime() {
        bip370(39);
    }

    #[test]
    fn both_inputs_have_time_and_height_locktime() { bip370(40); }

    #[test]
    fn input_1_time_locktime_input_2_both_time_and_height_locktime() { bip370(41); }

    #[test]
    fn input_1_both_time_and_height_locktime_input_2_time_locktime() { bip370(42); }

    #[test]
    fn cannot_be_determined() { bip370(43); }
}
