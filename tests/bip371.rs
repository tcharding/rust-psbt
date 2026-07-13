//! BIP-174 test vector executor.
//!
//! Parses `bip371.json` and runs each case through a single dispatcher
//! keyed on the `task` field. One `#[test]` per vector, named after its
//! `description`, so `cargo test` output maps 1-to-1 with the JSON document.

#![cfg(all(feature = "std", feature = "base64", feature = "serde", feature = "miniscript"))]

mod vectors;

use vectors::bip371;

mod invalid {
    use super::bip371;

    #[test]
    fn in_tap_internal_key_is_too_long() { bip371(0); }

    #[test]
    fn in_tap_key_sig_is_too_short() { bip371(1); }

    #[test]
    fn in_tap_key_sig_is_too_long() { bip371(2); }

    #[test]
    fn in_tap_bip32_derivation_key_is_too_long() { bip371(3); }

    #[test]
    fn out_tap_internal_key_is_too_long() { bip371(4); }

    #[test]
    fn out_tap_bip32_derivation_key_is_too_long() { bip371(5); }

    #[test]
    fn in_tap_script_sig_key_is_too_long() { bip371(6); }

    #[test]
    fn in_tap_script_sig_signature_is_too_long() { bip371(7); }

    #[test]
    fn in_tap_script_sig_signature_is_too_short() { bip371(8); }

    #[test]
    fn in_tap_leaf_script_control_block_is_too_long() { bip371(9); }

    #[test]
    fn in_tap_leaf_script_control_block_is_too_short() { bip371(10); }
}

mod valid {
    use super::bip371;

    #[test]
    fn one_p2tr_key_only_input_with_internal_key_and_derivation_path() { bip371(11); }

    #[test]
    fn one_p2tr_key_only_input_with_internal_key_derivation_path_and_signature() { bip371(12); }

    #[test]
    fn one_p2tr_key_only_output_with_internal_key_and_derivation_path() { bip371(13); }

    #[test]
    fn one_p2tr_script_path_only_input_with_dummy_internal_key_scripts_script_keys_derivation_paths_and_merkle_root(
    ) {
        bip371(14);
    }

    #[test]
    fn one_p2tr_script_path_only_output_with_dummy_internal_key_taptree_script_keys_and_derivation_paths(
    ) {
        bip371(15);
    }

    #[test]
    fn one_p2tr_script_path_only_input_with_dummy_internal_key_scripts_script_key_derivation_paths_merkle_root_and_script_path_signatures(
    ) {
        bip371(16);
    }
}
