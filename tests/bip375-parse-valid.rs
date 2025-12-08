//! BIP-375 Silent Payments Parse Valid Tests

#![cfg(all(feature = "std", feature = "base64", feature = "silent-payments"))]

mod util;

use core::str::FromStr;

use psbt_v2::v2::{Creator, Psbt};

/// Helper: Create a minimal valid PSBTv2 with BIP-375 fields populated correctly
fn valid_psbt_with_bip375_global_fields() -> Psbt {
    let mut psbt = Creator::new().psbt();
    let scan_key = vec![0x02u8; 33];
    let ecdh_share = vec![0x04u8; 33];
    let dleq_proof = vec![0xAAu8; 64];

    psbt.global.sp_ecdh_shares.insert(scan_key.clone(), ecdh_share);
    psbt.global.sp_dleq_proofs.insert(scan_key, dleq_proof);
    psbt
}

/// Test: Valid PSBT with both ECDH and DLEQ should succeed (sanity check)
#[test]
fn bip375_global_fields_both_present_valid() {
    let psbt = valid_psbt_with_bip375_global_fields();

    let bytes = psbt.serialize();
    let result = Psbt::deserialize(&bytes);
    assert!(result.is_ok(), "should succeed when both ECDH and DLEQ are present");

    let roundtrip = result.unwrap();
    assert_eq!(roundtrip.global.sp_ecdh_shares.len(), 1);
    assert_eq!(roundtrip.global.sp_dleq_proofs.len(), 1);
}

// =============================================================================
// BIP-375 Test Vectors - Valid Cases Serialization Constraints
// =============================================================================

/// Test: Single signer with global ECDH share
/// Source: BIP-375 test vectors
#[test]
fn bip375_test_vector_single_signer_global_shares_should_parse() {
    let base64 = "cHNidP8B+wQCAAAAAQIEAgAAAAEEBAEAAAABBQQBAAAAAQYBAyIHAtAp/5beLLz3gr5DWcSGIOqSvN1r7wMrlRWLkaFpP7T4IQJVFk55JtUNUqCf+ZBkel6Vwdsb/GimFvvC2iE5J/mL/yIIAtAp/5beLLz3gr5DWcSGIOqSvN1r7wMrlRWLkaFpP7T4QMHWfzh4gr+BeRXqFYIdZNWzg1wfwFxVjOPYJJKhfZCMEEh9u5vdwQgMjC2cGXGyZgg8aQVOIhk/JEEorGZzfmAAAQ4gbprLPJXWyu5NSnIlAmnrjz0Fcu1PhPS3/DOpmr4+OgUBDwQAAAAAAQEfoIYBAAAAAAAWABT42vdq2AOw76ldbP+K7giR068cjAEQBP7///8iBgPTV/fAcY8keOP9j4zMJynd2MDMrrHwKxgab0TUO5+NjQQAAAAAAQMEAQAAAAABAwgYcwEAAAAAAAEEIlEgrhn77icwoalS19JZjMcD/d87lyslFIse0aea6HOdXgcBCUIC0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPgCTVGDU/S9GNdpz2j/Yu8QZptwhiRrCmQD/le95JIRRIsA";

    assert!(
        psbt_v2::v2::Psbt::from_str(base64).is_ok(),
        "should parse: single signer global shares"
    );
}

/// Test: Multi-party with per-input ECDH shares
/// Source: BIP-375 test vectors
#[test]
fn bip375_test_vector_per_input_shares_should_parse() {
    let base64 = "cHNidP8B+wQCAAAAAQIEAgAAAAEEBAIAAAABBQQBAAAAAQYBAwABDiBc+IxEpEzVImNhvtEHUZRvn4cJUikR4HeBX19/B4WvaQEPBAAAAAABAR9QwwAAAAAAABYAFPja92rYA7DvqV1s/4ruCJHTrxyMARAE/v///yIGA9NX98BxjyR44/2PjMwnKd3YwMyusfArGBpvRNQ7n42NBAAAAAABAwQBAAAAIh0C0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPghAlUWTnkm1Q1SoJ/5kGR6XpXB2xv8aKYW+8LaITkn+Yv/Ih4C0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPhAwdZ/OHiCv4F5FeoVgh1k1bODXB/AXFWM49gkkqF9kIwQSH27m93BCAyMLZwZcbJmCDxpBU4iGT8kQSisZnN+YAABDiAT0u662aEJkUdBDIam/gsg7p23WdpBz9Tul5LNUBI3FQEPBAAAAAABAR9QwwAAAAAAABYAFEIccVrt+YOvDjtnb/fElNEFT826ARAE/v///yIGAo8dCC1gAfpLqJmkA9r5sdsBvpJcIlM69jDuZJOwvp95BAAAAAABAwQBAAAAIh0C0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPghA1voNBApxyR/ork41dS4Wzpp+9kxe62Fr2V5knHctCgBIh4C0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPhAwP4szFLfu5Jb0/9lS3qW2OwOAxpn0EG0+Zyw6BFJ4oeoK9PVG8D/czrOfTKrY9YSGGVFd4CPssf7BtK+Bv86tgABAwgYcwEAAAAAAAEEIlEgC9xqHau4dRdnjCtffc3/KXbcXRE1xN2T9mcj6++5jiUBCUIC0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPgCTVGDU/S9GNdpz2j/Yu8QZptwhiRrCmQD/le95JIRRIsA";

    assert!(
        psbt_v2::v2::Psbt::from_str(base64).is_ok(),
        "should parse: multi party per input shares"
    );
}

/// Test: Silent payment with change detection
/// Source: BIP-375 test vectors
#[test]
fn bip375_test_vector_output_with_change_should_parse() {
    let base64 = "cHNidP8B+wQCAAAAAQIEAgAAAAEEBAEAAAABBQQCAAAAAQYBAwABDiAlbK6m2hWAb7hW7a50mI1EDHqxtcCGHsgR0ZCSdHudHAEPBAAAAAABAR+ghgEAAAAAABYAFPja92rYA7DvqV1s/4ruCJHTrxyMARAE/v///yIGA9NX98BxjyR44/2PjMwnKd3YwMyusfArGBpvRNQ7n42NBAAAAAABAwQBAAAAIh0C0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPghAlUWTnkm1Q1SoJ/5kGR6XpXB2xv8aKYW+8LaITkn+Yv/Ih4C0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPhAwdZ/OHiCv4F5FeoVgh1k1bODXB/AXFWM49gkkqF9kIwQSH27m93BCAyMLZwZcbJmCDxpBU4iGT8kQSisZnN+YAABAwhQwwAAAAAAAAEEIlEgVbkWS8N9yG9biTYWgqowiLWz+lPa20PpXxvRE5uxwDUBCUIC0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPgD9SRDSFIBZWa8RdH6alxaGGLN2TPxXIQ7QnI4IvUlMjcBCgQBAAAAAAEDCMivAAAAAAAAAQQWABTjwxDMKvOsbmLK5L0j4+5SueHJWSICA9NX98BxjyR44/2PjMwnKd3YwMyusfArGBpvRNQ7n42NDAAAAAAAAAAAAAAAAQA=";

    assert!(
        psbt_v2::v2::Psbt::from_str(base64).is_ok(),
        "should parse: silent payment with change detection"
    );
}

/// Test: Multiple silent payment outputs to same scan key
/// Source: BIP-375 test vectors
#[test]
fn bip375_test_vector_multiple_outputs_same_key_should_parse() {
    let base64 = "cHNidP8B+wQCAAAAAQIEAgAAAAEEBAEAAAABBQQCAAAAAQYBAyIHAtAp/5beLLz3gr5DWcSGIOqSvN1r7wMrlRWLkaFpP7T4IQJVFk55JtUNUqCf+ZBkel6Vwdsb/GimFvvC2iE5J/mL/yIIAtAp/5beLLz3gr5DWcSGIOqSvN1r7wMrlRWLkaFpP7T4QMHWfzh4gr+BeRXqFYIdZNWzg1wfwFxVjOPYJJKhfZCMEEh9u5vdwQgMjC2cGXGyZgg8aQVOIhk/JEEorGZzfmAAAQ4gLHvTL/FQccCuAyc4ZKFDbIpWITVp4RMtz46nPsjDMiIBDwQAAAAAAQEfoIYBAAAAAAAWABT42vdq2AOw76ldbP+K7giR068cjAEQBP7///8iBgPTV/fAcY8keOP9j4zMJynd2MDMrrHwKxgab0TUO5+NjQQAAAAAAQMEAQAAAAABAwhAnAAAAAAAAAEEIlEg+ytxOv1SuiRxgbmYQapPLIhVut99rOLrLjBV2hPuK4wBCUIC0Cn/lt4svPeCvkNZxIYg6pK83WvvAyuVFYuRoWk/tPgCTVGDU/S9GNdpz2j/Yu8QZptwhiRrCmQD/le95JIRRIsAAQMI2NYAAAAAAAABBCJRIFmgqeG9mJh0IBNVOGDtC0S3JvvFIOnFcbxGSV8kefYYAQlCAtAp/5beLLz3gr5DWcSGIOqSvN1r7wMrlRWLkaFpP7T4Ak1Rg1P0vRjXac9o/2LvEGabcIYkawpkA/5XveSSEUSLAA==";

    assert!(
        psbt_v2::v2::Psbt::from_str(base64).is_ok(),
        "should parse: multiple outputs to same scan key"
    );
}
