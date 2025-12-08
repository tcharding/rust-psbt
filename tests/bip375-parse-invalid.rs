//! BIP-375 Silent Payments Parse Invalid Tests

#![cfg(all(feature = "std", feature = "base64", feature = "silent-payments"))]

mod util;

use core::str::FromStr;

use psbt_v2::v2::{Creator, Psbt};

/// Test: Global field mismatch - DLEQ proofs present but no ECDH shares
/// Expected error: DecodeError::FieldMismatch
#[test]
fn bip375_global_field_mismatch_dleq_only() {
    // Approach 1: Programmatic
    let mut psbt = Creator::new().psbt();
    psbt.global.sp_dleq_proofs.insert(vec![0x02u8; 33], vec![0xAAu8; 64]);

    let bytes = psbt.serialize();
    assert!(Psbt::deserialize(&bytes).is_err(), "should fail due to DLEQ without ECDH");
}

/// Test: Duplicate scan key in global ECDH shares
/// Expected error: InsertPairError::DuplicateKey
/// Note: This test demonstrates a limitation - BTreeMap prevents duplicates at construction,
/// so we must use raw hex to test the deserialization error path.
#[test]
fn bip375_global_duplicate_scan_key_ecdh() {
    // Raw hex with duplicate ECDH entries for the same scan key
    // This will be caught during deserialization when inserting the second occurrence
    let hex = concat!(
        "70736274ff", // magic
        "01fb04",
        "02000000", // version = 2
        "010204",
        "02000000", // tx_version = 2
        "010401",
        "00", // input_count = 0
        "010501",
        "00", // output_count = 0
        "010601",
        "00", // tx_modifiable = 0
        // First ECDH entry with scan_key = 0x02 repeated 33 times
        "2207",
        "020202020202020202020202020202020202020202020202020202020202020202", // ECDH key (33 bytes)
        "21",
        "040404040404040404040404040404040404040404040404040404040404040404", // ECDH value (33 bytes)
        // Second ECDH entry with SAME scan_key but different value
        "2207",
        "020202020202020202020202020202020202020202020202020202020202020202", // ECDH key (33 bytes) - DUPLICATE!
        "21",
        "050505050505050505050505050505050505050505050505050505050505050505", // ECDH value (33 bytes, different)
        // Matching DLEQ entries (required to avoid field mismatch error)
        "2208",
        "020202020202020202020202020202020202020202020202020202020202020202", // DLEQ key (33 bytes)
        "40", // DLEQ value length (64 bytes)
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // DLEQ value part 1
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // DLEQ value part 2
        "00", // global terminator
    );

    assert!(util::hex_psbt_v2(hex).is_err(), "should fail due to duplicate scan key in global");
}

/// Test: Per-input field mismatch - DLEQ proofs present but no ECDH shares
/// Expected error: DecodeError::FieldMismatch
#[test]
fn bip375_input_field_mismatch_dleq_only() {
    // Minimal PSBTv2 with one input containing DLEQ proof but no ECDH share
    let hex = concat!(
        "70736274ff", // magic
        "01fb04",
        "02000000", // version = 2
        "010204",
        "02000000", // tx_version = 2
        "010401",
        "01", // input_count = 1
        "010501",
        "00", // output_count = 0
        "010601",
        "00", // tx_modifiable = 0
        "00", // global terminator
        // Input 0
        "010e20",
        "0000000000000000000000000000000000000000000000000000000000000000", // prev txid
        "010f04",
        "00000000", // output index
        // DLEQ proof without matching ECDH share - MISMATCH!
        "221e",
        "020202020202020202020202020202020202020202020202020202020202020202", // DLEQ key (33 bytes)
        "40", // DLEQ value length (64 bytes)
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // DLEQ value part 1
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // DLEQ value part 2
        "00", // input terminator
    );

    assert!(util::hex_psbt_v2(hex).is_err(), "should fail: input has DLEQ proof but no ECDH share");
}

/// Test: Duplicate scan key in per-input ECDH shares
/// Expected error: InsertPairError::DuplicateKey
#[test]
fn bip375_input_duplicate_scan_key_ecdh() {
    // Minimal PSBTv2 with one input containing duplicate ECDH shares for the same scan key
    let hex = concat!(
        "70736274ff", // magic
        "01fb04",
        "02000000", // version = 2
        "010204",
        "02000000", // tx_version = 2
        "010401",
        "01", // input_count = 1
        "010501",
        "00", // output_count = 0
        "010601",
        "00", // tx_modifiable = 0
        "00", // global terminator
        // Input 0
        "010e20",
        "0000000000000000000000000000000000000000000000000000000000000000", // prev txid
        "010f04",
        "00000000", // output index
        // First per-input ECDH entry with scan_key = 0x02 repeated 33 times
        "221d",
        "020202020202020202020202020202020202020202020202020202020202020202", // ECDH key (33 bytes)
        "21",
        "040404040404040404040404040404040404040404040404040404040404040404", // ECDH value (33 bytes)
        // Second per-input ECDH entry with SAME scan_key - DUPLICATE!
        "221d",
        "020202020202020202020202020202020202020202020202020202020202020202", // ECDH key (33 bytes) - DUPLICATE!
        "21",
        "050505050505050505050505050505050505050505050505050505050505050505", // ECDH value (33 bytes, different)
        // Matching DLEQ entries (required to avoid field mismatch error)
        "221e",
        "020202020202020202020202020202020202020202020202020202020202020202", // DLEQ key (33 bytes)
        "40", // DLEQ value length (64 bytes)
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // DLEQ value part 1
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // DLEQ value part 2
        "00", // input terminator
    );

    assert!(util::hex_psbt_v2(hex).is_err(), "should fail due to duplicate scan key in input");
}

// =============================================================================
// BIP-375 Test Vectors - Invalid Cases Serialization Constraints
// =============================================================================

/// Test: Missing DLEQ proof for ECDH share (per-input)
/// Expected error: DecodeError::FieldMismatch
#[test]
fn bip375_test_vector_missing_input_dleq_proof() {
    let base64 = "cHNidP8B+wQCAAAAAQIEAgAAAAEEBAEAAAABBQQBAAAAAQYBAwABDiCrtYht20vGCALx8ZiisSkDZZzJ7nPgIx1FVehBiNyWQAEPBAAAAAABAR+ghgEAAAAAABYAFPja92rYA7DvqV1s/4ruCJHTrxyMARAE/v///yIGA9NX98BxjyR44/2PjMwnKd3YwMyusfArGBpvRNQ7n42NBAAAAAAiHQLQKf+W3iy894K+Q1nEhiDqkrzda+8DK5UVi5GhaT+0+CECVRZOeSbVDVKgn/mQZHpelcHbG/xophb7wtohOSf5i/8BAwQBAAAAAAEDCBhzAQAAAAAAAQQiUSAXu7qlEuAw+8o+5RT3sjgH4RGDGkdFRHCRNMn5v0a2xAEJQgLQKf+W3iy894K+Q1nEhiDqkrzda+8DK5UVi5GhaT+0+AJNUYNT9L0Y12nPaP9i7xBmm3CGJGsKZAP+V73kkhFEiwA=";

    assert!(
        psbt_v2::v2::Psbt::from_str(base64).is_err(),
        "should fail: input has ECDH share but no DLEQ proof"
    );
}

/// Test: Global ECDH share without DLEQ proof
/// Expected error: DecodeError::FieldMismatch
#[test]
fn bip375_test_vector_global_ecdh_without_dleq() {
    let base64 = "cHNidP8B+wQCAAAAAQIEAgAAAAEEBAEAAAABBQQBAAAAAQYBAyIHAtAp/5beLLz3gr5DWcSGIOqSvN1r7wMrlRWLkaFpP7T4IQJVFk55JtUNUqCf+ZBkel6Vwdsb/GimFvvC2iE5J/mL/wABDiD2W3/BmfoPsrzNsfoGEte1D2K0+PqV1WXEoB9MWC6SpAEPBAAAAAABAR+ghgEAAAAAABYAFPja92rYA7DvqV1s/4ruCJHTrxyMARAE/v///yIGA9NX98BxjyR44/2PjMwnKd3YwMyusfArGBpvRNQ7n42NBAAAAAABAwQBAAAAAAEDCBhzAQAAAAAAAQQiUSCBAAI55HC7UjfZ+r6wGeJ5j8RXLnnJOQtdHV42G7fgIAEJQgLQKf+W3iy894K+Q1nEhiDqkrzda+8DK5UVi5GhaT+0+AJNUYNT9L0Y12nPaP9i7xBmm3CGJGsKZAP+V73kkhFEiwA=";

    assert!(
        psbt_v2::v2::Psbt::from_str(base64).is_err(),
        "should fail: global ECDH share present but no DLEQ proof"
    );
}
