// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for PSBT v0 deserialization and serialization round-trips.

#![no_main]
use libfuzzer_sys::fuzz_target;
use psbt_v2::v0::Psbt;

fn do_test(data: (&[u8], &[u8])) {
    let (bytes_a, bytes_b) = data;

    // Deserialize first PSBT v0
    let Ok(psbt_a) = Psbt::deserialize(bytes_a) else {
        return;
    };

    // Test round-trip.
    let ser = psbt_a.serialize();
    if let Ok(deser) = Psbt::deserialize(&ser) {
        assert_eq!(ser, deser.serialize());
    }

    // Test combining two PSBTs.
    let Ok(mut psbt_b) = Psbt::deserialize(bytes_b) else {
        return;
    };

    let mut psbt_a_clone = psbt_a.clone();
    // Combining should be commutative in terms of success/failure.
    let result_ab = psbt_b.combine(psbt_a).is_ok();
    let result_ba = psbt_a_clone.combine(psbt_b).is_ok();
    assert_eq!(result_ab, result_ba);
}

fuzz_target!(|data: (&[u8], &[u8])| {
    do_test(data);
});
