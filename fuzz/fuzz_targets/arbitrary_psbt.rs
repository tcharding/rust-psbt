// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for arbitrary PSBT v0 construction and operations.

#![no_main]
use libfuzzer_sys::fuzz_target;
use psbt_v2::v0::Psbt;

fn do_test(data: &[u8]) {
    if let Ok(mut psbt) = Psbt::deserialize(data) {
        // Clone and check basic operations.
        let cloned = psbt.clone();
        let _ = cloned.serialize();

        // Try combining with another PSBT if we have more data.
        if data.len() > 10 {
            let split_point = data.len() / 2;
            if let Ok(other) = Psbt::deserialize(&data[split_point..]) {
                let _ = psbt.combine(other);
            }
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
