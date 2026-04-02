#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);

    let Ok(bytes_a) = <&[u8]>::arbitrary(&mut unstructured) else {
        return;
    };
    let Ok(bytes_b) = <&[u8]>::arbitrary(&mut unstructured) else {
        return;
    };

    let Ok(psbt_a) = psbt_v2::v0::Psbt::deserialize(bytes_a) else {
        return;
    };

    let ser = psbt_v2::v0::Psbt::serialize(&psbt_a);
    let deser = psbt_v2::v0::Psbt::deserialize(&ser).unwrap();
    assert_eq!(ser, psbt_v2::v0::Psbt::serialize(&deser));

    let Ok(mut psbt_b) = psbt_v2::v0::Psbt::deserialize(bytes_b) else {
        return;
    };

    let mut psbt_a_clone = psbt_a.clone();
    assert_eq!(psbt_b.combine(psbt_a).is_ok(), psbt_a_clone.combine(psbt_b).is_ok());
}

fuzz_target!(|data| {
    do_test(data);
});
