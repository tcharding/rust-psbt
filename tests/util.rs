#![cfg(all(feature = "std", feature = "base64"))]
// Functions in this file are all used but clippy complains still.
#![allow(dead_code)]

use core::str::FromStr;

use psbt::bitcoin::hex::{self, FromHex};
use psbt::v0;

#[track_caller]
pub fn hex_psbt_v0(s: &str) -> Result<v0::Psbt, psbt::Error> {
    let r: Result<Vec<u8>, hex::HexToBytesError> = Vec::from_hex(s);
    match r {
        Err(_e) => panic!("unable to parse PSBT v0 from hex string {}", s),
        Ok(v) => v0::Psbt::deserialize(&v),
    }
}

#[track_caller]
pub fn assert_valid_v0(hex: &str, base64: &str) {
    if let Err(e) = hex_psbt_v0(hex) {
        println!("Parse PSBT v0 (from hex) error: {:?}\n\n{}\n", e, hex);
        panic!()
    }
    // If we got this far decoding works so this is basically just a sanity check.
    assert!(v0::Psbt::from_str(base64).is_ok());
}

#[track_caller]
pub fn assert_invalid_v0(hex: &str, base64: &str) {
    assert!(hex_psbt_v0(hex).is_err());
    assert!(v0::Psbt::from_str(base64).is_err());
}
