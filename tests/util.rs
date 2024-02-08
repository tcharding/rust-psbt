#![cfg(all(feature = "std", feature = "base64"))]
// Functions in this file are all used but clippy complains still.
#![allow(dead_code)]

use core::str::FromStr;

use psbt_v2::bitcoin::hex::{self, FromHex};
use psbt_v2::{v0, v2};

#[track_caller]
pub fn hex_psbt_v0(s: &str) -> Result<v0::Psbt, v0::bitcoin::Error> {
    let r: Result<Vec<u8>, hex::HexToBytesError> = Vec::from_hex(s);
    match r {
        Err(_e) => panic!("unable to parse PSBT v0 from hex string {}", s),
        Ok(v) => v0::Psbt::deserialize(&v),
    }
}

#[track_caller]
pub fn hex_psbt_v2(s: &str) -> Result<v2::Psbt, v2::DeserializeError> {
    let r: Result<Vec<u8>, hex::HexToBytesError> = Vec::from_hex(s);
    match r {
        Err(_e) => panic!("unable to parse PSBT v2 from hex string {}", s),
        Ok(v) => v2::Psbt::deserialize(&v),
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
pub fn assert_valid_v2(hex: &str, base64: &str) {
    if let Err(e) = hex_psbt_v2(hex) {
        println!("Parse PSBT v2 (from hex) error: {:?}\n\n{}\n", e, hex);
        panic!()
    }
    // If we got this far decoding works so this is basically just a sanity check.
    assert!(v2::Psbt::from_str(base64).is_ok());
}

#[track_caller]
pub fn assert_invalid_v0(hex: &str, base64: &str) {
    assert!(hex_psbt_v0(hex).is_err());
    assert!(v0::Psbt::from_str(base64).is_err());
}

#[track_caller]
pub fn assert_invalid_v2(hex: &str, base64: &str) {
    assert!(hex_psbt_v2(hex).is_err());
    assert!(v2::Psbt::from_str(base64).is_err());
}
