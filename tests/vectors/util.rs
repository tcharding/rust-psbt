//! Test utility functions.

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
    assert!(base64.parse::<v0::Psbt>().is_ok());
}

#[track_caller]
pub fn assert_valid_v2(hex: Option<&str>, base64: &str) {
    if let Some(h) = hex.filter(|h| !h.is_empty()) {
        assert!(hex_psbt_v2(h).is_ok());
    }
    assert!(base64.parse::<v2::Psbt>().is_ok());
}

#[track_caller]
pub fn assert_invalid_v0(hex: &str, base64: &str) {
    assert!(hex_psbt_v0(hex).is_err());
    assert!(base64.parse::<v0::Psbt>().is_err());
}

#[track_caller]
pub fn assert_invalid_v2(hex: Option<&str>, base64: &str) {
    if let Some(h) = hex.filter(|h| !h.is_empty()) {
        assert!(hex_psbt_v2(h).is_err());
    }
    assert!(base64.parse::<v2::Psbt>().is_err());
}
