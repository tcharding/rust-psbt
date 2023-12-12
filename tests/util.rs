#![cfg(all(feature = "std", feature = "base64"))]

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
