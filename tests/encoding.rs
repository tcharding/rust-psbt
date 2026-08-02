// SPDX-License-Identifier: CC0-1.0

//! Integration tests for PSBT encoding.

use bitcoin::Sequence;
#[cfg(feature = "std")]
use psbt_v2::encoding::encode_to_writer;
use psbt_v2::encoding::{encode_to_hex, encode_to_vec};
use psbt_v2::Version;

#[test]
fn version_encode_to_vec() {
    let version = Version::TWO;
    let bytes = encode_to_vec(&version);
    assert_eq!(bytes, vec![0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn version_encode_to_hex() {
    let version = Version::ZERO;
    let hex = encode_to_hex(&version, bitcoin_consensus_encoding::hex::Case::Lower);
    assert_eq!(hex, "00000000");
}

#[cfg(feature = "std")]
#[test]
fn version_encode_to_writer() {
    use std::io::Cursor;

    let version = Version::TWO;
    let mut buf = vec![];
    let mut cursor = Cursor::new(&mut buf);
    encode_to_writer(&mut cursor, &version).expect("write failed");
    assert_eq!(buf, vec![0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn sequence_encode_to_vec() {
    let seq = Sequence::ZERO;
    let bytes = encode_to_vec(&seq);
    assert_eq!(bytes, vec![0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn sequence_encode_to_hex() {
    let seq = Sequence::MAX;
    let hex = encode_to_hex(&seq, bitcoin_consensus_encoding::hex::Case::Lower);
    assert_eq!(hex, "ffffffff");
}

#[cfg(feature = "std")]
#[test]
fn sequence_encode_to_writer() {
    use std::io::Cursor;

    let seq = Sequence::ZERO;
    let mut buf = vec![];
    let mut cursor = Cursor::new(&mut buf);
    encode_to_writer(&mut cursor, &seq).expect("write failed");
    assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x00]);
}
