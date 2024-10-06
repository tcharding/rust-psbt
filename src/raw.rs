// SPDX-License-Identifier: CC0-1.0

//! Raw PSBT key-value pairs.
//!
//! [BIP-174] defines the following:
//!
//! - `<keypair> := <key> <value>`
//! - `<key> := <keylen> <keytype> <keydata>`
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use core::convert::TryFrom;
use core::fmt;

use bitcoin::consensus::encode as consensus;
use bitcoin::consensus::encode::{
    deserialize, serialize, Decodable, Encodable, ReadExt, VarInt, WriteExt, MAX_VEC_SIZE,
};
use bitcoin::hex::DisplayHex;

use crate::io::{self, BufRead, Write};
use crate::prelude::*;
use crate::serialize::{Deserialize, Serialize};
use crate::{serialize, v0};

/// A PSBT key-value pair in its raw byte form.
///
/// - `<keypair> := <key> <value>`
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Pair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value of this key-value pair in raw byte form.
    ///
    /// - `<value> := <valuelen> <valuedata>`
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub value: Vec<u8>,
}

impl Pair {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, serialize::Error> {
        Ok(Pair { key: Key::decode(r)?, value: Decodable::consensus_decode(r)? })
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "type: {:#x}, key: {:x}", self.type_value, self.key.as_hex())
    }
}

impl Serialize for Pair {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.key.serialize());
        // <value> := <valuelen> <valuedata>
        self.value.consensus_encode(&mut buf).unwrap();
        buf
    }
}

impl Deserialize for Pair {
    fn deserialize(bytes: &[u8]) -> Result<Self, serialize::Error> {
        let mut decoder = bytes;
        Pair::decode(&mut decoder)
    }
}

/// The key of a key-value PSBT pair, in its raw byte form.
///
/// - `<key> := <keylen> <keytype> <keydata>`
///
/// We do not carry the `keylen` around, we just create the `VarInt` length when serializing and
/// deserializing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Key {
    /// The `keytype` of this PSBT map key (`keytype`).
    pub type_value: u8,
    /// The `keydata` itself in raw byte form.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

impl Key {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, serialize::Error> {
        let VarInt(byte_size): VarInt = Decodable::consensus_decode(r)?;

        if byte_size == 0 {
            return Err(serialize::Error::NoMorePairs);
        }

        let key_byte_size: u64 = byte_size - 1;

        if key_byte_size > MAX_VEC_SIZE as u64 {
            return Err(consensus::Error::OversizedVectorAllocation {
                requested: key_byte_size as usize,
                max: MAX_VEC_SIZE,
            }
            .into());
        }

        let type_value: u8 = Decodable::consensus_decode(r)?;

        let mut key = Vec::with_capacity(key_byte_size as usize);
        for _ in 0..key_byte_size {
            key.push(Decodable::consensus_decode(r)?);
        }

        Ok(Key { type_value, key })
    }

    pub(crate) fn into_v0(self) -> v0::bitcoin::raw::Key {
        v0::bitcoin::raw::Key { type_value: self.type_value, key: self.key }
    }
}

impl Serialize for Key {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        VarInt::from(self.key.len() + 1)
            .consensus_encode(&mut buf)
            .expect("in-memory writers don't error");

        self.type_value.consensus_encode(&mut buf).expect("in-memory writers don't error");

        for key in &self.key {
            key.consensus_encode(&mut buf).expect("in-memory writers don't error");
        }

        buf
    }
}

/// Default implementation for proprietary key subtyping
pub type ProprietaryType = u8;

/// Proprietary keys (i.e. keys starting with 0xFC byte) with their internal
/// structure according to BIP 174.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct ProprietaryKey<Subtype = ProprietaryType>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    /// Proprietary type prefix used for grouping together keys under some
    /// application and avoid namespace collision
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub prefix: Vec<u8>,
    /// Custom proprietary subtype
    pub subtype: Subtype,
    /// Additional key bytes (like serialized public key data etc)
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

impl<Subtype> ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    /// Constructs full [Key] corresponding to this proprietary key type
    pub fn to_key(&self) -> Key { Key { type_value: 0xFC, key: serialize(self) } }

    pub(crate) fn into_v0(self) -> v0::bitcoin::raw::ProprietaryKey<Subtype> {
        v0::bitcoin::raw::ProprietaryKey {
            prefix: self.prefix,
            subtype: self.subtype,
            key: self.key,
        }
    }
}

impl<Subtype> TryFrom<Key> for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    type Error = serialize::Error;

    /// Constructs a [`ProprietaryKey`] from a [`Key`].
    ///
    /// # Errors
    ///
    /// Returns [`serialize::Error::InvalidProprietaryKey`] if `key` does not start with `0xFC`.
    fn try_from(key: Key) -> Result<Self, Self::Error> {
        if key.type_value != 0xFC {
            return Err(serialize::Error::InvalidProprietaryKey);
        }

        Ok(deserialize(&key.key)?)
    }
}

impl<Subtype> Encodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)? + 1;
        w.emit_u8(self.subtype.into())?;
        w.write_all(&self.key)?;
        len += self.key.len();
        Ok(len)
    }
}

impl<Subtype> Decodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, consensus::Error> {
        let prefix = Vec::<u8>::consensus_decode(r)?;
        let subtype = Subtype::from(r.read_u8()?);

        // The limit is a DOS protection mechanism the exact value is not
        // important, 1024 bytes is bigger than any key should be.
        let mut key = vec![];
        let _ = r.read_to_limit(&mut key, 1024)?;

        Ok(ProprietaryKey { prefix, subtype, key })
    }
}
