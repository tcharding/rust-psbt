// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::{TapLeafHash, TapTree};
use bitcoin::{secp256k1, ScriptBuf};

use crate::consts::{
    PSBT_OUT_AMOUNT, PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_PROPRIETARY, PSBT_OUT_REDEEM_SCRIPT,
    PSBT_OUT_SCRIPT, PSBT_OUT_TAP_BIP32_DERIVATION, PSBT_OUT_TAP_INTERNAL_KEY, PSBT_OUT_TAP_TREE,
    PSBT_OUT_WITNESS_SCRIPT,
};
use crate::error::write_err;
use crate::prelude::*;
use crate::v0::map::Map;
use crate::{consts, io, raw, serialize};

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<ScriptBuf>,
    /// The witness script for this output.
    pub witness_script: Option<ScriptBuf>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivations: BTreeMap<secp256k1::PublicKey, KeySource>,
    /// The internal pubkey.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Output tree.
    pub tap_tree: Option<TapTree>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Proprietary key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    pub(in crate::v0) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        let mut rv = Self::default();

        loop {
            match raw::Pair::decode(r) {
                Ok(pair) => rv.insert_pair(pair)?,
                Err(serialize::Error::NoMorePairs) => break,
                Err(e) => return Err(DecodeError::DeserPair(e)),
            }
        }

        Ok(rv)
    }

    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), InsertPairError> {
        let raw::Pair { key: raw_key, value: raw_value } = pair;

        match raw_key.type_value {
            PSBT_OUT_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivations <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_OUT_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietaries.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    }
                    btree_map::Entry::Occupied(_) =>
                        return Err(InsertPairError::DuplicateKey(raw_key)),
                }
            }
            PSBT_OUT_TAP_INTERNAL_KEY => {
                impl_psbt_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|<raw_value: XOnlyPublicKey>
                }
            }
            PSBT_OUT_TAP_TREE => {
                impl_psbt_insert_pair! {
                    self.tap_tree <= <raw_key: _>|<raw_value: TapTree>
                }
            }
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.tap_key_origins <= <raw_key: XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
                }
            }
            v if v == PSBT_OUT_AMOUNT || v == PSBT_OUT_SCRIPT => {
                return Err(InsertPairError::ExcludedKey { key_type_value: v });
            }
            _ => match self.unknowns.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                btree_map::Entry::Occupied(k) =>
                    return Err(InsertPairError::DuplicateKey(k.key().clone())),
            },
        }

        Ok(())
    }

    /// Combines this [`Output`] with `other` `Output` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) {
        combine_option!(redeem_script, self, other);
        combine_option!(witness_script, self, other);
        combine_map!(bip32_derivations, self, other);
        combine_option!(tap_internal_key, self, other);
        combine_option!(tap_tree, self, other);
        combine_map!(tap_key_origins, self, other);
        combine_map!(proprietaries, self, other);
        combine_map!(unknowns, self, other);
    }
}

impl Map for Output {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_OUT_REDEEM_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_OUT_WITNESS_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivations, PSBT_OUT_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_OUT_TAP_INTERNAL_KEY)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_tree, PSBT_OUT_TAP_TREE)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_OUT_TAP_BIP32_DERIVATION)
        }

        for (key, value) in self.proprietaries.iter() {
            rv.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }

        for (key, value) in self.unknowns.iter() {
            rv.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        rv
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error deserializing a pair.
    DeserPair(serialize::Error),
    /// Key must be excluded from this version of PSBT (see consts.rs for u8 values).
    ExcludedKey { key_type_value: u8 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => write_err!(f, "error inserting a pair"; e),
            DeserPair(ref e) => write_err!(f, "error deserializing a pair"; e),
            ExcludedKey { key_type_value } => write!(
                f,
                "found a keypair type that is explicitly excluded: {}",
                consts::psbt_out_key_type_value_to_str(key_type_value)
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => Some(e),
            DeserPair(ref e) => Some(e),
            ExcludedKey { .. } => None,
        }
    }
}

impl From<InsertPairError> for DecodeError {
    fn from(e: InsertPairError) -> Self { Self::InsertPair(e) }
}

/// Error inserting a key-value pair.
#[derive(Debug)]
pub enum InsertPairError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Error deserializing raw value.
    Deser(serialize::Error),
    /// Key should contain data.
    InvalidKeyDataEmpty(raw::Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(raw::Key),
    /// Key must be excluded from this version of PSBT (see consts.rs for u8 values).
    ExcludedKey { key_type_value: u8 },
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InsertPairError::*;

        match *self {
            DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Deser(ref e) => write_err!(f, "error deserializing raw value"; e),
            InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            InvalidKeyDataNotEmpty(ref key) => write!(f, "key should not contain data: {}", key),
            ExcludedKey { key_type_value } => write!(
                f,
                "found a keypair type that is explicitly excluded: {}",
                consts::psbt_global_key_type_value_to_str(key_type_value)
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InsertPairError::*;

        match *self {
            Deser(ref e) => Some(e),
            DuplicateKey(_)
            | InvalidKeyDataEmpty(_)
            | InvalidKeyDataNotEmpty(_)
            | ExcludedKey { .. } => None,
        }
    }
}

impl From<serialize::Error> for InsertPairError {
    fn from(e: serialize::Error) -> Self { Self::Deser(e) }
}
