// SPDX-License-Identifier: CC0-1.0

#![allow(unused)]

use core::convert::TryFrom;
use core::{cmp, fmt};

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
use bitcoin::consensus::encode::MAX_VEC_SIZE;
use bitcoin::consensus::{self, Decodable};
use bitcoin::locktime::absolute;
use bitcoin::{bip32, transaction, Transaction, VarInt};

use crate::consts::{
    PSBT_GLOBAL_FALLBACK_LOCKTIME, PSBT_GLOBAL_INPUT_COUNT, PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_TX_MODIFIABLE, PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB,
};
use crate::error::write_err;
use crate::io::{self, Cursor, Read};
use crate::prelude::*;
use crate::serialize::{Deserialize, Serialize};
use crate::v2::error::InconsistentKeySourcesError;
use crate::v2::map::Map;
use crate::version::Version;
use crate::{raw, v0, Error, V0, V2};

/// The Inputs Modifiable Flag, set to 1 to indicate whether inputs can be added or removed.
const INPUTS_MODIFIABLE: u8 = 0x01 << 0;
/// The Outputs Modifiable Flag, set to 1 to indicate whether outputs can be added or removed.
const OUTPUTS_MODIFIABLE: u8 = 0x01 << 1;
/// The Has SIGHASH_SINGLE flag, set to 1 to indicate whether the transaction has a SIGHASH_SINGLE
/// signature who's input and output pairing must be preserved. Essentially indicates that the
/// Constructor must iterate the inputs to determine whether and how to add or remove an input.
const SIGHASH_SINGLE: u8 = 0x01 << 2;

/// The global key-value map.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Global {
    /// The version number of this PSBT.
    pub version: Version,

    /// The version number of the transaction being built.
    pub tx_version: transaction::Version,

    /// The transaction locktime to use if no inputs specify a required locktime.
    pub fallback_lock_time: Option<absolute::LockTime>,

    /// A bitfield for various transaction modification flags.
    pub tx_modifiable_flags: u8,

    /// The number of inputs in this PSBT.
    pub input_count: usize, // Serialized in compact form as a u64 (VarInt).

    /// The number of outputs in this PSBT.
    pub output_count: usize, // Serialized in compact form as a u64 (VarInt).

    /// A map from xpub to the used key fingerprint and derivation path as defined by BIP 32.
    pub xpubs: BTreeMap<Xpub, KeySource>,

    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

impl Global {
    fn new() -> Self {
        Global {
            version: V2,
            tx_version: transaction::Version::TWO,
            fallback_lock_time: None,
            tx_modifiable_flags: 0x00,
            input_count: 0,
            output_count: 0,
            xpubs: Default::default(),
            proprietaries: Default::default(),
            unknowns: Default::default(),
        }
    }

    /// Converts this `Global` to a `v0::Global`.
    pub(crate) fn into_v0(self, unsigned_tx: Transaction) -> v0::Global {
        v0::Global {
            unsigned_tx,
            version: 0,
            xpub: self.xpubs,
            proprietary: self.proprietaries,
            unknown: self.unknowns,
        }
    }

    pub(crate) fn set_inputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags |= INPUTS_MODIFIABLE;
    }

    pub(crate) fn set_outputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags |= OUTPUTS_MODIFIABLE;
    }

    pub(crate) fn set_sighash_single_flag(&mut self) { self.tx_modifiable_flags |= SIGHASH_SINGLE; }

    pub(crate) fn clear_inputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags &= !INPUTS_MODIFIABLE;
    }

    pub(crate) fn clear_outputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags &= !OUTPUTS_MODIFIABLE;
    }

    pub(crate) fn clear_sighash_single_flag(&mut self) {
        self.tx_modifiable_flags &= !SIGHASH_SINGLE;
    }

    pub(crate) fn is_inputs_modifiable(&self) -> bool {
        self.tx_modifiable_flags & INPUTS_MODIFIABLE > 0
    }

    pub(crate) fn is_outputs_modifiable(&self) -> bool {
        self.tx_modifiable_flags & OUTPUTS_MODIFIABLE > 0
    }

    pub(crate) fn has_sighash_single(&self) -> bool {
        self.tx_modifiable_flags & SIGHASH_SINGLE > 0
    }

    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        let mut r = r.take(MAX_VEC_SIZE as u64);
        let mut version: Option<u32> = None;
        let mut tx_version: Option<i32> = None;
        let mut fallback_lock_time: Option<absolute::LockTime> = None;
        let mut tx_modifiable_flags: Option<u8> = None;
        let mut input_count: Option<u64> = None;
        let mut output_count: Option<u64> = None;
        let mut xpubs: BTreeMap<Xpub, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::decode(&mut r) {
                Ok(pair) => {
                    match pair.key.type_value {
                        v if v == PSBT_GLOBAL_VERSION =>
                            if pair.key.key.is_empty() {
                                if version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(DecodeError::ValueWrongLength(vlen, 4));
                                    }
                                    let v = Decodable::consensus_decode(&mut decoder)?;
                                    if v != 2 {
                                        return Err(DecodeError::WrongVersion(v));
                                    }
                                    version = Some(v);
                                } else {
                                    return Err(DecodeError::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(DecodeError::InvalidKey(pair.key));
                            },
                        v if v == PSBT_GLOBAL_TX_VERSION =>
                            if pair.key.key.is_empty() {
                                if tx_version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(DecodeError::ValueWrongLength(vlen, 4));
                                    }
                                    tx_version = Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(DecodeError::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(DecodeError::InvalidKey(pair.key));
                            },
                        v if v == PSBT_GLOBAL_FALLBACK_LOCKTIME =>
                            if pair.key.key.is_empty() {
                                if fallback_lock_time.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(DecodeError::ValueWrongLength(vlen, 4));
                                    }
                                    fallback_lock_time =
                                        Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(DecodeError::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(DecodeError::InvalidKey(pair.key));
                            },
                        v if v == PSBT_GLOBAL_INPUT_COUNT =>
                            if pair.key.key.is_empty() {
                                if output_count.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    let count: VarInt = Decodable::consensus_decode(&mut decoder)?;
                                    input_count = Some(count.0);
                                } else {
                                    return Err(DecodeError::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(DecodeError::InvalidKey(pair.key));
                            },
                        v if v == PSBT_GLOBAL_OUTPUT_COUNT =>
                            if pair.key.key.is_empty() {
                                if output_count.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    let count: VarInt = Decodable::consensus_decode(&mut decoder)?;
                                    output_count = Some(count.0);
                                } else {
                                    return Err(DecodeError::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(DecodeError::InvalidKey(pair.key));
                            },
                        v if v == PSBT_GLOBAL_TX_MODIFIABLE =>
                            if pair.key.key.is_empty() {
                                if tx_modifiable_flags.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 1 {
                                        return Err(DecodeError::ValueWrongLength(vlen, 1));
                                    }
                                    tx_modifiable_flags =
                                        Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(DecodeError::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(DecodeError::InvalidKey(pair.key));
                            },
                        v if v == PSBT_GLOBAL_XPUB => {
                            if !pair.key.key.is_empty() {
                                let xpub = Xpub::decode(&pair.key.key)?;
                                if pair.value.is_empty() || pair.value.len() % 4 != 0 {
                                    // TODO: Add better error here.
                                    return Err(DecodeError::PathNotMod4(pair.value.len()));
                                }

                                let child_count = pair.value.len() / 4 - 1;
                                let mut decoder = Cursor::new(pair.value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..])?;
                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok(index) = u32::consensus_decode(&mut decoder) {
                                    path.push(ChildNumber::from(index))
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if let Some(key_source) =
                                    xpubs.insert(xpub, (Fingerprint::from(fingerprint), derivation))
                                {
                                    return Err(DecodeError::DuplicateXpub(key_source));
                                }
                            } else {
                                return Err(DecodeError::DuplicateKey(pair.key));
                            }
                        }
                        v if v == PSBT_GLOBAL_PROPRIETARY => match proprietaries
                            .entry(raw::ProprietaryKey::try_from(pair.key.clone())?)
                        {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(_) =>
                                return Err(DecodeError::DuplicateKey(pair.key)),
                        },
                        v if v == PSBT_GLOBAL_UNSIGNED_TX => return Err(DecodeError::UnsignedTx),
                        _ => match unknowns.entry(pair.key) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(k) =>
                                return Err(DecodeError::DuplicateKey(k.key().clone())),
                        },
                    }
                }
                Err(crate::Error::NoMorePairs) => break,
                Err(e) => return Err(DecodeError::Error(e)),
            }
        }
        let tx_version = tx_version.ok_or(DecodeError::MissingTxVersion)?;
        // TODO: Do checks for standard transaction version?
        let tx_version = transaction::Version(tx_version);

        let input_count = input_count.ok_or(DecodeError::MissingInputCount)?;
        // TODO: Is this a valid assumption, that a valid PSBT cannot have an input count that overflows a usize?
        let input_count: usize =
            usize::try_from(input_count).map_err(|_| DecodeError::CountOverflow(input_count))?;

        let output_count = output_count.ok_or(DecodeError::MissingOutputCount)?;
        // TODO: Same as for input_count.
        let output_count: usize =
            usize::try_from(output_count).map_err(|_| DecodeError::CountOverflow(output_count))?;

        // TODO: Check this default is correct.
        let tx_modifiable_flags = tx_modifiable_flags.unwrap_or(0_u8);

        let version = version.ok_or(DecodeError::MissingVersion)?;
        // TODO: Handle decoding either psbt v0 or psbt v2.
        if version != 2 {
            return Err(DecodeError::WrongVersion(version));
        }
        let version = Version::try_from(version).expect("checked above");

        Ok(Global {
            tx_version,
            fallback_lock_time,
            input_count,
            output_count,
            tx_modifiable_flags,
            version,
            xpubs,
            proprietaries,
            unknowns,
        })
    }

    /// Combines [`Global`] with `other`.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), InconsistentKeySourcesError> {
        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpubs {
            match self.xpubs.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if (derivation1 == derivation2 && fingerprint1 == fingerprint2)
                        || (derivation1.len() < derivation2.len()
                            && derivation1[..]
                                == derivation2[derivation2.len() - derivation1.len()..])
                    {
                        continue;
                    } else if derivation2[..]
                        == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(InconsistentKeySourcesError(xpub));
                }
            }
        }

        self.proprietaries.extend(other.proprietaries);
        self.unknowns.extend(other.unknowns);
        Ok(())
    }
}

impl Default for Global {
    fn default() -> Self { Self::new() }
}

impl Map for Global {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_VERSION, key: vec![] },
            value: self.version.serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_TX_VERSION, key: vec![] },
            value: self.tx_version.serialize(),
        });

        impl_psbt_get_pair! {
            rv.push(self.fallback_lock_time, PSBT_GLOBAL_FALLBACK_LOCKTIME)
        }

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_INPUT_COUNT, key: vec![] },
            value: VarInt::from(self.input_count).serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_OUTPUT_COUNT, key: vec![] },
            value: VarInt::from(self.output_count).serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_TX_MODIFIABLE, key: vec![] },
            value: vec![self.tx_modifiable_flags],
        });

        for (xpub, (fingerprint, derivation)) in &self.xpubs {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_XPUB, key: xpub.encode().to_vec() },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation.into_iter().for_each(|n| ret.extend(&u32::from(*n).to_le_bytes()));
                    ret
                },
            });
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
    /// I/O error.
    Io(io::Error),
    /// Error consensus deserializing type.
    Consensus(consensus::encode::Error),
    /// Serialized PSBT is missing the version number.
    MissingVersion,
    /// PSBT v2 expects the version to be 2.
    WrongVersion(u32),
    /// Serialized PSBT is missing the transaction version number.
    MissingTxVersion,
    /// Value (keyvalue pair) was not the correct length (got, want).
    ValueWrongLength(usize, usize),
    // TODO: Should we split this up?
    /// Failed to decode a BIP-32 type.
    Bip32(bip32::Error),
    /// xpub derivation path must be a list of 32 byte varints i.e., mod 4.
    PathNotMod4(usize),
    /// Serialized PSBT is missing the input count.
    MissingInputCount,
    /// Serialized PSBT is missing the output count.
    MissingOutputCount,
    /// Known keys must be according to spec.
    InvalidKey(raw::Key),
    /// Non-proprietary key type found when proprietary key was expected
    InvalidProprietaryKey,
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Count overflows word size for current architecture.
    CountOverflow(u64),
    /// xpubs must be unique.
    DuplicateXpub(KeySource),
    /// PSBT v2 requires exclusion of unsigned transaction.
    UnsignedTx,
    /// TODO: Remove this crate error
    Error(crate::error::Error),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            Io(ref e) => write_err!(f, "I/O error decoding global map"; e),
            Consensus(ref e) => write_err!(f, "error consensus deserializing type"; e),
            MissingVersion => write!(f, "serialized PSBT is missing the version number"),
            WrongVersion(v) => write!(f, "PSBT v2 expects the version to be 2, found: {}", v),
            MissingTxVersion =>
                write!(f, "serialized PSBT is missing the transaction version number"),
            ValueWrongLength(got, want) =>
                write!(f, "value (keyvalue pair) wrong length (got, want) {} {}", got, want),
            Bip32(ref e) => write_err!(f, "BIP-32 error"; e),
            PathNotMod4(len) =>
                write!(f, "derivation path should be a list of u32s i.e., modulo 4"),
            MissingInputCount => write!(f, "serialized PSBT is missing the input count"),
            MissingOutputCount => write!(f, "serialized PSBT is missing the output count"),
            InvalidKey(ref key) => write!(f, "invalid key: {}", key),
            InvalidProprietaryKey =>
                write!(f, "non-proprietary key type found when proprietary key was expected"),
            DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            CountOverflow(u64) => write!(f, "count overflows word size for current architecture"),
            // TODO: Use tuple instead of KeySource because this is ugly.
            DuplicateXpub(ref key_source) =>
                write!(f, "found duplicate xpub: ({}, {})", key_source.0, key_source.1),
            UnsignedTx => write!(f, "PSBT v2 requires exclusion of unsigned transaction"),
            Error(ref e) => write!(f, "TODO: Remove this"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            Io(ref e) => Some(e),
            Consensus(ref e) => Some(e),
            Bip32(ref e) => Some(e),
            Error(ref e) => Some(e),
            MissingVersion
            | WrongVersion(_)
            | MissingTxVersion
            | ValueWrongLength(..)
            | PathNotMod4(_)
            | MissingInputCount
            | MissingOutputCount
            | InvalidKey(_)
            | InvalidProprietaryKey
            | DuplicateKey(_)
            | CountOverflow(_)
            | DuplicateXpub(_)
            | UnsignedTx => None,
        }
    }
}

impl From<io::Error> for DecodeError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}

impl From<consensus::encode::Error> for DecodeError {
    fn from(e: consensus::encode::Error) -> Self { Self::Consensus(e) }
}

impl From<bip32::Error> for DecodeError {
    fn from(e: bip32::Error) -> Self { Self::Bip32(e) }
}

impl From<crate::error::Error> for DecodeError {
    fn from(e: crate::error::Error) -> Self { Self::Error(e) }
}
