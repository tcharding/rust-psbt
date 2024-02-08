// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
use bitcoin::consensus::{encode as consensus, Decodable};
use bitcoin::locktime::absolute;
use bitcoin::{bip32, transaction, VarInt};

use crate::consts::{
    PSBT_GLOBAL_FALLBACK_LOCKTIME, PSBT_GLOBAL_INPUT_COUNT, PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_TX_MODIFIABLE, PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB,
};
use crate::error::{write_err, InconsistentKeySourcesError};
use crate::io::{self, Cursor, Read};
use crate::prelude::*;
use crate::serialize::Serialize;
use crate::v2::map::Map;
use crate::version::Version;
use crate::{consts, raw, serialize, V2};

/// The Inputs Modifiable Flag, set to 1 to indicate whether inputs can be added or removed.
const INPUTS_MODIFIABLE: u8 = 0x01 << 0;
/// The Outputs Modifiable Flag, set to 1 to indicate whether outputs can be added or removed.
const OUTPUTS_MODIFIABLE: u8 = 0x01 << 1;
/// The Has SIGHASH_SINGLE flag, set to 1 to indicate whether the transaction has a SIGHASH_SINGLE
/// signature who's input and output pairing must be preserved. Essentially indicates that the
/// Constructor must iterate the inputs to determine whether and how to add or remove an input.
const SIGHASH_SINGLE: u8 = 0x01 << 2;

/// The global key-value map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
            // TODO: Is this default correct?
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

    pub(crate) fn set_inputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags |= INPUTS_MODIFIABLE;
    }

    pub(crate) fn set_outputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags |= OUTPUTS_MODIFIABLE;
    }

    // TODO: Handle SIGHASH_SINGLE correctly.
    #[allow(dead_code)]
    pub(crate) fn set_sighash_single_flag(&mut self) { self.tx_modifiable_flags |= SIGHASH_SINGLE; }

    pub(crate) fn clear_inputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags &= !INPUTS_MODIFIABLE;
    }

    pub(crate) fn clear_outputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags &= !OUTPUTS_MODIFIABLE;
    }

    // TODO: Handle SIGHASH_SINGLE correctly.
    #[allow(dead_code)]
    pub(crate) fn clear_sighash_single_flag(&mut self) {
        self.tx_modifiable_flags &= !SIGHASH_SINGLE;
    }

    pub(crate) fn is_inputs_modifiable(&self) -> bool {
        self.tx_modifiable_flags & INPUTS_MODIFIABLE > 0
    }

    pub(crate) fn is_outputs_modifiable(&self) -> bool {
        self.tx_modifiable_flags & OUTPUTS_MODIFIABLE > 0
    }

    // TODO: Investigate if we should be using this function?
    #[allow(dead_code)]
    pub(crate) fn has_sighash_single(&self) -> bool {
        self.tx_modifiable_flags & SIGHASH_SINGLE > 0
    }

    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        // TODO: Consider adding protection against memory exhaustion here by defining a maximum
        // PBST size and using `take` as we do in rust-bitcoin consensus decoding.
        let mut version: Option<Version> = None;
        let mut tx_version: Option<transaction::Version> = None;
        let mut fallback_lock_time: Option<absolute::LockTime> = None;
        let mut tx_modifiable_flags: Option<u8> = None;
        let mut input_count: Option<u64> = None;
        let mut output_count: Option<u64> = None;
        let mut xpubs: BTreeMap<Xpub, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();

        // Use a closure so we can insert pair into one of the mutable local variables above.
        let mut insert_pair = |pair: raw::Pair| {
            match pair.key.type_value {
                PSBT_GLOBAL_VERSION =>
                    if pair.key.key.is_empty() {
                        if version.is_none() {
                            let vlen: usize = pair.value.len();
                            let mut decoder = Cursor::new(pair.value);
                            if vlen != 4 {
                                return Err::<(), InsertPairError>(
                                    InsertPairError::ValueWrongLength(vlen, 4),
                                );
                            }
                            let ver = Decodable::consensus_decode(&mut decoder)?;
                            if ver != 2 {
                                return Err(InsertPairError::WrongVersion(ver));
                            }
                            version = Some(Version::try_from(ver).expect("valid, this is 2"));
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    },
                PSBT_GLOBAL_TX_VERSION =>
                    if pair.key.key.is_empty() {
                        if tx_version.is_none() {
                            let vlen: usize = pair.value.len();
                            let mut decoder = Cursor::new(pair.value);
                            if vlen != 4 {
                                return Err(InsertPairError::ValueWrongLength(vlen, 4));
                            }
                            // TODO: Consider doing checks for standard transaction version?
                            tx_version = Some(Decodable::consensus_decode(&mut decoder)?);
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    },
                PSBT_GLOBAL_FALLBACK_LOCKTIME =>
                    if pair.key.key.is_empty() {
                        if fallback_lock_time.is_none() {
                            let vlen: usize = pair.value.len();
                            if vlen != 4 {
                                return Err(InsertPairError::ValueWrongLength(vlen, 4));
                            }
                            let mut decoder = Cursor::new(pair.value);
                            fallback_lock_time = Some(Decodable::consensus_decode(&mut decoder)?);
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    },
                PSBT_GLOBAL_INPUT_COUNT =>
                    if pair.key.key.is_empty() {
                        if output_count.is_none() {
                            // TODO: Do we need to check the length for a VarInt?
                            // let vlen: usize = pair.value.len();
                            let mut decoder = Cursor::new(pair.value);
                            let count: VarInt = Decodable::consensus_decode(&mut decoder)?;
                            input_count = Some(count.0);
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    },
                PSBT_GLOBAL_OUTPUT_COUNT =>
                    if pair.key.key.is_empty() {
                        if output_count.is_none() {
                            // TODO: Do we need to check the length for a VarInt?
                            // let vlen: usize = pair.value.len();
                            let mut decoder = Cursor::new(pair.value);
                            let count: VarInt = Decodable::consensus_decode(&mut decoder)?;
                            output_count = Some(count.0);
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    },
                PSBT_GLOBAL_TX_MODIFIABLE =>
                    if pair.key.key.is_empty() {
                        if tx_modifiable_flags.is_none() {
                            let vlen: usize = pair.value.len();
                            if vlen != 1 {
                                return Err(InsertPairError::ValueWrongLength(vlen, 1));
                            }
                            let mut decoder = Cursor::new(pair.value);
                            tx_modifiable_flags = Some(Decodable::consensus_decode(&mut decoder)?);
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    },
                PSBT_GLOBAL_XPUB =>
                    if !pair.key.key.is_empty() {
                        let xpub = Xpub::decode(&pair.key.key)?;
                        if pair.value.is_empty() {
                            // TODO: keypair value is empty, consider adding a better error type.
                            return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                        }
                        if pair.value.len() < 4 {
                            // TODO: Add better error here.
                            return Err(InsertPairError::XpubInvalidFingerprint);
                        }
                        // TODO: Can we restrict the value further?
                        if pair.value.len() % 4 != 0 {
                            return Err(InsertPairError::XpubInvalidPath(pair.value.len()));
                        }

                        let child_count = pair.value.len() / 4 - 1;
                        let mut decoder = Cursor::new(pair.value);
                        let mut fingerprint = [0u8; 4];
                        decoder
                            .read_exact(&mut fingerprint[..])
                            .expect("in-memory readers don't err");
                        let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                        while let Ok(index) = u32::consensus_decode(&mut decoder) {
                            path.push(ChildNumber::from(index))
                        }
                        let derivation = DerivationPath::from(path);
                        // Keys, according to BIP-174, must be unique
                        if let Some(key_source) =
                            xpubs.insert(xpub, (Fingerprint::from(fingerprint), derivation))
                        {
                            return Err(InsertPairError::DuplicateXpub(key_source));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataEmpty(pair.key));
                    },
                // TODO: Remove clone by implementing TryFrom for reference.
                PSBT_GLOBAL_PROPRIETARY =>
                    if !pair.key.key.is_empty() {
                        match proprietaries.entry(
                            raw::ProprietaryKey::try_from(pair.key.clone())
                                .map_err(|_| InsertPairError::InvalidProprietaryKey)?,
                        ) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(_) =>
                                return Err(InsertPairError::DuplicateKey(pair.key)),
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataEmpty(pair.key));
                    },
                v if v == PSBT_GLOBAL_UNSIGNED_TX =>
                    return Err(InsertPairError::ExcludedKey { key_type_value: v }),
                _ => match unknowns.entry(pair.key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(pair.value);
                    }
                    btree_map::Entry::Occupied(k) => {
                        return Err(InsertPairError::DuplicateKey(k.key().clone()));
                    }
                },
            }
            Ok(())
        };

        loop {
            match raw::Pair::decode(r) {
                Ok(pair) => insert_pair(pair)?,
                Err(serialize::Error::NoMorePairs) => break,
                Err(e) => return Err(DecodeError::DeserPair(e)),
            }
        }

        // TODO: Handle decoding either psbt v0 or psbt v2.
        let version = version.ok_or(DecodeError::MissingVersion)?;

        // TODO: Do checks for standard transaction version?
        let tx_version = tx_version.ok_or(DecodeError::MissingTxVersion)?;

        // TODO: Check this default is correct.
        let tx_modifiable_flags = tx_modifiable_flags.unwrap_or(0_u8);

        let input_count = usize::try_from(input_count.ok_or(DecodeError::MissingInputCount)?)
            .map_err(|_| DecodeError::InputCountOverflow(input_count.expect("is some")))?;

        let output_count = usize::try_from(output_count.ok_or(DecodeError::MissingOutputCount)?)
            .map_err(|_| DecodeError::OutputCountOverflow(output_count.expect("is some")))?;

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
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        // Combining different versions of PSBT without explicit conversion is out of scope.
        if self.version != other.version {
            return Err(CombineError::VersionMismatch { this: self.version, that: other.version });
        }

        // No real reason to support this either.
        if self.tx_version != other.tx_version {
            return Err(CombineError::TxVersionMismatch {
                this: self.tx_version,
                that: other.tx_version,
            });
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

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
                    return Err(InconsistentKeySourcesError(xpub).into());
                }
            }
        }

        v2_combine_map!(proprietaries, self, other);
        v2_combine_map!(unknowns, self, other);

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

        v2_impl_psbt_get_pair! {
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

/// An error while decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error deserializing a pair.
    DeserPair(serialize::Error),
    /// Serialized PSBT is missing the version number.
    MissingVersion,
    /// Serialized PSBT is missing the transaction version number.
    MissingTxVersion,
    /// Serialized PSBT is missing the input count.
    MissingInputCount,
    /// Input count overflows word size for current architecture.
    InputCountOverflow(u64),
    /// Serialized PSBT is missing the output count.
    MissingOutputCount,
    /// Output count overflows word size for current architecture.
    OutputCountOverflow(u64),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => write_err!(f, "error inserting a pair"; e),
            DeserPair(ref e) => write_err!(f, "error deserializing a pair"; e),
            MissingVersion => write!(f, "serialized PSBT is missing the version number"),
            MissingTxVersion =>
                write!(f, "serialized PSBT is missing the transaction version number"),
            MissingInputCount => write!(f, "serialized PSBT is missing the input count"),
            InputCountOverflow(count) =>
                write!(f, "input count overflows word size for current architecture: {}", count),
            MissingOutputCount => write!(f, "serialized PSBT is missing the output count"),
            OutputCountOverflow(count) =>
                write!(f, "output count overflows word size for current architecture: {}", count),
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
            MissingVersion
            | MissingTxVersion
            | MissingInputCount
            | InputCountOverflow(_)
            | MissingOutputCount
            | OutputCountOverflow(_) => None,
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
    /// Key should contain data.
    InvalidKeyDataEmpty(raw::Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(raw::Key),
    /// Error deserializing raw value.
    Deser(serialize::Error),
    /// Error consensus deserializing value.
    Consensus(consensus::Error),
    /// Value was not the correct length (got, want).
    // TODO: Use struct instead of tuple.
    ValueWrongLength(usize, usize),
    /// PSBT_GLOBAL_VERSION: PSBT v2 expects the version to be 2.
    WrongVersion(u32),
    /// PSBT_GLOBAL_XPUB: Must contain 4 bytes for the xpub fingerprint.
    XpubInvalidFingerprint,
    /// PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints.
    XpubInvalidPath(usize),
    /// PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type.
    Bip32(bip32::Error),
    /// PSBT_GLOBAL_XPUB: xpubs must be unique.
    DuplicateXpub(KeySource),
    /// PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key.
    InvalidProprietaryKey,
    /// Key must be excluded from this version of PSBT (see consts.rs for u8 values).
    ExcludedKey {
        /// Key type value we found.
        key_type_value: u8,
    },
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InsertPairError::*;

        match *self {
            DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            InvalidKeyDataNotEmpty(ref key) => write!(f, "key should not contain data: {}", key),
            Deser(ref e) => write_err!(f, "error deserializing raw value"; e),
            Consensus(ref e) => write_err!(f, "error consensus deserializing type"; e),
            ValueWrongLength(got, want) =>
                write!(f, "value (keyvalue pair) wrong length (got, want) {} {}", got, want),
            WrongVersion(v) =>
                write!(f, "PSBT_GLOBAL_VERSION: PSBT v2 expects the version to be 2, found: {}", v),
            XpubInvalidFingerprint =>
                write!(f, "PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints"),
            XpubInvalidPath(len) => write!(
                f,
                "PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints: {}",
                len
            ),
            Bip32(ref e) => write_err!(f, "PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type"; e),
            DuplicateXpub((fingerprint, ref derivation_path)) => write!(
                f,
                "PSBT_GLOBAL_XPUB: xpubs must be unique ({}, {})",
                fingerprint, derivation_path
            ),
            InvalidProprietaryKey => write!(f, "PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key"),
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
            Consensus(ref e) => Some(e),
            Bip32(ref e) => Some(e),
            DuplicateKey(_)
            | InvalidKeyDataEmpty(_)
            | InvalidKeyDataNotEmpty(_)
            | ValueWrongLength(..)
            | WrongVersion(_)
            | XpubInvalidFingerprint
            | XpubInvalidPath(_)
            | DuplicateXpub(_)
            | InvalidProprietaryKey
            | ExcludedKey { .. } => None,
        }
    }
}

impl From<serialize::Error> for InsertPairError {
    fn from(e: serialize::Error) -> Self { Self::Deser(e) }
}

impl From<consensus::Error> for InsertPairError {
    fn from(e: consensus::Error) -> Self { Self::Consensus(e) }
}

impl From<bip32::Error> for InsertPairError {
    fn from(e: bip32::Error) -> Self { Self::Bip32(e) }
}

/// Error combining two global maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// The version numbers are not the same.
    VersionMismatch {
        /// Attempted to combine a PBST with `this` version.
        this: Version,
        /// Into a PBST with `that` version.
        that: Version,
    },
    /// The transaction version numbers are not the same.
    TxVersionMismatch {
        /// Attempted to combine a PBST with `this` tx version.
        this: transaction::Version,
        /// Into a PBST with `that` tx version.
        that: transaction::Version,
    },
    /// Xpubs have inconsistent key sources.
    InconsistentKeySources(InconsistentKeySourcesError),
}

impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CombineError::*;

        match *self {
            VersionMismatch { ref this, ref that } =>
                write!(f, "combine two PSBTs with different versions: {:?} {:?}", this, that),
            TxVersionMismatch { ref this, ref that } =>
                write!(f, "combine two PSBTs with different tx versions: {:?} {:?}", this, that),
            InconsistentKeySources(ref e) =>
                write_err!(f, "combine with inconsistent key sources"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use CombineError::*;

        match *self {
            InconsistentKeySources(ref e) => Some(e),
            VersionMismatch { .. } | TxVersionMismatch { .. } => None,
        }
    }
}

impl From<InconsistentKeySourcesError> for CombineError {
    fn from(e: InconsistentKeySourcesError) -> Self { Self::InconsistentKeySources(e) }
}
