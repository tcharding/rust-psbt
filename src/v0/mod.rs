// SPDX-License-Identifier: CC0-1.0

//! The Partially Signed Bitcoin Transaction Format (PSBTv0).
//!
//! Implementation of the Partially Signed Bitcoin Transaction Format as defined in [BIP-174].
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

mod error;
mod extractor;
mod map;
#[cfg(feature = "miniscript")]
pub mod miniscript;

use core::fmt;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use bitcoin::bip32::{self, KeySource, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::{PrivateKey, PublicKey};
use bitcoin::secp256k1::{Message, Secp256k1, Signing};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::{ecdsa, Amount, ScriptBuf};

use crate::error::{write_err, FeeError, FundingUtxoError};
use crate::prelude::*;
use crate::v0::map::Map;

#[rustfmt::skip]                // Keep pubic re-exports separate
pub use self::{
    error::{IndexOutOfBoundsError, SignerChecksError, SignError, CombineError, UnsignedTxChecksError, DeserializePsbtError},
    map::{Input, Output, Global},
};

#[rustfmt::skip]                // Keep public re-exports separate.
#[cfg(feature = "base64")]
pub use self::display_from_str::PsbtParseError;

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Psbt {
    /// The global map.
    pub global: Global,
    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

impl Psbt {
    /// Serialize a value as bytes in hex.
    pub fn serialize_hex(&self) -> String { self.serialize().to_lower_hex_string() }

    /// Serialize as raw binary data
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        //  <magic>
        buf.extend_from_slice(b"psbt");

        buf.push(0xff_u8);

        buf.extend(self.global.serialize_map());

        for i in &self.inputs {
            buf.extend(i.serialize_map());
        }

        for i in &self.outputs {
            buf.extend(i.serialize_map());
        }

        buf
    }

    // TODO: Change this to use DeserializePsbtError (although that name is shit) same as v2.
    /// Deserialize a value from raw binary data.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DeserializePsbtError> {
        const MAGIC_BYTES: &[u8] = b"psbt";
        if bytes.get(0..MAGIC_BYTES.len()) != Some(MAGIC_BYTES) {
            return Err(DeserializePsbtError::InvalidMagic);
        }

        const PSBT_SERPARATOR: u8 = 0xff_u8;
        if bytes.get(MAGIC_BYTES.len()) != Some(&PSBT_SERPARATOR) {
            return Err(DeserializePsbtError::InvalidSeparator);
        }

        let mut d = bytes.get(5..).ok_or(DeserializePsbtError::NoMorePairs)?;

        let global = Global::decode(&mut d)?;
        global.unsigned_tx_checks()?;

        let inputs: Vec<Input> = {
            let inputs_len: usize = (global.unsigned_tx.input).len();

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for _ in 0..inputs_len {
                inputs.push(Input::decode(&mut d)?);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len: usize = (global.unsigned_tx.output).len();

            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for _ in 0..outputs_len {
                outputs.push(Output::decode(&mut d)?);
            }

            outputs
        };

        Ok(Psbt { global, inputs, outputs })
    }

    /// Returns an iterator for the funding UTXOs of the psbt
    ///
    /// For each PSBT input that contains UTXO information `Ok` is returned containing that information.
    /// The order of returned items is same as the order of inputs.
    ///
    /// ## Errors
    ///
    /// The function returns error when UTXO information is not present or is invalid.
    ///
    /// ## Panics
    ///
    /// The function panics if the length of transaction inputs is not equal to the length of PSBT inputs.
    pub fn iter_funding_utxos(&self) -> impl Iterator<Item = Result<&TxOut, FundingUtxoError>> {
        use FundingUtxoError::*;

        assert_eq!(self.inputs.len(), self.global.unsigned_tx.input.len());
        self.global.unsigned_tx.input.iter().zip(&self.inputs).map(|(tx_input, psbt_input)| match (
            &psbt_input.witness_utxo,
            &psbt_input.non_witness_utxo,
        ) {
            (Some(witness_utxo), _) => Ok(witness_utxo),
            (None, Some(non_witness_utxo)) => {
                let vout = tx_input.previous_output.vout as usize;
                non_witness_utxo
                    .output
                    .get(vout)
                    .ok_or(OutOfBounds { vout, len: non_witness_utxo.output.len() })
            }
            (None, None) => Err(MissingUtxo),
        })
    }

    /// Creates a PSBT from an unsigned transaction.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, UnsignedTxChecksError> {
        let input_len = tx.input.len();
        let output_len = tx.output.len();

        let psbt = Psbt {
            global: Global::from_unsigned_tx(tx)?,
            inputs: vec![Default::default(); input_len],
            outputs: vec![Default::default(); output_len],
        };
        Ok(psbt)
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP 174.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        self.global.combine(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.combine(other_input);
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.combine(other_output);
        }

        Ok(())
    }

    /// Returns `Ok` if PSBT is
    ///
    /// From BIP-174:
    ///
    /// For a Signer to only produce valid signatures for what it expects to sign, it must check that the following conditions are true:
    ///
    /// - If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
    /// - If a witness UTXO is provided, no non-witness signature may be created
    /// - If a redeemScript is provided, the scriptPubKey must be for that redeemScript
    /// - If a witnessScript is provided, the scriptPubKey or the redeemScript must be for that witnessScript
    /// - If a sighash type is provided, the signer must check that the sighash is acceptable. If unacceptable, they must fail.
    /// - If a sighash type is not provided, the signer should sign using SIGHASH_ALL, but may use any sighash type they wish.
    pub fn signer_checks(&self) -> Result<(), SignerChecksError> {
        let unsigned_tx = &self.global.unsigned_tx;
        for (i, input) in self.inputs.iter().enumerate() {
            if input.witness_utxo.is_some() {
                match self.output_type(i) {
                    Ok(OutputType::Bare) => return Err(SignerChecksError::NonWitnessSig),
                    Ok(_) => {}
                    Err(_) => {} // TODO: Is this correct?
                }
            }

            if let Some(ref tx) = input.non_witness_utxo {
                if tx.txid() != unsigned_tx.input[i].previous_output.txid {
                    return Err(SignerChecksError::NonWitnessUtxoTxidMismatch);
                }
            }

            if let Some(ref redeem_script) = input.redeem_script {
                match input.witness_utxo {
                    Some(ref tx_out) => {
                        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
                        if tx_out.script_pubkey != script_pubkey {
                            return Err(SignerChecksError::RedeemScriptMismatch);
                        }
                    }
                    None => return Err(SignerChecksError::MissingTxOut),
                }
            }

            if let Some(ref witness_script) = input.witness_script {
                match input.witness_utxo {
                    Some(ref utxo) => {
                        let script_pubkey = &utxo.script_pubkey;
                        if script_pubkey.is_p2wsh() {
                            if ScriptBuf::new_p2wsh(&witness_script.wscript_hash())
                                != *script_pubkey
                            {
                                return Err(SignerChecksError::WitnessScriptMismatchWsh);
                            }
                        } else if script_pubkey.is_p2sh() {
                            if let Some(ref redeem_script) = input.redeem_script {
                                if ScriptBuf::new_p2wsh(&redeem_script.wscript_hash())
                                    != *script_pubkey
                                {
                                    return Err(SignerChecksError::WitnessScriptMismatchShWsh);
                                }
                            }
                        } else {
                            // BIP does not specifically say there should not be a witness script here?
                        }
                    }
                    None => return Err(SignerChecksError::MissingTxOut),
                }
            }

            if let Some(_sighash_type) = input.sighash_type {
                // TODO: Check that sighash is accetable, what does that mean?
                {}
            }
        }
        Ok(())
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// **NOTE**: Taproot inputs are, as yet, not supported by this function. We currently only
    /// attempt to sign ECDSA inputs.
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`. This
    /// function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// Either Ok(SigningKeys) or Err((SigningKeys, SigningErrors)), where
    /// - SigningKeys: A map of input index -> pubkey associated with secret key used to sign.
    /// - SigningKeys: A map of input index -> the error encountered while attempting to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    pub fn sign<C, K>(
        &mut self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<SigningKeys, (SigningKeys, SigningErrors)>
    where
        C: Signing,
        K: GetKey,
    {
        let tx = self.global.unsigned_tx.clone(); // clone because we need to mutably borrow when signing.
        let mut cache = SighashCache::new(&tx);

        let mut used = BTreeMap::new();
        let mut errors = BTreeMap::new();

        for i in 0..self.inputs.len() {
            if let Ok(SigningAlgorithm::Ecdsa) = self.signing_algorithm(i) {
                match self.bip32_sign_ecdsa(k, i, &mut cache, secp) {
                    Ok(v) => {
                        used.insert(i, v);
                    }
                    Err(e) => {
                        errors.insert(i, e);
                    }
                }
            };
        }
        if errors.is_empty() {
            Ok(used)
        } else {
            Err((used, errors))
        }
    }

    /// Attempts to create all signatures required by this PSBT's `bip32_derivation` field, adding
    /// them to `partial_sigs`.
    ///
    /// # Returns
    ///
    /// - Ok: A list of the public keys used in signing.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key.
    fn bip32_sign_ecdsa<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: Signing,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let msg_sighash_ty_res = self.sighash_ecdsa(input_index, cache);

        let input = &mut self.inputs[input_index]; // Index checked in call to `sighash_ecdsa`.

        let mut used = vec![]; // List of pubkeys used to sign the input.

        for (pk, key_source) in input.bip32_derivations.iter() {
            let sk = if let Ok(Some(sk)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(KeyRequest::Pubkey(PublicKey::new(*pk)), secp) {
                sk
            } else {
                continue;
            };

            // Only return the error if we have a secret key to sign this input.
            let (msg, sighash_ty) = match msg_sighash_ty_res {
                Err(e) => return Err(e),
                Ok((msg, sighash_ty)) => (msg, sighash_ty),
            };

            let sig =
                ecdsa::Signature { sig: secp.sign_ecdsa(&msg, &sk.inner), hash_ty: sighash_ty };

            let pk = sk.public_key(secp);

            input.partial_sigs.insert(pk, sig);
            used.push(pk);
        }

        Ok(used)
    }

    /// Returns the sighash message to sign an ECDSA input along with the sighash type.
    ///
    /// Uses the [`EcdsaSighashType`] from this input if one is specified. If no sighash type is
    /// specified uses [`EcdsaSighashType::All`]. This function does not support scripts that
    /// contain `OP_CODESEPARATOR`.
    pub fn sighash_ecdsa<T: Borrow<Transaction>>(
        &self,
        input_index: usize,
        cache: &mut SighashCache<T>,
    ) -> Result<(Message, EcdsaSighashType), SignError> {
        use OutputType::*;

        if self.signing_algorithm(input_index)? != SigningAlgorithm::Ecdsa {
            return Err(SignError::WrongSigningAlgorithm);
        }

        let input = self.checked_input(input_index)?;
        let utxo = self.spend_utxo(input_index)?;
        let spk = &utxo.script_pubkey; // scriptPubkey for input spend utxo.

        let hash_ty = input.ecdsa_hash_ty().map_err(|_| SignError::InvalidSighashType)?; // Only support standard sighash types.

        match self.output_type(input_index)? {
            Bare => {
                let sighash = cache.legacy_signature_hash(input_index, spk, hash_ty.to_u32())?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Sh => {
                let script_code =
                    input.redeem_script.as_ref().ok_or(SignError::MissingRedeemScript)?;
                let sighash =
                    cache.legacy_signature_hash(input_index, script_code, hash_ty.to_u32())?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Wpkh => {
                let sighash = cache.p2wpkh_signature_hash(input_index, spk, utxo.value, hash_ty)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            ShWpkh => {
                let redeem_script = input.redeem_script.as_ref().expect("checked above");
                let sighash =
                    cache.p2wpkh_signature_hash(input_index, redeem_script, utxo.value, hash_ty)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Wsh | ShWsh => {
                let witness_script =
                    input.witness_script.as_ref().ok_or(SignError::MissingWitnessScript)?;
                let sighash =
                    cache.p2wsh_signature_hash(input_index, witness_script, utxo.value, hash_ty)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Tr => {
                // This PSBT signing API is WIP, taproot to come shortly.
                Err(SignError::Unsupported)
            }
        }
    }

    /// Returns the spending utxo for this PSBT's input at `input_index`.
    pub fn spend_utxo(&self, input_index: usize) -> Result<&TxOut, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = if let Some(witness_utxo) = &input.witness_utxo {
            witness_utxo
        } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let vout = self.global.unsigned_tx.input[input_index].previous_output.vout;
            &non_witness_utxo.output[vout as usize]
        } else {
            return Err(SignError::MissingSpendUtxo);
        };
        Ok(utxo)
    }

    /// Gets the input at `input_index` after checking that it is a valid index.
    fn checked_input(&self, input_index: usize) -> Result<&Input, IndexOutOfBoundsError> {
        self.check_index_is_within_bounds(input_index)?;
        Ok(&self.inputs[input_index])
    }

    /// Checks `input_index` is within bounds for the PSBT `inputs` array and
    /// for the PSBT `unsigned_tx` `input` array.
    fn check_index_is_within_bounds(
        &self,
        input_index: usize,
    ) -> Result<(), IndexOutOfBoundsError> {
        if input_index >= self.inputs.len() {
            return Err(IndexOutOfBoundsError::Inputs {
                index: input_index,
                length: self.inputs.len(),
            });
        }

        if input_index >= self.global.unsigned_tx.input.len() {
            return Err(IndexOutOfBoundsError::TxInput {
                index: input_index,
                length: self.global.unsigned_tx.input.len(),
            });
        }

        Ok(())
    }

    /// Returns the algorithm used to sign this PSBT's input at `input_index`.
    fn signing_algorithm(&self, input_index: usize) -> Result<SigningAlgorithm, SignError> {
        let output_type = self.output_type(input_index)?;
        Ok(output_type.signing_algorithm())
    }

    /// Returns the [`OutputType`] of the spend utxo for this PBST's input at `input_index`.
    fn output_type(&self, input_index: usize) -> Result<OutputType, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = self.spend_utxo(input_index)?;
        let spk = utxo.script_pubkey.clone();

        // Anything that is not segwit and is not p2sh is `Bare`.
        if !(spk.is_witness_program() || spk.is_p2sh()) {
            return Ok(OutputType::Bare);
        }

        if spk.is_p2wpkh() {
            return Ok(OutputType::Wpkh);
        }

        if spk.is_p2wsh() {
            return Ok(OutputType::Wsh);
        }

        if spk.is_p2sh() {
            if input.redeem_script.as_ref().map(|s| s.is_p2wpkh()).unwrap_or(false) {
                return Ok(OutputType::ShWpkh);
            }
            if input.redeem_script.as_ref().map(|x| x.is_p2wsh()).unwrap_or(false) {
                return Ok(OutputType::ShWsh);
            }
            return Ok(OutputType::Sh);
        }

        if spk.is_p2tr() {
            return Ok(OutputType::Tr);
        }

        // Something is wrong with the input scriptPubkey or we do not know how to sign
        // because there has been a new softfork that we do not yet support.
        Err(SignError::UnknownOutputType)
    }

    /// Calculates transaction fee.
    ///
    /// 'Fee' being the amount that will be paid for mining a transaction with the current inputs
    /// and outputs i.e., the difference in value of the total inputs and the total outputs.
    ///
    /// ## Errors
    ///
    /// - [`Error::MissingUtxo`] when UTXO information for any input is not present or is invalid.
    /// - [`Error::NegativeFee`] if calculated value is negative.
    /// - [`Error::FeeOverflow`] if an integer overflow occurs.
    pub fn fee(&self) -> Result<Amount, FeeError> {
        use FeeError::*;

        let mut inputs: u64 = 0;
        for utxo in self.iter_funding_utxos() {
            inputs = inputs.checked_add(utxo?.value.to_sat()).ok_or(InputOverflow)?;
        }
        let mut outputs: u64 = 0;
        for out in &self.global.unsigned_tx.output {
            outputs = outputs.checked_add(out.value.to_sat()).ok_or(OutputOverflow)?;
        }
        inputs.checked_sub(outputs).map(Amount::from_sat).ok_or(Negative)
    }
}

/// If the "base64" feature is enabled we implement `Display` and `FromStr` using base64 encoding.
#[cfg(feature = "base64")]
mod display_from_str {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use bitcoin::base64::display::Base64Display;
    use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};

    use super::*;

    impl Display for Psbt {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}", Base64Display::new(&self.serialize(), &BASE64_STANDARD))
        }
    }

    impl FromStr for Psbt {
        type Err = PsbtParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = BASE64_STANDARD.decode(s).map_err(PsbtParseError::Base64Encoding)?;
            Psbt::deserialize(&data).map_err(PsbtParseError::PsbtEncoding)
        }
    }

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum PsbtParseError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(DeserializePsbtError),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(bitcoin::base64::DecodeError),
    }

    impl Display for PsbtParseError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use self::PsbtParseError::*;

            match *self {
                PsbtEncoding(ref e) => write_err!(f, "error in internal PSBT data structure"; e),
                Base64Encoding(ref e) => write_err!(f, "error in PSBT base64 encoding"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for PsbtParseError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use self::PsbtParseError::*;

            match self {
                PsbtEncoding(e) => Some(e),
                Base64Encoding(e) => Some(e),
            }
        }
    }
}

/// Data required to call [`GetKey`] to get the private key to sign an input.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRequest {
    /// Request a private key using the associated public key.
    Pubkey(PublicKey),
    /// Request a private key using BIP-32 fingerprint and derivation path.
    Bip32(KeySource),
}

/// Trait to get a private key from a key request, key is then used to sign an input.
pub trait GetKey {
    /// An error occurred while getting the key.
    type Error: core::fmt::Debug;

    /// Attempts to get the private key for `key_request`.
    ///
    /// # Returns
    /// - `Some(key)` if the key is found.
    /// - `None` if the key was not found but no error was encountered.
    /// - `Err` if an error was encountered while looking for the key.
    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error>;
}

impl GetKey for Xpriv {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                let key = if self.fingerprint(secp) == fingerprint {
                    let k = self.derive_priv(secp, &path)?;
                    Some(k.to_priv())
                } else {
                    None
                };
                Ok(key)
            }
        }
    }
}

/// Map of input index -> pubkey associated with secret key used to create signature for that input.
pub type SigningKeys = BTreeMap<usize, Vec<PublicKey>>;

/// Map of input index -> the error encountered while attempting to sign that input.
pub type SigningErrors = BTreeMap<usize, SignError>;

#[rustfmt::skip]
macro_rules! impl_get_key_for_set {
    ($set:ident) => {

impl GetKey for $set<Xpriv> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                for xpriv in self.iter() {
                    if xpriv.parent_fingerprint == fingerprint {
                        let k = xpriv.derive_priv(secp, &path)?;
                        return Ok(Some(k.to_priv()));
                    }
                }
                Ok(None)
            }
        }
    }
}}}

impl_get_key_for_set!(BTreeSet);
#[cfg(feature = "std")]
impl_get_key_for_set!(HashSet);

#[rustfmt::skip]
macro_rules! impl_get_key_for_map {
    ($map:ident) => {

impl GetKey for $map<PublicKey, PrivateKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        _: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(pk) => Ok(self.get(&pk).cloned()),
            KeyRequest::Bip32(_) => Err(GetKeyError::NotSupported),
        }
    }
}}}
impl_get_key_for_map!(BTreeMap);
#[cfg(feature = "std")]
impl_get_key_for_map!(HashMap);

/// Errors when getting a key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetKeyError {
    /// A bip32 error.
    Bip32(bip32::Error),
    /// The GetKey operation is not supported for this key request.
    NotSupported,
}

impl fmt::Display for GetKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use GetKeyError::*;

        match *self {
            Bip32(ref e) => write_err!(f, "a bip23 error"; e),
            NotSupported =>
                f.write_str("the GetKey operation is not supported for this key request"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use GetKeyError::*;

        match *self {
            NotSupported => None,
            Bip32(ref e) => Some(e),
        }
    }
}

impl From<bip32::Error> for GetKeyError {
    fn from(e: bip32::Error) -> Self { GetKeyError::Bip32(e) }
}

/// The various output types supported by the Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OutputType {
    /// An output of type: pay-to-pubkey or pay-to-pubkey-hash.
    Bare,
    /// A pay-to-witness-pubkey-hash output (P2WPKH).
    Wpkh,
    /// A pay-to-witness-script-hash output (P2WSH).
    Wsh,
    /// A nested segwit output, pay-to-witness-pubkey-hash nested in a pay-to-script-hash.
    ShWpkh,
    /// A nested segwit output, pay-to-witness-script-hash nested in a pay-to-script-hash.
    ShWsh,
    /// A pay-to-script-hash output excluding wrapped segwit (P2SH).
    Sh,
    /// A taproot output (P2TR).
    Tr,
}

impl OutputType {
    /// The signing algorithm used to sign this output type.
    pub fn signing_algorithm(&self) -> SigningAlgorithm {
        use OutputType::*;

        match self {
            Bare | Wpkh | Wsh | ShWpkh | ShWsh | Sh => SigningAlgorithm::Ecdsa,
            Tr => SigningAlgorithm::Schnorr,
        }
    }
}

/// Signing algorithms supported by the Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlgorithm {
    /// The Elliptic Curve Digital Signature Algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    Ecdsa,
    /// The Schnorr signature algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Schnorr_signature
    Schnorr,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::bip32::{ChildNumber, KeySource, Xpriv, Xpub};
    use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
    use bitcoin::hex::{test_hex_unwrap as hex, FromHex};
    use bitcoin::locktime::absolute;
    use bitcoin::secp256k1::Secp256k1;
    #[cfg(feature = "rand-std")]
    use bitcoin::secp256k1::{All, SecretKey};
    use bitcoin::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut};
    use bitcoin::Network::Bitcoin;
    use bitcoin::{FeeRate, ScriptBuf, Witness};

    use super::*;
    use crate::serialize::{Deserialize, Serialize};
    use crate::v0::error::ExtractTxError;
    use crate::{io, raw, V0};

    #[track_caller]
    pub fn hex_psbt(s: &str) -> Result<Psbt, DeserializePsbtError> {
        let r: Result<Vec<u8>, bitcoin::hex::HexToBytesError> = Vec::from_hex(s);
        match r {
            Err(_e) => panic!("unable to parse hex string {}", s),
            Ok(v) => Psbt::deserialize(&v),
        }
    }

    #[track_caller]
    fn psbt_with_values(input: u64, output: u64) -> Psbt {
        Psbt {
            global: Global {
                unsigned_tx: Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint {
                            txid:
                                "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
                                    .parse()
                                    .unwrap(),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        witness: Witness::default(),
                    }],
                    output: vec![TxOut {
                        value: Amount::from_sat(output),
                        script_pubkey: ScriptBuf::from_hex(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                        )
                        .unwrap(),
                    }],
                },
                xpubs: Default::default(),
                version: V0,
                proprietaries: BTreeMap::new(),
                unknowns: BTreeMap::new(),
            },
            inputs: vec![Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(input),
                    script_pubkey: ScriptBuf::from_hex(
                        "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                    )
                    .unwrap(),
                }),
                ..Default::default()
            }],
            outputs: vec![],
        }
    }

    #[test]
    fn trivial_psbt() {
        let psbt = Psbt {
            global: Global {
                unsigned_tx: Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                },
                xpubs: Default::default(),
                version: V0,
                proprietaries: BTreeMap::new(),
                unknowns: BTreeMap::new(),
            },
            inputs: vec![],
            outputs: vec![],
        };
        assert_eq!(psbt.serialize_hex(), "70736274ff01000a0200000000000000000000");
    }

    #[test]
    fn psbt_uncompressed_key() {
        let psbt: Psbt = hex_psbt("70736274ff01003302000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000000420204bb0d5d0cca36e7b9c80f63bc04c1240babb83bcd2803ef7ac8b6e2af594291daec281e856c98d210c5ab14dfd5828761f8ee7d5f45ca21ad3e4c4b41b747a3a047304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe70100").unwrap();
        assert!(psbt.inputs[0].partial_sigs.len() == 1);
        let pk = psbt.inputs[0].partial_sigs.iter().next().unwrap().0;
        assert!(!pk.compressed);
    }

    #[test]
    fn psbt_high_fee_checks() {
        let psbt = psbt_with_values(5_000_000_000_000, 1000);
        assert_eq!(
            psbt.clone().extract_tx().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(FeeRate::from_sat_per_kwu(15060240960843))
        );
        assert_eq!(
            psbt.clone().extract_tx_fee_rate_limit().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(FeeRate::from_sat_per_kwu(15060240960843))
        );
        assert_eq!(
            psbt.clone()
                .extract_tx_with_fee_rate_limit(FeeRate::from_sat_per_kwu(15060240960842))
                .map_err(|e| match e {
                    ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                    _ => panic!(""),
                }),
            Err(FeeRate::from_sat_per_kwu(15060240960843))
        );
        assert!(psbt
            .extract_tx_with_fee_rate_limit(FeeRate::from_sat_per_kwu(15060240960843))
            .is_ok());

        // Testing that extract_tx will error at 25k sat/vbyte (6250000 sat/kwu)
        assert_eq!(
            psbt_with_values(2076001, 1000).extract_tx().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(FeeRate::from_sat_per_kwu(6250003)) // 6250000 is 25k sat/vbyte
        );

        // Lowering the input satoshis by 1 lowers the sat/kwu by 3
        // Putting it exactly at 25k sat/vbyte
        assert!(psbt_with_values(2076000, 1000).extract_tx().is_ok());
    }

    #[test]
    fn serialize_then_deserialize_output() {
        let secp = &Secp256k1::new();
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        let mut hd_keypaths: BTreeMap<bitcoin::secp256k1::PublicKey, KeySource> =
            Default::default();

        let mut sk: Xpriv = Xpriv::new_master(Bitcoin, &seed).unwrap();

        let fprint = sk.fingerprint(secp);

        let dpath: Vec<ChildNumber> = vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_normal_idx(2).unwrap(),
            ChildNumber::from_normal_idx(4).unwrap(),
            ChildNumber::from_normal_idx(42).unwrap(),
            ChildNumber::from_hardened_idx(69).unwrap(),
            ChildNumber::from_normal_idx(420).unwrap(),
            ChildNumber::from_normal_idx(31337).unwrap(),
        ];

        sk = sk.derive_priv(secp, &dpath).unwrap();

        let pk = Xpub::from_priv(secp, &sk);

        hd_keypaths.insert(pk.public_key, (fprint, dpath.into()));

        let expected: Output = Output {
            redeem_script: Some(
                ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
            ),
            witness_script: Some(
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
            ),
            bip32_derivations: hd_keypaths,
            ..Default::default()
        };

        let mut decoder = io::Cursor::new(expected.serialize_map());
        let actual = Output::decode(&mut decoder).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_global() {
        let expected = Psbt {
            global: Global {
                unsigned_tx: Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::from_consensus(1257139),
                    input: vec![TxIn {
                        previous_output: OutPoint {
                            txid:
                                "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
                                    .parse()
                                    .unwrap(),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        witness: Witness::default(),
                    }],
                    output: vec![
                        TxOut {
                            value: Amount::from_sat(99_999_699),
                            script_pubkey: ScriptBuf::from_hex(
                                "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac",
                            )
                            .unwrap(),
                        },
                        TxOut {
                            value: Amount::from_sat(100_000_000),
                            script_pubkey: ScriptBuf::from_hex(
                                "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                            )
                            .unwrap(),
                        },
                    ],
                },
                xpubs: Default::default(),
                version: V0,
                proprietaries: Default::default(),
                unknowns: Default::default(),
            },
            inputs: vec![Input::default()],
            outputs: vec![Output::default(), Output::default()],
        };

        let actual: Psbt = Psbt::deserialize(&expected.serialize()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_psbtkvpair() {
        let expected = raw::Pair {
            key: raw::Key { type_value: 0u8, key: vec![42u8, 69u8] },
            value: vec![69u8, 42u8, 4u8],
        };

        let actual = raw::Pair::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn deserialize_and_serialize_psbt_with_two_partial_sigs() {
        let hex = "70736274ff0100890200000001207ae985d787dfe6143d5c58fad79cc7105e0e799fcf033b7f2ba17e62d7b3200000000000ffffffff02563d03000000000022002019899534b9a011043c0dd57c3ff9a381c3522c5f27c6a42319085b56ca543a1d6adc020000000000220020618b47a07ebecca4e156edb1b9ea7c24bdee0139fc049237965ffdaf56d5ee73000000000001012b801a0600000000002200201148e93e9315e37dbed2121be5239257af35adc03ffdfc5d914b083afa44dab82202025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee076473044022007e06b362e89912abd4661f47945430739b006a85d1b2a16c01dc1a4bd07acab022061576d7aa834988b7ab94ef21d8eebd996ea59ea20529a19b15f0c9cebe3d8ac01220202b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a473044022002787f926d6817504431ee281183b8119b6845bfaa6befae45e13b6d430c9d2f02202859f149a6cd26ae2f03a107e7f33c7d91730dade305fe077bae677b5d44952a01010547522102b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a21025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee07652ae0001014752210283ef76537f2d58ae3aa3a4bd8ae41c3f230ccadffb1a0bd3ca504d871cff05e7210353d79cc0cb1396f4ce278d005f16d948e02a6aec9ed1109f13747ecb1507b37b52ae00010147522102b3937241777b6665e0d694e52f9c1b188433641df852da6fc42187b5d8a368a321034cdd474f01cc5aa7ff834ad8bcc882a87e854affc775486bc2a9f62e8f49bd7852ae00";
        let psbt: Psbt = hex_psbt(hex).unwrap();
        assert_eq!(hex, psbt.serialize_hex());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_psbt() {
        //! Create a full PSBT value with various fields filled and make sure it can be JSONized.
        use bitcoin::hashes::sha256d;

        use crate::sighash_type::PsbtSighashType;
        use crate::v0::map::Input;

        // create some values to use in the PSBT
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389"
                        .parse()
                        .unwrap(),
                    vout: 1,
                },
                script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985")
                    .unwrap(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[hex!(
                    "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"
                )]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(190_303_501_938),
                script_pubkey: ScriptBuf::from_hex(
                    "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                )
                .unwrap(),
            }],
        };
        let unknowns: BTreeMap<raw::Key, Vec<u8>> =
            vec![(raw::Key { type_value: 1, key: vec![0, 1] }, vec![3, 4, 5])]
                .into_iter()
                .collect();
        let key_source = ("deadbeef".parse().unwrap(), "m/0'/1".parse().unwrap());
        let keypaths: BTreeMap<bitcoin::secp256k1::PublicKey, KeySource> = vec![(
            "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
            key_source.clone(),
        )]
        .into_iter()
        .collect();

        let proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>> = vec![(
            raw::ProprietaryKey {
                prefix: "prefx".as_bytes().to_vec(),
                subtype: 42,
                key: "test_key".as_bytes().to_vec(),
            },
            vec![5, 6, 7],
        )]
        .into_iter()
        .collect();

        let psbt = Psbt {
            global: Global {
                version: V0,
                xpubs: {
                    let xpub: Xpub =
                        "xpub661MyMwAqRbcGoRVtwfvzZsq2VBJR1LAHfQstHUoxqDorV89vRoMxUZ27kLrraAj6MPi\
                         QfrDb27gigC1VS1dBXi5jGpxmMeBXEkKkcXUTg4".parse().unwrap();
                    vec![(xpub, key_source)].into_iter().collect()
                },
                unsigned_tx: {
                    let mut unsigned = tx.clone();
                    unsigned.input[0].script_sig = ScriptBuf::new();
                    unsigned.input[0].witness = Witness::default();
                    unsigned
                },
                proprietaries: proprietaries.clone(),
                unknowns: unknowns.clone(),
            },
            inputs: vec![
                Input {
                    non_witness_utxo: Some(tx),
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(190_303_501_938),
                        script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                    }),
                    sighash_type: Some("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY".parse::<PsbtSighashType>().unwrap()),
                    redeem_script: Some(vec![0x51].into()),
                    witness_script: None,
                    partial_sigs: vec![(
                        "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
                        "304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe701".parse().unwrap(),
                    )].into_iter().collect(),
                    bip32_derivations: keypaths.clone(),
                    final_script_witness: Some(Witness::from_slice(&[vec![1, 3], vec![5]])),
                    ripemd160_preimages: vec![(ripemd160::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    sha256_preimages: vec![(sha256::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    hash160_preimages: vec![(hash160::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    hash256_preimages: vec![(sha256d::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    proprietaries: proprietaries.clone(),
                    unknowns: unknowns.clone(),
                    ..Default::default()
                }
            ],
            outputs: vec![
                Output {
                    bip32_derivations: keypaths,
                    proprietaries,
                    unknowns,
                    ..Default::default()
                }
            ],
        };
        let encoded = serde_json::to_string(&psbt).unwrap();
        let decoded: Psbt = serde_json::from_str(&encoded).unwrap();
        assert_eq!(psbt, decoded);
    }

    #[test]
    fn serialize_and_deserialize_preimage_psbt() {
        // create a sha preimage map
        let mut sha256_preimages = BTreeMap::new();
        sha256_preimages.insert(sha256::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        sha256_preimages.insert(sha256::Hash::hash(&[1u8]), vec![1u8]);

        // same for hash160
        let mut hash160_preimages = BTreeMap::new();
        hash160_preimages.insert(hash160::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        hash160_preimages.insert(hash160::Hash::hash(&[1u8]), vec![1u8]);

        // same vector as valid_vector_1 from BIPs with added
        let mut unserialized = Psbt {
            global: Global {
                unsigned_tx: Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::from_consensus(1257139),
                    input: vec![
                        TxIn {
                            previous_output: OutPoint {
                                txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                                vout: 0,
                            },
                            script_sig: ScriptBuf::new(),
                            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                            witness: Witness::default(),
                        }
                    ],
                    output: vec![
                        TxOut {
                            value: Amount::from_sat(99_999_699),
                            script_pubkey: ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
                        },
                        TxOut {
                            value: Amount::from_sat(100_000_000),
                            script_pubkey: ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
                        },
                    ],
                },
                version: V0,
                xpubs: Default::default(),
                proprietaries: Default::default(),
                unknowns: BTreeMap::new(),
            },
            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: transaction::Version::ONE,
                        lock_time: absolute::LockTime::ZERO,
                        input: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985").unwrap(),
                                sequence: Sequence::MAX,
                                witness: Witness::from_slice(&[
                                    hex!("304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01"),
                                    hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"),
                                ]),
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptBuf::from_hex("160014fe3e9ef1a745e974d902c4355943abcb34bd5353").unwrap(),
                                sequence: Sequence::MAX,
                                witness: Witness::from_slice(&[
                                    hex!("3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01"),
                                    hex!("0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3"),
                                ]),
                            }
                        ],
                        output: vec![
                            TxOut {
                                value: Amount::from_sat(200_000_000),
                                script_pubkey: ScriptBuf::from_hex("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac").unwrap(),
                            },
                            TxOut {
                                value: Amount::from_sat(190_303_501_938),
                                script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        unserialized.inputs[0].hash160_preimages = hash160_preimages;
        unserialized.inputs[0].sha256_preimages = sha256_preimages;

        let rtt: Psbt = hex_psbt(&unserialized.serialize_hex()).unwrap();
        assert_eq!(rtt, unserialized);

        // Now add an ripemd160 with incorrect preimage
        let mut ripemd160_preimages = BTreeMap::new();
        ripemd160_preimages.insert(ripemd160::Hash::hash(&[17u8]), vec![18u8]);
        unserialized.inputs[0].ripemd160_preimages = ripemd160_preimages;

        // Now the roundtrip should fail as the preimage is incorrect.
        let rtt: Result<Psbt, _> = hex_psbt(&unserialized.serialize_hex());
        assert!(rtt.is_err());
    }

    #[test]
    fn serialize_and_deserialize_proprietaries() {
        let mut psbt: Psbt = hex_psbt("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        psbt.global.proprietaries.insert(
            raw::ProprietaryKey { prefix: b"test".to_vec(), subtype: 0u8, key: b"test".to_vec() },
            b"test".to_vec(),
        );
        assert!(!psbt.global.proprietaries.is_empty());
        let rtt: Psbt = hex_psbt(&psbt.serialize_hex()).unwrap();
        assert!(!rtt.global.proprietaries.is_empty());
    }

    // PSBTs taken from BIP 174 test vectors.
    #[test]
    fn combine_psbts() {
        let mut psbt1 = hex_psbt(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let psbt2 = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();
        let psbt_combined = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();

        psbt1.combine(psbt2).expect("psbt combine to succeed");
        assert_eq!(psbt1, psbt_combined);
    }

    #[test]
    fn combine_psbts_commutative() {
        let mut psbt1 = hex_psbt(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let mut psbt2 = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();

        let psbt1_clone = psbt1.clone();
        let psbt2_clone = psbt2.clone();

        psbt1.combine(psbt2_clone).expect("psbt1 combine to succeed");
        psbt2.combine(psbt1_clone).expect("psbt2 combine to succeed");

        assert_eq!(psbt1, psbt2);
    }

    #[cfg(feature = "rand-std")]
    fn gen_keys() -> (PrivateKey, PublicKey, Secp256k1<All>) {
        use bitcoin::secp256k1::rand::thread_rng;

        let secp = Secp256k1::new();

        let sk = SecretKey::new(&mut thread_rng());
        let priv_key = PrivateKey::new(sk, bitcoin::Network::Regtest);
        let pk = PublicKey::from_private_key(&secp, &priv_key);

        (priv_key, pk, secp)
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn get_key_btree_map() {
        let (priv_key, pk, secp) = gen_keys();

        let mut key_map = BTreeMap::new();
        key_map.insert(pk, priv_key);

        let got = key_map.get_key(KeyRequest::Pubkey(pk), &secp).expect("failed to get key");
        assert_eq!(got.unwrap(), priv_key)
    }

    #[test]
    fn test_fee() {
        let output_0_val = Amount::from_sat(99_999_699);
        let output_1_val = Amount::from_sat(100_000_000);
        let prev_output_val = Amount::from_sat(200_000_000);

        let mut t = Psbt {
            global: Global {
                unsigned_tx: Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::from_consensus(1257139),
                    input: vec![
                        TxIn {
                            previous_output: OutPoint {
                                txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                                vout: 0,
                            },
                            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                            ..Default::default()
                        }
                    ],
                    output: vec![
                        TxOut {
                            value: output_0_val,
                            script_pubkey:  ScriptBuf::new()
                        },
                        TxOut {
                            value: output_1_val,
                            script_pubkey:  ScriptBuf::new()
                        },
                    ],
                },
                xpubs: Default::default(),
                version: V0,
                proprietaries: BTreeMap::new(),
                unknowns: BTreeMap::new(),
            },
            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: transaction::Version::ONE,
                        lock_time: absolute::LockTime::ZERO,
                        input: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: Sequence::MAX,
                                ..Default::default()
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: Sequence::MAX,
                                ..Default::default()
                            }
                        ],
                        output: vec![
                            TxOut {
                                value: prev_output_val,
                                script_pubkey:  ScriptBuf::new()
                            },
                            TxOut {
                                value: Amount::from_sat(190_303_501_938),
                                script_pubkey:  ScriptBuf::new()
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        assert_eq!(
            t.fee().expect("fee calculation"),
            prev_output_val - (output_0_val + output_1_val)
        );
        // no previous output
        let mut t2 = t.clone();
        t2.inputs[0].non_witness_utxo = None;
        match t2.fee().unwrap_err() {
            FeeError::FundingUtxo(FundingUtxoError::MissingUtxo) => {}
            e => panic!("unexpected error: {:?}", e),
        }
        //  negative fee
        let mut t3 = t.clone();
        t3.global.unsigned_tx.output[0].value = prev_output_val;
        match t3.fee().unwrap_err() {
            FeeError::Negative => {}
            e => panic!("unexpected error: {:?}", e),
        }
        // overflow
        t.global.unsigned_tx.output[0].value = Amount::MAX;
        t.global.unsigned_tx.output[1].value = Amount::MAX;
        match t.fee().unwrap_err() {
            FeeError::OutputOverflow => {}
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn sign_psbt() {
        use bitcoin::bip32::{DerivationPath, Fingerprint};
        use bitcoin::witness_version::WitnessVersion;
        use bitcoin::{WPubkeyHash, WitnessProgram};

        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default(), TxIn::default()],
            output: vec![TxOut::NULL],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let (priv_key, pk, secp) = gen_keys();

        // key_map implements `GetKey` using KeyRequest::Pubkey. A pubkey key request does not use
        // keysource so we use default `KeySource` (fingreprint and derivation path) below.
        let mut key_map = BTreeMap::new();
        key_map.insert(pk, priv_key);

        // First input we can spend. See comment above on key_map for why we use defaults here.
        let txout_wpkh = TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&pk.to_bytes())),
        };
        psbt.inputs[0].witness_utxo = Some(txout_wpkh);

        let mut map = BTreeMap::new();
        map.insert(pk.inner, (Fingerprint::default(), DerivationPath::default()));
        psbt.inputs[0].bip32_derivation = map;

        // Second input is unspendable by us e.g., from another wallet that supports future upgrades.
        let unknown_prog = WitnessProgram::new(WitnessVersion::V4, vec![0xaa; 34]).unwrap();
        let txout_unknown_future = TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::new_witness_program(&unknown_prog),
        };
        psbt.inputs[1].witness_utxo = Some(txout_unknown_future);

        let sigs = psbt.sign(&key_map, &secp).unwrap();

        assert!(sigs.len() == 1);
        assert!(sigs[&0] == vec![pk]);
    }
}
