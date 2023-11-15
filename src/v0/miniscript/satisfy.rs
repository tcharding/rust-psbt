// SPDX-License-Identifier: CC0-1.0

use crate::bitcoin::hashes::{hash160, sha256d, Hash};
use crate::bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use crate::bitcoin::{absolute, transaction, Sequence};
use crate::miniscript::{MiniscriptKey, Preimage32, Satisfier, SigType, ToPublicKey};
use crate::prelude::*;
use crate::v0::Psbt;

/// A PSBT [`Satisfier`] for an input at a particular index.
///
/// Contains reference to the [`Psbt`] because multiple inputs will share the same PSBT. All
/// operations on this structure will panic if index is more than number of inputs in pbst
///
/// [`Satisfier`]: crate::miniscript::Satisfier
pub struct PsbtInputSatisfier<'a> {
    /// Reference to the [`Psbt`].
    pub psbt: &'a Psbt,
    /// Index of the input we are satisfying.
    pub index: usize,
}

impl<'a> PsbtInputSatisfier<'a> {
    /// Creates a new `PsbtInputSatisfier` from `psbt` and `index`.
    pub fn new(psbt: &'a Psbt, index: usize) -> Self { Self { psbt, index } }
}

impl<'a, Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for PsbtInputSatisfier<'a> {
    fn lookup_tap_key_spend_sig(&self) -> Option<bitcoin::taproot::Signature> {
        self.psbt.inputs[self.index].tap_key_sig
    }

    fn lookup_tap_leaf_script_sig(
        &self,
        pk: &Pk,
        lh: &TapLeafHash,
    ) -> Option<bitcoin::taproot::Signature> {
        self.psbt.inputs[self.index].tap_script_sigs.get(&(pk.to_x_only_pubkey(), *lh)).copied()
    }

    fn lookup_raw_pkh_pk(&self, pkh: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        self.psbt.inputs[self.index]
            .bip32_derivation
            .iter()
            .find(|&(pubkey, _)| pubkey.to_pubkeyhash(SigType::Ecdsa) == *pkh)
            .map(|(pubkey, _)| bitcoin::PublicKey::new(*pubkey))
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (bitcoin::ScriptBuf, LeafVersion)>> {
        Some(&self.psbt.inputs[self.index].tap_scripts)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pkh: &(hash160::Hash, TapLeafHash),
    ) -> Option<(bitcoin::secp256k1::XOnlyPublicKey, bitcoin::taproot::Signature)> {
        self.psbt.inputs[self.index]
            .tap_script_sigs
            .iter()
            .find(|&((pubkey, lh), _sig)| {
                pubkey.to_pubkeyhash(SigType::Schnorr) == pkh.0 && *lh == pkh.1
            })
            .map(|((x_only_pk, _leaf_hash), sig)| (*x_only_pk, *sig))
    }

    fn lookup_ecdsa_sig(&self, pk: &Pk) -> Option<bitcoin::ecdsa::Signature> {
        self.psbt.inputs[self.index].partial_sigs.get(&pk.to_public_key()).copied()
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pkh: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, bitcoin::ecdsa::Signature)> {
        self.psbt.inputs[self.index]
            .partial_sigs
            .iter()
            .find(|&(pubkey, _sig)| pubkey.to_pubkeyhash(SigType::Ecdsa) == *pkh)
            .map(|(pk, sig)| (*pk, *sig))
    }

    fn check_after(&self, n: absolute::LockTime) -> bool {
        if !self.psbt.global.unsigned_tx.input[self.index].enables_lock_time() {
            return false;
        }

        let lock_time = self.psbt.global.unsigned_tx.lock_time;

        <dyn Satisfier<Pk>>::check_after(&lock_time, n)
    }

    fn check_older(&self, n: Sequence) -> bool {
        let seq = self.psbt.global.unsigned_tx.input[self.index].sequence;

        // https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
        // Disable flag set => return true.
        if !n.is_relative_lock_time() {
            return true;
        }

        if self.psbt.global.unsigned_tx.version < transaction::Version::TWO
            || !seq.is_relative_lock_time()
        {
            return false;
        }

        <dyn Satisfier<Pk>>::check_older(&seq, n)
    }

    fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
        self.psbt.inputs[self.index]
            .hash160_preimages
            .get(&Pk::to_hash160(h))
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
        self.psbt.inputs[self.index]
            .sha256_preimages
            .get(&Pk::to_sha256(h))
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
        self.psbt.inputs[self.index]
            .hash256_preimages
            .get(&sha256d::Hash::from_byte_array(Pk::to_hash256(h).to_byte_array())) // upstream psbt operates on hash256
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
        self.psbt.inputs[self.index]
            .ripemd160_preimages
            .get(&Pk::to_ripemd160(h))
            .and_then(try_vec_as_preimage32)
    }
}

fn try_vec_as_preimage32(vec: &Vec<u8>) -> Option<Preimage32> {
    if vec.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(vec);
        Some(arr)
    } else {
        None
    }
}
