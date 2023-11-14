//! Common utilities used by various examples.
//!
//! Includes abstracting over a signer, i.e. something with access to secret keys.
//!
//! The rest of this stuff is all just to get the examples to build, in a real application one would
//! need to provide valid data in place of these utilities.

use psbt::bitcoin::secp256k1::{self, rand, Message, SECP256K1};
use psbt::bitcoin::sighash::{self, EcdsaSighashType, SighashCache};
use psbt::bitcoin::{self, ecdsa, Amount};
use psbt::v0::Psbt;

pub const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
pub const SPEND_AMOUNT: Amount = Amount::from_sat(20_000_000);

/// An entity that can take on one of the PSBT roles.
pub struct Entity {
    sk: secp256k1::SecretKey,
    pk: secp256k1::PublicKey,
}

impl Entity {
    /// Creates a new entity with random keys.
    pub fn new_random() -> Self {
        let (sk, pk) = random_keys();
        Entity { sk, pk }
    }
    /// Returns the public key for this entity.
    ///
    /// All examples use segwit so this key is serialize in compressed form.
    pub fn public_key(&self) -> bitcoin::PublicKey { bitcoin::PublicKey::new(self.pk) }

    /// Signs a P2WPKH input using the `bitcoin::sighash::SighashCache` API.
    ///
    /// # Panics
    ///
    /// Panics if `input_index` is out of range.
    pub fn sign_p2wpkh_input(
        &self,
        psbt: &Psbt,
        input_index: usize,
    ) -> Result<ecdsa::Signature, sighash::Error> {
        let input = psbt.inputs[input_index].witness_utxo.as_ref().expect("witness utxo");

        // Get the sighash to sign.
        let sighash_type = EcdsaSighashType::All;
        let mut sighasher = SighashCache::new(&psbt.global.unsigned_tx);
        let sighash = sighasher.p2wpkh_signature_hash(
            input_index,
            &input.script_pubkey,
            SPEND_AMOUNT,
            sighash_type,
        )?;

        // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
        let msg = Message::from(sighash);
        let sig = SECP256K1.sign_ecdsa(&msg, &self.sk);

        let sig = ecdsa::Signature { sig, hash_ty: sighash_type };
        Ok(sig)
    }
}

/// Creates a set of random secp256k1 keys.
///
/// In a real application these would come from actual secrets.
fn random_keys() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let sk = secp256k1::SecretKey::new(&mut rand::thread_rng());
    let pk = sk.public_key(&SECP256K1);
    (sk, pk)
}
