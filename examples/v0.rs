//! PSBT v0 2 of 2 multisig example.
//!
//! An example of using PSBT v0 to create a 2 of 2 multisig by spending two native segwit v0 inputs
//! to a native segwit v0 output (the multisig output).
//!
//! We sign invalid inputs, this code is not run against Bitcoin Core so everything here should be
//! taken as NOT PROVEN CORRECT.

use std::collections::BTreeMap;

use psbt_v2::bitcoin::hashes::Hash as _;
use psbt_v2::bitcoin::locktime::absolute;
use psbt_v2::bitcoin::opcodes::all::OP_CHECKMULTISIG;
use psbt_v2::bitcoin::secp256k1::{self, rand, SECP256K1};
use psbt_v2::bitcoin::{
    script, transaction, Address, Amount, CompressedPublicKey, Network, OutPoint, PublicKey,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use psbt_v2::v0::{self, Psbt};

pub const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
pub const SPEND_AMOUNT: Amount = Amount::from_sat(20_000_000);

const MAINNET: Network = Network::Bitcoin; // Bitcoin mainnet network.
const FEE: Amount = Amount::from_sat(1_000); // Usually this would be calculated.
const DUMMY_CHANGE_AMOUNT: Amount = Amount::from_sat(100_000);

fn main() -> anyhow::Result<()> {
    // Mimic two people, Alice and Bob, who wish to create a 2-of-2 multisig output together.
    let alice = Alice::new();
    let bob = Bob::new();

    // Each person provides their pubkey.
    let pk_a = alice.public_key();
    let pk_b = bob.public_key();

    // Each party will be contributing 20,000,000 sats to the mulitsig output, as such each party
    // provides an unspent input to create the multisig output (and any change details if needed).

    // Alice has a UTXO that is too big, she needs change.
    let (previous_output_a, change_address_a, change_value_a) = alice.contribute_to_multisig();

    // Bob has a UTXO the right size so no change needed.
    let previous_output_b = bob.contribute_to_multisig();

    // In PSBT v0 the creator is responsible for creating the transaction.

    // Build the inputs using information provide by each party.
    let input_0 = TxIn {
        previous_output: previous_output_a,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };
    let input_1 = TxIn {
        previous_output: previous_output_b,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    // Build Alice's change output.
    let change = TxOut { value: change_value_a, script_pubkey: change_address_a.script_pubkey() };

    // Create the witness script, receive address, and the locking script.
    let witness_script = multisig_witness_script(&pk_a, &pk_b);
    let address = Address::p2wsh(&witness_script, MAINNET);
    let value = SPEND_AMOUNT * 2 - FEE;
    // The spend output is locked by the witness script.
    let multi = TxOut { value, script_pubkey: address.script_pubkey() };

    // And create the transaction.
    let tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
        input: vec![input_0, input_1],
        output: vec![multi, change],
    };

    // Now the creator can create the PSBT.
    let mut psbt = v0::Psbt::from_unsigned_tx(tx)?;

    // Update the PSBT with the inputs described by `previous_output_a` and `previous_output_b`
    // above, here we get them from Alice and Bob, typically the update would have access to chain
    // data and would get them from there.
    psbt.inputs[0].witness_utxo = Some(alice.input_utxo());
    psbt.inputs[1].witness_utxo = Some(bob.input_utxo());

    // Since we are spending 2 p2wpkh inputs there are no other updates needed.

    // Each party signs a copy of the PSBT.
    let signed_by_a = alice.sign(psbt.clone())?;
    let _ = bob.sign(signed_by_a)?;

    // At this stage we would usually finalize with miniscript and extract the transaction.

    Ok(())
}

/// Creates a 2-of-2 multisig script locking to a and b's keys.
fn multisig_witness_script(a: &PublicKey, b: &PublicKey) -> ScriptBuf {
    script::Builder::new()
        .push_int(2)
        .push_key(a)
        .push_key(b)
        .push_int(2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

/// Party 1 in a 2-of-2 multisig.
pub struct Alice(Entity);

impl Alice {
    /// Creates a new actor with random keys.
    pub fn new() -> Self { Self(Entity::new_random()) }

    /// Returns the public key for this entity.
    pub fn public_key(&self) -> bitcoin::PublicKey { self.0.public_key() }

    /// Alice provides an input to be used to create the multisig and the details required to get
    /// some change back (change address and amount).
    pub fn contribute_to_multisig(&self) -> (OutPoint, Address, Amount) {
        // An obviously invalid output, we just use all zeros then use the `vout` to differentiate
        // Alice's output from Bob's.
        let out = OutPoint { txid: Txid::all_zeros(), vout: 0 };

        // The usual caveat about reusing addresses applies here, this is just an example.
        let compressed =
            CompressedPublicKey::try_from(self.public_key()).expect("uncompressed key");
        let address = Address::p2wpkh(&compressed, Network::Bitcoin);

        // This is a made up value, it is supposed to represent the outpoints value minus the value
        // contributed to the multisig.
        let amount = DUMMY_CHANGE_AMOUNT;

        (out, address, amount)
    }

    /// Provides the actual UTXO that Alice is contributing, this would usually come from the chain.
    pub fn input_utxo(&self) -> TxOut {
        // A dummy script_pubkey representing a UTXO that is locked to a pubkey that Alice controls.
        let script_pubkey =
            ScriptBuf::new_p2wpkh(&self.public_key().wpubkey_hash().expect("uncompressed key"));
        TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey }
    }

    /// Signs `psbt`.
    pub fn sign(&self, psbt: Psbt) -> anyhow::Result<Psbt> { self.0.sign_ecdsa(psbt) }
}

impl Default for Alice {
    fn default() -> Self { Self::new() }
}

/// Party 2 in a 2-of-2 multisig.
pub struct Bob(Entity);

impl Bob {
    /// Creates a new actor with random keys.
    pub fn new() -> Self { Self(Entity::new_random()) }

    /// Returns the public key for this entity.
    pub fn public_key(&self) -> bitcoin::PublicKey { self.0.public_key() }

    /// Bob provides an input to be used to create the multisig, its the right size so no change.
    pub fn contribute_to_multisig(&self) -> OutPoint {
        // An obviously invalid output, we just use all zeros then use the `vout` to differentiate
        // Alice's output from Bob's.
        OutPoint { txid: Txid::all_zeros(), vout: 1 }
    }

    /// Provides the actual UTXO that Alice is contributing, this would usually come from the chain.
    pub fn input_utxo(&self) -> TxOut {
        // A dummy script_pubkey representing a UTXO that is locked to a pubkey that Bob controls.
        let script_pubkey =
            ScriptBuf::new_p2wpkh(&self.public_key().wpubkey_hash().expect("uncompressed key"));
        TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey }
    }

    /// Signs `psbt`.
    pub fn sign(&self, psbt: Psbt) -> anyhow::Result<Psbt> { self.0.sign_ecdsa(psbt) }
}

impl Default for Bob {
    fn default() -> Self { Self::new() }
}

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

    /// Returns the private key for this entity.
    fn private_key(&self) -> bitcoin::PrivateKey { bitcoin::PrivateKey::new(self.sk, MAINNET) }

    /// Returns the public key for this entity.
    ///
    /// All examples use segwit so this key is serialize in compressed form.
    pub fn public_key(&self) -> bitcoin::PublicKey { bitcoin::PublicKey::new(self.pk) }

    /// Signs any ECDSA inputs for which we have keys.
    pub fn sign_ecdsa(&self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
        // TODO: Should this be called internally in the `v0` module?
        psbt.signer_checks()?;

        let sk = self.private_key();
        let pk = self.public_key();

        let mut keys = BTreeMap::new();
        keys.insert(pk, sk);
        psbt.sign(&keys, SECP256K1).expect("failed to sign psbt");

        Ok(psbt)
    }
}

/// Creates a set of random secp256k1 keys.
///
/// In a real application these would come from actual secrets.
fn random_keys() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let sk = secp256k1::SecretKey::new(&mut rand::thread_rng());
    let pk = sk.public_key(SECP256K1);
    (sk, pk)
}
