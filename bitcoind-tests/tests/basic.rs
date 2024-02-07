//! A basic PSBT test, a single entity using PSBTv2 to create and sign a transaction.

use core::str::FromStr;

// Only depend on `psbt` (and `bitcoind_tests`) because we are explicitly testing the `psbt_v2` crate.
use bitcoind_tests::client::Client;
use psbt::bitcoin::{Address, Amount, Network, OutPoint, PublicKey, Script, Transaction, TxOut};
use psbt::v2::{Constructor, InputBuilder, Modifiable, OutputBuilder};
// The `psbt_v2` crate, as we expect downstream to use it
// E.g., in manifest file `use psbt = { package = "psbt_v2" ... }`
use psbt_v2 as psbt;

const NETWORK: Network = Network::Regtest;
const TWO_BTC: Amount = Amount::from_int_btc(2);
const ONE_BTC: Amount = Amount::from_int_btc(1);
const FEE: Amount = Amount::from_sat(1000); // Arbitrary fee.

#[test]
fn basic() -> anyhow::Result<()> {
    // Create the RPC client and a wallet controlled by Bitcoin Core.
    let mut client = Client::new()?;
    // Fund the wallet with 50 BTC.
    client.mine_a_block()?;

    // Create an entity who wishes to use PSBTs to create a transaction.
    let alice = Alice::new();
    let alice_address = alice.address();

    // Send coin from the Core controlled wallet to Alice.
    let txid = client.send(TWO_BTC, &alice.address())?;
    client.balance.send(TWO_BTC);
    client.mine_a_block()?;
    client.assert_balance_is_as_expected()?;

    // Get the chain data for Alice's UTXO shew wishes to spend from.
    let tx = client.get_transaction(&txid)?;
    let utxos = tx.outputs_encumbered_by(&alice_address.script_pubkey());
    assert_eq!(utxos.len(), 1);
    let (out_point, fund) = utxos[0];

    let receiver = client.core_wallet_controlled_address()?;
    let spend_amount = ONE_BTC;
    let change_amount = fund.value - spend_amount - FEE;

    let constructor = Constructor::<Modifiable>::default();

    let spend_output = TxOut { value: spend_amount, script_pubkey: receiver.script_pubkey() };
    let change_output = TxOut {
        value: change_amount,
        // Since this is a basic example, just send back to same address.
        script_pubkey: alice_address.script_pubkey(),
    };

    let input = InputBuilder::new(&out_point).segwit_fund(fund.clone()).build();
    let spend = OutputBuilder::new(spend_output).build();
    let change = OutputBuilder::new(change_output).build();

    let psbt = constructor.input(input).output(spend).output(change).psbt()?;
    psbt.determine_lock_time()?;

    // Serialize and pass to hardware wallet to sign.
    println!("PSBTv2 ready for signing\n{:#?}", psbt);

    Ok(())
}

pub trait TransactionExt {
    /// Returns a list of UTXOs in this transaction that are encumbered by `script_pubkey`.
    fn outputs_encumbered_by(&self, script_pubkey: &Script) -> Vec<(OutPoint, &TxOut)>;
}

impl TransactionExt for Transaction {
    fn outputs_encumbered_by(&self, script_pubkey: &Script) -> Vec<(OutPoint, &TxOut)> {
        let mut utxos = vec![];
        for (index, utxo) in self.output.iter().enumerate() {
            if &utxo.script_pubkey == script_pubkey {
                let out_point = OutPoint { txid: self.txid(), vout: index as u32 };

                utxos.push((out_point, utxo));
            }
        }
        utxos
    }
}

/// A super basic entity with a single public key.
pub struct Alice {
    /// The single public key.
    public_key: PublicKey,
}

impl Alice {
    /// Creates a new Alice.
    pub fn new() -> Self {
        // An arbitrary public key, assume the secret key is held by another entity.
        let public_key = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();

        Alice { public_key }
    }

    /// Returns a bech32m address from a key Alice controls.
    pub fn address(&self) -> Address {
        Address::p2wpkh(&self.public_key, NETWORK).expect("uncompressed key")
    }
}
