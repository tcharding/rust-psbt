//! Test the bitcoind infrastructure.

mod client;

use client::Client;
use psbt_v2::bitcoin::Amount;

#[track_caller]
fn client() -> Client {
    let client = Client::new().expect("failed to create client");
    // Sanity check.
    assert_eq!(0, client.get_blockchain_info().unwrap().blocks);

    client.fund().expect("failed to fund client");
    client
}

#[test]
fn bitcoind_get_core_wallet_controlled_address() {
    let client = client();
    let address = client.core_wallet_controlled_address().expect("get_new_address failed");
    println!("address: {}", address);
}

#[test]
fn bitcoind_fund_core_controlled_wallet() {
    let client = client();
    assert!(client.fund().is_ok())
}

#[test]
fn bitcoind_send() {
    let client = client();

    let address = client.core_wallet_controlled_address().expect("get_new_address failed");
    let amount = Amount::ONE_BTC;

    let txid = client.send(amount, &address).expect("send failed");
    println!("txid: {}", txid);
}
