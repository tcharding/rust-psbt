// SPDX-License-Identifier: CC0-1.0

//! Implements a client that wraps the `bitcoind` client (which uses the `bitcoincore-rpc` client).
//!
//! Adds balance tracking that is specific to how Bitcoin Core works on regtest.

// We depend upon and import directly from bitcoin because this module is not concerned with PSBT
// i.e., it is lower down the stack than the psbt_v2 crate.
use psbt_v2::bitcoin::{Address, Amount, Transaction, Txid};
use bitcoind::{AddressType, Node, vtype::GetBlockchainInfo};

const FIFTY_BTC: Amount = Amount::from_int_btc(50);

/// A custom bitcoind client.
pub struct Client {
    /// Handle for the regtest `bitcoind` instance.
    bitcoind: Node,
    /// This is public so we don't have to handle the complexity of know if send/receives are
    /// to/from the Core controlled wallet or somewhere else. User is required to manage this.
    pub balance: BalanceTracker,
}

impl Client {
    /// Creates a new [`Client`].
    pub fn new() -> anyhow::Result<Self> {
        let exe_path = bitcoind::exe_path()?;
        let bitcoind = Node::new(exe_path)?;
        let balance = BalanceTracker::zero();

        let client = Client { bitcoind, balance };

        // Sanity check.
        assert_eq!(0, client.get_blockchain_info().unwrap().blocks);

        client.mine_blocks(100)?;
        assert_eq!(100, client.get_blockchain_info().unwrap().blocks);

        client.assert_balance_is_as_expected()?; // Sanity check.

        Ok(client)
    }

    /// Mines a block to a new address controlled by the currently loaded Bitcoin Core wallet.
    pub fn mine_a_block(&mut self) -> anyhow::Result<()> {
        self.mine_blocks(1)?;
        self.balance.mine_a_block();
        Ok(())
    }

    /// Returns the amount in the balance tracker.
    pub fn tracked_balance(&self) -> Amount { self.balance.balance }

    #[track_caller]
    pub fn assert_balance_is_as_expected(&self) -> anyhow::Result<()> {
        let balance = self.balance()?;
        self.balance.assert(balance);
        Ok(())
    }

    /// Calls through to bitcoincore_rpc client.
    pub fn get_blockchain_info(&self) -> anyhow::Result<GetBlockchainInfo> {
        let client = &self.bitcoind.client;
        Ok(client.get_blockchain_info()?)
    }

    /// Gets an address controlled by the currently loaded Bitcoin Core wallet (via `bitcoind`).
    pub fn core_wallet_controlled_address(&self) -> anyhow::Result<Address> {
        let client = &self.bitcoind.client;
        // Use Bech32 (segwit v0) for compatibility with all Bitcoin Core versions.
        // Bech32m (taproot) is only available from Bitcoin Core 22.0+.
        let address = client.new_address_with_type(AddressType::Bech32)?;
        Ok(address)
    }

    pub fn balance(&self) -> anyhow::Result<Amount> {
        let client = &self.bitcoind.client;
        let balance = client.get_balance()?.balance()?;
        Ok(balance)
    }

    /// Mines `n` blocks to a new address controlled by the currently loaded Bitcoin Core wallet.
    fn mine_blocks(&self, n: usize) -> anyhow::Result<()> {
        let client = &self.bitcoind.client;
        // Generate to an address controlled by the bitcoind wallet and wait for funds to mature.
        let address = self.core_wallet_controlled_address()?;
        let _ = client.generate_to_address(n, &address)?;

        Ok(())
    }

    /// Send `amount` to `address`.
    ///
    /// Caller required to update balance (ie, call self.balance.send()).
    pub fn send(&self, amount: Amount, address: &Address) -> anyhow::Result<Txid> {
        let client = &self.bitcoind.client;
        let txid = client.send_to_address(address, amount)?.txid()?;
        Ok(txid)
    }

    pub fn get_transaction(&self, txid: &Txid) -> anyhow::Result<Transaction> {
        let client = &self.bitcoind.client;
        let res = client.get_transaction(*txid)?;
        let tx = res.into_model()?.tx;
        Ok(tx)
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> anyhow::Result<Txid> {
        let client = &self.bitcoind.client;
        let txid = client.send_raw_transaction(tx)?.txid()?;
        Ok(txid)
    }
}

/// Tracks the amount we expect the Core controlled wallet to hold.
///
/// We are sending whole bitcoin amounts back and forth, as a rough check that the transactions have
/// been mined we test against the integer floor of the amount, this allows us to not track fees.
pub struct BalanceTracker {
    balance: Amount,
}

impl BalanceTracker {
    /// Creates a new `BalanceTracker`.
    fn zero() -> Self { Self { balance: Amount::ZERO } }

    /// Everytime we mine a block we release another coinbase reward.
    fn mine_a_block(&mut self) { self.balance += FIFTY_BTC }

    /// Mimic sending, deduct token fee amount.
    pub fn send_to_self(&mut self) { self.send(Amount::ZERO) }

    /// Update balance by sending `amount`.
    pub fn send(&mut self, amount: Amount) {
        // 1000 mimics some fee amount, the exact amount is not important
        // because we ignore everything after the decimal place.
        self.balance = self.balance - amount - Amount::from_sat(1000);
    }

    /// Update balance by receiving `amount`.
    pub fn receive(&mut self, amount: Amount) {
        // 1000 mimics some fee amount, the exact amount is not important
        // because we ignore everything after the decimal place.
        self.balance = self.balance + amount + FIFTY_BTC - Amount::from_sat(1000)
    }

    /// Asserts balance against `want` ignoring everything except
    /// whole bitcoin, this allows us to ignore fees.
    #[track_caller]
    fn assert(&self, want: Amount) {
        let got = floor(self.balance);
        let floor_want = floor(want);
        if got != floor_want {
            panic!("We have {} but were expecting to have {} ({})", got, floor_want, want);
        }
    }
}

fn floor(x: Amount) -> Amount {
    let one = 100_000_000;
    let sats = x.to_sat();
    Amount::from_sat(sats / one * one)
}
