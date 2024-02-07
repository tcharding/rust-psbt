//! Tools to help with testing against Bitcoin Core using [`bitcoind`] and [`bitcoincore-rpc`].
//!
//! [`bitcoind`]: <https://github.com/rust-bitcoin/bitcoind>
//! [`bitcoincore-rpc`]: <https://github.com/rust-bitcoin/rust-bitcoincore-rpc/>

/// A wrapper around the `bitcoind` client.
pub mod client;
