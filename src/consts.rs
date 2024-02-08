// SPDX-License-Identifier: CC0-1.0

//! The keytype conts defined in [BIP-174] and [BIP-370].
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

#![allow(dead_code)]

/// Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
pub(crate) const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
pub(crate) const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// Type: Transaction Version PSBT_GLOBAL_TX_VERSION = 0x02
pub(crate) const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
/// Type: Fallback Locktime PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
pub(crate) const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
/// Type: Input Count PSBT_GLOBAL_INPUT_COUNT = 0x04
pub(crate) const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
/// Type: Output Count PSBT_GLOBAL_OUTPUT_COUNT = 0x05
pub(crate) const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
/// Type: Transaction Modifiable Flags PSBT_GLOBAL_TX_MODIFIABLE = 0x06
pub(crate) const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
pub(crate) const PSBT_GLOBAL_VERSION: u8 = 0xFB;
/// Type: Proprietary Use Type PSBT_GLOBAL_PROPRIETARY = 0xFC
pub(crate) const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

/// Type: Non-Witness UTXO PSBT_IN_NON_WITNESS_UTXO = 0x00
pub(crate) const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
/// Type: Witness UTXO PSBT_IN_WITNESS_UTXO = 0x01
pub(crate) const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
/// Type: Partial Signature PSBT_IN_PARTIAL_SIG = 0x02
pub(crate) const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
/// Type: Sighash Type PSBT_IN_SIGHASH_TYPE = 0x03
pub(crate) const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
/// Type: Redeem Script PSBT_IN_REDEEM_SCRIPT = 0x04
pub(crate) const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
/// Type: Witness Script PSBT_IN_WITNESS_SCRIPT = 0x05
pub(crate) const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
/// Type: BIP 32 Derivation Path PSBT_IN_BIP32_DERIVATION = 0x06
pub(crate) const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
/// Type: Finalized scriptSig PSBT_IN_FINAL_SCRIPTSIG = 0x07
pub(crate) const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
/// Type: Finalized scriptWitness PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
pub(crate) const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
/// Type: Proof-of-reserves commitment PSBT_IN_POR_COMMITMENT = 0x09
#[allow(unused)] // PSBT v0
pub(crate) const PSBT_IN_POR_COMMITMENT: u8 = 0x09;
/// Type: RIPEMD160 preimage PSBT_IN_RIPEMD160 = 0x0a
pub(crate) const PSBT_IN_RIPEMD160: u8 = 0x0a;
/// Type: SHA256 preimage PSBT_IN_SHA256 = 0x0b
pub(crate) const PSBT_IN_SHA256: u8 = 0x0b;
/// Type: HASH160 preimage PSBT_IN_HASH160 = 0x0c
pub(crate) const PSBT_IN_HASH160: u8 = 0x0c;
/// Type: HASH256 preimage PSBT_IN_HASH256 = 0x0d
pub(crate) const PSBT_IN_HASH256: u8 = 0x0d;
/// Type: Previous TXID PSBT_IN_PREVIOUS_TXID = 0x0e
pub(crate) const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
/// Type: Spent Output Index PSBT_IN_OUTPUT_INDEX = 0x0f
pub(crate) const PSBT_IN_OUTPUT_INDEX: u8 = 0x0f;
/// Type: Sequence Number PSBT_IN_SEQUENCE = 0x10
pub(crate) const PSBT_IN_SEQUENCE: u8 = 0x10;
/// Type: Required Time-based Locktime PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11
pub(crate) const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
/// Type: Required Height-based Locktime PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
pub(crate) const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
/// Type: Taproot Signature in Key Spend PSBT_IN_TAP_KEY_SIG = 0x13
pub(crate) const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
/// Type: Taproot Signature in Script Spend PSBT_IN_TAP_SCRIPT_SIG = 0x14
pub(crate) const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
/// Type: Taproot Leaf Script PSBT_IN_TAP_LEAF_SCRIPT = 0x14
pub(crate) const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_IN_TAP_BIP32_DERIVATION = 0x16
pub(crate) const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
/// Type: Taproot Internal Key PSBT_IN_TAP_INTERNAL_KEY = 0x17
pub(crate) const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
/// Type: Taproot Merkle Root PSBT_IN_TAP_MERKLE_ROOT = 0x18
pub(crate) const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;
/// Type: Proprietary Use Type PSBT_IN_PROPRIETARY = 0xFC
pub(crate) const PSBT_IN_PROPRIETARY: u8 = 0xFC;

/// Type: Redeem ScriptBuf PSBT_OUT_REDEEM_SCRIPT = 0x00
pub(crate) const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
/// Type: Witness ScriptBuf PSBT_OUT_WITNESS_SCRIPT = 0x01
pub(crate) const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
/// Type: BIP 32 Derivation Path PSBT_OUT_BIP32_DERIVATION = 0x02
pub(crate) const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
/// Type: Output Amount PSBT_OUT_AMOUNT = 0x03
pub(crate) const PSBT_OUT_AMOUNT: u8 = 0x03;
/// Type: Output Script PSBT_OUT_SCRIPT = 0x04
pub(crate) const PSBT_OUT_SCRIPT: u8 = 0x04;
/// Type: Taproot Internal Key PSBT_OUT_TAP_INTERNAL_KEY = 0x05
pub(crate) const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
/// Type: Taproot Tree PSBT_OUT_TAP_TREE = 0x06
pub(crate) const PSBT_OUT_TAP_TREE: u8 = 0x06;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
pub(crate) const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
/// Type: Proprietary Use Type PSBT_IN_PROPRIETARY = 0xFC
pub(crate) const PSBT_OUT_PROPRIETARY: u8 = 0xFC;

/// Converts a global key type value consts to a string, useful for debugging.
pub(crate) fn psbt_global_key_type_value_to_str(v: u8) -> &'static str {
    match v {
        PSBT_GLOBAL_UNSIGNED_TX => "PSBT_GLOBAL_UNSIGNED_TX",
        PSBT_GLOBAL_XPUB => "PSBT_GLOBAL_XPUB",
        PSBT_GLOBAL_TX_VERSION => "PSBT_GLOBAL_TX_VERSION",
        PSBT_GLOBAL_FALLBACK_LOCKTIME => "PSBT_GLOBAL_FALLBACK_LOCKTIME",
        PSBT_GLOBAL_INPUT_COUNT => "PSBT_GLOBAL_INPUT_COUNT",
        PSBT_GLOBAL_OUTPUT_COUNT => "PSBT_GLOBAL_OUTPUT_COUNT",
        PSBT_GLOBAL_TX_MODIFIABLE => "PSBT_GLOBAL_TX_MODIFIABLE",
        PSBT_GLOBAL_VERSION => "PSBT_GLOBAL_VERSION",
        PSBT_GLOBAL_PROPRIETARY => "PSBT_GLOBAL_PROPRIETARY",
        _ => "unknown PSBT_GLOBAL_ key type value",
    }
}

/// Converts an input key type value consts to a string, useful for debugging.
pub(crate) fn psbt_in_key_type_value_to_str(v: u8) -> &'static str {
    match v {
        PSBT_IN_NON_WITNESS_UTXO => "PSBT_IN_NON_WITNESS_UTXO",
        PSBT_IN_WITNESS_UTXO => "PSBT_IN_WITNESS_UTXO",
        PSBT_IN_PARTIAL_SIG => "PSBT_IN_PARTIAL_SIG",
        PSBT_IN_SIGHASH_TYPE => "PSBT_IN_SIGHASH_TYPE",
        PSBT_IN_REDEEM_SCRIPT => "PSBT_IN_REDEEM_SCRIPT",
        PSBT_IN_WITNESS_SCRIPT => "PSBT_IN_WITNESS_SCRIPT",
        PSBT_IN_BIP32_DERIVATION => "PSBT_IN_BIP32_DERIVATION",
        PSBT_IN_FINAL_SCRIPTSIG => "PSBT_IN_FINAL_SCRIPTSIG",
        PSBT_IN_FINAL_SCRIPTWITNESS => "PSBT_IN_FINAL_SCRIPTWITNESS",
        PSBT_IN_POR_COMMITMENT => "PSBT_IN_POR_COMMITMENT",
        PSBT_IN_RIPEMD160 => "PSBT_IN_RIPEMD160",
        PSBT_IN_SHA256 => "PSBT_IN_SHA256",
        PSBT_IN_HASH160 => "PSBT_IN_HASH160",
        PSBT_IN_HASH256 => "PSBT_IN_HASH256",
        PSBT_IN_PREVIOUS_TXID => "PSBT_IN_PREVIOUS_TXID",
        PSBT_IN_OUTPUT_INDEX => "PSBT_IN_OUTPUT_INDEX",
        PSBT_IN_SEQUENCE => "PSBT_IN_SEQUENCE",
        PSBT_IN_REQUIRED_TIME_LOCKTIME => "PSBT_IN_REQUIRED_TIME_LOCKTIME",
        PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
        PSBT_IN_TAP_KEY_SIG => "PSBT_IN_TAP_KEY_SIG",
        PSBT_IN_TAP_SCRIPT_SIG => "PSBT_IN_TAP_SCRIPT_SIG",
        PSBT_IN_TAP_LEAF_SCRIPT => "PSBT_IN_TAP_LEAF_SCRIPT",
        PSBT_IN_TAP_BIP32_DERIVATION => "PSBT_IN_TAP_BIP32_DERIVATION",
        PSBT_IN_TAP_INTERNAL_KEY => "PSBT_IN_TAP_INTERNAL_KEY",
        PSBT_IN_TAP_MERKLE_ROOT => "PSBT_IN_TAP_MERKLE_ROOT",
        PSBT_IN_PROPRIETARY => "PSBT_IN_PROPRIETARY",
        _ => "unknown PSBT_IN_ key type value",
    }
}

/// Converts an output key type value consts to a string, useful for debugging.
pub(crate) fn psbt_out_key_type_value_to_str(v: u8) -> &'static str {
    match v {
        PSBT_OUT_REDEEM_SCRIPT => "PSBT_OUT_REDEEM_SCRIPT",
        PSBT_OUT_WITNESS_SCRIPT => "PSBT_OUT_WITNESS_SCRIPT",
        PSBT_OUT_BIP32_DERIVATION => "PSBT_OUT_BIP32_DERIVATION",
        PSBT_OUT_AMOUNT => "PSBT_OUT_AMOUNT",
        PSBT_OUT_SCRIPT => "PSBT_OUT_SCRIPT",
        PSBT_OUT_TAP_INTERNAL_KEY => "PSBT_OUT_TAP_INTERNAL_KEY",
        PSBT_OUT_TAP_TREE => "PSBT_OUT_TAP_TREE",
        PSBT_OUT_TAP_BIP32_DERIVATION => "PSBT_OUT_TAP_BIP32_DERIVATION",
        PSBT_OUT_PROPRIETARY => "PSBT_OUT_PROPRIETARY",
        _ => "unknown PSBT_OUT_ key type value",
    }
}
