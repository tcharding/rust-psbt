// SPDX-License-Identifier: CC0-1.0

//! Private utils copied from `rust-miniscript`'s `util` module.

use crate::prelude::*;
use bitcoin::consensus::encode::VarInt;
use miniscript::miniscript::satisfy::Placeholder;
use miniscript::MiniscriptKey;

// Privately scoped stuff taken from `miniscript::util`, this is duplicated in the v2 module.

pub(crate) trait ItemSize {
    fn size(&self) -> usize;
}

impl<Pk: MiniscriptKey> ItemSize for Placeholder<Pk> {
    fn size(&self) -> usize {
        match self {
            Self::Pubkey(_, size) => *size,
            Self::PubkeyHash(_, size) => *size,
            Self::EcdsaSigPk(_) | Self::EcdsaSigPkHash(_) => 73,
            Self::SchnorrSigPk(_, _, size) | Self::SchnorrSigPkHash(_, _, size) =>
                size + 1, // +1 for the OP_PUSH
            Self::HashDissatisfaction
            | Self::Sha256Preimage(_)
            | Self::Hash256Preimage(_)
            | Self::Ripemd160Preimage(_)
            | Self::Hash160Preimage(_) => 33,
            Self::PushOne => 2, // On legacy this should be 1 ?
            Self::PushZero => 1,
            Self::TapScript(s) => s.len(),
            Self::TapControlBlock(cb) => cb.serialize().len(),
        }
    }
}

impl ItemSize for Vec<u8> {
    fn size(&self) -> usize { self.len() }
}

// Helper function to calculate witness size
pub(crate) fn witness_size<T: ItemSize>(wit: &[T]) -> usize {
    wit.iter().map(T::size).sum::<usize>() + varint_len(wit.len())
}

pub(crate) fn varint_len(n: usize) -> usize { VarInt(n as u64).size() }
