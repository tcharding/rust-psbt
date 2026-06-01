// SPDX-License-Identifier: CC0-1.0

//! This module complements the Updater role defined in BIP 174, PSBT, described at
//! `https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#updater`

use crate::v0::Input;

/// Extension trait for the [`Plan`] miniscript module.
pub trait PlanExt {
    /// Modify an [`Input`] using the current struct as data source.
    fn update_psbt_input(&self, input: &mut Input);
}
