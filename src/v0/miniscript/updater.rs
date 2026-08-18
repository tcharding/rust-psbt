// SPDX-License-Identifier: CC0-1.0

//! This module complements the Updater role defined in BIP 174, PSBT, described at
//! `https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#updater`

use alloc::collections::BTreeMap;

use bitcoin::{ScriptBuf, TapLeafHash, XOnlyPublicKey, bip32};
use bitcoin::taproot::{ControlBlock, LeafVersion};
use miniscript::miniscript::satisfy::{Placeholder, SchnorrSigType};
use miniscript::{Descriptor, ToPublicKey, descriptor};
use miniscript::plan::Plan;

use crate::v0::Input;

#[allow(unused)]
/// Extension trait for the [`Plan`] miniscript module.
pub trait PlanExt {
    /// Modify an [`Input`] using the current struct as data source.
    fn update_psbt_input(&self, input: &mut Input);
}

impl PlanExt for Plan {
    /// Update a PSBT input with the metadata required to complete this plan
    ///
    /// This will only add the metadata for items required to complete this plan. For example, if
    /// there are multiple keys present in the descriptor, only the few used by this plan will be
    /// added to the PSBT.
    fn update_psbt_input(&self, input: &mut Input) {
        if let Descriptor::Tr(tr) = &self.descriptor {
            enum SpendType {
                KeySpend { internal_key: XOnlyPublicKey },
                ScriptSpend { leaf_hash: TapLeafHash },
            }

            #[derive(Default)]
            struct TrDescriptorData {
                tap_script: Option<ScriptBuf>,
                control_block: Option<ControlBlock>,
                spend_type: Option<SpendType>,
                key_origins: BTreeMap<XOnlyPublicKey, bip32::KeySource>,
            }

            let spend_info = tr.spend_info();
            input.tap_merkle_root = spend_info.merkle_root();

            let data = self
                .witness_template()
                .iter()
                .fold(TrDescriptorData::default(), |mut data, item| {
                    match item {
                        Placeholder::TapScript(script) => data.tap_script = Some(script.clone()),
                        Placeholder::TapControlBlock(cb) => data.control_block = Some(cb.clone()),
                        Placeholder::SchnorrSigPk(pk, sig_type, _) => {
                            let raw_pk = pk.to_x_only_pubkey();

                            match (&data.spend_type, sig_type) {
                                // First encountered schnorr sig, update the `TrDescriptorData` accordingly
                                (None, SchnorrSigType::KeySpend { .. }) => data.spend_type = Some(SpendType::KeySpend { internal_key: raw_pk }),
                                (None, SchnorrSigType::ScriptSpend { leaf_hash }) => data.spend_type = Some(SpendType::ScriptSpend { leaf_hash: *leaf_hash }),

                                // Inconsistent placeholders (should be unreachable with the
                                // current implementation)
                                (Some(SpendType::KeySpend {..}), SchnorrSigType::ScriptSpend { .. }) | (Some(SpendType::ScriptSpend {..}), SchnorrSigType::KeySpend{..}) => unreachable!("Mixed taproot key-spend and script-spend placeholders in the same plan"),

                                _ => {},
                            }

                            for path in pk.full_derivation_paths() {
                                data.key_origins.insert(raw_pk, (pk.master_fingerprint(), path));
                            }
                        }
                        Placeholder::SchnorrSigPkHash(_, tap_leaf_hash, _) => {
                            data.spend_type = Some(SpendType::ScriptSpend { leaf_hash: *tap_leaf_hash });
                        }
                        _ => {}
                    }

                    data
                });

            let leaf_hash = match data.spend_type {
                Some(SpendType::KeySpend { internal_key }) => {
                    input.tap_internal_key = Some(internal_key);
                    None
                }
                Some(SpendType::ScriptSpend { leaf_hash }) => Some(leaf_hash),
                _ => None,
            };
            for (pk, key_source) in data.key_origins {
                input
                    .tap_key_origins
                    .entry(pk)
                    .and_modify(|(leaf_hashes, _)| {
                        if let Some(lh) = leaf_hash {
                            if leaf_hashes.iter().all(|&i| i != lh) {
                                leaf_hashes.push(lh);
                            }
                        }
                    })
                    .or_insert_with(|| (vec![], key_source));
            }
            if let (Some(tap_script), Some(control_block)) = (data.tap_script, data.control_block) {
                input
                    .tap_scripts
                    .insert(control_block, (tap_script, LeafVersion::TapScript));
            }
        } else {
            for item in self.witness_template() {
                if let Placeholder::EcdsaSigPk(pk) = item {
                    let public_key = pk.to_public_key();
                    let master_fingerprint = pk.master_fingerprint();
                    for derivation_path in pk.full_derivation_paths() {
                        input
                            .bip32_derivation
                            .insert(public_key, (master_fingerprint, derivation_path));
                    }
                }
            }

            match &self.descriptor {
                Descriptor::Bare(_) | Descriptor::Pkh(_) | Descriptor::Wpkh(_) => {}
                Descriptor::Sh(sh) => match sh.as_inner() {
                    descriptor::ShInner::Wsh(wsh) => {
                        input.witness_script = Some(wsh.inner_script());
                        input.redeem_script = Some(wsh.inner_script().to_p2wsh());
                    }
                    descriptor::ShInner::Wpkh(..) => input.redeem_script = Some(sh.inner_script()),
                    descriptor::ShInner::SortedMulti(_) | descriptor::ShInner::Ms(_) => {
                        input.redeem_script = Some(sh.inner_script())
                    }
                },
                Descriptor::Wsh(wsh) => input.witness_script = Some(wsh.inner_script()),
                Descriptor::Tr(_) => unreachable!("Tr is dealt with separately"),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use bitcoin::bip32::Xpub;
    use miniscript::plan::Assets;
    use miniscript::{Descriptor, DescriptorPublicKey};
    use super::*;

    #[test]
    fn update_tr_psbt_input_with_plan() {
        // keys taken from: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#Specifications
        let root_xpub: Xpub = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8".parse().unwrap();
        let fingerprint = root_xpub.fingerprint();
        let xpub = format!("[{}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ", fingerprint);
        let desc =
            format!("tr({}/0/0,{{pkh({}/0/1),multi_a(2,{}/1/0,{}/1/1)}})", xpub, xpub, xpub, xpub);

        let desc: Descriptor<_> = desc.parse().unwrap();

        let internal_key: DescriptorPublicKey = format!("{}/0/0", xpub).parse().unwrap();
        let first_branch: DescriptorPublicKey = format!("{}/0/1", xpub).parse().unwrap();
        let second_branch: DescriptorPublicKey = format!("{}/1/*", xpub).parse().unwrap(); // Note this is a wildcard key, so it can sign for the whole multi_a

        let mut psbt_input = Input::default();
        let assets = Assets::new().add(internal_key);
        let plan = desc.clone().plan(&assets).unwrap();
        <Plan as PlanExt>::update_psbt_input(&plan, &mut psbt_input);

        assert!(psbt_input.tap_internal_key.is_some(), "Internal key is missing");
        assert!(psbt_input.tap_merkle_root.is_some(), "Merkle root is missing");
        assert_eq!(psbt_input.tap_key_origins.len(), 1, "Unexpected number of tap_key_origins");
        assert_eq!(psbt_input.tap_scripts.len(), 0, "Unexpected number of tap_scripts");

        let mut psbt_input = Input::default();
        let assets = Assets::new().add(first_branch);
        let plan = desc.clone().plan(&assets).unwrap();
        <Plan as PlanExt>::update_psbt_input(&plan, &mut psbt_input);

        assert!(psbt_input.tap_internal_key.is_none(), "Internal key is present");
        assert!(psbt_input.tap_merkle_root.is_some(), "Merkle root is missing");
        assert_eq!(psbt_input.tap_key_origins.len(), 1, "Unexpected number of tap_key_origins");
        assert_eq!(psbt_input.tap_scripts.len(), 1, "Unexpected number of tap_scripts");

        let mut psbt_input = Input::default();
        let assets = Assets::new().add(second_branch);
        let plan = desc.plan(&assets).unwrap();
        <Plan as PlanExt>::update_psbt_input(&plan, &mut psbt_input);

        assert!(psbt_input.tap_internal_key.is_none(), "Internal key is present");
        assert!(psbt_input.tap_merkle_root.is_some(), "Merkle root is missing");
        assert_eq!(psbt_input.tap_key_origins.len(), 2, "Unexpected number of tap_key_origins");
        assert_eq!(psbt_input.tap_scripts.len(), 1, "Unexpected number of tap_scripts");
    }

    #[test]
    fn update_segwit_psbt_input_with_plan() {
        // keys taken from: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#Specifications
        let root_xpub: Xpub = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8".parse().unwrap();
        let fingerprint = root_xpub.fingerprint();
        let xpub = format!("[{}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ", fingerprint);
        let desc = format!("wsh(multi(2,{}/1/0,{}/1/1))", xpub, xpub);

        let desc: Descriptor<_> = desc.parse().unwrap();

        let asset_key: DescriptorPublicKey = format!("{}/1/*", xpub).parse().unwrap(); // Note this is a wildcard key, so it can sign for the whole multi

        let mut psbt_input = Input::default();
        let assets = Assets::new().add(asset_key);
        let plan = desc.plan(&assets).unwrap();
        <Plan as PlanExt>::update_psbt_input(&plan, &mut psbt_input);

        assert!(psbt_input.witness_script.is_some(), "Witness script missing");
        assert!(psbt_input.redeem_script.is_none(), "Redeem script present");
        assert_eq!(psbt_input.bip32_derivation.len(), 2, "Unexpected number of bip32_derivation");
    }
}
