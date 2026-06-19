use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::{Secp256k1, Signing};
use miniscript::descriptor::{DescriptorSecretKey, KeyMap};

use crate::prelude::*;
use crate::v0::bitcoin::{GetKey, GetKeyError, KeyRequest};

impl GetKey for DescriptorSecretKey {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match (self, key_request) {
            (Self::Single(single_priv), key_request) => {
                let sk = single_priv.key;
                let pk = sk.public_key(secp);
                let pubkey_map = BTreeMap::from([(pk, sk)]);
                pubkey_map.get_key(key_request, secp)
            }
            (Self::XPrv(descriptor_xkey), KeyRequest::Pubkey(public_key)) => {
                let xpriv = descriptor_xkey
                    .xkey
                    .derive_priv(secp, &descriptor_xkey.derivation_path)
                    .map_err(GetKeyError::Bip32)?;
                let pk = xpriv.private_key.public_key(secp);

                if public_key.inner.eq(&pk) {
                    Ok(Some(xpriv.to_priv()))
                } else {
                    Ok(None)
                }
            }
            (
                Self::XPrv(descriptor_xkey),
                key_request @ KeyRequest::Bip32(ref key_source),
            ) => {
                if let Some(key) = descriptor_xkey.xkey.get_key(key_request, secp)? {
                    return Ok(Some(key));
                }

                if let Some(matched_path) = descriptor_xkey.matches(key_source, secp) {
                    let (_, full_path) = key_source;

                    let derivation_path = &full_path[matched_path.len()..];

                    return Ok(Some(
                        descriptor_xkey
                            .xkey
                            .derive_priv(secp, &derivation_path)
                            .map_err(GetKeyError::Bip32)?
                            .to_priv(),
                    ));
                }

                Ok(None)
            }
            (Self::XPrv(_), KeyRequest::XOnlyPubkey(_)) => {
                Err(GetKeyError::NotSupported)
            }
            (
                desc_multi_sk @ Self::MultiXPrv(_descriptor_multi_xkey),
                key_request,
            ) => {
                for desc_sk in &desc_multi_sk.clone().into_single_keys() {
                    // If any key is an error, then all of them will, so here we propagate errors with ?.
                    if let Some(pk) = desc_sk.get_key(&key_request.clone(), secp)? {
                        return Ok(Some(pk));
                    }
                }
                Ok(None)
            }
        }
    }
}

impl GetKey for KeyMap {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<bitcoin::PrivateKey>, Self::Error> {
        Ok(self.clone().into_iter().find_map(|(_desc_pk, desc_sk)| -> Option<PrivateKey> {
            match desc_sk.get_key(&key_request.clone(), secp) {
                Ok(Some(pk)) => Some(pk),
                // When looking up keys in a map, we eat errors on individual keys, on
                // the assumption that some other key in the map might not error.
                Ok(None) | Err(_) => None,
            }
        }))
    }
}
