// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "rsa")]

use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};

use super::{Key, Kind, Type};

use crate::alg::{Algorithm, Algorithm::Signing, Signing::*};
use crate::key::KeyInfo;

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl<T: Type<Rsa = RsaPublicKey>> From<RsaPublicKey> for Key<T> {
    fn from(value: RsaPublicKey) -> Self {
        Self {
            kind: Kind::Rsa(value),
            algo: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl<T: Type<Rsa = RsaPrivateKey>> From<RsaPrivateKey> for Key<T> {
    fn from(value: RsaPrivateKey) -> Self {
        Self {
            kind: Kind::Rsa(value),
            algo: None,
        }
    }
}
