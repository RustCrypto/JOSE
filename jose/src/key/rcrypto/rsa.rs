// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

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

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl KeyInfo for RsaPublicKey {
    fn strength(&self) -> usize {
        self.size() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        // RFC 7518 Section 3.3
        //
        // I would actually prefer stronger requirements here based on the
        // algorithm below. However, the RFCs actually specify examples that
        // this would break. Note that we generate stronger keys by default.
        if self.strength() < 16 {
            return false;
        }

        match algo {
            Signing(Rs256) => true,
            Signing(Rs384) => true,
            Signing(Rs512) => true,

            #[cfg(feature = "rand")]
            Signing(Ps256) => true,
            #[cfg(feature = "rand")]
            Signing(Ps384) => true,
            #[cfg(feature = "rand")]
            Signing(Ps512) => true,

            _ => false,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl KeyInfo for RsaPrivateKey {
    fn strength(&self) -> usize {
        self.size() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        match (algo, self.strength()) {
            (Signing(Rs256), 16..) => true,
            (Signing(Rs384), 24..) => true,
            (Signing(Rs512), 32..) => true,

            #[cfg(feature = "rand")]
            (Signing(Ps256), 16..) => true,
            #[cfg(feature = "rand")]
            (Signing(Ps384), 24..) => true,
            #[cfg(feature = "rand")]
            (Signing(Ps512), 32..) => true,

            _ => false,
        }
    }
}
