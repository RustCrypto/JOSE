// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "p256")]

use p256::{PublicKey, SecretKey};

#[cfg(feature = "jws")]
use p256::ecdsa::{SigningKey, VerifyingKey};

use super::key::{Key, Kind, Type};

use crate::alg::{Algorithm, Algorithm::Signing, Signing::*};
use crate::key::KeyInfo;

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl<T: Type<P256 = U>, U: From<PublicKey>> From<PublicKey> for Key<T> {
    fn from(value: PublicKey) -> Self {
        Self {
            kind: Kind::P256(value.into()),
            algo: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl<T: Type<P256 = U>, U: From<SecretKey>> From<SecretKey> for Key<T> {
    fn from(value: SecretKey) -> Self {
        Self {
            kind: Kind::P256(value.into()),
            algo: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl KeyInfo for PublicKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es256))
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl KeyInfo for SecretKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es256))
    }
}

#[cfg(feature = "jws")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "jws", feature = "p256"))))]
impl KeyInfo for VerifyingKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es256))
    }
}

#[cfg(feature = "jws")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "jws", feature = "p256"))))]
impl KeyInfo for SigningKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es256))
    }
}
