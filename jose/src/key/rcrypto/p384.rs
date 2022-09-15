// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "p384")]

use p384::{PublicKey, SecretKey};

#[cfg(feature = "jws")]
use p384::ecdsa::{SigningKey, VerifyingKey};

use super::key::{Key, Kind, Type};

use crate::alg::{Algorithm, Algorithm::Signing, Signing::*};
use crate::key::KeyInfo;

#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
impl<T: Type<P384 = U>, U: From<PublicKey>> From<PublicKey> for Key<T> {
    fn from(value: PublicKey) -> Self {
        Self {
            kind: Kind::P384(value.into()),
            algo: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
impl<T: Type<P384 = U>, U: From<SecretKey>> From<SecretKey> for Key<T> {
    fn from(value: SecretKey) -> Self {
        Self {
            kind: Kind::P384(value.into()),
            algo: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
impl KeyInfo for PublicKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es384))
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
impl KeyInfo for SecretKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es384))
    }
}

#[cfg(feature = "jws")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "jws", feature = "p384"))))]
impl KeyInfo for VerifyingKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es384))
    }
}

#[cfg(feature = "jws")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "jws", feature = "p384"))))]
impl KeyInfo for SigningKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es384))
    }
}
