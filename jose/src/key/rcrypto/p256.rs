// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "p256")]

use p256::{PublicKey, SecretKey};

#[cfg(feature = "jws")]
use p256::ecdsa::{SigningKey, VerifyingKey};

use super::key::{Key, Kind, Type};

use crate::alg::{Algorithm, Algorithm::Signing, Signing::*};
use crate::key::KeyInfo;

impl<T: Type<P256 = U>, U: From<PublicKey>> From<PublicKey> for Key<T> {
    fn from(value: PublicKey) -> Self {
        Self {
            kind: Kind::P256(value.into()),
            algo: None,
        }
    }
}

impl<T: Type<P256 = U>, U: From<SecretKey>> From<SecretKey> for Key<T> {
    fn from(value: SecretKey) -> Self {
        Self {
            kind: Kind::P256(value.into()),
            algo: None,
        }
    }
}

#[cfg(feature = "jws")]
impl KeyInfo for VerifyingKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es256))
    }
}

#[cfg(feature = "jws")]
impl KeyInfo for SigningKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es256))
    }
}
