// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK key material.

use serde::{Deserialize, Serialize};

mod ec;
mod oct;
mod okp;
mod rsa;

pub use self::ec::{Ec, EcCurves};
pub use self::oct::Oct;
pub use self::okp::{Okp, OkpCurves};
pub use self::rsa::{Rsa, RsaOptional, RsaOtherPrimes, RsaPrivate};

/// A key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
#[non_exhaustive]
pub enum Key {
    /// An elliptic-curve key.
    #[serde(rename = "EC")]
    Ec(Ec),

    /// An RSA key.
    #[serde(rename = "RSA")]
    Rsa(Rsa),

    /// A symmetric key.
    #[serde(rename = "oct")]
    Oct(Oct),

    /// A CFRG-curve key.
    #[serde(rename = "OKP")]
    Okp(Okp),
}

impl crate::key::KeyInfo for Key {
    fn strength(&self) -> usize {
        match self {
            Key::Ec(x) => x.strength(),
            Key::Rsa(x) => x.strength(),
            Key::Oct(x) => x.strength(),
            Key::Okp(x) => x.strength(),
        }
    }

    fn is_supported(&self, algo: &crate::alg::Algorithm) -> bool {
        match self {
            Key::Ec(x) => x.is_supported(algo),
            Key::Rsa(x) => x.is_supported(algo),
            Key::Oct(x) => x.is_supported(algo),
            Key::Okp(x) => x.is_supported(algo),
        }
    }
}

impl From<Ec> for Key {
    #[inline(always)]
    fn from(key: Ec) -> Self {
        Self::Ec(key)
    }
}

impl From<Rsa> for Key {
    #[inline(always)]
    fn from(key: Rsa) -> Self {
        Self::Rsa(key)
    }
}

impl From<Oct> for Key {
    #[inline(always)]
    fn from(key: Oct) -> Self {
        Self::Oct(key)
    }
}

impl From<Okp> for Key {
    #[inline(always)]
    fn from(key: Okp) -> Self {
        Self::Okp(key)
    }
}
