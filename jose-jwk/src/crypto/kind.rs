// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use jose_jwa::Algorithm;

use super::KeyInfo;

/// The kind of a key (public or private).
pub enum Kind<P, S> {
    /// A public key.
    Public(P),

    /// A private key.
    Secret(S),
}

impl<P: KeyInfo, S: KeyInfo> KeyInfo for Kind<P, S> {
    fn strength(&self) -> usize {
        match self {
            Self::Public(k) => k.strength(),
            Self::Secret(k) => k.strength(),
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        match self {
            Self::Public(k) => k.is_supported(algo),
            Self::Secret(k) => k.is_supported(algo),
        }
    }
}

#[cfg(feature = "rsa")]
impl From<&Kind<rsa::RsaPublicKey, rsa::RsaPrivateKey>> for crate::Rsa {
    fn from(value: &Kind<rsa::RsaPublicKey, rsa::RsaPrivateKey>) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&crate::Rsa> for Kind<rsa::RsaPublicKey, rsa::RsaPrivateKey> {
    type Error = super::Error;

    fn try_from(value: &crate::Rsa) -> Result<Self, Self::Error> {
        if value.prv.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}

#[cfg(feature = "p256")]
impl From<&Kind<p256::PublicKey, p256::SecretKey>> for crate::Ec {
    fn from(value: &Kind<p256::PublicKey, p256::SecretKey>) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "p256")]
impl TryFrom<&crate::Ec> for Kind<p256::PublicKey, p256::SecretKey> {
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        if value.d.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}

#[cfg(feature = "p384")]
impl From<&Kind<p384::PublicKey, p384::SecretKey>> for crate::Ec {
    fn from(value: &Kind<p384::PublicKey, p384::SecretKey>) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "p384")]
impl TryFrom<&crate::Ec> for Kind<p384::PublicKey, p384::SecretKey> {
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        if value.d.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}

#[cfg(feature = "p521")]
impl From<&Kind<p521::PublicKey, p521::SecretKey>> for crate::Ec {
    fn from(value: &Kind<p521::PublicKey, p521::SecretKey>) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "p521")]
impl TryFrom<&crate::Ec> for Kind<p521::PublicKey, p521::SecretKey> {
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        if value.d.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}
