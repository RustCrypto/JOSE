// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;

use jose_jwa::Algorithm;
use zeroize::Zeroizing;

use super::KeyInfo;

/// A fully parsed Key that mimics the runtime behavior of a JWK.
///
/// A JWK is a half-parsed key. This means that it reprsents a parsed view of
/// the data structure on the wire. But this is not yet usable to perform
/// cryptographic operations. A Key, on the other hand, is a fully parsed key
/// ready to perform cryptogrpahic operations.
///
/// Since RustCrypto provides strong typing and, in order to match the
/// behavior of a JWK, this structure allows us to represent the different
/// kinds of JWKs at runtime using a single object.
#[allow(clippy::large_enum_variant)]
pub enum Key {
    /// A symmetric key.
    Oct(Zeroizing<Box<[u8]>>),

    /// An RSA key.
    #[cfg(feature = "rsa")]
    Rsa(super::Kind<rsa::RsaPublicKey, rsa::RsaPrivateKey>),

    /// A P-256 key.
    #[cfg(feature = "p256")]
    P256(super::Kind<p256::PublicKey, p256::SecretKey>),

    /// A P-384 key.
    #[cfg(feature = "p384")]
    P384(super::Kind<p384::PublicKey, p384::SecretKey>),

    /// A P-521 key
    #[cfg(feature = "p521")]
    P521(super::Kind<p521::PublicKey, p521::SecretKey>),
}

impl KeyInfo for Key {
    fn strength(&self) -> usize {
        match self {
            Self::Oct(k) => k.strength(),

            #[cfg(feature = "rsa")]
            Self::Rsa(k) => k.strength(),

            #[cfg(feature = "p256")]
            Self::P256(k) => k.strength(),

            #[cfg(feature = "p384")]
            Self::P384(k) => k.strength(),

            #[cfg(feature = "p521")]
            Self::P521(k) => k.strength(),
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        match self {
            Self::Oct(k) => k.is_supported(algo),

            #[cfg(feature = "rsa")]
            Self::Rsa(k) => k.is_supported(algo),

            #[cfg(feature = "p256")]
            Self::P256(k) => k.is_supported(algo),

            #[cfg(feature = "p384")]
            Self::P384(k) => k.is_supported(algo),

            #[cfg(feature = "p521")]
            Self::P521(k) => k.is_supported(algo),
        }
    }
}

impl From<Zeroizing<Box<[u8]>>> for Key {
    fn from(value: Zeroizing<Box<[u8]>>) -> Self {
        Self::Oct(value)
    }
}

#[cfg(feature = "rsa")]
impl From<super::Kind<rsa::RsaPublicKey, rsa::RsaPrivateKey>> for Key {
    fn from(value: super::Kind<rsa::RsaPublicKey, rsa::RsaPrivateKey>) -> Self {
        Self::Rsa(value)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::RsaPublicKey> for Key {
    fn from(value: rsa::RsaPublicKey) -> Self {
        Self::Rsa(super::Kind::Public(value))
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::RsaPrivateKey> for Key {
    fn from(value: rsa::RsaPrivateKey) -> Self {
        Self::Rsa(super::Kind::Secret(value))
    }
}

#[cfg(feature = "p256")]
impl From<super::Kind<p256::PublicKey, p256::SecretKey>> for Key {
    fn from(value: super::Kind<p256::PublicKey, p256::SecretKey>) -> Self {
        Self::P256(value)
    }
}

#[cfg(feature = "p256")]
impl From<p256::PublicKey> for Key {
    fn from(value: p256::PublicKey) -> Self {
        Self::P256(super::Kind::Public(value))
    }
}

#[cfg(feature = "p256")]
impl From<p256::SecretKey> for Key {
    fn from(value: p256::SecretKey) -> Self {
        Self::P256(super::Kind::Secret(value))
    }
}

#[cfg(feature = "p384")]
impl From<super::Kind<p384::PublicKey, p384::SecretKey>> for Key {
    fn from(value: super::Kind<p384::PublicKey, p384::SecretKey>) -> Self {
        Self::P384(value)
    }
}

#[cfg(feature = "p384")]
impl From<p384::PublicKey> for Key {
    fn from(value: p384::PublicKey) -> Self {
        Self::P384(super::Kind::Public(value))
    }
}

#[cfg(feature = "p384")]
impl From<p384::SecretKey> for Key {
    fn from(value: p384::SecretKey) -> Self {
        Self::P384(super::Kind::Secret(value))
    }
}

#[cfg(feature = "p521")]
impl From<super::Kind<p521::PublicKey, p521::SecretKey>> for Key {
    fn from(value: super::Kind<p521::PublicKey, p521::SecretKey>) -> Self {
        Self::P521(value)
    }
}

#[cfg(feature = "p521")]
impl From<p521::PublicKey> for Key {
    fn from(value: p521::PublicKey) -> Self {
        Self::P521(super::Kind::Public(value))
    }
}

#[cfg(feature = "p521")]
impl From<p521::SecretKey> for Key {
    fn from(value: p521::SecretKey) -> Self {
        Self::P521(super::Kind::Secret(value))
    }
}

impl From<&crate::Oct> for Key {
    fn from(value: &crate::Oct) -> Self {
        Self::Oct(value.k.to_vec().into_boxed_slice().into())
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&crate::Rsa> for Key {
    type Error = super::Error;

    fn try_from(value: &crate::Rsa) -> Result<Self, Self::Error> {
        Ok(Self::Rsa(value.try_into()?))
    }
}

#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
impl TryFrom<&crate::Ec> for Key {
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        match value.crv {
            #[cfg(feature = "p256")]
            crate::EcCurves::P256 => Ok(Self::P256(value.try_into()?)),

            #[cfg(feature = "p384")]
            crate::EcCurves::P384 => Ok(Self::P384(value.try_into()?)),

            #[cfg(feature = "p521")]
            crate::EcCurves::P521 => Ok(Self::P521(value.try_into()?)),

            _ => Err(super::Error::Unsupported),
        }
    }
}

impl TryFrom<&crate::Key> for Key {
    type Error = super::Error;

    fn try_from(value: &crate::Key) -> Result<Self, Self::Error> {
        match value {
            crate::Key::Oct(oct) => Ok(oct.into()),

            #[cfg(feature = "rsa")]
            crate::Key::Rsa(rsa) => rsa.try_into(),

            #[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
            crate::Key::Ec(ec) => ec.try_into(),

            _ => Err(super::Error::Unsupported),
        }
    }
}

impl From<&Key> for crate::Key {
    fn from(value: &Key) -> Self {
        match value {
            Key::Oct(oct) => Self::Oct(crate::Oct {
                k: oct.to_vec().into(),
            }),

            #[cfg(feature = "rsa")]
            Key::Rsa(kind) => match kind {
                super::Kind::Public(public) => Self::Rsa(public.into()),
                super::Kind::Secret(secret) => Self::Rsa(secret.into()),
            },

            #[cfg(feature = "p256")]
            Key::P256(kind) => match kind {
                super::Kind::Public(public) => Self::Ec(public.into()),
                super::Kind::Secret(secret) => Self::Ec(secret.into()),
            },

            #[cfg(feature = "p384")]
            Key::P384(kind) => match kind {
                super::Kind::Public(public) => Self::Ec(public.into()),
                super::Kind::Secret(secret) => Self::Ec(secret.into()),
            },

            #[cfg(feature = "p521")]
            Key::P521(kind) => match kind {
                super::Kind::Public(public) => Self::Ec(public.into()),
                super::Kind::Secret(secret) => Self::Ec(secret.into()),
            },
        }
    }
}
