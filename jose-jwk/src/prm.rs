// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK parameter types

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use jose_b64::base64ct::Base64;
use jose_b64::serde::Bytes;
use jose_jwa::Algorithm;

/// JWK parameters unrelated to the key implementation
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameters {
    /// The algorithm used with this key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<Algorithm>,

    /// The key identifier.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,

    /// The key class (called `use` in the RFC).
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "use")]
    pub cls: Option<Class>,

    /// The key operations (called `key_ops` in the RFC).
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "key_ops")]
    pub ops: Option<BTreeSet<Operations>>,

    /// The URL of the X.509 certificate associated with this key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[cfg(feature = "url")]
    pub x5u: Option<url::Url>,

    /// The X.509 certificate associated with this key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x5c: Option<Vec<Bytes<Box<[u8]>, Base64>>>, // base64, not base64url

    /// The X.509 thumbprint associated with this key.
    #[serde(flatten)]
    pub x5t: Thumbprint,

    /// Whether the key is extractable.
    ///
    /// This parameter is defined by the [W3C Web Cryptography API].
    ///
    /// [W3C Web Cryptography API]: https://www.w3.org/TR/WebCryptoAPI/
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ext: Option<bool>,

    /// Time when this key was issued.
    ///
    /// Expressed as Seconds Since the Epoch per [RFC 7519].
    ///
    /// This parameter is defined in [OpenID Federation 1.0, Section 8.7.2].
    ///
    /// [RFC 7519]: https://datatracker.ietf.org/doc/html/rfc7519
    /// [OpenID Federation 1.0, Section 8.7.2]: https://openid.github.io/federation/main.html#section-8.7.2
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub iat: Option<i64>,

    /// Time before which the key MUST NOT be considered valid.
    ///
    /// Expressed as Seconds Since the Epoch per [RFC 7519].
    ///
    /// This parameter is defined in [OpenID Federation 1.0, Section 8.7.2].
    ///
    /// [RFC 7519]: https://datatracker.ietf.org/doc/html/rfc7519
    /// [OpenID Federation 1.0, Section 8.7.2]: https://openid.github.io/federation/main.html#section-8.7.2
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nbf: Option<i64>,

    /// Expiration time after which the key MUST NOT be considered valid.
    ///
    /// Expressed as Seconds Since the Epoch per [RFC 7519].
    ///
    /// This parameter is defined in [OpenID Federation 1.0, Section 8.7.2].
    ///
    /// [RFC 7519]: https://datatracker.ietf.org/doc/html/rfc7519
    /// [OpenID Federation 1.0, Section 8.7.2]: https://openid.github.io/federation/main.html#section-8.7.2
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exp: Option<i64>,

    /// Revoked key properties.
    ///
    /// This parameter is defined in [OpenID Federation 1.0, Section 8.7.2].
    ///
    /// [OpenID Federation 1.0, Section 8.7.2]: https://openid.github.io/federation/main.html#section-8.7.2
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revoked: Option<Revoked>,
}

impl<T: Into<Algorithm>> From<T> for Parameters {
    fn from(value: T) -> Self {
        let alg = Some(value.into());

        let cls = match alg {
            Some(Algorithm::Signing(..)) => Some(Class::Signing),
            _ => None,
        };

        Self {
            alg,
            cls,
            ..Default::default()
        }
    }
}

/// Key Class (i.e. `use` in the RFC)
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum Class {
    #[serde(rename = "enc")]
    Encryption,

    #[serde(rename = "sig")]
    Signing,
}

/// Key operations (i.e. `key_use` in the RFC)
// NOTE: Keep in lexicographical order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum Operations {
    Decrypt,
    DeriveBits,
    DeriveKey,
    Encrypt,
    Sign,
    UnwrapKey,
    Verify,
    WrapKey,
}

/// An X.509 thumbprint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thumbprint {
    /// An X.509 thumbprint (SHA-1).
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t", default)]
    pub s1: Option<Bytes<[u8; 20]>>,

    /// An X.509 thumbprint (SHA-2 256).
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t#S256", default)]
    pub s256: Option<Bytes<[u8; 32]>>,
}

/// Revoked key properties.
///
/// This type is defined in [OpenID Federation 1.0, Section 8.7.2].
///
/// [OpenID Federation 1.0, Section 8.7.2]: https://openid.github.io/federation/main.html#section-8.7.2
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoked {
    /// Time when the key was revoked or must be considered revoked.
    ///
    /// Expressed as Seconds Since the Epoch per [RFC 7519].
    ///
    /// [RFC 7519]: https://datatracker.ietf.org/doc/html/rfc7519
    pub revoked_at: i64,

    /// The reason for the key revocation.
    ///
    /// The reason values are defined in [OpenID Federation 1.0, Section 8.7.3].
    ///
    /// [OpenID Federation 1.0, Section 8.7.3]: https://openid.github.io/federation/main.html#section-8.7.3
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<RevocationReason>,
}

/// Revocation reason for a key.
///
/// These reasons are inspired by Section 5.3.1 of [RFC 5280] and defined
/// in [OpenID Federation 1.0, Section 8.7.3].
///
/// [RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
/// [OpenID Federation 1.0, Section 8.7.3]: https://openid.github.io/federation/main.html#section-8.7.3
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// General or unspecified reason for the key status change.
    #[serde(rename = "unspecified")]
    Unspecified,

    /// The private key is believed to have been compromised.
    #[serde(rename = "compromised")]
    Compromised,

    /// The key is no longer active.
    #[serde(rename = "superseded")]
    Superseded,

    /// A federation MAY specify and utilize additional reasons depending on the trust or security framework in use.
    #[serde(untagged)]
    Other(String),
}
