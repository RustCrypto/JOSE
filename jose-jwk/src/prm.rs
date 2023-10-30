// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK parameter types

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use jose_b64::base64ct::Base64;
use jose_b64::B64Bytes;
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
    pub x5c: Option<Vec<B64Bytes<Box<[u8]>, Base64>>>, // base64, not base64url

    /// The X.509 thumbprint associated with this key.
    #[serde(flatten)]
    pub x5t: Thumbprint,
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
    pub s1: Option<B64Bytes<[u8; 20]>>,

    /// An X.509 thumbprint (SHA-2 256).
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t#S256", default)]
    pub s256: Option<B64Bytes<[u8; 32]>>,
}
