// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! JWK parameter types.

pub use crate::x5t::Thumbprint;

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::alg::Algorithm;
use crate::b64::{Bytes, StandardPad};

/// JWK parameters
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
    #[cfg_attr(docsrs, doc(cfg(feature = "url")))]
    #[cfg(feature = "url")]
    pub x5u: Option<url::Url>,

    /// The X.509 certificate associated with this key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x5c: Option<Vec<Bytes<Box<[u8]>, StandardPad>>>, // base64, not base64url

    /// The X.509 thumbprint associated with this key.
    #[serde(flatten)]
    pub x5t: Thumbprint,
}

impl<T: Into<Algorithm>> From<T> for Parameters {
    fn from(value: T) -> Self {
        let alg = Some(value.into());

        let cls = match alg {
            Some(Algorithm::Signing(..)) => Some(Class::Signing),
            Some(Algorithm::Unknown(..)) => None,
            None => None,
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
#[allow(missing_docs)]
#[non_exhaustive]
pub enum Operations {
    #[serde(rename = "decrypt")]
    Decrypt,

    #[serde(rename = "deriveBits")]
    DeriveBits,

    #[serde(rename = "deriveKey")]
    DeriveKey,

    #[serde(rename = "encrypt")]
    Encrypt,

    #[serde(rename = "sign")]
    Sign,

    #[serde(rename = "unwrapKey")]
    UnwrapKey,

    #[serde(rename = "verify")]
    Verify,

    #[serde(rename = "wrapKey")]
    WrapKey,
}
