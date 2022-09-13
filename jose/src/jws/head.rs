// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

pub use crate::x5t::Thumbprint;

use alloc::vec::Vec;
use alloc::{boxed::Box, string::String};

use serde::{Deserialize, Serialize};

use crate::b64::{Bytes, StandardPad};

#[inline]
fn b64_default() -> bool {
    true
}

#[inline]
fn b64_serialize(value: &bool) -> bool {
    !value
}

/// The JWS Protected Header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protected {
    /// RFC 7517 Section 4.1.11
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub crit: Option<Vec<String>>,

    /// RFC 8555 Section 6.4.1
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[cfg_attr(docsrs, doc(cfg(feature = "url")))]
    #[cfg(feature = "url")]
    pub url: Option<url::Url>,

    /// RFC 8555 Section 6.5.2
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nonce: Option<Bytes>,

    /// RFC 7797 Section 3
    #[serde(skip_serializing_if = "b64_serialize", default = "b64_default")]
    pub b64: bool,

    /// Other values that may appear in the protected header.
    #[serde(flatten)]
    pub oth: Unprotected,
}

impl Default for Protected {
    fn default() -> Self {
        Self {
            crit: None,
            nonce: None,
            b64: true,
            oth: Unprotected::default(),

            #[cfg(feature = "url")]
            url: None,
        }
    }
}

/// The JWS Unprotected Header
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Unprotected {
    /// RFC 7517 Section 4.1.1
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<crate::alg::Signing>,

    /// RFC 7517 Section 4.1.2
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[cfg_attr(docsrs, doc(cfg(feature = "url")))]
    #[cfg(feature = "url")]
    pub jku: Option<url::Url>,

    /// RFC 7517 Section 4.1.3
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    #[cfg(feature = "jwk")]
    pub jwk: Option<crate::jwk::Jwk>,

    /// RFC 7517 Section 4.1.4
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,

    /// RFC 7517 Section 4.1.5
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[cfg(feature = "url")]
    pub x5u: Option<url::Url>,

    /// RFC 7517 Section 4.1.6
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x5c: Option<Vec<Bytes<Box<[u8]>, StandardPad>>>, // base64, not base64url

    /// RFC 7517 Section 4.1.7-8
    #[serde(flatten)]
    pub x5t: Thumbprint,

    /// RFC 7517 Section 4.1.9
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub typ: Option<String>,

    /// RFC 7517 Section 4.1.10
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cty: Option<String>,
}
