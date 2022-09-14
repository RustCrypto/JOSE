// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! IANA-Defined Algorithms

use serde::{Deserialize, Serialize};

/// Algorithms
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    Signing(Signing),
    Unknown(alloc::string::String),
}

impl From<Signing> for Algorithm {
    #[inline(always)]
    fn from(alg: Signing) -> Self {
        Self::Signing(alg)
    }
}

/// Signing Algorithms
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Signing {
    /// EdDSA signature algorithms (Optional)
    #[serde(rename = "EdDSA")]
    EdDsa,

    /// ECDSA using P-256 and SHA-256 (Recommended+)
    #[serde(rename = "ES256")]
    Es256,

    /// ECDSA using secp256k1 curve and SHA-256 (Optional)
    #[serde(rename = "ES256K")]
    Es256K,

    /// ECDSA using P-384 and SHA-384 (Optional)
    #[serde(rename = "ES384")]
    Es384,

    /// ECDSA using P-521 and SHA-512 (Optional)
    #[serde(rename = "ES512")]
    Es512,

    /// HMAC using SHA-256 (Required)
    #[serde(rename = "HS256")]
    Hs256,

    /// HMAC using SHA-384 (Optional)
    #[serde(rename = "HS384")]
    Hs384,

    /// HMAC using SHA-512 (Optional)
    #[serde(rename = "HS512")]
    Hs512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
    #[serde(rename = "PS256")]
    Ps256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
    #[serde(rename = "PS384")]
    Ps384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
    #[serde(rename = "PS512")]
    Ps512,

    /// RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
    #[serde(rename = "RS256")]
    Rs256,

    /// RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
    #[serde(rename = "RS384")]
    Rs384,

    /// RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
    #[serde(rename = "RS512")]
    Rs512,

    /// No digital signature or MAC performed (Optional)
    ///
    /// This variant is renamed as `Null` to avoid colliding with `Option::None`.
    #[serde(rename = "none")]
    Null,
}
