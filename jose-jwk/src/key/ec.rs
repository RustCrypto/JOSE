// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK elliptic-curve key material.

use serde::{Deserialize, Serialize};

use jose_b64::{B64Bytes, B64Secret};

/// An elliptic-curve key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ec {
    /// The elliptic curve identifier.
    pub crv: EcCurves,

    /// The public x coordinate.
    pub x: B64Bytes,

    /// The public y coordinate.
    pub y: B64Bytes,

    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<B64Secret>,
}

/// The elliptic curve.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EcCurves {
    /// P-256
    #[serde(rename = "P-256")]
    P256,

    /// P-384
    #[serde(rename = "P-384")]
    P384,

    /// P-521
    #[serde(rename = "P-521")]
    P521,

    /// P-256K
    #[serde(rename = "secp256k1")]
    P256K,
}
