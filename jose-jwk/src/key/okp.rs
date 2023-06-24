// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK CFRG-curve key material.

use serde::{Deserialize, Serialize};

use jose_b64::{B64Bytes, B64Secret};

/// A octet key pair CFRG-curve key, as defined in [RFC 8037]
///
/// [RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Okp {
    /// The CFRG curve.
    pub crv: OkpCurves,

    /// The public key.
    pub x: B64Bytes,

    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<B64Secret>,
}

/// The CFRG Curve.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OkpCurves {
    /// Ed25519
    Ed25519,

    /// Ed448
    Ed448,

    /// X25519
    X25519,

    /// X448
    X448,
}
