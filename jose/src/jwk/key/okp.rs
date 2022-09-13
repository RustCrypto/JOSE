// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! JWK CFRG-curve key material.

use serde::{Deserialize, Serialize};

use crate::alg::{Algorithm, Algorithm::Signing, Signing::*};
use crate::b64::{Bytes, Secret};

/// A CFRG-curve key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Okp {
    /// The CFRG curve.
    pub crv: OkpCurves,

    /// The public key.
    pub x: Bytes,

    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<Secret>,
}

impl crate::key::KeyInfo for Okp {
    fn strength(&self) -> usize {
        match self.crv {
            OkpCurves::Ed25519 => 16,
            OkpCurves::Ed448 => 24,
            OkpCurves::X25519 => 16,
            OkpCurves::X448 => 24,
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(EdDsa))
    }
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
