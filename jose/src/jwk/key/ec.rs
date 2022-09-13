// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! JWK elliptic-curve key material.

use serde::{Deserialize, Serialize};

use crate::alg::{Algorithm, Algorithm::Signing, Signing::*};
use crate::b64::{Bytes, Secret};

/// An elliptic-curve key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ec {
    /// The elliptic curve identifier.
    pub crv: EcCurves,

    /// The public x coordinate.
    pub x: Bytes,

    /// The public y coordinate.
    pub y: Bytes,

    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<Secret>,
}

impl crate::key::KeyInfo for Ec {
    fn strength(&self) -> usize {
        match self.crv {
            EcCurves::P256 => 16,
            EcCurves::P256K => 16,
            EcCurves::P384 => 24,
            EcCurves::P521 => 32,
        }
    }

    #[allow(clippy::match_like_matches_macro)]
    fn is_supported(&self, algo: &Algorithm) -> bool {
        match (self.crv, algo) {
            (EcCurves::P256, Signing(Es256)) => true,
            (EcCurves::P256K, Signing(Es256K)) => true,
            (EcCurves::P384, Signing(Es384)) => true,
            (EcCurves::P521, Signing(Es512)) => true,
            _ => false,
        }
    }
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
