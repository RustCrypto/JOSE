// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK: JSON Web Key

#![cfg(feature = "jwk")]
#![cfg_attr(docsrs, doc(cfg(feature = "jwk")))]

pub mod crypto;

mod key;
mod prm;

pub use key::*;
pub use prm::{Class, Operations, Parameters, Thumbprint};

use serde::{Deserialize, Serialize};

use crate::alg::Algorithm;

/// A set of JSON Web Keys.
///
/// This type is defined in [RFC7517 Section 5].
///
/// [RFC7517 Section 5]: https://datatracker.ietf.org/doc/html/rfc7517#section-5
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    /// The keys in the set.
    pub keys: alloc::vec::Vec<Jwk>,
}

/// A JSON Web Key.
///
/// This type is defined in [RFC7517 Section 4].
///
/// [RFC7517 Section 4]: https://datatracker.ietf.org/doc/html/rfc7517#section-4
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// The key material.
    #[serde(flatten)]
    pub key: Key,

    /// The key parameters.
    #[serde(flatten)]
    pub prm: Parameters,
}

impl crate::key::KeyInfo for Jwk {
    fn strength(&self) -> usize {
        self.key.strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.key.is_supported(algo) && algo == self.prm.alg.as_ref().unwrap_or(algo)
    }
}
