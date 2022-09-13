// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! JWK symmetric key material.

use serde::{Deserialize, Serialize};

use crate::alg::{Algorithm, Algorithm::Signing, Signing::*};
use crate::b64::Secret;

/// A symmetric key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oct {
    /// The symmetric key.
    pub k: Secret,
}

impl crate::key::KeyInfo for Oct {
    fn strength(&self) -> usize {
        self.k.len()
    }

    #[allow(clippy::match_like_matches_macro)]
    fn is_supported(&self, algo: &Algorithm) -> bool {
        match (algo, self.strength()) {
            (Signing(Hs256), 16..) => true,
            (Signing(Hs384), 24..) => true,
            (Signing(Hs512), 32..) => true,
            _ => false,
        }
    }
}
