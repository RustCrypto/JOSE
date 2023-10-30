// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK symmetric key material.

use serde::{Deserialize, Serialize};

use jose_b64::B64Secret;

/// A symmetric octet key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oct {
    /// The symmetric key.
    pub k: B64Secret,
}
