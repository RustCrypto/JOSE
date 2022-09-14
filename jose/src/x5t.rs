// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::b64::Bytes;
use serde::{Deserialize, Serialize};

/// An X.509 thumbprint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thumbprint {
    /// An X.509 thumbprint (SHA-1).
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t", default)]
    pub s1: Option<Bytes<[u8; 20]>>,

    /// An X.509 thumbprint (SHA-2 256).
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t#S256", default)]
    pub s256: Option<Bytes<[u8; 32]>>,
}
