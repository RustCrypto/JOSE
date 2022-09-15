// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

mod compact;
mod head;

pub use head::{Protected, Unprotected};

use alloc::{vec, vec::Vec};

use jose_b64::serde::{Bytes, Json};
use serde::{Deserialize, Serialize};

/// The JSON Web Signature
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
#[serde(untagged)]
pub enum Jws {
    /// General Serialization
    General(General),

    /// Flattened Serialization
    Flattened(Flattened),
}

impl From<General> for Jws {
    fn from(value: General) -> Self {
        Jws::General(value)
    }
}

impl From<Flattened> for Jws {
    fn from(value: Flattened) -> Self {
        Jws::Flattened(value)
    }
}

/// General Serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct General {
    /// The payload of the signature.
    pub payload: Option<Bytes>,

    /// The signatures over the payload.
    pub signatures: Vec<Signature>,
}

impl From<Flattened> for General {
    fn from(value: Flattened) -> Self {
        Self {
            payload: value.payload,
            signatures: vec![value.signature],
        }
    }
}

/// Flattened Serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flattened {
    /// The payload of the signature.
    pub payload: Option<Bytes>,

    /// The signature over the payload.
    #[serde(flatten)]
    pub signature: Signature,
}

/// A Signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// The JWS Unprotected Header
    pub header: Option<Unprotected>,

    /// The JWS Protected Header
    pub protected: Option<Json<Protected>>,

    /// The Signature Bytes
    pub signature: Bytes,
}
