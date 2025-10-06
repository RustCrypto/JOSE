// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
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

pub mod crypto;

mod compact;
mod head;

pub use head::{Protected, Unprotected};

use alloc::{vec, vec::Vec};

use jose_b64::serde::{Bytes, Json};
use serde::{Deserialize, Serialize};

/// A JSON Web Signature representation
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
#[serde(bound(deserialize = "U: Deserialize<'de>, P: serde::de::DeserializeOwned"))]
#[serde(untagged)]
pub enum Jws<U = Unprotected, P = Protected<U>> {
    /// General Serialization. This is
    General(General<U, P>),

    /// Flattened Serialization
    Flattened(Flattened<U, P>),
}

impl<U, P> From<General<U, P>> for Jws<U, P> {
    fn from(value: General<U, P>) -> Self {
        Jws::General(value)
    }
}

impl<U, P> From<Flattened<U, P>> for Jws<U, P> {
    fn from(value: Flattened<U, P>) -> Self {
        Jws::Flattened(value)
    }
}

/// General Serialization
///
/// This is the usual JWS form, which allows multiple signatures to be
/// specified.
///
/// ```json
/// {
///     "payload":"<payload contents>",
///     "signatures":[
///      {"protected":"<integrity-protected header 1 contents>",
///       "header":<non-integrity-protected header 1 contents>,
///       "signature":"<signature 1 contents>"},
///      ...
///      {"protected":"<integrity-protected header N contents>",
///       "header":<non-integrity-protected header N contents>,
///       "signature":"<signature N contents>"}]
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "U: Deserialize<'de>, P: serde::de::DeserializeOwned"))]
pub struct General<U = Unprotected, P = Protected<U>> {
    /// The payload of the signature.
    pub payload: Option<Bytes>,

    /// The signatures over the payload.
    pub signatures: Vec<Signature<U, P>>,
}

impl<U, P> From<Flattened<U, P>> for General<U, P> {
    fn from(value: Flattened<U, P>) -> Self {
        Self {
            payload: value.payload,
            signatures: vec![value.signature],
        }
    }
}

/// Flattened Serialization
///
/// This is similar to the general serialization but is more compact, only
/// supporting one signature.
///
/// ```json
/// {
///     "payload":"<payload contents>",
///     "protected":"<integrity-protected header contents>",
///     "header":<non-integrity-protected header contents>,
///     "signature":"<signature contents>"
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "U: Deserialize<'de>, P: serde::de::DeserializeOwned"))]
pub struct Flattened<U = Unprotected, P = Protected<U>> {
    /// The payload of the signature.
    pub payload: Option<Bytes>,

    /// The signature over the payload.
    #[serde(flatten)]
    pub signature: Signature<U, P>,
}

/// A Signature
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "U: Deserialize<'de>, P: serde::de::DeserializeOwned"))]
pub struct Signature<U = Unprotected, P = Protected<U>> {
    /// The JWS Unprotected Header
    pub header: Option<U>,

    /// The JWS Protected Header
    pub protected: Option<Json<P>>,

    /// The Signature Bytes
    pub signature: Bytes,
}
