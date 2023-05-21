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

mod key;
mod prm;

pub use key::*;
pub use prm::{Class, Operations, Parameters, Thumbprint};

pub use jose_b64;
pub use jose_jwa;

use serde::{Deserialize, Serialize};

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
