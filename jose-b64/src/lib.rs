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
#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![warn(
    clippy::panic,
    clippy::panic_in_result_fn,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

mod fake_zeroize;
pub mod stream;
mod wrapper_bytes;
mod wrapper_json;
mod wrapper_secret;

pub use base64ct;

#[cfg(feature = "serde")]
pub use wrapper_bytes::B64Bytes;

#[cfg(feature = "secret")]
pub use wrapper_secret::B64Secret;

#[cfg(feature = "json")]
pub use wrapper_json::Json;

#[cfg(feature = "secret")]
use zeroize::{Zeroize, Zeroizing};

#[cfg(not(feature = "secret"))]
use fake_zeroize::{Zeroize, Zeroizing};
