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

pub mod serde;
pub mod stream;

mod zero;

pub use base64ct;

#[cfg(feature = "secret")]
use zeroize::{Zeroize, Zeroizing};

#[cfg(not(feature = "secret"))]
use zero::{Zeroize, Zeroizing};
