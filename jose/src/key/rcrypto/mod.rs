// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Integration with RustCrypto types.

#![cfg(any(feature = "hmac", feature = "p256", feature = "p384", feature = "rsa"))]
#![cfg_attr(
    docsrs,
    doc(cfg(any(feature = "hmac", feature = "p256", feature = "p384", feature = "rsa")))
)]

use core::convert::Infallible;

mod key;
mod oct;
mod p256;
mod p384;
mod rsa;

pub use key::Key;
pub(crate) use key::{Kind, Type};

/// An error related to key material.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Error {
    /// The key or signature is invalid.
    #[default]
    Invalid,

    /// The private key is unknown.
    NotPrivate,

    /// An algorithm mismatch occurred.
    AlgMismatch,

    /// The specified criteria are unsupported.
    Unsupported,
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}
