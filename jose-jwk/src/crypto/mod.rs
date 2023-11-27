// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Cryptographic primitives for JWK

mod key;
mod keyinfo;
mod kind;
mod p256;
mod p384;
mod p521;
mod rsa;

pub use key::Key;
pub use keyinfo::KeyInfo;
pub use kind::Kind;

use core::convert::Infallible;

/// An error related to key material.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Error {
    /// The inputs are invalid.
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
