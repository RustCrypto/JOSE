// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Streamed encoding/decoding types
//!
//! NOTE WELL: DO NOT use these types for decoding secrets.
//!
//! These types are useful for streams feeding into JWS or JWE. However, since
//! they report invalid base64 errors for each block, this could be used in a
//! timing attack if used to decode secrets.

use core::convert::Infallible;

mod dec;
mod enc;
mod optional;
mod update;

pub use dec::Decoder;
pub use enc::Encoder;
pub use optional::Optional;
pub use update::Update;

/// A Base64 error.
#[derive(Debug)]
pub enum Error<T> {
    /// An embedded error.
    Inner(T),

    /// The length is invalid.
    Length,

    /// An invalid value was found.
    Value,
}

impl Error<Infallible> {
    /// Casts an infallible error to any other kind of error.
    pub fn cast<T>(&self) -> Error<T> {
        match self {
            Self::Inner(..) => unreachable!(),
            Self::Length => Error::Length,
            Self::Value => Error::Value,
        }
    }
}

impl<T> From<base64ct::Error> for Error<T> {
    fn from(error: base64ct::Error) -> Self {
        match error {
            base64ct::Error::InvalidEncoding => Self::Value,
            base64ct::Error::InvalidLength => Self::Length,
        }
    }
}
