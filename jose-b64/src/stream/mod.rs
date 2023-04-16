// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Streamed encoding/decoding types
//!
//! **SECURITY NOTE**: DO NOT use these types for decoding secrets.
//!
//! These types are useful for streams feeding into JWS or JWE. However, since
//! they report invalid base64 errors for each block, this could be used in a
//! timing attack if used to decode secrets.
//!
//! ```
//! use jose_b64::stream::{Decoder, Encoder, Update};
//! use jose_b64::base64ct::Base64UrlUnpadded;
//!
//! let mut enc: Encoder<String, Base64UrlUnpadded> = Encoder::default();
//! enc.update("Hello world!").unwrap();
//! let encoded = enc.finish().unwrap();
//! assert_eq!(encoded, "SGVsbG8gd29ybGQh");
//!
//! // If you may need to serialize potentially invalid UTF8 or can't guarantee that your
//! // chunks are at utf8 boundaries, use `Decoder<Vec<u8>, _>` instead
//! let mut dec: Decoder<String, Base64UrlUnpadded> = Decoder::default();
//! dec.update(encoded).unwrap();
//! let decoded = dec.finish().unwrap();
//! assert_eq!(decoded, "Hello world!");
//! ```

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
