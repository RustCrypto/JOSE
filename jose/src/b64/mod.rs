// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Base64 Conversion Utilities

mod bytes;
mod codec;
mod json;
mod optional;
mod secret;

use alloc::vec::Vec;

#[cfg(feature = "jws")]
pub use json::Json;

pub use bytes::Bytes;
pub use codec::{Config, Decoder, Encoder, Error, Standard, StandardPad, UrlSafe, UrlSafePad};
pub use optional::Optional;
pub use secret::Secret;

use core::convert::Infallible;

use zeroize::{Zeroize, Zeroizing};

/// A type that can be updated with bytes.
///
/// This type is similar to `std::io::Write` or `digest::Update`.
pub trait Update {
    /// The error that may occur during update.
    type Error;

    /// Update the instance with the provided bytes.
    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error>;

    /// Perform a chain update.
    fn chain(mut self, chunk: impl AsRef<[u8]>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        self.update(chunk)?;
        Ok(self)
    }
}

impl Update for Vec<u8> {
    type Error = Infallible;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.extend(chunk.as_ref());
        Ok(())
    }
}

impl<T: Zeroize + Update> Update for Zeroizing<T> {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        (**self).update(chunk)
    }
}

impl<T: Update> Update for Vec<T> {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        for x in self.iter_mut() {
            x.update(chunk.as_ref())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use alloc::string::String;

    const VALUES: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn encode() {
        for (dec, enc) in VALUES {
            let out = Standard::encode(dec);
            assert_eq!(enc.trim_end_matches('='), &String::from_utf8(out).unwrap());

            let out = StandardPad::encode(dec);
            assert_eq!(enc, &String::from_utf8(out).unwrap());

            let out = UrlSafe::encode(dec);
            assert_eq!(enc.trim_end_matches('='), &String::from_utf8(out).unwrap());

            let out = UrlSafePad::encode(dec);
            assert_eq!(enc, &String::from_utf8(out).unwrap());
        }
    }

    #[test]
    fn decode() {
        for (dec, enc) in VALUES {
            let out = Standard::decode(enc.trim_end_matches('=').as_bytes()).unwrap();
            assert_eq!(dec, &out);

            let out = StandardPad::decode(enc.as_bytes()).unwrap();
            assert_eq!(dec, &out);

            let out = UrlSafe::decode(enc.trim_end_matches('=').as_bytes()).unwrap();
            assert_eq!(dec, &out);

            let out = UrlSafePad::decode(enc.as_bytes()).unwrap();
            assert_eq!(dec, &out);
        }
    }
}
