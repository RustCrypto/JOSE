// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use base64ct::{Base64UrlUnpadded, Encoding};

use super::{Encoder, Update};

/// Runtime optional base64 encoding
pub enum Optional<T, E = Base64UrlUnpadded> {
    #[allow(missing_docs)]
    Unencoded(T),

    #[allow(missing_docs)]
    Encoded(Encoder<T, E>),
}

impl<T, E> Optional<T, E> {
    /// Creates a new instance.
    pub fn new(inner: T, b64: bool) -> Self {
        match b64 {
            false => Self::Unencoded(inner),
            true => Self::Encoded(inner.into()),
        }
    }
}

impl<T: Update, E: Encoding> Optional<T, E> {
    /// Complete encoding and return the updater.
    pub fn finish(self) -> Result<T, T::Error> {
        match self {
            Self::Unencoded(x) => Ok(x),
            Self::Encoded(x) => x.finish(),
        }
    }
}

impl<T: Update, E: Encoding> Update for Optional<T, E> {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        match self {
            Self::Unencoded(x) => x.update(chunk),
            Self::Encoded(x) => x.update(chunk),
        }
    }
}
