// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::Infallible;
use core::marker::PhantomData;
use zeroize::Zeroizing;

use super::Codec;
use crate::{Config, Update, UrlSafe};

/// A Base64 decoding error.
#[derive(Debug)]
pub enum Error<T> {
    /// An invalid value was found at the specified offset.
    Value(usize),

    /// An embedded error.
    Inner(T),

    /// The base64 value has an invalid length.
    Length,
}

impl<T> From<T> for Error<T> {
    fn from(value: T) -> Self {
        Self::Inner(value)
    }
}

impl Error<Infallible> {
    /// Casts an infallible error to any other kind of error.
    pub fn cast<T>(&self) -> Error<T> {
        match self {
            Self::Value(offset) => Error::Value(*offset),
            Self::Inner(..) => unreachable!(),
            Self::Length => Error::Length,
        }
    }
}

/// A base64 streaming decoder.
pub struct Decoder<T, C = UrlSafe> {
    decoded: Zeroizing<[u8; 3]>,
    encoded: Zeroizing<[u8; 4]>,
    config: PhantomData<C>,
    used: usize,
    all: usize,
    next: T,
}

impl<T: Default, C> Default for Decoder<T, C> {
    fn default() -> Self {
        Self::from(T::default())
    }
}

impl<T, C> From<T> for Decoder<T, C> {
    fn from(next: T) -> Self {
        Self {
            decoded: Default::default(),
            encoded: Default::default(),
            config: Default::default(),
            used: Default::default(),
            all: Default::default(),
            next,
        }
    }
}

impl<T: Update, C: Config> Update for Decoder<T, C> {
    type Error = Error<T::Error>;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        for byte in chunk.as_ref() {
            if self.used == 4 {
                *self.decoded = C::e2d(*self.encoded, self.all - 4).map_err(Error::Value)?;
                self.next.update(&self.decoded)?;
                self.used = 0;
            }

            self.encoded[self.used] = *byte;
            self.used += 1;
            self.all += 1;
        }

        Ok(())
    }
}

impl<T: Update, C: Config> Decoder<T, C> {
    /// Finish base64 decoding and return the inner type.
    pub fn finish(mut self) -> Result<T, Error<T::Error>> {
        let len = match self.used {
            n @ 2..=4 if !C::PAD => n,
            4 if C::PAD => match (self.encoded[2], self.encoded[3]) {
                (b'=', b'=') => 2,
                (.., b'=') => 3,
                _ => 4,
            },

            0 => return Ok(self.next),
            _ => return Err(Error::Length),
        };

        self.encoded[len..].copy_from_slice(&[b'A'; 4][len..]);
        *self.decoded = C::e2d(*self.encoded, self.all - self.used).map_err(Error::Value)?;
        self.next.update(&self.decoded[..len - 1])?;

        Ok(self.next)
    }
}
