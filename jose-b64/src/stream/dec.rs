// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::marker::PhantomData;

use base64ct::{Base64UrlUnpadded, Encoding};

use super::{Error, Update};
use crate::Zeroizing;

/// A base64 streaming decoder.
pub struct Decoder<T, E = Base64UrlUnpadded> {
    decoded: Zeroizing<[u8; 3]>,
    encoded: Zeroizing<[u8; 4]>,
    config: PhantomData<E>,
    used: usize,
    all: usize,
    next: T,
}

impl<T: Default, E> Default for Decoder<T, E> {
    fn default() -> Self {
        Self::from(T::default())
    }
}

impl<T, E> From<T> for Decoder<T, E> {
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

impl<T: Update, E: Encoding> Update for Decoder<T, E> {
    type Error = Error<T::Error>;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        for byte in chunk.as_ref() {
            if self.used == 4 {
                if E::decode_3bytes(&self.encoded[..], &mut self.decoded[..]) != 0 {
                    return Err(Error::Value);
                }

                self.next.update(&self.decoded).map_err(Error::Inner)?;
                self.used = 0;
            }

            self.encoded[self.used] = *byte;
            self.used += 1;
            self.all += 1;
        }

        Ok(())
    }
}

impl<T: Update, E: Encoding> Decoder<T, E> {
    /// Finish base64 decoding and return the inner type.
    pub fn finish(mut self) -> Result<T, Error<T::Error>> {
        let encoded = &self.encoded[..self.used];
        let decoded = E::decode(encoded, &mut self.decoded[..])?;
        self.next.update(decoded).map_err(Error::Inner)?;
        Ok(self.next)
    }
}
