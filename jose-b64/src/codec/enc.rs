// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::marker::PhantomData;

use super::{Codec, Config, UrlSafe};
use crate::{Update, Zeroizing};

/// A base64 streaming encoder.
pub struct Encoder<T, C = UrlSafe> {
    decoded: Zeroizing<[u8; 3]>,
    encoded: Zeroizing<[u8; 4]>,
    config: PhantomData<C>,
    used: usize,
    next: T,
}

impl<T: Default, C> Default for Encoder<T, C> {
    fn default() -> Self {
        Self::from(T::default())
    }
}

impl<T, C> From<T> for Encoder<T, C> {
    fn from(next: T) -> Self {
        Self {
            decoded: Default::default(),
            encoded: Default::default(),
            config: Default::default(),
            used: Default::default(),
            next,
        }
    }
}

impl<T: Update, C: Config> Update for Encoder<T, C> {
    type Error = T::Error;

    fn update(&mut self, buf: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        for byte in buf.as_ref() {
            self.decoded[self.used] = *byte;

            match self.used {
                2 => {
                    *self.encoded = C::d2e(*self.decoded);
                    self.next.update(&self.encoded)?;
                    self.used = 0
                }

                _ => self.used += 1,
            }
        }

        Ok(())
    }
}

impl<T: Update, C: Config> Encoder<T, C> {
    /// Finish base64 encoding and return the inner type.
    pub fn finish(mut self) -> Result<T, T::Error> {
        if self.used > 0 {
            self.decoded[self.used..].copy_from_slice(&[0u8; 3][self.used..]);
            *self.encoded = C::d2e(*self.decoded);
            self.used += 1;

            while C::PAD && self.used < 4 {
                self.encoded[self.used] = b'=';
                self.used += 1;
            }

            self.next.update(&self.encoded[..self.used])?;
        }

        Ok(self.next)
    }
}
