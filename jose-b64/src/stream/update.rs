// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::string::String;
use alloc::vec::Vec;

use core::convert::Infallible;

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

impl Update for String {
    type Error = core::str::Utf8Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.push_str(core::str::from_utf8(chunk.as_ref())?);
        Ok(())
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

impl<T: crate::Zeroize + Update> Update for crate::Zeroizing<T> {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        (**self).update(chunk)
    }
}
