// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! When the zeroize crate is not used (`secret` feature is not enabled), this
//! implements the required zeroize trait in a non-secret way

#![cfg(not(feature = "secret"))]

use core::ops::{Deref, DerefMut};

pub trait Zeroize {
    fn zeroize(&mut self);
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Zeroizing<T>(T);

impl<T> From<T> for Zeroizing<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for Zeroizing<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: AsRef<U>, U: ?Sized> AsRef<U> for Zeroizing<T> {
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

impl<T: AsMut<U>, U: ?Sized> AsMut<U> for Zeroizing<T> {
    fn as_mut(&mut self) -> &mut U {
        self.0.as_mut()
    }
}
