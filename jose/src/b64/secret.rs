// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use core::fmt::Debug;
use core::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::{Bytes, UrlSafe};

/// A serde wrapper for base64-encoded secrets.
///
/// A secret is like the [`Bytes`] type, with some additional protections:
///
///   1. It is zeroed on drop.
///   2. Its equality implementation is constant time.
///   2. Its contents are not printed in the debug formatter.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[serde(bound(serialize = "Bytes<T, C>: Serialize"))]
#[serde(bound(deserialize = "Bytes<T, C>: Deserialize<'de>"))]
pub struct Secret<T: Zeroize = Box<[u8]>, C = UrlSafe>(Zeroizing<Bytes<T, C>>);

impl<T: Zeroize, C> Debug for Secret<T, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret(***)")
    }
}

impl<T: Zeroize, U: Into<Bytes<T, C>>, C> From<U> for Secret<T, C> {
    fn from(value: U) -> Self {
        Self(Zeroizing::new(value.into()))
    }
}

impl<T: Zeroize, C> Deref for Secret<T, C> {
    type Target = Bytes<T, C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Zeroize, C> DerefMut for Secret<T, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Zeroize, U, C> AsRef<U> for Secret<T, C>
where
    Bytes<T, C>: AsRef<U>,
{
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

impl<T: Zeroize, U, C> AsMut<U> for Secret<T, C>
where
    Bytes<T, C>: AsMut<U>,
{
    fn as_mut(&mut self) -> &mut U {
        self.0.as_mut()
    }
}

impl<T: Zeroize + AsRef<[u8]> + Sized, C> ConstantTimeEq for Secret<T, C> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.as_ref().ct_eq(other.0.as_ref())
    }
}

impl<T: Zeroize + AsRef<[u8]>, C> Eq for Secret<T, C> {}
impl<T: Zeroize + AsRef<[u8]>, C> PartialEq for Secret<T, C> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}
