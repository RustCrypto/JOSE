// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "serde")]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::stream::Error;

/// A serde wrapper for non-secure base64-encoded bytes. Available with the
/// feature `serde`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct B64Bytes<T = Box<[u8]>, E = Base64UrlUnpadded> {
    buf: T,
    cfg: PhantomData<E>,
}

impl<T: crate::Zeroize, E> crate::Zeroize for B64Bytes<T, E> {
    fn zeroize(&mut self) {
        self.buf.zeroize()
    }
}

impl<T: Debug, E> Debug for B64Bytes<T, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Bytes").field(&self.buf).finish()
    }
}

impl<T, E> Deref for B64Bytes<T, E> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl<T, E> DerefMut for B64Bytes<T, E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl<T: AsRef<U>, U: ?Sized, E> AsRef<U> for B64Bytes<T, E> {
    fn as_ref(&self) -> &U {
        self.buf.as_ref()
    }
}

impl<T: AsMut<U>, U: ?Sized, E> AsMut<U> for B64Bytes<T, E> {
    fn as_mut(&mut self) -> &mut U {
        self.buf.as_mut()
    }
}

impl<T, E> From<T> for B64Bytes<T, E> {
    fn from(buf: T) -> Self {
        Self {
            buf,
            cfg: PhantomData,
        }
    }
}

impl<E> From<Vec<u8>> for B64Bytes<Box<[u8]>, E> {
    fn from(buf: Vec<u8>) -> Self {
        Self::from(buf.into_boxed_slice())
    }
}

impl<E> From<B64Bytes<Vec<u8>, E>> for B64Bytes<Box<[u8]>, E> {
    fn from(bytes: B64Bytes<Vec<u8>, E>) -> Self {
        Self::from(bytes.buf.into_boxed_slice())
    }
}

impl<E> From<Box<[u8]>> for B64Bytes<Vec<u8>, E> {
    fn from(buf: Box<[u8]>) -> Self {
        Self::from(buf.into_vec())
    }
}

impl<E> From<B64Bytes<Box<[u8]>, E>> for B64Bytes<Vec<u8>, E> {
    fn from(bytes: B64Bytes<Box<[u8]>, E>) -> Self {
        Self::from(bytes.buf.into_vec())
    }
}

impl<E: Encoding> FromStr for B64Bytes<Vec<u8>, E> {
    type Err = Error<Infallible>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            buf: E::decode_vec(s)?,
            cfg: PhantomData,
        })
    }
}

impl<E: Encoding> FromStr for B64Bytes<Box<[u8]>, E> {
    type Err = Error<Infallible>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        B64Bytes::<Vec<u8>, E>::from_str(s).map(|x| x.buf.into_boxed_slice().into())
    }
}

impl<T: AsRef<[u8]>, E: Encoding> Serialize for B64Bytes<T, E> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let b64 = crate::Zeroizing::from(E::encode_string(self.buf.as_ref()));
        b64.serialize(serializer)
    }
}

impl<'de, E: Encoding> Deserialize<'de> for B64Bytes<Vec<u8>, E> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let enc = crate::Zeroizing::from(String::deserialize(deserializer)?);
        let dec = E::decode_vec(&enc).map_err(|_| D::Error::custom("invalid base64"))?;

        Ok(Self {
            cfg: PhantomData,
            buf: dec,
        })
    }
}

impl<'de, E: Encoding> Deserialize<'de> for B64Bytes<Box<[u8]>, E> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        B64Bytes::<Vec<u8>, E>::deserialize(deserializer).map(|x| x.buf.into_boxed_slice().into())
    }
}

impl<'de, E: Encoding, const N: usize> Deserialize<'de> for B64Bytes<[u8; N], E> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = B64Bytes::<Vec<u8>, E>::deserialize(deserializer)?;
        let array = <[u8; N]>::try_from(bytes.buf);

        Ok(array
            .map_err(|_| D::Error::custom("invalid base64 length"))?
            .into())
    }
}
