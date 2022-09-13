// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::str::FromStr;

use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use super::{Config, UrlSafe};

/// A serde wrapper for base64-encoded bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bytes<T = Box<[u8]>, C = UrlSafe> {
    buf: T,
    cfg: PhantomData<C>,
}

impl<T: Zeroize, C> Zeroize for Bytes<T, C> {
    fn zeroize(&mut self) {
        self.buf.zeroize()
    }
}

impl<T: Debug, C> Debug for Bytes<T, C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Bytes").field(&self.buf).finish()
    }
}

impl<T, C> Deref for Bytes<T, C> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl<T, C> DerefMut for Bytes<T, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl<T: AsRef<U>, U: ?Sized, C> AsRef<U> for Bytes<T, C> {
    fn as_ref(&self) -> &U {
        self.buf.as_ref()
    }
}

impl<T: AsMut<U>, U: ?Sized, C> AsMut<U> for Bytes<T, C> {
    fn as_mut(&mut self) -> &mut U {
        self.buf.as_mut()
    }
}

impl<T, C> From<T> for Bytes<T, C> {
    fn from(buf: T) -> Self {
        Self {
            buf,
            cfg: PhantomData,
        }
    }
}

impl<C> From<Vec<u8>> for Bytes<Box<[u8]>, C> {
    fn from(buf: Vec<u8>) -> Self {
        Self::from(buf.into_boxed_slice())
    }
}

impl<C> From<Bytes<Vec<u8>, C>> for Bytes<Box<[u8]>, C> {
    fn from(bytes: Bytes<Vec<u8>, C>) -> Self {
        Self::from(bytes.buf.into_boxed_slice())
    }
}

impl<C> From<Box<[u8]>> for Bytes<Vec<u8>, C> {
    fn from(buf: Box<[u8]>) -> Self {
        Self::from(buf.into_vec())
    }
}

impl<C> From<Bytes<Box<[u8]>, C>> for Bytes<Vec<u8>, C> {
    fn from(bytes: Bytes<Box<[u8]>, C>) -> Self {
        Self::from(bytes.buf.into_vec())
    }
}

impl<C: Config> FromStr for Bytes<Vec<u8>, C> {
    type Err = super::Error<Infallible>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            buf: C::decode(s.as_bytes())?,
            cfg: PhantomData,
        })
    }
}

impl<C: Config> FromStr for Bytes<Box<[u8]>, C> {
    type Err = super::Error<Infallible>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bytes::<Vec<u8>, C>::from_str(s).map(|x| x.buf.into_boxed_slice().into())
    }
}

impl<T: AsRef<[u8]>, C: Config> Serialize for Bytes<T, C> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let b64 = C::encode(self.buf.as_ref());
        let b64 = Zeroizing::new(String::from_utf8(b64).expect("unreachable"));
        b64.serialize(serializer)
    }
}

impl<'de, C: Config> Deserialize<'de> for Bytes<Vec<u8>, C> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let enc = Zeroizing::new(String::deserialize(deserializer)?);
        let dec = C::decode(enc.as_bytes()).map_err(|_| D::Error::custom("invalid base64"))?;

        Ok(Self {
            cfg: PhantomData,
            buf: dec,
        })
    }
}

impl<'de, C: Config> Deserialize<'de> for Bytes<Box<[u8]>, C> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Bytes::<Vec<u8>, C>::deserialize(deserializer).map(|x| x.buf.into_boxed_slice().into())
    }
}

impl<'de, C: Config, const N: usize> Deserialize<'de> for Bytes<[u8; N], C> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Bytes::<Vec<u8>, C>::deserialize(deserializer)?;
        let array = <[u8; N]>::try_from(bytes.buf);

        Ok(array
            .map_err(|_| D::Error::custom("invalid base64 length"))?
            .into())
    }
}
