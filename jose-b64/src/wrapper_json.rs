// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "json")]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt::Debug;
use core::ops::Deref;
use core::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize};

use super::B64Bytes;
use crate::stream::Error;

/// A wrapper for nested, base64-encoded JSON. Available with the feature
/// `json`.
///
/// [`Json`] handles the case where a type (`T`) is serialized to JSON and then
/// embedded into another JSON object as a base64-string. Note that [`Json`]
/// internally stores both the originally decoded bytes **and** the
/// doubly-decoded value. While this uses additional memory, it ensures that the
/// original serialization is not lost. This is important in cryptogrpahic
/// contexts where the original serialization may be included in a cryptogrpahic
/// measurement.
///
/// During deserialization, a full double deserialization is performed. This
/// ensures that an instantiated [`Json`] object is always fully parsed. During
/// serialization, only the pre-serialized bytes are used; the type (`T`) is
/// **not** reserialized.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(bound(serialize = "B64Bytes<B, E>: Serialize"))]
#[serde(transparent)]
pub struct Json<T, B = Box<[u8]>, E = Base64UrlUnpadded> {
    buf: B64Bytes<B, E>,

    #[serde(skip_serializing)]
    val: T,
}

impl<T, B, E> Deref for Json<T, B, E> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<T, B: AsRef<[u8]>, E> AsRef<[u8]> for Json<T, B, E> {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_ref()
    }
}

impl<T, B, E> TryFrom<B64Bytes<B, E>> for Json<T, B, E>
where
    B64Bytes<B, E>: AsRef<[u8]>,
    T: DeserializeOwned,
{
    type Error = serde_json::Error;

    fn try_from(buf: B64Bytes<B, E>) -> Result<Self, Self::Error> {
        Ok(Self {
            val: serde_json::from_slice(buf.as_ref())?,
            buf,
        })
    }
}

impl<T, B, E> Json<T, B, E>
where
    B64Bytes<B, E>: From<Vec<u8>>,
    T: Serialize,
{
    /// Creates a new instance by serializing the input to JSON.
    ///
    /// The value `T` is serialized and **both** `T` and its serialized bytes
    /// are stored in the object.
    pub fn new(value: T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            buf: serde_json::to_vec(&value)?.into(),
            val: value,
        })
    }
}

impl<T, B, E: Encoding> FromStr for Json<T, B, E>
where
    B64Bytes<B, E>: FromStr<Err = Error<Infallible>>,
    B64Bytes<B, E>: AsRef<[u8]>,
    T: DeserializeOwned,
{
    type Err = Error<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let buf = B64Bytes::from_str(s).map_err(|e| e.cast())?;
        buf.try_into().map_err(Error::Inner)
    }
}

impl<'de, T, B, E> Deserialize<'de> for Json<T, B, E>
where
    B64Bytes<B, E>: Deserialize<'de>,
    B64Bytes<B, E>: AsRef<[u8]>,
    T: DeserializeOwned,
    E: Encoding,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Self::try_from(B64Bytes::deserialize(deserializer)?) {
            Err(e) => return Err(D::Error::custom(e)),
            Ok(x) => x,
        })
    }
}
