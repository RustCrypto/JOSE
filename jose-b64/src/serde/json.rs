// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "json")]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::{Infallible, TryInto};
use core::fmt::Debug;
use core::ops::Deref;
use core::str::FromStr;

use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize};

use super::Bytes;
use crate::codec::{Config, Error, UrlSafe};

/// A wrapper for nested, base64-encoded JSON
///
/// [`Json`] handles the case where a type (`T`) is serialized to JSON and then
/// embedded into another JSON object as a base64-string. Note that [`Json`]
/// internally stores both the originally decoded bytes **and** the
/// doubly-decoded value. While this uses additional memory, it ensures that
/// the original serialization is not lost. This is important in cryptogrpahic
/// contexts where the original serialization may be included in a
/// cryptogrpahic measurement.
///
/// During deserialization, a full double deserialization is performed. This
/// ensures that an instantiated [`Json`] object is always fully parsed. During
/// serialization, only the pre-serialized bytes are used; the type (`T`) is
/// **not** reserialized.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(bound(serialize = "Bytes<B, C>: Serialize"))]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
#[serde(transparent)]
pub struct Json<T, B = Box<[u8]>, C = UrlSafe> {
    buf: Bytes<B, C>,

    #[serde(skip_serializing)]
    val: T,
}

impl<T, B, C> Deref for Json<T, B, C> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<T, B: AsRef<[u8]>, C> AsRef<[u8]> for Json<T, B, C> {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_ref()
    }
}

impl<T, B, C> TryFrom<Bytes<B, C>> for Json<T, B, C>
where
    Bytes<B, C>: AsRef<[u8]>,
    T: DeserializeOwned,
{
    type Error = serde_json::Error;

    fn try_from(buf: Bytes<B, C>) -> Result<Self, Self::Error> {
        Ok(Self {
            val: serde_json::from_slice(buf.as_ref())?,
            buf,
        })
    }
}

impl<T, B, C> Json<T, B, C>
where
    Bytes<B, C>: From<Vec<u8>>,
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

impl<T, B, C: Config> FromStr for Json<T, B, C>
where
    Bytes<B, C>: FromStr<Err = Error<Infallible>>,
    Bytes<B, C>: AsRef<[u8]>,
    T: DeserializeOwned,
{
    type Err = Error<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let buf = Bytes::from_str(s).map_err(|x| x.cast())?;
        buf.try_into().map_err(Error::Inner)
    }
}

impl<'de, T, B, C> Deserialize<'de> for Json<T, B, C>
where
    Bytes<B, C>: Deserialize<'de>,
    Bytes<B, C>: AsRef<[u8]>,
    T: DeserializeOwned,
    C: Config,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Self::try_from(Bytes::deserialize(deserializer)?) {
            Err(e) => return Err(D::Error::custom(e)),
            Ok(x) => x,
        })
    }
}
