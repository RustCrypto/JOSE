// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! JWS: JSON Web Signature

#![cfg(feature = "jws")]
#![cfg_attr(docsrs, doc(cfg(feature = "jws")))]

pub mod crypto;

mod head;

pub use head::{Protected, Unprotected};

use alloc::{vec, vec::Vec};
use core::{convert::Infallible, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::b64::{Bytes, Error, Json};

/// The JSON Web Signature
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
#[serde(untagged)]
pub enum Jws {
    /// General Serialization
    General(General),

    /// Flattened Serialization
    Flattened(Flattened),
}

impl From<General> for Jws {
    fn from(value: General) -> Self {
        Jws::General(value)
    }
}

impl From<Flattened> for Jws {
    fn from(value: Flattened) -> Self {
        Jws::Flattened(value)
    }
}

impl FromStr for Jws {
    type Err = <Flattened as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Flattened::from_str(s)?.into())
    }
}

/// General Serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct General {
    /// The payload of the signature.
    pub payload: Option<Bytes>,

    /// The signatures over the payload.
    pub signatures: Vec<Signature>,
}

impl From<Flattened> for General {
    fn from(value: Flattened) -> Self {
        Self {
            payload: value.payload,
            signatures: vec![value.signature],
        }
    }
}

impl FromStr for General {
    type Err = <Flattened as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Flattened::from_str(s)?.into())
    }
}

/// Flattened Serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flattened {
    /// The payload of the signature.
    pub payload: Option<Bytes>,

    /// The signature over the payload.
    #[serde(flatten)]
    pub signature: Signature,
}

impl FromStr for Flattened {
    type Err = Error<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split('.');

        let prot = iter.next().ok_or(Error::Length)?;
        let payl = iter.next().ok_or(Error::Length)?;
        let sign = iter.next().ok_or(Error::Length)?;
        if iter.next().is_some() {
            return Err(Error::Length);
        }

        let payload = match payl {
            "" => None,
            _ => Some(payl.parse().map_err(|e: Error<Infallible>| e.cast())?),
        };

        Ok(Self {
            payload,
            signature: Signature {
                protected: Some(prot.parse()?),
                header: None,
                signature: sign.parse().map_err(|e: Error<Infallible>| e.cast())?,
            },
        })
    }
}

/// A Signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// The JWS Unprotected Header
    pub header: Option<Unprotected>,

    /// The JWS Protected Header
    pub protected: Option<Json<Protected>>,

    /// The Signature Bytes
    pub signature: Bytes,
}
