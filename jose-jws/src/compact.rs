// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt::Display;
use core::{convert::Infallible, str::FromStr};

use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
use jose_b64::stream::Error;

use crate::{Flattened, General, Jws, Signature};

impl FromStr for Jws {
    type Err = Error<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Flattened::from_str(s)?.into())
    }
}

impl FromStr for General {
    type Err = Error<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Flattened::from_str(s)?.into())
    }
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

impl Display for Flattened {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut prot = alloc::string::String::new();
        if let Some(x) = self.signature.protected.as_ref() {
            prot = Base64UrlUnpadded::encode_string(x.as_ref());
        }

        let mut payl = alloc::string::String::new();
        if let Some(x) = self.payload.as_ref() {
            payl = Base64UrlUnpadded::encode_string(x);
        }

        let sign = Base64UrlUnpadded::encode_string(&self.signature.signature);
        write!(f, "{prot}.{payl}.{sign}")
    }
}
