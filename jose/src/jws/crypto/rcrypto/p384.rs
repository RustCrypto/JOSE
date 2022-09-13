// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "p384")]

use p384::ecdsa::{SigningKey, VerifyingKey};

use super::super::core::{CoreSigningKey, CoreVerifyingKey};
use super::state::Inner;
use super::{Signing, State, Verifying};

use crate::alg::{Signing as Sign, Signing::*};
use crate::key::rcrypto::{Error, Key, Kind};

#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
impl From<VerifyingKey> for Key<Verifying> {
    fn from(value: VerifyingKey) -> Self {
        Self {
            kind: Kind::P384(value),
            algo: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
impl From<SigningKey> for Key<Signing> {
    fn from(value: SigningKey) -> Self {
        Self {
            kind: Kind::P384(value),
            algo: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
impl<'a> CoreVerifyingKey<'a> for VerifyingKey {
    type StartError = Error;
    type Finish = State<'a, Verifying>;

    fn verify(&'a self, sign: Sign) -> Result<Self::Finish, Self::StartError> {
        match sign {
            Es384 => Ok(Inner::Es384(Default::default(), self).into()),
            _ => Err(Error::Unsupported),
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
impl<'a> CoreSigningKey<'a> for SigningKey {
    type StartError = Error;
    type Finish = State<'a, Signing>;

    fn sign(&'a self, sign: Sign) -> Result<Self::Finish, Self::StartError> {
        match sign {
            Es384 => Ok(Inner::Es384(Default::default(), self).into()),
            _ => Err(Error::AlgMismatch),
        }
    }
}
