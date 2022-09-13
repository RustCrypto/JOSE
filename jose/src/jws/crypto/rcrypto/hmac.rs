// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "hmac")]

use core::marker::PhantomData;

use hmac::{Hmac, Mac};

use super::super::core::{CoreSigningKey, CoreVerifyingKey};
use super::{state::Inner, Signing, State, Verifying};

use crate::alg::{Algorithm, Signing as Sign, Signing::*};
use crate::key::rcrypto::Error;
use crate::key::KeyInfo;

#[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
impl<'a> CoreVerifyingKey<'a> for [u8] {
    type StartError = Error;
    type Finish = State<'a, Verifying>;

    fn verify(&'a self, sign: Sign) -> Result<Self::Finish, Self::StartError> {
        if !self.is_supported(&Algorithm::Signing(sign)) {
            return Err(Error::Unsupported);
        }

        match sign {
            Hs256 => Ok(Inner::Hs256(Hmac::new_from_slice(self).unwrap(), PhantomData).into()),
            Hs384 => Ok(Inner::Hs384(Hmac::new_from_slice(self).unwrap(), PhantomData).into()),
            Hs512 => Ok(Inner::Hs512(Hmac::new_from_slice(self).unwrap(), PhantomData).into()),
            _ => Err(Error::Unsupported),
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
impl<'a> CoreSigningKey<'a> for [u8] {
    type StartError = Error;
    type Finish = State<'a, Signing>;

    fn sign(&'a self, sign: Sign) -> Result<Self::Finish, Self::StartError> {
        if !self.is_supported(&Algorithm::Signing(sign)) {
            return Err(Error::Unsupported);
        }

        match sign {
            Hs256 => Ok(Inner::Hs256(Hmac::new_from_slice(self).unwrap(), PhantomData).into()),
            Hs384 => Ok(Inner::Hs384(Hmac::new_from_slice(self).unwrap(), PhantomData).into()),
            Hs512 => Ok(Inner::Hs512(Hmac::new_from_slice(self).unwrap(), PhantomData).into()),
            _ => Err(Error::Unsupported),
        }
    }
}
