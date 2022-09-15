// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "rsa")]

use rsa::{RsaPrivateKey, RsaPublicKey};

use super::super::core::{CoreSigningKey, CoreVerifyingKey};
use super::{state::Inner, Signing, State, Verifying};

use crate::alg::{Algorithm, Signing as Sign, Signing::*};
use crate::key::rcrypto::Error;
use crate::key::KeyInfo;

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl<'a> CoreVerifyingKey<'a> for RsaPublicKey {
    type StartError = Error;
    type Finish = State<'a, Verifying>;

    fn verify(&'a self, sign: Sign) -> Result<Self::Finish, Self::StartError> {
        if !self.is_supported(&Algorithm::Signing(sign)) {
            return Err(Error::Unsupported);
        }

        match sign {
            Rs256 => Ok(Inner::Rs256(Default::default(), self).into()),
            Rs384 => Ok(Inner::Rs384(Default::default(), self).into()),
            Rs512 => Ok(Inner::Rs512(Default::default(), self).into()),

            #[cfg(feature = "rand")]
            Ps256 => Ok(Inner::Ps256(Default::default(), self).into()),
            #[cfg(feature = "rand")]
            Ps384 => Ok(Inner::Ps384(Default::default(), self).into()),
            #[cfg(feature = "rand")]
            Ps512 => Ok(Inner::Ps512(Default::default(), self).into()),

            _ => Err(Error::Unsupported),
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl<'a> CoreSigningKey<'a> for RsaPrivateKey {
    type StartError = Error;
    type Finish = State<'a, Signing>;

    fn sign(&'a self, sign: Sign) -> Result<Self::Finish, Self::StartError> {
        if !self.is_supported(&Algorithm::Signing(sign)) {
            return Err(Error::Unsupported);
        }

        match sign {
            Rs256 => Ok(Inner::Rs256(Default::default(), self).into()),
            Rs384 => Ok(Inner::Rs384(Default::default(), self).into()),
            Rs512 => Ok(Inner::Rs512(Default::default(), self).into()),

            #[cfg(feature = "rand")]
            Ps256 => Ok(Inner::Ps256(Default::default(), self).into()),
            #[cfg(feature = "rand")]
            Ps384 => Ok(Inner::Ps384(Default::default(), self).into()),
            #[cfg(feature = "rand")]
            Ps512 => Ok(Inner::Ps512(Default::default(), self).into()),

            _ => Err(Error::Unsupported),
        }
    }
}
