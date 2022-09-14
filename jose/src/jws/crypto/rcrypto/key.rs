// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;

#[cfg(feature = "hmac")]
use core::marker::PhantomData;

use zeroize::Zeroizing;

use super::super::core::{CoreSigningKey, CoreVerifyingKey};
use super::state::Inner;
use super::State;

use crate::alg::{Algorithm, Signing as Sign, Signing::*};
use crate::key::rcrypto::{Error, Key, Kind, Kind::*, Type};
use crate::key::KeyInfo;

/// Signing Key Types
pub struct Signing(());

impl Type for Signing {
    type Oct = Zeroizing<Box<[u8]>>;

    #[cfg(feature = "p256")]
    #[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
    type P256 = p256::ecdsa::SigningKey;

    #[cfg(feature = "p384")]
    #[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
    type P384 = p384::ecdsa::SigningKey;

    #[cfg(feature = "rsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
    type Rsa = rsa::RsaPrivateKey;
}

/// Verifying Key Types
pub struct Verifying(());

impl Type for Verifying {
    type Oct = Zeroizing<Box<[u8]>>;

    #[cfg(feature = "p256")]
    type P256 = p256::ecdsa::VerifyingKey;

    #[cfg(feature = "p384")]
    type P384 = p384::ecdsa::VerifyingKey;

    #[cfg(feature = "rsa")]
    type Rsa = rsa::RsaPublicKey;
}

impl From<Key<Signing>> for Key<Verifying> {
    fn from(value: Key<Signing>) -> Self {
        let kind: Kind<Verifying> = match value.kind {
            Oct(x) => Oct(x),
            P256(x) => P256(x.verifying_key()),
            P384(x) => P384(x.verifying_key()),
            Rsa(x) => Rsa(x.to_public_key()),
        };

        let algo = value.algo;
        Self { kind, algo }
    }
}

#[cfg(feature = "jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
impl TryFrom<&crate::jwk::Jwk> for Key<Signing> {
    type Error = Error;

    fn try_from(value: &crate::jwk::Jwk) -> Result<Self, Self::Error> {
        use crate::jwk::EcCurves;
        use crate::jwk::Key;

        let kind = match &value.key {
            Key::Oct(k) => Oct(Zeroizing::new(Box::from(&***k.k))),

            #[cfg(feature = "rsa")]
            Key::Rsa(k) => Rsa(k.try_into()?),

            #[cfg(feature = "p256")]
            Key::Ec(k) if k.crv == EcCurves::P256 => P256(k.try_into()?),

            #[cfg(feature = "p384")]
            Key::Ec(k) if k.crv == EcCurves::P384 => P384(k.try_into()?),

            _ => return Err(Error::Unsupported),
        };

        Ok(Self {
            kind,
            algo: value.prm.alg.clone(),
        })
    }
}

#[cfg(feature = "jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
impl TryFrom<&crate::jwk::Jwk> for Key<Verifying> {
    type Error = Error;

    fn try_from(value: &crate::jwk::Jwk) -> Result<Self, Self::Error> {
        use crate::jwk::EcCurves;
        use crate::jwk::Key;

        let kind = match &value.key {
            Key::Oct(k) => Oct(Zeroizing::new(Box::from(&***k.k))),

            #[cfg(feature = "rsa")]
            Key::Rsa(k) => Rsa(k.try_into()?),

            #[cfg(feature = "p256")]
            Key::Ec(k) if k.crv == EcCurves::P256 => P256(k.try_into()?),

            #[cfg(feature = "p384")]
            Key::Ec(k) if k.crv == EcCurves::P384 => P384(k.try_into()?),

            _ => return Err(Error::Unsupported),
        };

        Ok(Self {
            kind,
            algo: value.prm.alg.clone(),
        })
    }
}

impl<'a> CoreVerifyingKey<'a> for Key<Verifying> {
    type StartError = Error;
    type Finish = State<'a, Verifying>;

    fn verify(&'a self, sign: Sign) -> Result<Self::Finish, Self::StartError> {
        if !self.is_supported(&Algorithm::Signing(sign)) {
            return Err(Error::Unsupported);
        }

        Ok(State::from(match (&self.kind, sign) {
            #[cfg(feature = "hmac")]
            (Oct(k), Hs256) => Inner::Hs256(hmac::Mac::new_from_slice(k).unwrap(), PhantomData),
            #[cfg(feature = "hmac")]
            (Oct(k), Hs384) => Inner::Hs384(hmac::Mac::new_from_slice(k).unwrap(), PhantomData),
            #[cfg(feature = "hmac")]
            (Oct(k), Hs512) => Inner::Hs512(hmac::Mac::new_from_slice(k).unwrap(), PhantomData),

            #[cfg(feature = "p256")]
            (P256(k), Es256) => Inner::Es256(Default::default(), k),
            #[cfg(feature = "p384")]
            (P384(k), Es384) => Inner::Es384(Default::default(), k),

            #[cfg(feature = "rsa")]
            (Rsa(k), Rs256) => Inner::Rs256(Default::default(), k),
            #[cfg(feature = "rsa")]
            (Rsa(k), Rs384) => Inner::Rs384(Default::default(), k),
            #[cfg(feature = "rsa")]
            (Rsa(k), Rs512) => Inner::Rs512(Default::default(), k),

            #[cfg(all(feature = "rsa", feature = "rand"))]
            (Rsa(k), Ps256) => Inner::Ps256(Default::default(), k),
            #[cfg(all(feature = "rsa", feature = "rand"))]
            (Rsa(k), Ps384) => Inner::Ps384(Default::default(), k),
            #[cfg(all(feature = "rsa", feature = "rand"))]
            (Rsa(k), Ps512) => Inner::Ps512(Default::default(), k),

            _ => return Err(Error::Unsupported),
        }))
    }
}

impl<'a> CoreSigningKey<'a> for Key<Signing> {
    type StartError = Error;
    type Finish = State<'a, Signing>;

    fn sign(&'a self, sign: Sign) -> Result<Self::Finish, Self::StartError> {
        if !self.is_supported(&Algorithm::Signing(sign)) {
            return Err(Error::Unsupported);
        }

        Ok(State::from(match (&self.kind, sign) {
            #[cfg(feature = "hmac")]
            (Oct(k), Hs256) => Inner::Hs256(hmac::Mac::new_from_slice(k).unwrap(), PhantomData),
            #[cfg(feature = "hmac")]
            (Oct(k), Hs384) => Inner::Hs384(hmac::Mac::new_from_slice(k).unwrap(), PhantomData),
            #[cfg(feature = "hmac")]
            (Oct(k), Hs512) => Inner::Hs512(hmac::Mac::new_from_slice(k).unwrap(), PhantomData),

            #[cfg(feature = "p256")]
            (P256(k), Es256) => Inner::Es256(Default::default(), k),
            #[cfg(feature = "p384")]
            (P384(k), Es384) => Inner::Es384(Default::default(), k),

            #[cfg(feature = "rsa")]
            (Rsa(k), Rs256) => Inner::Rs256(Default::default(), k),
            #[cfg(feature = "rsa")]
            (Rsa(k), Rs384) => Inner::Rs384(Default::default(), k),
            #[cfg(feature = "rsa")]
            (Rsa(k), Rs512) => Inner::Rs512(Default::default(), k),

            #[cfg(all(feature = "rsa", feature = "rand"))]
            (Rsa(k), Ps256) => Inner::Ps256(Default::default(), k),
            #[cfg(all(feature = "rsa", feature = "rand"))]
            (Rsa(k), Ps384) => Inner::Ps384(Default::default(), k),
            #[cfg(all(feature = "rsa", feature = "rand"))]
            (Rsa(k), Ps512) => Inner::Ps512(Default::default(), k),

            _ => return Err(Error::Unsupported),
        }))
    }
}
