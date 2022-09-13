// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! JWK integrations with RustCrypto types

#![cfg(any(feature = "hmac", feature = "p256", feature = "p384", feature = "rsa"))]
#![cfg_attr(
    docsrs,
    doc(cfg(any(feature = "hmac", feature = "p256", feature = "p384", feature = "rsa")))
)]

mod key;
mod p256;
mod p384;
mod rsa;

use core::convert::Infallible;

use rand_core::{CryptoRng, RngCore};

use super::Generator;
use crate::alg::{Algorithm::Signing, Signing::*};
use crate::jwk::*;
use crate::key::rcrypto::Error;

impl<T: RngCore + CryptoRng> Generator<usize, Oct> for T {
    type Error = Infallible;

    fn generate(&mut self, bytes: usize) -> Result<Oct, Self::Error> {
        let mut buf = alloc::vec![0u8; bytes].into_boxed_slice();
        self.fill_bytes(&mut *buf);
        Ok(Oct { k: buf.into() })
    }
}

impl<R: RngCore + CryptoRng> Generator<EcCurves, Ec> for R {
    type Error = Error;

    fn generate(&mut self, curve: EcCurves) -> Result<Ec, Self::Error> {
        match curve {
            #[cfg(feature = "p256")]
            EcCurves::P256 => Ok(::p256::SecretKey::random(self).into()),

            #[cfg(feature = "p384")]
            EcCurves::P384 => Ok(::p384::SecretKey::random(self).into()),

            _ => Err(Error::Unsupported),
        }
    }
}

#[cfg(feature = "rsa")]
impl<R: RngCore + CryptoRng> Generator<usize, Rsa> for R {
    type Error = ::rsa::errors::Error;

    fn generate(&mut self, bits: usize) -> Result<Rsa, Self::Error> {
        ::rsa::RsaPrivateKey::new(self, bits).map(|x| x.into())
    }
}

impl<R: RngCore + CryptoRng, A: Into<Parameters>> Generator<A, Jwk> for R {
    type Error = Error;

    fn generate(&mut self, params: A) -> Result<Jwk, Self::Error> {
        macro_rules! gen {
            ($self:expr, $arg:expr, $kind:path) => {
                <Self as Generator<_, $kind>>::generate($self, $arg).map_err(|_| Error::Unsupported)
            };
        }

        let prm = params.into();
        let key = match prm.alg.as_ref().ok_or(Error::Unsupported)? {
            #[cfg(feature = "p256")]
            Signing(Es256) => gen!(self, EcCurves::P256, Ec)?.into(),
            #[cfg(feature = "p384")]
            Signing(Es384) => gen!(self, EcCurves::P384, Ec)?.into(),

            Signing(Hs256) => gen!(self, 16, Oct)?.into(),
            Signing(Hs384) => gen!(self, 24, Oct)?.into(),
            Signing(Hs512) => gen!(self, 32, Oct)?.into(),

            #[cfg(feature = "rsa")]
            Signing(Rs256) => gen!(self, 2048, Rsa)?.into(),
            #[cfg(feature = "rsa")]
            Signing(Rs384) => gen!(self, 3072, Rsa)?.into(),
            #[cfg(feature = "rsa")]
            Signing(Rs512) => gen!(self, 4096, Rsa)?.into(),

            #[cfg(feature = "rsa")]
            Signing(Ps256) => gen!(self, 2048, Rsa)?.into(),
            #[cfg(feature = "rsa")]
            Signing(Ps384) => gen!(self, 3072, Rsa)?.into(),
            #[cfg(feature = "rsa")]
            Signing(Ps512) => gen!(self, 4096, Rsa)?.into(),

            _ => return Err(Error::Unsupported),
        };

        Ok(Jwk { prm, key })
    }
}
