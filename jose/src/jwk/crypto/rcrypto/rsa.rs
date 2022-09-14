// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "rsa")]

use rsa::{BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey};

use crate::jwk::{Rsa, RsaPrivate};
use crate::key::rcrypto::Error;

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<&RsaPublicKey> for Rsa {
    fn from(pk: &RsaPublicKey) -> Self {
        Self {
            n: pk.n().to_bytes_be().into(),
            e: pk.e().to_bytes_be().into(),
            prv: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<RsaPublicKey> for Rsa {
    fn from(sk: RsaPublicKey) -> Self {
        (&sk).into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl TryFrom<&Rsa> for RsaPublicKey {
    type Error = Error;

    fn try_from(value: &Rsa) -> Result<Self, Self::Error> {
        let n = BigUint::from_bytes_be(&value.n);
        let e = BigUint::from_bytes_be(&value.e);
        RsaPublicKey::new(n, e).map_err(|_| Error::Invalid)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl TryFrom<Rsa> for RsaPublicKey {
    type Error = Error;

    fn try_from(value: Rsa) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

// TODO: patch rsa crate to export the optional values
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<&RsaPrivateKey> for Rsa {
    fn from(pk: &RsaPrivateKey) -> Self {
        Self {
            n: pk.n().to_bytes_be().into(),
            e: pk.e().to_bytes_be().into(),
            prv: Some(RsaPrivate {
                d: pk.d().to_bytes_be().into(),
                opt: None,
            }),
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<RsaPrivateKey> for Rsa {
    fn from(sk: RsaPrivateKey) -> Self {
        (&sk).into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl TryFrom<&Rsa> for RsaPrivateKey {
    type Error = Error;

    fn try_from(value: &Rsa) -> Result<Self, Self::Error> {
        if let Some(prv) = value.prv.as_ref() {
            if let Some(opt) = prv.opt.as_ref() {
                let n = BigUint::from_bytes_be(&value.n);
                let e = BigUint::from_bytes_be(&value.e);
                let d = BigUint::from_bytes_be(&prv.d);
                let p = BigUint::from_bytes_be(&opt.p);
                let q = BigUint::from_bytes_be(&opt.q);

                let mut primes = alloc::vec![p, q];
                primes.extend(opt.oth.iter().map(|x| BigUint::from_bytes_be(&x.r)));

                return Ok(Self::from_components(n, e, d, primes));
            }

            return Err(Error::Unsupported);
        }

        Err(Error::NotPrivate)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl TryFrom<Rsa> for RsaPrivateKey {
    type Error = Error;

    fn try_from(value: Rsa) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
