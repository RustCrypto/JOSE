// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "rsa")]

use rsa::{
    BoxedUint, RsaPrivateKey, RsaPublicKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};

use jose_jwa::{Algorithm, Algorithm::Signing, Signing::*};

use super::Error;
use super::KeyInfo;
use crate::{Rsa, RsaOptional, RsaPrivate};

impl KeyInfo for RsaPublicKey {
    fn strength(&self) -> usize {
        self.size() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        // RFC 7518 Section 3.3
        //
        // I would actually prefer stronger requirements here based on the
        // algorithm below. However, the RFCs actually specify examples that
        // this would break. Note that we generate stronger keys by default.
        if self.strength() < 16 {
            return false;
        }

        #[allow(clippy::match_like_matches_macro)]
        match algo {
            Signing(Rs256) => true,
            Signing(Rs384) => true,
            Signing(Rs512) => true,
            Signing(Ps256) => true,
            Signing(Ps384) => true,
            Signing(Ps512) => true,
            _ => false,
        }
    }
}

impl KeyInfo for RsaPrivateKey {
    fn strength(&self) -> usize {
        self.size() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match (algo, self.strength()) {
            (Signing(Rs256), 16..) => true,
            (Signing(Rs384), 24..) => true,
            (Signing(Rs512), 32..) => true,
            (Signing(Ps256), 16..) => true,
            (Signing(Ps384), 24..) => true,
            (Signing(Ps512), 32..) => true,
            _ => false,
        }
    }
}

impl From<&RsaPublicKey> for Rsa {
    fn from(pk: &RsaPublicKey) -> Self {
        Self {
            n: pk.n().to_be_bytes_trimmed_vartime().into(),
            e: pk.e().to_be_bytes_trimmed_vartime().into(),
            prv: None,
        }
    }
}

impl From<RsaPublicKey> for Rsa {
    fn from(sk: RsaPublicKey) -> Self {
        (&sk).into()
    }
}

impl TryFrom<&Rsa> for RsaPublicKey {
    type Error = Error;

    fn try_from(value: &Rsa) -> Result<Self, Self::Error> {
        let n = BoxedUint::from_be_slice_vartime(&value.n);
        let e = BoxedUint::from_be_slice_vartime(&value.e);
        RsaPublicKey::new(n, e).map_err(|_| Error::Invalid)
    }
}

impl TryFrom<Rsa> for RsaPublicKey {
    type Error = Error;

    fn try_from(value: Rsa) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<&RsaPrivateKey> for Rsa {
    fn from(pk: &RsaPrivateKey) -> Self {
        let opt = Some(RsaOptional {
            p: pk.primes()[0].to_be_bytes().into(),
            q: pk.primes()[1].to_be_bytes().into(),
            dp: pk.dp().expect("unreachable").to_be_bytes().into(),
            dq: pk.dq().expect("unreachable").to_be_bytes().into(),
            qi: pk
                .qinv()
                .expect("unreachable")
                .retrieve()
                .to_be_bytes()
                .into(),
            oth: alloc::vec![],
        });
        Self {
            n: pk.n().to_be_bytes_trimmed_vartime().into(),
            e: pk.e().to_be_bytes_trimmed_vartime().into(),
            prv: Some(RsaPrivate {
                d: pk.d().to_be_bytes().into(),
                opt,
            }),
        }
    }
}

impl From<RsaPrivateKey> for Rsa {
    fn from(sk: RsaPrivateKey) -> Self {
        (&sk).into()
    }
}

impl TryFrom<&Rsa> for RsaPrivateKey {
    type Error = Error;

    fn try_from(value: &Rsa) -> Result<Self, Self::Error> {
        if let Some(prv) = value.prv.as_ref() {
            if let Some(opt) = prv.opt.as_ref() {
                let bits = u32::try_from(value.n.len()).map_err(|_| Error::Invalid)? * 8;
                let n = BoxedUint::from_be_slice_vartime(&value.n);
                let e = BoxedUint::from_be_slice_vartime(&value.e);
                let d = BoxedUint::from_be_slice(&prv.d, bits).map_err(|_| Error::Invalid)?;
                let p = BoxedUint::from_be_slice(&opt.p, bits).map_err(|_| Error::Invalid)?;
                let q = BoxedUint::from_be_slice(&opt.q, bits).map_err(|_| Error::Invalid)?;

                let mut primes = alloc::vec![p, q];
                for p in opt.oth.iter() {
                    primes.push(BoxedUint::from_be_slice(&p.r, bits).map_err(|_| Error::Invalid)?);
                }

                return Self::from_components(n, e, d, primes).map_err(|_| Error::Invalid);
            }

            return Err(Error::Unsupported);
        }

        Err(Error::NotPrivate)
    }
}

impl TryFrom<Rsa> for RsaPrivateKey {
    type Error = Error;

    fn try_from(value: Rsa) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
