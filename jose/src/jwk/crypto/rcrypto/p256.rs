// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "p256")]

use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, FieldBytes, PublicKey, SecretKey};

#[cfg(feature = "jws")]
use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::jwk::{Ec, EcCurves};
use crate::key::rcrypto::Error;

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl From<&PublicKey> for Ec {
    fn from(pk: &PublicKey) -> Self {
        let ep = pk.to_encoded_point(false);

        Self {
            crv: EcCurves::P256,
            x: ep.x().unwrap().to_vec().into(),
            y: ep.y().unwrap().to_vec().into(),
            d: None,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl From<PublicKey> for Ec {
    fn from(sk: PublicKey) -> Self {
        (&sk).into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<&Ec> for PublicKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256 {
            return Err(Error::AlgMismatch);
        }

        let mut x = FieldBytes::default();
        if value.x.len() != x.len() {
            return Err(Error::Invalid);
        }

        let mut y = FieldBytes::default();
        if value.y.len() != y.len() {
            return Err(Error::Invalid);
        }

        x.copy_from_slice(&value.x);
        y.copy_from_slice(&value.y);

        let ep = EncodedPoint::from_affine_coordinates(&x, &y, false);
        Option::from(Self::from_encoded_point(&ep)).ok_or(Error::Invalid)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<Ec> for PublicKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl From<&SecretKey> for Ec {
    fn from(sk: &SecretKey) -> Self {
        let mut key: Self = sk.public_key().into();
        key.d = Some(sk.to_be_bytes().to_vec().into());
        key
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl From<SecretKey> for Ec {
    fn from(sk: SecretKey) -> Self {
        (&sk).into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<&Ec> for SecretKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256 {
            return Err(Error::AlgMismatch);
        }

        if let Some(d) = value.d.as_ref() {
            return Self::from_be_bytes(d).map_err(|_| Error::Invalid);
        }

        Err(Error::NotPrivate)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<Ec> for SecretKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

#[cfg(feature = "jws")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "jws", feature = "p256"))))]
impl TryFrom<&Ec> for VerifyingKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        Ok(PublicKey::try_from(value)?.into())
    }
}

#[cfg(feature = "jws")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "jws", feature = "p256"))))]
impl TryFrom<Ec> for VerifyingKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        Ok(PublicKey::try_from(value)?.into())
    }
}

#[cfg(feature = "jws")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "jws", feature = "p256"))))]
impl TryFrom<&Ec> for SigningKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        Ok(SecretKey::try_from(value)?.into())
    }
}

#[cfg(feature = "jws")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "jws", feature = "p256"))))]
impl TryFrom<Ec> for SigningKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        Ok(SecretKey::try_from(value)?.into())
    }
}
