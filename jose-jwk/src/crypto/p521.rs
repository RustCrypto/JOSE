// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "p521")]

use p521::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p521::{EncodedPoint, FieldBytes, PublicKey, SecretKey};

use jose_jwa::{Algorithm, Algorithm::Signing, Signing::*};

use super::Error;
use super::KeyInfo;
use crate::{Ec, EcCurves};

impl KeyInfo for PublicKey {
    fn strength(&self) -> usize {
        32
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es512))
    }
}

impl KeyInfo for SecretKey {
    fn strength(&self) -> usize {
        32
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(Es512))
    }
}

impl From<&PublicKey> for Ec {
    fn from(pk: &PublicKey) -> Self {
        let ep = pk.to_encoded_point(false);

        Self {
            crv: EcCurves::P521,
            x: ep.x().expect("unreachable").to_vec().into(),
            y: ep.y().expect("unreachable").to_vec().into(),
            d: None,
        }
    }
}

impl From<PublicKey> for Ec {
    fn from(sk: PublicKey) -> Self {
        (&sk).into()
    }
}

impl TryFrom<&Ec> for PublicKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P521 {
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

impl TryFrom<Ec> for PublicKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<&SecretKey> for Ec {
    fn from(sk: &SecretKey) -> Self {
        let mut key: Self = sk.public_key().into();
        key.d = Some(sk.to_bytes().to_vec().into());
        key
    }
}

impl From<SecretKey> for Ec {
    fn from(sk: SecretKey) -> Self {
        (&sk).into()
    }
}

impl TryFrom<&Ec> for SecretKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P521 {
            return Err(Error::AlgMismatch);
        }

        if let Some(d) = value.d.as_ref() {
            return Self::from_slice(d).map_err(|_| Error::Invalid);
        }

        Err(Error::NotPrivate)
    }
}

impl TryFrom<Ec> for SecretKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
