// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod sig;
mod ver;

use core::convert::Infallible;

use digest::Update as _;

use crate::{b64::Update, key::rcrypto::Type};

pub(super) enum Inner<'a, T: Type> {
    #[cfg(feature = "hmac")]
    Hs256(hmac::Hmac<sha2::Sha256>, core::marker::PhantomData<&'a T>),

    #[cfg(feature = "hmac")]
    Hs384(hmac::Hmac<sha2::Sha384>, core::marker::PhantomData<&'a T>),

    #[cfg(feature = "hmac")]
    Hs512(hmac::Hmac<sha2::Sha512>, core::marker::PhantomData<&'a T>),

    #[cfg(feature = "p256")]
    Es256(sha2::Sha256, &'a T::P256),

    #[cfg(feature = "p384")]
    Es384(sha2::Sha384, &'a T::P384),

    #[cfg(feature = "rsa")]
    Rs256(sha2::Sha256, &'a T::Rsa),

    #[cfg(feature = "rsa")]
    Rs384(sha2::Sha384, &'a T::Rsa),

    #[cfg(feature = "rsa")]
    Rs512(sha2::Sha512, &'a T::Rsa),

    #[cfg(all(feature = "rsa", feature = "rand"))]
    Ps256(sha2::Sha256, &'a T::Rsa),

    #[cfg(all(feature = "rsa", feature = "rand"))]
    Ps384(sha2::Sha384, &'a T::Rsa),

    #[cfg(all(feature = "rsa", feature = "rand"))]
    Ps512(sha2::Sha512, &'a T::Rsa),
}

/// Signing and Verification State
pub struct State<'a, T: Type>(Inner<'a, T>);

impl<'a, T: Type> From<Inner<'a, T>> for State<'a, T> {
    fn from(value: Inner<'a, T>) -> Self {
        Self(value)
    }
}

impl<'a, T: Type> Update for State<'a, T> {
    type Error = Infallible;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        match &mut self.0 {
            #[cfg(feature = "hmac")]
            Inner::Hs256(s, ..) => s.update(chunk.as_ref()),
            #[cfg(feature = "hmac")]
            Inner::Hs384(s, ..) => s.update(chunk.as_ref()),
            #[cfg(feature = "hmac")]
            Inner::Hs512(s, ..) => s.update(chunk.as_ref()),

            #[cfg(feature = "p256")]
            Inner::Es256(s, ..) => s.update(chunk.as_ref()),
            #[cfg(feature = "p384")]
            Inner::Es384(s, ..) => s.update(chunk.as_ref()),

            #[cfg(feature = "rsa")]
            Inner::Rs256(s, ..) => s.update(chunk.as_ref()),
            #[cfg(feature = "rsa")]
            Inner::Rs384(s, ..) => s.update(chunk.as_ref()),
            #[cfg(feature = "rsa")]
            Inner::Rs512(s, ..) => s.update(chunk.as_ref()),

            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps256(s, ..) => s.update(chunk.as_ref()),
            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps384(s, ..) => s.update(chunk.as_ref()),
            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps512(s, ..) => s.update(chunk.as_ref()),
        }

        Ok(())
    }
}
