// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::alg::Algorithm;

use super::super::KeyInfo;

pub trait Type {
    type Oct: KeyInfo;

    #[cfg(feature = "p256")]
    type P256: KeyInfo;

    #[cfg(feature = "p384")]
    type P384: KeyInfo;

    #[cfg(feature = "rsa")]
    type Rsa: KeyInfo;
}

pub enum Kind<T: Type> {
    Oct(T::Oct),

    #[cfg(feature = "p256")]
    P256(T::P256),

    #[cfg(feature = "p384")]
    P384(T::P384),

    #[cfg(feature = "rsa")]
    Rsa(T::Rsa),
}

/// An abstract key type.
pub struct Key<T: Type> {
    pub(crate) kind: Kind<T>,
    pub(crate) algo: Option<Algorithm>,
}

impl<T: Type> KeyInfo for Key<T> {
    fn strength(&self) -> usize {
        match &self.kind {
            Kind::Oct(x) => x.strength(),

            #[cfg(feature = "p256")]
            Kind::P256(x) => x.strength(),

            #[cfg(feature = "p384")]
            Kind::P384(x) => x.strength(),

            #[cfg(feature = "rsa")]
            Kind::Rsa(x) => x.strength(),
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        if self.algo.as_ref().unwrap_or(algo) != algo {
            return false;
        }

        match &self.kind {
            #[cfg(feature = "p256")]
            Kind::P256(k) => k.is_supported(algo),

            #[cfg(feature = "p384")]
            Kind::P384(k) => k.is_supported(algo),

            #[cfg(feature = "hmac")]
            Kind::Oct(k) => k.is_supported(algo),

            #[cfg(feature = "rsa")]
            Kind::Rsa(k) => k.is_supported(algo),
        }
    }
}
