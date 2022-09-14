// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::ops::Deref;

use alloc::{boxed::Box, vec::Vec};
use jose_jwa::{Algorithm, Algorithm::Signing, Signing::*};

use crate::{Ec, EcCurves, Jwk, Key, Oct, Okp, OkpCurves, Rsa};

/// Information about a cryptographic key.
pub trait KeyInfo {
    /// Returns the strength of the key
    ///
    /// The units here is the number of bytes of a symmetric key. For
    /// example, a P-256 elliptic curve key has an approximate strength of
    /// `16` since it is comparable to a 16-byte symmetric key.
    fn strength(&self) -> usize;

    /// Tests if the provide algorithm is supported.
    fn is_supported(&self, algo: &Algorithm) -> bool;
}

impl<T: KeyInfo + ?Sized> KeyInfo for &T {
    fn strength(&self) -> usize {
        (**self).strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        (**self).is_supported(algo)
    }
}

impl<T: KeyInfo + ?Sized> KeyInfo for &mut T {
    fn strength(&self) -> usize {
        (**self).strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        (**self).is_supported(algo)
    }
}

impl<T: KeyInfo + ?Sized> KeyInfo for Box<T> {
    fn strength(&self) -> usize {
        self.deref().strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.deref().is_supported(algo)
    }
}

impl KeyInfo for Vec<u8> {
    fn strength(&self) -> usize {
        self.deref().strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.deref().is_supported(algo)
    }
}

impl KeyInfo for [u8] {
    fn strength(&self) -> usize {
        self.len()
    }

    #[allow(clippy::match_like_matches_macro)]
    fn is_supported(&self, algo: &Algorithm) -> bool {
        match (algo, self.strength()) {
            (Signing(Hs256), 16..) => true,
            (Signing(Hs384), 24..) => true,
            (Signing(Hs512), 32..) => true,
            _ => false,
        }
    }
}

impl KeyInfo for Jwk {
    fn strength(&self) -> usize {
        self.key.strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.key.is_supported(algo) && algo == self.prm.alg.as_ref().unwrap_or(algo)
    }
}

impl KeyInfo for Key {
    fn strength(&self) -> usize {
        match self {
            Key::Ec(x) => x.strength(),
            Key::Rsa(x) => x.strength(),
            Key::Oct(x) => x.strength(),
            Key::Okp(x) => x.strength(),
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        match self {
            Key::Ec(x) => x.is_supported(algo),
            Key::Rsa(x) => x.is_supported(algo),
            Key::Oct(x) => x.is_supported(algo),
            Key::Okp(x) => x.is_supported(algo),
        }
    }
}

impl KeyInfo for Ec {
    fn strength(&self) -> usize {
        match self.crv {
            EcCurves::P256 => 16,
            EcCurves::P256K => 16,
            EcCurves::P384 => 24,
            EcCurves::P521 => 32,
        }
    }

    #[allow(clippy::match_like_matches_macro)]
    fn is_supported(&self, algo: &Algorithm) -> bool {
        match (self.crv, algo) {
            (EcCurves::P256, Signing(Es256)) => true,
            (EcCurves::P256K, Signing(Es256K)) => true,
            (EcCurves::P384, Signing(Es384)) => true,
            (EcCurves::P521, Signing(Es512)) => true,
            _ => false,
        }
    }
}

impl KeyInfo for Oct {
    fn strength(&self) -> usize {
        self.k.len()
    }

    #[allow(clippy::match_like_matches_macro)]
    fn is_supported(&self, algo: &Algorithm) -> bool {
        match (algo, self.strength()) {
            (Signing(Hs256), 16..) => true,
            (Signing(Hs384), 24..) => true,
            (Signing(Hs512), 32..) => true,
            _ => false,
        }
    }
}

impl KeyInfo for Okp {
    fn strength(&self) -> usize {
        match self.crv {
            OkpCurves::Ed25519 => 16,
            OkpCurves::Ed448 => 24,
            OkpCurves::X25519 => 16,
            OkpCurves::X448 => 24,
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(algo, Signing(EdDsa))
    }
}

impl KeyInfo for Rsa {
    fn strength(&self) -> usize {
        self.n.len() / 16
    }

    #[allow(clippy::match_like_matches_macro)]
    fn is_supported(&self, algo: &Algorithm) -> bool {
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
