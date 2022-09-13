// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic Key Types

pub mod rcrypto;

use alloc::boxed::Box;
use core::ops::Deref;

use zeroize::{Zeroize, Zeroizing};

use crate::alg::{Algorithm, Algorithm::Signing, Signing::*};

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

impl<T: KeyInfo + ?Sized> KeyInfo for Box<T> {
    fn strength(&self) -> usize {
        self.deref().strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.deref().is_supported(algo)
    }
}

impl<T: KeyInfo + Zeroize> KeyInfo for Zeroizing<T> {
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
