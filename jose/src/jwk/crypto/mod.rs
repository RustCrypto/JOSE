// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! JWK Cryptographic Implementation

mod rcrypto;

/// A key generator
pub trait Generator<A, T> {
    /// A key generation error
    type Error;

    /// Generates a key.
    fn generate(&mut self, arg: A) -> Result<T, Self::Error>;
}
