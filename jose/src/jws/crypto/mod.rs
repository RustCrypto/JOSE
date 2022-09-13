// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

//! JWS Cryptographic Implementation

pub mod rcrypto;

mod core;
mod sig;

pub use sig::State;

use alloc::{vec, vec::Vec};

use crate::b64::Update;
use crate::jws::{Protected, Signature, Unprotected};

use super::{Flattened, General, Jws};

/// Signature creation state
pub trait Signer: Update {
    #[allow(missing_docs)]
    type FinishError: From<Self::Error>;

    /// Finish processing payload and create the signature.
    fn finish(self) -> Result<Signature, Self::FinishError>;
}

/// A signature creation key
pub trait SigningKey<'a> {
    #[allow(missing_docs)]
    type StartError: From<<Self::Signer as Update>::Error>;

    /// The state object used during signing.
    type Signer: Signer;

    /// Begin the signature creation process.
    fn sign(
        &'a self,
        prot: Option<Protected>,
        head: Option<Unprotected>,
    ) -> Result<Self::Signer, Self::StartError>;
}

/// Signature verification state
pub trait Verifier<'a>: Update {
    #[allow(missing_docs)]
    type FinishError: From<Self::Error>;

    /// Finish processing payload and verify the signature.
    fn finish(self) -> Result<(), Self::FinishError>;
}

impl<'a, T: Verifier<'a>> Verifier<'a> for Vec<T>
where
    T::FinishError: Default,
{
    type FinishError = T::FinishError;

    fn finish(self) -> Result<(), Self::FinishError> {
        let mut last = T::FinishError::default();

        for x in self {
            match x.finish() {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
        }

        Err(last)
    }
}

/// A signature verification key
pub trait VerifyingKey<'a, T> {
    #[allow(missing_docs)]
    type StartError: From<<Self::Verifier as Update>::Error>;

    /// The state object used during signing.
    type Verifier: Verifier<'a>;

    /// Begin the signature verification process.
    fn verify(&'a self, val: T) -> Result<Self::Verifier, Self::StartError>;
}

impl<'a, A, T, V> VerifyingKey<'a, A> for [T]
where
    T: VerifyingKey<'a, A, Verifier = Vec<V>>,
    V::FinishError: Default,
    V: Verifier<'a>,
    V: Update,
    A: Copy,
{
    type StartError = T::StartError;
    type Verifier = Vec<V>;

    fn verify(&'a self, val: A) -> Result<Self::Verifier, Self::StartError> {
        let mut all = Vec::new();

        for key in self {
            all.extend(key.verify(val)?);
        }

        Ok(all)
    }
}

impl<'a, T: VerifyingKey<'a, &'a Signature>> VerifyingKey<'a, &'a Flattened> for T
where
    <T::Verifier as Verifier<'a>>::FinishError: Default,
{
    type StartError = T::StartError;
    type Verifier = Vec<T::Verifier>;

    fn verify(&'a self, flattened: &'a Flattened) -> Result<Self::Verifier, Self::StartError> {
        Ok(vec![self.verify(&flattened.signature)?])
    }
}

impl<'a, T: VerifyingKey<'a, &'a Signature>> VerifyingKey<'a, &'a General> for T
where
    <T::Verifier as Verifier<'a>>::FinishError: Default,
{
    type StartError = T::StartError;
    type Verifier = Vec<T::Verifier>;

    fn verify(&'a self, general: &'a General) -> Result<Self::Verifier, Self::StartError> {
        general
            .signatures
            .iter()
            .map(|sig| self.verify(sig))
            .collect()
    }
}

impl<'a, T, V, E> VerifyingKey<'a, &'a Jws> for T
where
    T: VerifyingKey<'a, &'a Flattened, Verifier = V, StartError = E>,
    T: VerifyingKey<'a, &'a General, Verifier = V, StartError = E>,
    E: From<V::Error>,
    V: Verifier<'a>,
{
    type StartError = E;
    type Verifier = V;

    fn verify(&'a self, jws: &'a Jws) -> Result<Self::Verifier, Self::StartError> {
        match jws {
            Jws::General(general) => self.verify(general),
            Jws::Flattened(flattened) => self.verify(flattened),
        }
    }
}
