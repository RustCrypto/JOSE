// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;

use crate::{alg::Signing, b64::Update};

pub trait CoreSigner: Update {
    type FinishError: From<Self::Error>;

    fn finish(self) -> Result<Vec<u8>, Self::FinishError>;
}

pub trait CoreSigningKey<'a> {
    type StartError: From<<Self::Finish as Update>::Error>;
    type Finish: CoreSigner;

    fn sign(&'a self, alg: Signing) -> Result<Self::Finish, Self::StartError>;
}

pub trait CoreVerifier: Update {
    type FinishError: From<Self::Error>;

    fn finish(self, signature: &[u8]) -> Result<(), Self::FinishError>;
}

pub trait CoreVerifyingKey<'a> {
    type StartError: From<<Self::Finish as Update>::Error>;
    type Finish: CoreVerifier;

    fn verify(&'a self, alg: Signing) -> Result<Self::Finish, Self::StartError>;
}
