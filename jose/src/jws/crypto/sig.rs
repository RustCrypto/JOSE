// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::vec::Vec;

use super::core::{CoreSigner, CoreSigningKey, CoreVerifier, CoreVerifyingKey};
use super::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::alg::{Algorithm, Signing};
use crate::b64::{Encoder, Json, Optional, Update, UrlSafe};
use crate::jws::{Protected, Signature, Unprotected};
use crate::key::KeyInfo;

/// This contains a list of algorithms from (roughly) strongest to weakest.
///
/// A note about our methodology is in order. First, we regard HMAC as the
/// strongest in its "size" category since it does not rely on any
/// asymmetric cryptography. This is followed by RSA given that its
/// large key sizes may better withstand a quantum attack. We prioritize
/// PSS padding over PKCS1v1.5 since it is not deterministic.
///
/// This list is primarily used to choose a signing algorithm in
/// conjunction with a key. The intent in ordering this list according to
/// strength is that the signer can choose the first algorithm applicable
/// to the key type. This list should not be taken as a strong assertion
/// about security.
const BY_STRENGTH: &[Signing] = &[
    Signing::Hs512,
    Signing::Ps512,
    Signing::Rs512,
    Signing::Es512,
    Signing::Hs384,
    Signing::Ps384,
    Signing::Rs384,
    Signing::Es384,
    Signing::Hs256,
    Signing::Ps256,
    Signing::Rs256,
    Signing::Es256,
    Signing::Es256K,
];

impl<'a, T: KeyInfo + CoreSigningKey<'a>> SigningKey<'a> for T
where
    <T::Finish as CoreSigner>::FinishError: Default,
    T::StartError: Default,
{
    type StartError = T::StartError;
    type Signer = State<T::Finish, (Option<Json<Protected>>, Option<Unprotected>)>;

    fn sign(
        &'a self,
        mut prot: Option<Protected>,
        head: Option<Unprotected>,
    ) -> Result<Self::Signer, Self::StartError> {
        let palg = prot.as_ref().and_then(|x| x.oth.alg);
        let halg = head.as_ref().and_then(|x| x.alg);

        let b64 = prot.as_ref().map(|x| x.b64).unwrap_or(true);
        let alg = match (palg, halg) {
            // If both headers contain an algorithm, ensure they are equal.
            (Some(p), Some(h)) if p != h => return Err(Default::default()),
            (Some(p), Some(_)) => p,

            // If only one header contains an algorithm, use it.
            (Some(p), None) => p,
            (None, Some(h)) => h,

            // If neither header contains an algorithm...
            (None, None) => {
                // Detect an algorithm.
                let p = BY_STRENGTH
                    .iter()
                    .cloned()
                    .find(|a| self.is_supported(&Algorithm::Signing(*a)))
                    .ok_or_else(T::StartError::default)?;

                // Add the algorithm.
                prot.get_or_insert_with(Protected::default).oth.alg = Some(p);
                p
            }
        };

        // Serialize the protected header.
        let prot = prot.map(|p| Json::new(p).unwrap());

        // Write out the protected header.
        let mut pre = Encoder::<_, UrlSafe>::from(self.sign(alg)?);
        pre.update(prot.as_ref().map(|x| x.as_ref()).unwrap_or(&[]))?;

        // Write out the separator.
        let mut signer = pre.finish()?;
        signer.update(b".")?;

        Ok(State {
            sink: Optional::new(signer, b64),
            sign: (prot, head),
        })
    }
}

impl<'a, T: KeyInfo + CoreVerifyingKey<'a>> VerifyingKey<'a, &'a Signature> for T
where
    <T::Finish as CoreVerifier>::FinishError: Default,
{
    type StartError = T::StartError;
    type Verifier = State<Vec<T::Finish>, &'a [u8]>;

    fn verify(&'a self, sig: &'a Signature) -> Result<Self::Verifier, Self::StartError> {
        let prot = sig.protected.as_ref();

        // Get the algorithm (possibly unspecified).
        let alg = prot
            .and_then(|x| x.oth.alg)
            .or_else(|| sig.header.as_ref().and_then(|x| x.alg));

        // Get a list of verifiers for each supported key.
        let verifiers: Vec<_> = BY_STRENGTH
            .iter()
            .filter(|a| self.is_supported(&Algorithm::Signing(**a)))
            .filter(|a| alg.unwrap_or(**a) == **a)
            .map(|a| self.verify(*a))
            .collect::<Result<_, _>>()?;

        // Write out the protected header.
        let mut pre = Encoder::<_, UrlSafe>::from(verifiers);
        pre.update(prot.map(|x| x.as_ref()).unwrap_or(&[]))?;

        // Write out the separator.
        let mut verifiers = pre.finish()?;
        verifiers.update(b".")?;

        Ok(State {
            sink: Optional::new(verifiers, prot.map(|x| x.b64).unwrap_or(true)),
            sign: &**sig.signature,
        })
    }
}

/// Signature verification state
pub struct State<T, U> {
    sink: Optional<T>,
    sign: U,
}

impl<T: Update, U> Update for State<T, U> {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.sink.update(chunk)
    }
}

impl<T: CoreSigner> Signer for State<T, (Option<Json<Protected>>, Option<Unprotected>)>
where
    T::FinishError: Default,
{
    type FinishError = T::FinishError;

    fn finish(self) -> Result<Signature, Self::FinishError> {
        Ok(Signature {
            protected: self.sign.0,
            header: self.sign.1,
            signature: self.sink.finish()?.finish()?.into(),
        })
    }
}

impl<'a, T: CoreVerifier> Verifier<'a> for State<Vec<T>, &'a [u8]>
where
    T::FinishError: Default,
{
    type FinishError = T::FinishError;

    fn finish(self) -> Result<(), Self::FinishError> {
        let mut last = T::FinishError::default();

        for x in self.sink.finish()? {
            match x.finish(self.sign) {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
        }

        Err(last)
    }
}
