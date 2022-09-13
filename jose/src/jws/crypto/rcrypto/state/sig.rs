// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;

#[cfg(feature = "rsa")]
use rsa::{Hash, PaddingScheme, RsaPrivateKey};

use super::super::super::core::CoreSigner;
use super::super::Signing;
use super::{Inner, State};
use crate::key::rcrypto::Error;

#[cfg(feature = "rsa")]
fn rs(k: &RsaPrivateKey, h: Hash, d: impl digest::Digest) -> Result<Vec<u8>, Error> {
    let p = PaddingScheme::PKCS1v15Sign { hash: Some(h) };

    k.sign(p, &d.finalize()).map_err(|_| Error::Invalid)
}

#[cfg(all(feature = "rsa", feature = "rand"))]
fn ps<D: 'static + Default + digest::Digest + digest::DynDigest + digest::OutputSizeUser>(
    k: &RsaPrivateKey,
    d: D,
) -> Result<Vec<u8>, Error> {
    let p = PaddingScheme::PSS {
        salt_rng: alloc::boxed::Box::new(rand::thread_rng()),
        digest: alloc::boxed::Box::new(D::default()),
        salt_len: Some(d.output_size()),
    };

    k.sign(p, &d.finalize()).map_err(|_| Error::Invalid)
}

impl<'a> CoreSigner for State<'a, Signing> {
    type FinishError = Error;

    fn finish(self) -> Result<Vec<u8>, Self::FinishError> {
        #[cfg(feature = "hmac")]
        use hmac::Mac;

        Ok(match self.0 {
            #[cfg(feature = "hmac")]
            Inner::Hs256(s, ..) => s.finalize().into_bytes().to_vec(),
            #[cfg(feature = "hmac")]
            Inner::Hs384(s, ..) => s.finalize().into_bytes().to_vec(),
            #[cfg(feature = "hmac")]
            Inner::Hs512(s, ..) => s.finalize().into_bytes().to_vec(),

            #[cfg(feature = "rsa")]
            Inner::Rs256(d, k) => rs(k, Hash::SHA2_256, d)?,
            #[cfg(feature = "rsa")]
            Inner::Rs384(d, k) => rs(k, Hash::SHA2_384, d)?,
            #[cfg(feature = "rsa")]
            Inner::Rs512(d, k) => rs(k, Hash::SHA2_512, d)?,

            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps256(d, k) => ps(k, d)?,
            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps384(d, k) => ps(k, d)?,
            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps512(d, k) => ps(k, d)?,

            #[cfg(feature = "p256")]
            Inner::Es256(d, k) => {
                use p256::ecdsa::signature::DigestSigner;
                let (r, s) = k.sign_digest(d).split_bytes();
                let mut sig = Vec::with_capacity(r.len() + s.len());
                sig.extend_from_slice(&r);
                sig.extend_from_slice(&s);
                sig
            }

            #[cfg(feature = "p384")]
            Inner::Es384(d, k) => {
                use p384::ecdsa::signature::DigestSigner;
                let (r, s) = k.sign_digest(d).split_bytes();
                let mut sig = Vec::with_capacity(r.len() + s.len());
                sig.extend_from_slice(&r);
                sig.extend_from_slice(&s);
                sig
            }
        })
    }
}
