// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "rsa")]
use rsa::{Hash, PaddingScheme, PublicKey, RsaPublicKey};

use super::super::super::core::CoreVerifier;
use super::super::Verifying;
use super::{Inner, State};
use crate::key::rcrypto::Error;

#[cfg(feature = "rsa")]
fn rs(k: &RsaPublicKey, h: Hash, d: impl digest::Digest, s: &[u8]) -> Result<(), Error> {
    let p = PaddingScheme::PKCS1v15Sign { hash: Some(h) };
    k.verify(p, &d.finalize(), s).map_err(|_| Error::Invalid)
}

#[cfg(all(feature = "rsa", feature = "rand"))]
fn ps<D: 'static + Default + digest::Digest + digest::DynDigest + digest::OutputSizeUser>(
    k: &RsaPublicKey,
    d: D,
    s: &[u8],
) -> Result<(), Error> {
    let p = PaddingScheme::PSS {
        salt_rng: alloc::boxed::Box::new(rand::thread_rng()),
        digest: alloc::boxed::Box::new(D::default()),
        salt_len: Some(d.output_size()),
    };

    k.verify(p, &d.finalize(), s).map_err(|_| Error::Invalid)
}

impl<'a> CoreVerifier for State<'a, Verifying> {
    type FinishError = Error;

    fn finish(self, signature: &[u8]) -> Result<(), Self::FinishError> {
        #[cfg(feature = "hmac")]
        use hmac::Mac;

        match self.0 {
            #[cfg(feature = "hmac")]
            Inner::Hs256(s, ..) => s.verify_slice(signature).map_err(|_| Error::Invalid),
            #[cfg(feature = "hmac")]
            Inner::Hs384(s, ..) => s.verify_slice(signature).map_err(|_| Error::Invalid),
            #[cfg(feature = "hmac")]
            Inner::Hs512(s, ..) => s.verify_slice(signature).map_err(|_| Error::Invalid),

            #[cfg(feature = "rsa")]
            Inner::Rs256(d, k) => rs(k, Hash::SHA2_256, d, signature),
            #[cfg(feature = "rsa")]
            Inner::Rs384(d, k) => rs(k, Hash::SHA2_384, d, signature),
            #[cfg(feature = "rsa")]
            Inner::Rs512(d, k) => rs(k, Hash::SHA2_512, d, signature),

            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps256(d, k) => ps(k, d, signature),
            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps384(d, k) => ps(k, d, signature),
            #[cfg(all(feature = "rsa", feature = "rand"))]
            Inner::Ps512(d, k) => ps(k, d, signature),

            #[cfg(feature = "p256")]
            Inner::Es256(d, k) => {
                use p256::ecdsa::signature::DigestVerifier;

                let mut r = p256::FieldBytes::default();
                let mut s = p256::FieldBytes::default();
                if signature.len() == r.len() + s.len() {
                    r.copy_from_slice(&signature[..s.len()]);
                    s.copy_from_slice(&signature[r.len()..]);

                    if let Ok(sig) = p256::ecdsa::Signature::from_scalars(r, s) {
                        if let Ok(()) = k.verify_digest(d, &sig) {
                            return Ok(());
                        }
                    }
                }

                Err(Error::Invalid)
            }

            #[cfg(feature = "p384")]
            Inner::Es384(d, k) => {
                use p384::ecdsa::signature::DigestVerifier;

                let mut r = p384::FieldBytes::default();
                let mut s = p384::FieldBytes::default();
                if signature.len() == r.len() + s.len() {
                    r.copy_from_slice(&signature[..s.len()]);
                    s.copy_from_slice(&signature[r.len()..]);

                    if let Ok(sig) = p384::ecdsa::Signature::from_scalars(r, s) {
                        if let Ok(()) = k.verify_digest(d, &sig) {
                            return Ok(());
                        }
                    }
                }

                Err(Error::Invalid)
            }
        }
    }
}
