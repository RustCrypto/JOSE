// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "jwk")]
#![cfg(any(feature = "p256", feature = "p384", feature = "hmac", feature = "rsa"))]

mod rcrypto {
    use jose::alg::Signing::*;
    use jose::jwk::crypto::Generator;
    use jose::jwk::*;

    #[test]
    #[cfg(feature = "p256")]
    fn es256() {
        use EcCurves::P256;
        let jwk: Jwk = rand::thread_rng().generate(Es256).unwrap();
        assert_eq!(jwk.prm, Es256.into());
        assert!(matches!(jwk.key, Key::Ec(Ec { crv: P256, .. })));
    }

    #[test]
    #[cfg(feature = "p384")]
    fn es384() {
        use EcCurves::P384;
        let jwk: Jwk = rand::thread_rng().generate(Es384).unwrap();
        assert_eq!(jwk.prm, Es384.into());
        assert!(matches!(jwk.key, Key::Ec(Ec { crv: P384, .. })));
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn hs256() {
        let jwk: Jwk = rand::thread_rng().generate(Hs256).unwrap();
        assert_eq!(jwk.prm, Hs256.into());
        match jwk.key {
            Key::Oct(Oct { k }) => assert_eq!(k.len(), 16),
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn hs384() {
        let jwk: Jwk = rand::thread_rng().generate(Hs384).unwrap();
        assert_eq!(jwk.prm, Hs384.into());
        match jwk.key {
            Key::Oct(Oct { k }) => assert_eq!(k.len(), 24),
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn hs512() {
        let jwk: Jwk = rand::thread_rng().generate(Hs512).unwrap();
        assert_eq!(jwk.prm, Hs512.into());
        match jwk.key {
            Key::Oct(Oct { k }) => assert_eq!(k.len(), 32),
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn rs256() {
        let jwk: Jwk = rand::thread_rng().generate(Rs256).unwrap();
        assert_eq!(jwk.prm, Rs256.into());
        match jwk.key {
            Key::Rsa(Rsa { n, e, prv }) => {
                assert!(n.len() > 256 - 8);
                assert_eq!(e.as_ref(), &[1, 0, 1]);
                match prv {
                    Some(RsaPrivate { d, opt: None, .. }) => assert!(d.len() > 256 - 8),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn rs384() {
        let jwk: Jwk = rand::thread_rng().generate(Rs384).unwrap();
        assert_eq!(jwk.prm, Rs384.into());
        match jwk.key {
            Key::Rsa(Rsa { n, e, prv }) => {
                assert!(n.len() > 384 - 8);
                assert_eq!(e.as_ref(), &[1, 0, 1]);
                match prv {
                    Some(RsaPrivate { d, opt: None, .. }) => assert!(d.len() > 384 - 8),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn rs512() {
        let jwk: Jwk = rand::thread_rng().generate(Rs512).unwrap();
        assert_eq!(jwk.prm, Rs512.into());
        match jwk.key {
            Key::Rsa(Rsa { n, e, prv }) => {
                assert!(n.len() > 512 - 8);
                assert_eq!(e.as_ref(), &[1, 0, 1]);
                match prv {
                    Some(RsaPrivate { d, opt: None, .. }) => assert!(d.len() > 512 - 8),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn ps256() {
        let jwk: Jwk = rand::thread_rng().generate(Ps256).unwrap();
        assert_eq!(jwk.prm, Ps256.into());
        match jwk.key {
            Key::Rsa(Rsa { n, e, prv }) => {
                assert!(n.len() > 256 - 8);
                assert_eq!(e.as_ref(), &[1, 0, 1]);
                match prv {
                    Some(RsaPrivate { d, opt: None, .. }) => assert!(d.len() > 256 - 8),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn ps384() {
        let jwk: Jwk = rand::thread_rng().generate(Ps384).unwrap();
        assert_eq!(jwk.prm, Ps384.into());
        match jwk.key {
            Key::Rsa(Rsa { n, e, prv }) => {
                assert!(n.len() > 384 - 8);
                assert_eq!(e.as_ref(), &[1, 0, 1]);
                match prv {
                    Some(RsaPrivate { d, opt: None, .. }) => assert!(d.len() > 384 - 8),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn ps512() {
        let jwk: Jwk = rand::thread_rng().generate(Ps512).unwrap();
        assert_eq!(jwk.prm, Ps512.into());
        match jwk.key {
            Key::Rsa(Rsa { n, e, prv }) => {
                assert!(n.len() > 512 - 8);
                assert_eq!(e.as_ref(), &[1, 0, 1]);
                match prv {
                    Some(RsaPrivate { d, opt: None, .. }) => assert!(d.len() > 512 - 8),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }
}
