// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK Thumbprint tests including RFC 7638 examples.

#![cfg(feature = "thumbprint")]
#![allow(clippy::indexing_slicing)] // usage is always valid

use std::collections::HashSet;

use jose_jwk::*;
use sha2::{Sha256, Sha384, Sha512};

/// Test the RSA key example from RFC 7638 Section 3.1.
#[test]
fn test_rfc7638_rsa_example() {
    // This is the RSA key from RFC 7638 Section 3.1
    let rsa_key = Rsa {
        e: vec![1, 0, 1].into(), // "AQAB" in base64url
        n: vec![
            210, 252, 123, 106, 10, 30, 108, 103, 16, 74, 235, 143, 136, 178, 87, 102, 155, 77,
            246, 121, 221, 173, 9, 155, 92, 74, 108, 217, 168, 128, 21, 181, 161, 51, 191, 11, 133,
            108, 120, 113, 182, 223, 0, 11, 85, 79, 206, 179, 194, 237, 81, 43, 182, 143, 20, 92,
            110, 132, 52, 117, 47, 171, 82, 161, 207, 193, 36, 64, 143, 121, 181, 138, 69, 120,
            193, 100, 40, 133, 87, 137, 247, 162, 73, 227, 132, 203, 45, 159, 174, 45, 103, 253,
            150, 251, 146, 108, 25, 142, 7, 115, 153, 253, 200, 21, 192, 175, 9, 125, 222, 90, 173,
            239, 244, 77, 231, 14, 130, 127, 72, 120, 67, 36, 57, 191, 238, 185, 96, 104, 208, 71,
            79, 197, 13, 109, 144, 191, 58, 152, 223, 175, 16, 64, 200, 156, 2, 214, 146, 171, 59,
            60, 40, 150, 96, 157, 134, 253, 115, 183, 116, 206, 7, 64, 100, 124, 238, 234, 163, 16,
            189, 18, 249, 133, 168, 235, 159, 89, 253, 212, 38, 206, 165, 178, 18, 15, 79, 42, 52,
            188, 171, 118, 75, 126, 108, 84, 214, 132, 2, 56, 188, 196, 5, 135, 165, 158, 102, 237,
            31, 51, 137, 69, 119, 99, 92, 71, 10, 247, 92, 249, 44, 32, 209, 218, 67, 225, 191,
            196, 25, 226, 34, 166, 240, 208, 187, 53, 140, 94, 56, 249, 203, 5, 10, 234, 254, 144,
            72, 20, 241, 172, 26, 164, 156, 202, 158, 160, 202, 131,
        ]
        .into(),
        prv: None,
    };

    let jwk = Jwk {
        key: Key::Rsa(rsa_key),
        prm: Parameters::default(),
    };

    let thumbprint = jwk.thumbprint();

    // Expected result from RFC 7638 Section 3.1
    assert_eq!(thumbprint, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
}

/// Test EC P-256 key thumbprint using RFC 7517 Appendix A.1 example.
/// Reference: https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1
#[test]
fn test_ec_p256_thumbprint() {
    // Key values from RFC 7517 A.1:
    // x: MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4
    // y: 4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM
    // crv: P-256
    let ec_key = Ec {
        crv: EcCurves::P256,
        x: vec![
            48, 160, 66, 76, 210, 28, 41, 68, 131, 138, 45, 117, 201, 43, 55, 231, 110, 162, 13,
            159, 0, 137, 58, 59, 78, 238, 138, 60, 10, 175, 236, 62,
        ]
        .into(),
        y: vec![
            224, 75, 101, 233, 36, 86, 217, 136, 139, 82, 179, 121, 189, 251, 213, 30, 232, 105,
            239, 31, 15, 198, 91, 102, 89, 105, 91, 108, 206, 8, 23, 35,
        ]
        .into(),
        d: None,
    };

    let jwk = Jwk {
        key: Key::Ec(ec_key),
        prm: Parameters::default(),
    };

    let thumbprint = jwk.thumbprint();

    // Computed from SHA-256 of:
    // {"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
    assert_eq!(thumbprint, "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s");
}

/// Test OKP Ed25519 key thumbprint using RFC 8037 Appendix A.2 example.
/// Reference: https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.2
#[test]
fn test_okp_ed25519_thumbprint() {
    // Key values from RFC 8037 A.2:
    // x: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo
    // crv: Ed25519
    let okp_key = Okp {
        crv: OkpCurves::Ed25519,
        x: vec![
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ]
        .into(),
        d: None,
    };

    let jwk = Jwk {
        key: Key::Okp(okp_key),
        prm: Parameters::default(),
    };

    let thumbprint = jwk.thumbprint();

    // Computed from SHA-256 of:
    // {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    assert_eq!(thumbprint, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
}

/// Test Oct (symmetric) key thumbprint.
#[test]
fn test_oct_thumbprint() {
    // k = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    // Base64url: AQIDBAUGBwgJCgsMDQ4PEA
    let oct_key = Oct {
        k: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].into(),
    };

    let jwk = Jwk {
        key: Key::Oct(oct_key),
        prm: Parameters::default(),
    };

    let thumbprint = jwk.thumbprint();

    // Computed from SHA-256 of: {"k":"AQIDBAUGBwgJCgsMDQ4PEA","kty":"oct"}
    assert_eq!(thumbprint, "enhFVP7_AlQw84MU6KWN9VKO0JkRsxKFtrIwGhIJhzo");
}

/// Test that private and public key representations produce the same thumbprint.
#[test]
fn test_private_public_key_same_thumbprint() {
    // EC test
    let ec_public = Ec {
        crv: EcCurves::P256,
        x: vec![1; 32].into(),
        y: vec![2; 32].into(),
        d: None,
    };
    let ec_private = Ec {
        crv: ec_public.crv,
        x: ec_public.x.clone(),
        y: ec_public.y.clone(),
        d: Some(vec![100; 32].into()),
    };
    assert_eq!(ec_public.thumbprint(), ec_private.thumbprint());

    // OKP test
    let okp_public = Okp {
        crv: OkpCurves::Ed25519,
        x: vec![1; 32].into(),
        d: None,
    };
    let okp_private = Okp {
        crv: okp_public.crv,
        x: okp_public.x.clone(),
        d: Some(vec![100; 32].into()),
    };
    assert_eq!(okp_public.thumbprint(), okp_private.thumbprint());

    // RSA test
    let rsa_public = Rsa {
        e: vec![1, 0, 1].into(),
        n: vec![0x12, 0x34].into(),
        prv: None,
    };
    let rsa_private = Rsa {
        e: rsa_public.e.clone(),
        n: rsa_public.n.clone(),
        prv: Some(RsaPrivate {
            d: vec![0xAB].into(),
            opt: None,
        }),
    };
    assert_eq!(rsa_public.thumbprint(), rsa_private.thumbprint());
}

/// Test different hash algorithms produce different results with expected lengths.
#[test]
fn test_hash_algorithms() {
    let rsa_key = Rsa {
        e: vec![1, 0, 1].into(),
        n: vec![0xAB, 0xCD, 0xEF, 0x12].into(),
        prv: None,
    };

    let jwk = Jwk {
        key: Key::Rsa(rsa_key),
        prm: Parameters::default(),
    };

    let sha256_tp = jwk.thumbprint_with_digest::<Sha256>();
    let sha384_tp = jwk.thumbprint_with_digest::<Sha384>();
    let sha512_tp = jwk.thumbprint_with_digest::<Sha512>();

    // Verify expected lengths
    assert_eq!(sha256_tp.len(), 43); // 256 bits
    assert_eq!(sha384_tp.len(), 64); // 384 bits
    assert_eq!(sha512_tp.len(), 86); // 512 bits

    // All should be different
    assert_ne!(sha256_tp, sha384_tp);
    assert_ne!(sha256_tp, sha512_tp);
    assert_ne!(sha384_tp, sha512_tp);

    // All should be valid base64url
    for tp in [&sha256_tp, &sha384_tp, &sha512_tp] {
        assert!(!tp.contains('='));
        assert!(!tp.contains('+'));
        assert!(!tp.contains('/'));
    }
}

/// Test that different curves produce different thumbprints.
#[test]
fn test_curve_differentiation() {
    // EC curves
    let ec_curves = [
        EcCurves::P256,
        EcCurves::P384,
        EcCurves::P521,
        EcCurves::P256K,
    ];

    let mut ec_thumbprints = Vec::new();
    for curve in ec_curves {
        let ec = Ec {
            crv: curve,
            x: vec![1; 32].into(),
            y: vec![2; 32].into(),
            d: None,
        };
        ec_thumbprints.push(ec.thumbprint());
    }

    // All EC thumbprints should be different
    for i in 0..ec_thumbprints.len() {
        for j in (i + 1)..ec_thumbprints.len() {
            assert_ne!(ec_thumbprints[i], ec_thumbprints[j]);
        }
    }

    // OKP curves
    let okp_curves = [
        OkpCurves::Ed25519,
        OkpCurves::Ed448,
        OkpCurves::X25519,
        OkpCurves::X448,
    ];

    // All OKP thumbprints should be different
    let mut okp_thumbprints = HashSet::new();
    for curve in okp_curves {
        let okp = Okp {
            crv: curve,
            x: vec![1; 32].into(),
            d: None,
        };
        let thumbprint = okp.thumbprint();
        assert!(!okp_thumbprints.contains(&thumbprint));
        okp_thumbprints.insert(thumbprint);
    }
}

/// Test thumbprint consistency and determinism.
#[test]
fn test_thumbprint_determinism() {
    let rsa_key = Rsa {
        e: vec![1, 0, 1].into(),
        n: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
        prv: None,
    };

    // Test Jwk vs Key consistency
    let key_tp = rsa_key.thumbprint();
    let jwk_tp = Jwk {
        key: Key::Rsa(rsa_key.clone()),
        prm: Parameters::default(),
    }
    .thumbprint();
    assert_eq!(key_tp, jwk_tp);

    // Test determinism across multiple computations
    let first = rsa_key.thumbprint();
    for _ in 0..10 {
        assert_eq!(rsa_key.thumbprint(), first);
    }
}

/// Test various key sizes and edge cases.
#[test]
fn test_key_size_edge_cases() {
    // RSA with different sizes
    let test_keys = vec![
        Key::Rsa(Rsa {
            e: vec![1].into(),
            n: vec![3].into(),
            prv: None,
        }),
        Key::Rsa(Rsa {
            e: vec![0x00, 0x01, 0x00, 0x01].into(), // Leading zeros
            n: vec![0xFF; 256].into(),              // Large modulus
            prv: None,
        }),
        Key::Ec(Ec {
            crv: EcCurves::P256,
            x: vec![1].into(),
            y: vec![2].into(),
            d: None,
        }),
        Key::Ec(Ec {
            crv: EcCurves::P521,
            x: vec![0xFF; 66].into(),
            y: vec![0xEE; 66].into(),
            d: None,
        }),
        Key::Oct(Oct {
            k: vec![0x42].into(),
        }),
        Key::Oct(Oct {
            k: vec![0x5A; 1024].into(),
        }),
        Key::Okp(Okp {
            crv: OkpCurves::Ed25519,
            x: vec![1].into(),
            d: None,
        }),
    ];

    for key in test_keys {
        let thumbprint = key.thumbprint();
        assert!(!thumbprint.is_empty());
        assert!(!thumbprint.contains('='));
    }
}

/// Test that different key types produce different thumbprints.
#[test]
fn test_key_type_differentiation() {
    let same_bytes = vec![0x01, 0x02, 0x03, 0x04];

    let oct_tp = Oct {
        k: same_bytes.clone().into(),
    }
    .thumbprint();

    let okp_tp = Okp {
        crv: OkpCurves::Ed25519,
        x: same_bytes.into(),
        d: None,
    }
    .thumbprint();

    assert_ne!(oct_tp, okp_tp);
}
