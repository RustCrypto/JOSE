// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "jwk")]
#![cfg(feature = "jws")]
#![cfg(feature = "rsa")]
#![cfg(feature = "p256")]
#![cfg(feature = "hmac")]
#![cfg(feature = "sha2")]

use jose::alg::Signing::*;
use jose::b64::Update;
use jose::jws::crypto::rcrypto::{Signing, Verifying};
use jose::jws::crypto::{Signer, SigningKey, Verifier, VerifyingKey};
use jose::jws::Jws;
use jose::key::rcrypto::{Error, Key};

const EMPTY: [Key<Verifying>; 0] = [];

fn ver<K: Into<Key<Verifying>>, const N: usize>(jws: &Jws, keys: [K; N]) -> Result<(), Error> {
    let pay = match jws {
        Jws::Flattened(f) => f.payload.as_ref().unwrap(),
        Jws::General(g) => g.payload.as_ref().unwrap(),
    };

    keys.into_iter()
        .map(|x| x.into())
        .collect::<Vec<_>>()
        .verify(jws)
        .unwrap()
        .chain(pay)
        .unwrap()
        .finish()
}

fn valid<K: Into<Key<Verifying>>, const N: usize>(jws: &Jws, keys: [K; N]) {
    ver(jws, keys).unwrap();
}

fn invld<K: Into<Key<Verifying>>, const N: usize>(jws: &Jws, keys: [K; N]) {
    assert_eq!(ver(jws, keys).unwrap_err(), Error::Invalid);
}

fn modify(jws: &mut Jws) {
    match jws {
        Jws::Flattened(f) => f.signature.signature[0] += 1,
        Jws::General(g) => {
            for sig in &mut g.signatures {
                sig.signature[0] += 1;
            }
        }
    }
}

fn attach(jws: &mut Jws, pay: &str) {
    match jws {
        Jws::Flattened(f) => {
            assert!(f.payload.is_none());
            f.payload = Some(pay.parse().unwrap());
        }

        Jws::General(g) => {
            assert!(g.payload.is_none());
            g.payload = Some(pay.parse().unwrap());
        }
    }
}

mod rfc7515 {
    use super::*;

    use jose::jwk::Jwk;
    use jose::jws::{Flattened, General};
    use serde_json::json;

    fn oct() -> Key<Signing> {
        let raw = json!({
            "kty": "oct",
            "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        });

        let jwk: Jwk = serde_json::from_value(raw).unwrap();
        Key::try_from(jwk).unwrap()
    }

    fn rsa() -> Key<Signing> {
        let raw = json!({
            "kty":"RSA",
            "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e":"AQAB",
            "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
            "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
            "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
            "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
            "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
            "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
        });

        let jwk: Jwk = serde_json::from_value(raw).unwrap();
        Key::try_from(jwk).unwrap()
    }

    fn p256() -> Key<Signing> {
        let raw = json!({
            "kty":"EC",
            "crv":"P-256",
            "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        });

        let jwk: Jwk = serde_json::from_value(raw).unwrap();
        Key::try_from(jwk).unwrap()
    }

    #[test]
    fn sign() {
        for (key, alg) in [(oct(), Hs512), (rsa(), Ps256), (p256(), Es256)] {
            let sig = key
                .sign(None, None)
                .unwrap()
                .chain(b"foo")
                .unwrap()
                .finish()
                .unwrap();

            eprintln!("{:#?}", sig);
            assert_eq!(sig.protected.as_ref().unwrap().oth.alg, Some(alg));

            Key::<Verifying>::from(key)
                .verify(&sig)
                .unwrap()
                .chain(b"foo")
                .unwrap()
                .finish()
                .unwrap();
        }
    }

    #[test]
    fn a1() {
        const JWS: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut jws: Jws = JWS.parse().unwrap();

        invld(&jws, EMPTY);

        invld(&jws, [p256()]);
        invld(&jws, [rsa()]);
        valid(&jws, [oct()]);

        invld(&jws, [p256(), rsa()]);
        valid(&jws, [p256(), oct()]);
        invld(&jws, [rsa(), p256()]);
        valid(&jws, [rsa(), oct()]);
        valid(&jws, [oct(), p256()]);
        valid(&jws, [oct(), rsa()]);

        valid(&jws, [p256(), rsa(), oct()]);
        valid(&jws, [p256(), oct(), rsa()]);
        valid(&jws, [rsa(), oct(), p256()]);
        valid(&jws, [rsa(), p256(), oct()]);
        valid(&jws, [oct(), p256(), rsa()]);
        valid(&jws, [oct(), rsa(), p256()]);

        modify(&mut jws);
        invld(&jws, [oct()]);
    }

    #[test]
    fn a2() {
        const JWS: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        let mut jws: Jws = JWS.parse().unwrap();

        invld(&jws, EMPTY);

        invld(&jws, [p256()]);
        valid(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [p256(), rsa()]);
        invld(&jws, [p256(), oct()]);
        valid(&jws, [rsa(), p256()]);
        valid(&jws, [rsa(), oct()]);
        invld(&jws, [oct(), p256()]);
        valid(&jws, [oct(), rsa()]);

        valid(&jws, [p256(), rsa(), oct()]);
        valid(&jws, [p256(), oct(), rsa()]);
        valid(&jws, [rsa(), oct(), p256()]);
        valid(&jws, [rsa(), p256(), oct()]);
        valid(&jws, [oct(), p256(), rsa()]);
        valid(&jws, [oct(), rsa(), p256()]);

        modify(&mut jws);
        invld(&jws, [rsa()]);
    }

    #[test]
    fn a2d() {
        const JWS: &str = "eyJhbGciOiJSUzI1NiJ9..cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        let mut jws: Jws = JWS.parse().unwrap();
        attach(&mut jws, "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");

        invld(&jws, EMPTY);

        invld(&jws, [p256()]);
        valid(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [p256(), rsa()]);
        invld(&jws, [p256(), oct()]);
        valid(&jws, [rsa(), p256()]);
        valid(&jws, [rsa(), oct()]);
        invld(&jws, [oct(), p256()]);
        valid(&jws, [oct(), rsa()]);

        valid(&jws, [p256(), rsa(), oct()]);
        valid(&jws, [p256(), oct(), rsa()]);
        valid(&jws, [rsa(), oct(), p256()]);
        valid(&jws, [rsa(), p256(), oct()]);
        valid(&jws, [oct(), p256(), rsa()]);
        valid(&jws, [oct(), rsa(), p256()]);

        modify(&mut jws);
        invld(&jws, [rsa()]);
    }

    #[test]
    fn a3() {
        const JWS: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
        let mut jws: Jws = JWS.parse().unwrap();

        invld(&jws, EMPTY);

        valid(&jws, [p256()]);
        invld(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [p256(), rsa()]);
        valid(&jws, [p256(), oct()]);
        valid(&jws, [rsa(), p256()]);
        invld(&jws, [rsa(), oct()]);
        valid(&jws, [oct(), p256()]);
        invld(&jws, [oct(), rsa()]);

        valid(&jws, [p256(), rsa(), oct()]);
        valid(&jws, [p256(), oct(), rsa()]);
        valid(&jws, [rsa(), oct(), p256()]);
        valid(&jws, [rsa(), p256(), oct()]);
        valid(&jws, [oct(), p256(), rsa()]);
        valid(&jws, [oct(), rsa(), p256()]);

        modify(&mut jws);
        invld(&jws, [p256()]);
    }

    // This UNSECURED JWS MUST fail all validations.
    #[test]
    fn a5() {
        const JWS: &str = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
        let jws: Jws = JWS.parse().unwrap();

        invld(&jws, EMPTY);

        invld(&jws, [p256()]);
        invld(&jws, [rsa()]);
        invld(&jws, [oct()]);

        invld(&jws, [p256(), rsa()]);
        invld(&jws, [p256(), oct()]);
        invld(&jws, [rsa(), p256()]);
        invld(&jws, [rsa(), oct()]);
        invld(&jws, [oct(), p256()]);
        invld(&jws, [oct(), rsa()]);

        invld(&jws, [p256(), rsa(), oct()]);
        invld(&jws, [p256(), oct(), rsa()]);
        invld(&jws, [rsa(), oct(), p256()]);
        invld(&jws, [rsa(), p256(), oct()]);
        invld(&jws, [oct(), p256(), rsa()]);
        invld(&jws, [oct(), rsa(), p256()]);
    }

    #[test]
    fn a6() {
        let raw = json!({
            "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {
                    "protected":"eyJhbGciOiJSUzI1NiJ9",
                    "header": { "kid":"2010-12-29" },
                    "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
                },
                {
                    "protected":"eyJhbGciOiJFUzI1NiJ9",
                    "header": { "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d" },
                    "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
                }
            ]
        });

        let mut jws: Jws = serde_json::from_value::<General>(raw).unwrap().into();

        invld(&jws, EMPTY);

        valid(&jws, [p256()]);
        valid(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [p256(), rsa()]);
        valid(&jws, [p256(), oct()]);
        valid(&jws, [rsa(), p256()]);
        valid(&jws, [rsa(), oct()]);
        valid(&jws, [oct(), p256()]);
        valid(&jws, [oct(), rsa()]);

        valid(&jws, [p256(), rsa(), oct()]);
        valid(&jws, [p256(), oct(), rsa()]);
        valid(&jws, [rsa(), oct(), p256()]);
        valid(&jws, [rsa(), p256(), oct()]);
        valid(&jws, [oct(), p256(), rsa()]);
        valid(&jws, [oct(), rsa(), p256()]);

        modify(&mut jws);
        invld(&jws, [p256()]);
        invld(&jws, [rsa()]);
    }

    #[test]
    fn a6d() {
        let raw = json!({
            "signatures": [
                {
                    "protected":"eyJhbGciOiJSUzI1NiJ9",
                    "header": { "kid":"2010-12-29" },
                    "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
                },
                {
                    "protected":"eyJhbGciOiJFUzI1NiJ9",
                    "header": { "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d" },
                    "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
                }
            ]
        });

        let mut jws: Jws = serde_json::from_value::<General>(raw).unwrap().into();
        attach(&mut jws, "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");

        invld(&jws, EMPTY);

        valid(&jws, [p256()]);
        valid(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [p256(), rsa()]);
        valid(&jws, [p256(), oct()]);
        valid(&jws, [rsa(), p256()]);
        valid(&jws, [rsa(), oct()]);
        valid(&jws, [oct(), p256()]);
        valid(&jws, [oct(), rsa()]);

        valid(&jws, [p256(), rsa(), oct()]);
        valid(&jws, [p256(), oct(), rsa()]);
        valid(&jws, [rsa(), oct(), p256()]);
        valid(&jws, [rsa(), p256(), oct()]);
        valid(&jws, [oct(), p256(), rsa()]);
        valid(&jws, [oct(), rsa(), p256()]);

        modify(&mut jws);
        invld(&jws, [p256()]);
        invld(&jws, [rsa()]);
    }

    #[test]
    fn a7() {
        let raw = json!({
            "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "protected":"eyJhbGciOiJFUzI1NiJ9",
            "header": { "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d" },
            "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        });

        let mut jws: Jws = serde_json::from_value::<Flattened>(raw).unwrap().into();

        invld(&jws, EMPTY);

        valid(&jws, [p256()]);
        invld(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [p256(), rsa()]);
        valid(&jws, [p256(), oct()]);
        valid(&jws, [rsa(), p256()]);
        invld(&jws, [rsa(), oct()]);
        valid(&jws, [oct(), p256()]);
        invld(&jws, [oct(), rsa()]);

        valid(&jws, [p256(), rsa(), oct()]);
        valid(&jws, [p256(), oct(), rsa()]);
        valid(&jws, [rsa(), oct(), p256()]);
        valid(&jws, [rsa(), p256(), oct()]);
        valid(&jws, [oct(), p256(), rsa()]);
        valid(&jws, [oct(), rsa(), p256()]);

        modify(&mut jws);
        invld(&jws, [p256()]);
    }

    #[test]
    fn a7d() {
        let raw = json!({
            "protected":"eyJhbGciOiJFUzI1NiJ9",
            "header": { "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d" },
            "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        });

        let mut jws: Jws = serde_json::from_value::<Flattened>(raw).unwrap().into();
        attach(&mut jws, "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");

        invld(&jws, EMPTY);

        valid(&jws, [p256()]);
        invld(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [p256(), rsa()]);
        valid(&jws, [p256(), oct()]);
        valid(&jws, [rsa(), p256()]);
        invld(&jws, [rsa(), oct()]);
        valid(&jws, [oct(), p256()]);
        invld(&jws, [oct(), rsa()]);

        valid(&jws, [p256(), rsa(), oct()]);
        valid(&jws, [p256(), oct(), rsa()]);
        valid(&jws, [rsa(), oct(), p256()]);
        valid(&jws, [rsa(), p256(), oct()]);
        valid(&jws, [oct(), p256(), rsa()]);
        valid(&jws, [oct(), rsa(), p256()]);

        modify(&mut jws);
        invld(&jws, [p256()]);
    }
}

mod rfc7520 {
    use super::*;

    use jose::jwk::Jwk;
    use serde_json::json;

    fn oct() -> Key<Signing> {
        let raw = json!({
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
        });

        let jwk: Jwk = serde_json::from_value(raw).unwrap();
        Key::try_from(jwk).unwrap()
    }

    fn rsa() -> Key<Signing> {
        let raw = json!({
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
            "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
            "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
            "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
            "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",
            "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
            "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"
        });

        let jwk: Jwk = serde_json::from_value(raw).unwrap();
        Key::try_from(jwk).unwrap()
    }

    #[test]
    fn sign() {
        for (key, alg) in [(oct(), Hs256), (rsa(), Ps256)] {
            let sig = key
                .sign(None, None)
                .unwrap()
                .chain(b"foo")
                .unwrap()
                .finish()
                .unwrap();

            eprintln!("{:#?}", sig);
            assert_eq!(sig.protected.as_ref().unwrap().oth.alg, Some(alg));

            Key::<Verifying>::from(key)
                .verify(&sig)
                .unwrap()
                .chain(b"foo")
                .unwrap()
                .finish()
                .unwrap();
        }
    }

    #[test]
    fn s41() {
        const JWS: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg";
        let mut jws: Jws = JWS.parse().unwrap();

        invld(&jws, EMPTY);

        valid(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [rsa(), oct()]);

        modify(&mut jws);
        invld(&jws, [rsa()]);
    }

    #[test]
    fn s42() {
        const JWS: &str = "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw";
        let mut jws: Jws = JWS.parse().unwrap();

        invld(&jws, EMPTY);

        valid(&jws, [rsa()]);
        invld(&jws, [oct()]);

        valid(&jws, [rsa(), oct()]);

        modify(&mut jws);
        invld(&jws, [rsa()]);
    }

    #[test]
    fn s44() {
        const JWS: &str = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";
        let mut jws: Jws = JWS.parse().unwrap();

        invld(&jws, EMPTY);

        valid(&jws, [oct()]);
        invld(&jws, [rsa()]);

        valid(&jws, [rsa(), oct()]);

        modify(&mut jws);
        invld(&jws, [oct()]);
    }

    #[test]
    fn s45() {
        const JWS: &str = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9..s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";
        let mut jws: Jws = JWS.parse().unwrap();

        attach(&mut jws, "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4");

        invld(&jws, EMPTY);

        valid(&jws, [oct()]);
        invld(&jws, [rsa()]);

        valid(&jws, [rsa(), oct()]);

        modify(&mut jws);
        invld(&jws, [oct()]);
    }

    #[test]
    fn s46() {
        let mut jws: Jws = serde_json::from_value(json!({
            "payload": "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
            "signatures": [{
                "protected": "eyJhbGciOiJIUzI1NiJ9",
                "header": { "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037" },
                "signature": "bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"
            }]
        })).unwrap();

        invld(&jws, EMPTY);

        valid(&jws, [oct()]);
        invld(&jws, [rsa()]);

        valid(&jws, [rsa(), oct()]);

        modify(&mut jws);
        invld(&jws, [oct()]);
    }

    #[test]
    fn s47() {
        let mut jws: Jws = serde_json::from_value(json!({
            "payload": "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
            "signatures": [{
                "signature": "xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk",
                "header": {
                    "alg": "HS256",
                    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
                }
            }]
        })).unwrap();

        invld(&jws, EMPTY);

        valid(&jws, [oct()]);
        invld(&jws, [rsa()]);

        valid(&jws, [rsa(), oct()]);

        modify(&mut jws);
        invld(&jws, [oct()]);
    }

    #[test]
    fn s48() {
        let mut jws: Jws = serde_json::from_value(json!({
            "payload": "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
            "signatures": [
                {
                    "protected": "eyJhbGciOiJSUzI1NiJ9",
                    "header": {
                        "kid": "bilbo.baggins@hobbiton.example"
                    },
                    "signature": "MIsjqtVlOpa71KE-Mss8_Nq2YH4FGhiocsqrgi5NvyG53uoimic1tcMdSg-qptrzZc7CG6Svw2Y13TDIqHzTUrL_lR2ZFcryNFiHkSw129EghGpwkpxaTn_THJTCglNbADko1MZBCdwzJxwqZc-1RlpO2HibUYyXSwO97BSe0_evZKdjvvKSgsIqjytKSeAMbhMBdMma622_BG5t4sdbuCHtFjp9iJmkio47AIwqkZV1aIZsv33uPUqBBCXbYoQJwt7mxPftHmNlGoOSMxR_3thmXTCm4US-xiNOyhbm8afKK64jU6_TPtQHiJeQJxz9G3Tx-083B745_AfYOnlC9w"
                },
                {
                    "header": {
                        "alg": "ES512",
                        "kid": "bilbo.baggins@hobbiton.example"
                    },
                    "signature": "ARcVLnaJJaUWG8fG-8t5BREVAuTY8n8YHjwDO1muhcdCoFZFFjfISu0Cdkn9Ybdlmi54ho0x924DUz8sK7ZXkhc7AFM8ObLfTvNCrqcI3Jkl2U5IX3utNhODH6v7xgy1Qahsn0fyb4zSAkje8bAWz4vIfj5pCMYxxm4fgV3q7ZYhm5eD"
                },
                {
                    "protected": "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9",
                    "signature": "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
                }
            ]
        }))
        .unwrap();

        invld(&jws, EMPTY);

        valid(&jws, [oct()]);
        valid(&jws, [rsa()]);

        valid(&jws, [rsa(), oct()]);

        modify(&mut jws);
        invld(&jws, [oct()]);
    }
}
