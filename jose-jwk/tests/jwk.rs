// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod rfc7517 {
    use jose_jwa::Signing;
    use jose_jwk::*;

    /// From https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1
    #[test]
    fn a1() {
        let val = serde_json::json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "use": "enc",
                    "kid": "1",
                },
                {
                    "kty": "RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "kid": "2011-04-29",
                }
            ]
        });

        let jwk = JwkSet {
            keys: vec![
                Jwk {
                    key: Key::Ec(Ec {
                        crv: EcCurves::P256,
                        d: None,
                        x: vec![
                            48, 160, 66, 76, 210, 28, 41, 68, 131, 138, 45, 117, 201, 43, 55, 231,
                            110, 162, 13, 159, 0, 137, 58, 59, 78, 238, 138, 60, 10, 175, 236, 62,
                        ]
                        .into(),
                        y: vec![
                            224, 75, 101, 233, 36, 86, 217, 136, 139, 82, 179, 121, 189, 251, 213,
                            30, 232, 105, 239, 31, 15, 198, 91, 102, 89, 105, 91, 108, 206, 8, 23,
                            35,
                        ]
                        .into(),
                    }),
                    prm: Parameters {
                        kid: Some("1".to_string()),
                        cls: Some(Class::Encryption),
                        ..Default::default()
                    },
                },
                Jwk {
                    key: Key::Rsa(Rsa {
                        prv: None,
                        e: vec![1, 0, 1].into(),
                        n: vec![
                            210, 252, 123, 106, 10, 30, 108, 103, 16, 74, 235, 143, 136, 178, 87,
                            102, 155, 77, 246, 121, 221, 173, 9, 155, 92, 74, 108, 217, 168, 128,
                            21, 181, 161, 51, 191, 11, 133, 108, 120, 113, 182, 223, 0, 11, 85, 79,
                            206, 179, 194, 237, 81, 43, 182, 143, 20, 92, 110, 132, 52, 117, 47,
                            171, 82, 161, 207, 193, 36, 64, 143, 121, 181, 138, 69, 120, 193, 100,
                            40, 133, 87, 137, 247, 162, 73, 227, 132, 203, 45, 159, 174, 45, 103,
                            253, 150, 251, 146, 108, 25, 142, 7, 115, 153, 253, 200, 21, 192, 175,
                            9, 125, 222, 90, 173, 239, 244, 77, 231, 14, 130, 127, 72, 120, 67, 36,
                            57, 191, 238, 185, 96, 104, 208, 71, 79, 197, 13, 109, 144, 191, 58,
                            152, 223, 175, 16, 64, 200, 156, 2, 214, 146, 171, 59, 60, 40, 150, 96,
                            157, 134, 253, 115, 183, 116, 206, 7, 64, 100, 124, 238, 234, 163, 16,
                            189, 18, 249, 133, 168, 235, 159, 89, 253, 212, 38, 206, 165, 178, 18,
                            15, 79, 42, 52, 188, 171, 118, 75, 126, 108, 84, 214, 132, 2, 56, 188,
                            196, 5, 135, 165, 158, 102, 237, 31, 51, 137, 69, 119, 99, 92, 71, 10,
                            247, 92, 249, 44, 32, 209, 218, 67, 225, 191, 196, 25, 226, 34, 166,
                            240, 208, 187, 53, 140, 94, 56, 249, 203, 5, 10, 234, 254, 144, 72, 20,
                            241, 172, 26, 164, 156, 202, 158, 160, 202, 131,
                        ]
                        .into(),
                    }),
                    prm: Parameters {
                        alg: Some(Signing::Rs256.into()),
                        kid: Some("2011-04-29".to_string()),
                        ..Default::default()
                    },
                },
            ],
        };

        assert_eq!(jwk, serde_json::from_value(val.clone()).unwrap());
        assert_eq!(val, serde_json::to_value(&jwk).unwrap());

        #[cfg(feature = "p256")]
        if let Key::Ec(key) = &jwk.keys[0].key {
            let pk = p256::PublicKey::try_from(key).unwrap();
            assert_eq!(key, &pk.into());
        } else {
            unreachable!()
        }

        #[cfg(feature = "rsa")]
        if let Key::Rsa(key) = &jwk.keys[1].key {
            let pk = ::rsa::RsaPublicKey::try_from(key).unwrap();
            assert_eq!(key, &pk.into());
        } else {
            unreachable!()
        }
    }

    /// From https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    #[test]
    fn a2() {
        let val = serde_json::json!({
            "keys": [
                {
                    "kty":"EC",
                    "crv":"P-256",
                    "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
                    "use":"enc",
                    "kid":"1"
                },

                {
                    "kty":"RSA",
                    "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e":"AQAB",
                    "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
                    "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
                    "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
                    "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
                    "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
                    "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
                    "alg":"RS256",
                    "kid":"2011-04-29"
                },
            ]
        });

        let jwk = JwkSet {
            keys: vec![
                Jwk {
                    key: Key::Ec(Ec {
                        crv: EcCurves::P256,
                        d: Some(
                            vec![
                                243, 189, 12, 7, 168, 31, 185, 50, 120, 30, 213, 39, 82, 246, 12,
                                200, 154, 107, 229, 229, 25, 52, 254, 1, 147, 141, 219, 85, 216,
                                247, 120, 1,
                            ]
                            .into(),
                        ),
                        x: vec![
                            48, 160, 66, 76, 210, 28, 41, 68, 131, 138, 45, 117, 201, 43, 55, 231,
                            110, 162, 13, 159, 0, 137, 58, 59, 78, 238, 138, 60, 10, 175, 236, 62,
                        ]
                        .into(),
                        y: vec![
                            224, 75, 101, 233, 36, 86, 217, 136, 139, 82, 179, 121, 189, 251, 213,
                            30, 232, 105, 239, 31, 15, 198, 91, 102, 89, 105, 91, 108, 206, 8, 23,
                            35,
                        ]
                        .into(),
                    }),
                    prm: Parameters {
                        kid: Some("1".to_string()),
                        cls: Some(Class::Encryption),
                        ..Default::default()
                    },
                },
                Jwk {
                    key: Key::Rsa(Rsa {
                        e: vec![1, 0, 1].into(),
                        n: vec![
                            210, 252, 123, 106, 10, 30, 108, 103, 16, 74, 235, 143, 136, 178, 87,
                            102, 155, 77, 246, 121, 221, 173, 9, 155, 92, 74, 108, 217, 168, 128,
                            21, 181, 161, 51, 191, 11, 133, 108, 120, 113, 182, 223, 0, 11, 85, 79,
                            206, 179, 194, 237, 81, 43, 182, 143, 20, 92, 110, 132, 52, 117, 47,
                            171, 82, 161, 207, 193, 36, 64, 143, 121, 181, 138, 69, 120, 193, 100,
                            40, 133, 87, 137, 247, 162, 73, 227, 132, 203, 45, 159, 174, 45, 103,
                            253, 150, 251, 146, 108, 25, 142, 7, 115, 153, 253, 200, 21, 192, 175,
                            9, 125, 222, 90, 173, 239, 244, 77, 231, 14, 130, 127, 72, 120, 67, 36,
                            57, 191, 238, 185, 96, 104, 208, 71, 79, 197, 13, 109, 144, 191, 58,
                            152, 223, 175, 16, 64, 200, 156, 2, 214, 146, 171, 59, 60, 40, 150, 96,
                            157, 134, 253, 115, 183, 116, 206, 7, 64, 100, 124, 238, 234, 163, 16,
                            189, 18, 249, 133, 168, 235, 159, 89, 253, 212, 38, 206, 165, 178, 18,
                            15, 79, 42, 52, 188, 171, 118, 75, 126, 108, 84, 214, 132, 2, 56, 188,
                            196, 5, 135, 165, 158, 102, 237, 31, 51, 137, 69, 119, 99, 92, 71, 10,
                            247, 92, 249, 44, 32, 209, 218, 67, 225, 191, 196, 25, 226, 34, 166,
                            240, 208, 187, 53, 140, 94, 56, 249, 203, 5, 10, 234, 254, 144, 72, 20,
                            241, 172, 26, 164, 156, 202, 158, 160, 202, 131,
                        ]
                        .into(),
                        prv: Some(RsaPrivate {
                            d: vec![
                                95, 135, 19, 181, 226, 88, 254, 9, 248, 21, 131, 236, 92, 31, 43,
                                117, 120, 177, 230, 252, 44, 131, 81, 75, 55, 145, 55, 17, 161,
                                186, 68, 154, 21, 31, 225, 203, 44, 160, 253, 51, 183, 113, 230,
                                138, 59, 25, 68, 100, 157, 200, 103, 173, 28, 30, 82, 64, 187, 133,
                                62, 95, 36, 179, 52, 89, 177, 64, 40, 210, 214, 99, 107, 239, 236,
                                30, 141, 169, 116, 179, 82, 252, 83, 211, 246, 18, 126, 168, 163,
                                194, 157, 209, 79, 57, 65, 104, 44, 86, 167, 135, 104, 22, 78, 77,
                                218, 143, 6, 203, 249, 199, 52, 170, 232, 0, 50, 36, 39, 142, 169,
                                69, 74, 33, 177, 124, 176, 109, 23, 128, 117, 134, 140, 192, 91,
                                61, 182, 255, 29, 253, 195, 213, 99, 120, 180, 237, 173, 237, 240,
                                195, 122, 76, 220, 38, 209, 212, 154, 194, 111, 111, 227, 181, 34,
                                10, 93, 210, 147, 150, 98, 27, 188, 104, 140, 242, 238, 226, 198,
                                224, 213, 77, 163, 199, 130, 1, 76, 208, 115, 157, 178, 82, 204,
                                81, 202, 235, 168, 211, 241, 184, 36, 186, 171, 36, 208, 104, 236,
                                144, 50, 100, 215, 214, 120, 171, 8, 240, 110, 201, 231, 226, 61,
                                150, 6, 40, 183, 68, 191, 148, 179, 105, 70, 86, 70, 60, 126, 65,
                                115, 153, 237, 115, 208, 118, 200, 145, 252, 244, 99, 169, 170,
                                156, 230, 45, 169, 205, 23, 226, 55, 220, 42, 128, 2, 241,
                            ]
                            .into(),

                            opt: Some(RsaOptional {
                                p: vec![
                                    243, 120, 190, 236, 139, 204, 25, 122, 12, 92, 43, 36, 191,
                                    189, 211, 42, 191, 58, 223, 177, 98, 59, 182, 118, 239, 59,
                                    252, 162, 62, 169, 109, 101, 16, 200, 179, 208, 5, 12, 109, 61,
                                    89, 240, 15, 109, 17, 251, 173, 30, 76, 57, 131, 218, 232, 231,
                                    50, 222, 79, 162, 163, 43, 155, 196, 95, 152, 216, 85, 88, 59,
                                    99, 140, 201, 130, 50, 51, 169, 73, 120, 156, 20, 120, 251, 92,
                                    235, 149, 33, 132, 50, 169, 85, 165, 88, 72, 122, 116, 221,
                                    250, 25, 86, 88, 147, 221, 205, 240, 23, 61, 189, 142, 53, 199,
                                    47, 1, 245, 28, 243, 56, 101, 80, 205, 123, 205, 18, 249, 251,
                                    59, 73, 213, 109, 251,
                                ]
                                .into(),
                                q: vec![
                                    221, 215, 206, 71, 215, 46, 98, 175, 180, 75, 233, 164, 20,
                                    188, 224, 34, 216, 12, 17, 241, 115, 7, 106, 183, 133, 103,
                                    161, 50, 225, 180, 160, 43, 170, 157, 189, 239, 161, 178, 242,
                                    186, 106, 163, 85, 148, 14, 213, 210, 43, 119, 8, 19, 156, 39,
                                    105, 99, 48, 92, 57, 245, 185, 175, 126, 244, 0, 85, 227, 137,
                                    103, 237, 252, 209, 132, 138, 139, 232, 158, 44, 225, 42, 154,
                                    61, 85, 84, 187, 241, 60, 197, 131, 25, 8, 118, 183, 156, 69,
                                    236, 236, 103, 237, 100, 97, 223, 236, 214, 160, 219, 198, 217,
                                    3, 18, 7, 192, 33, 48, 6, 244, 181, 39, 0, 59, 167, 226, 242,
                                    28, 111, 172, 158, 151, 25,
                                ]
                                .into(),
                                dp: vec![
                                    27, 139, 15, 94, 71, 58, 97, 175, 114, 242, 130, 86, 247, 242,
                                    11, 143, 140, 110, 166, 155, 180, 151, 56, 191, 31, 181, 83,
                                    145, 47, 49, 143, 148, 157, 95, 119, 40, 19, 74, 34, 153, 140,
                                    49, 34, 45, 158, 153, 48, 46, 123, 69, 14, 107, 151, 105, 128,
                                    81, 178, 4, 158, 28, 242, 212, 54, 84, 94, 52, 217, 116, 110,
                                    128, 160, 211, 63, 198, 164, 98, 17, 104, 230, 208, 0, 239,
                                    180, 30, 252, 217, 173, 185, 134, 92, 220, 45, 230, 220, 141,
                                    184, 27, 97, 175, 71, 155, 18, 15, 21, 50, 0, 221, 179, 171,
                                    194, 223, 159, 209, 20, 154, 206, 171, 99, 115, 155, 241, 135,
                                    162, 42, 68, 226, 6, 61,
                                ]
                                .into(),
                                dq: vec![
                                    179, 217, 64, 31, 215, 224, 128, 27, 40, 21, 31, 14, 105, 205,
                                    145, 252, 77, 160, 195, 111, 54, 173, 61, 164, 24, 224, 33,
                                    188, 137, 101, 17, 49, 53, 121, 250, 192, 234, 27, 148, 82,
                                    243, 31, 5, 195, 41, 159, 201, 106, 121, 110, 175, 207, 57,
                                    216, 99, 148, 146, 64, 94, 233, 49, 208, 191, 106, 2, 55, 156,
                                    111, 8, 110, 157, 65, 81, 189, 9, 82, 42, 218, 68, 218, 148,
                                    124, 184, 92, 65, 191, 221, 244, 97, 120, 14, 30, 222, 239,
                                    133, 155, 70, 202, 27, 70, 137, 238, 141, 54, 13, 215, 16, 154,
                                    63, 164, 206, 235, 88, 239, 90, 181, 254, 47, 95, 45, 197, 124,
                                    56, 247, 132, 63, 114, 9,
                                ]
                                .into(),
                                qi: vec![
                                    27, 35, 63, 167, 162, 107, 95, 36, 162, 207, 91, 104, 22, 2,
                                    155, 89, 95, 137, 116, 141, 227, 67, 140, 169, 187, 218, 219,
                                    49, 108, 119, 173, 2, 65, 126, 107, 116, 22, 134, 51, 129, 66,
                                    25, 17, 81, 68, 112, 234, 176, 122, 100, 77, 243, 92, 232, 12,
                                    6, 154, 248, 25, 52, 41, 99, 70, 14, 50, 71, 100, 55, 67, 152,
                                    88, 86, 220, 3, 123, 148, 143, 169, 187, 25, 63, 152, 118, 70,
                                    39, 93, 107, 199, 36, 124, 59, 158, 87, 45, 39, 183, 72, 249,
                                    145, 124, 172, 25, 35, 172, 148, 219, 134, 113, 189, 2, 133,
                                    96, 139, 93, 149, 213, 10, 27, 51, 186, 33, 174, 179, 76, 168,
                                    64, 85, 21,
                                ]
                                .into(),
                                oth: vec![],
                            }),
                        }),
                    }),
                    prm: Parameters {
                        alg: Some(Signing::Rs256.into()),
                        kid: Some("2011-04-29".to_string()),
                        ..Default::default()
                    },
                },
            ],
        };

        assert_eq!(jwk, serde_json::from_value(val.clone()).unwrap());
        assert_eq!(val, serde_json::to_value(&jwk).unwrap());

        #[cfg(feature = "p256")]
        if let Key::Ec(key) = &jwk.keys[0].key {
            let sk = p256::SecretKey::try_from(key).unwrap();
            assert_eq!(key, &sk.into());
        } else {
            unreachable!()
        }

        #[cfg(feature = "rsa")]
        if let Key::Rsa(key) = &jwk.keys[1].key {
            let pk = ::rsa::RsaPrivateKey::try_from(key).unwrap();
            assert_eq!(key, &pk.into());
        } else {
            unreachable!()
        }
    }

    /// From https://datatracker.ietf.org/doc/html/rfc7517#appendix-B
    #[test]
    fn b() {
        let val = serde_json::json!({
            "kty":"RSA",
            "use":"sig",
            "kid":"1b94c",
            "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
            "e":"AQAB",
            "x5c": [
                "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="
            ]
        });

        let jwk = Jwk {
            key: Key::Rsa(Rsa {
                prv: None,
                e: vec![1, 0, 1].into(),
                n: vec![
                    190, 184, 206, 127, 63, 66, 113, 216, 49, 230, 116, 46, 119, 40, 93, 161, 29,
                    123, 87, 226, 46, 109, 99, 30, 57, 144, 176, 95, 248, 227, 210, 24, 0, 179, 61,
                    137, 254, 154, 152, 91, 79, 15, 45, 178, 191, 61, 216, 149, 24, 163, 235, 171,
                    57, 131, 34, 194, 200, 238, 192, 54, 229, 81, 39, 29, 77, 110, 8, 179, 112, 6,
                    229, 34, 8, 237, 117, 255, 238, 221, 97, 187, 43, 226, 34, 102, 27, 68, 46,
                    218, 63, 3, 177, 92, 147, 213, 172, 233, 36, 47, 205, 27, 206, 19, 203, 146,
                    138, 182, 27, 130, 104, 250, 29, 238, 34, 59, 195, 66, 202, 246, 138, 210, 50,
                    16, 68, 195, 6, 67, 11, 20, 214, 171, 134, 152, 88, 7, 33, 115, 203, 126, 122,
                    103, 125, 168, 235, 214, 181, 83, 3, 11, 96, 87, 146, 196, 103, 130, 30, 151,
                    229, 181, 24, 47, 46, 128, 200, 114, 175, 143, 233, 212, 203, 92, 32, 206, 54,
                    16, 15, 1, 204, 78, 153, 66, 160, 187, 84, 250, 143, 188, 72, 217, 217, 214,
                    217, 145, 160, 97, 61, 184, 153, 1, 45, 216, 121, 128, 81, 13, 105, 181, 167,
                    83, 153, 181, 102, 166, 79, 119, 4, 190, 170, 143, 166, 120, 203, 213, 124,
                    150, 250, 140, 149, 86, 70, 153, 118, 73, 75, 66, 157, 129, 182, 11, 125, 170,
                    189, 181, 155, 141, 159, 227, 4, 240, 249, 122, 233, 234, 176, 138, 53, 189,
                ]
                .into(),
            }),
            prm: Parameters {
                kid: Some("1b94c".to_string()),
                cls: Some(Class::Signing),
                x5c: Some(vec![From::from(vec![
                    48, 130, 3, 66, 48, 130, 2, 42, 160, 3, 2, 1, 2, 2, 6, 1, 60, 255, 22, 226,
                    226, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 5, 5, 0, 48, 98, 49, 11,
                    48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 19, 2, 67,
                    79, 49, 15, 48, 13, 6, 3, 85, 4, 7, 19, 6, 68, 101, 110, 118, 101, 114, 49, 28,
                    48, 26, 6, 3, 85, 4, 10, 19, 19, 80, 105, 110, 103, 32, 73, 100, 101, 110, 116,
                    105, 116, 121, 32, 67, 111, 114, 112, 46, 49, 23, 48, 21, 6, 3, 85, 4, 3, 19,
                    14, 66, 114, 105, 97, 110, 32, 67, 97, 109, 112, 98, 101, 108, 108, 48, 30, 23,
                    13, 49, 51, 48, 50, 50, 49, 50, 51, 50, 57, 49, 53, 90, 23, 13, 49, 56, 48, 56,
                    49, 52, 50, 50, 50, 57, 49, 53, 90, 48, 98, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19,
                    2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 19, 2, 67, 79, 49, 15, 48, 13, 6, 3,
                    85, 4, 7, 19, 6, 68, 101, 110, 118, 101, 114, 49, 28, 48, 26, 6, 3, 85, 4, 10,
                    19, 19, 80, 105, 110, 103, 32, 73, 100, 101, 110, 116, 105, 116, 121, 32, 67,
                    111, 114, 112, 46, 49, 23, 48, 21, 6, 3, 85, 4, 3, 19, 14, 66, 114, 105, 97,
                    110, 32, 67, 97, 109, 112, 98, 101, 108, 108, 48, 130, 1, 34, 48, 13, 6, 9, 42,
                    134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130,
                    1, 1, 0, 190, 184, 206, 127, 63, 66, 113, 216, 49, 230, 116, 46, 119, 40, 93,
                    161, 29, 123, 87, 226, 46, 109, 99, 30, 57, 144, 176, 95, 248, 227, 210, 24, 0,
                    179, 61, 137, 254, 154, 152, 91, 79, 15, 45, 178, 191, 61, 216, 149, 24, 163,
                    235, 171, 57, 131, 34, 194, 200, 238, 192, 54, 229, 81, 39, 29, 77, 110, 8,
                    179, 112, 6, 229, 34, 8, 237, 117, 255, 238, 221, 97, 187, 43, 226, 34, 102,
                    27, 68, 46, 218, 63, 3, 177, 92, 147, 213, 172, 233, 36, 47, 205, 27, 206, 19,
                    203, 146, 138, 182, 27, 130, 104, 250, 29, 238, 34, 59, 195, 66, 202, 246, 138,
                    210, 50, 16, 68, 195, 6, 67, 11, 20, 214, 171, 134, 152, 88, 7, 33, 115, 203,
                    126, 122, 103, 125, 168, 235, 214, 181, 83, 3, 11, 96, 87, 146, 196, 103, 130,
                    30, 151, 229, 181, 24, 47, 46, 128, 200, 114, 175, 143, 233, 212, 203, 92, 32,
                    206, 54, 16, 15, 1, 204, 78, 153, 66, 160, 187, 84, 250, 143, 188, 72, 217,
                    217, 214, 217, 145, 160, 97, 61, 184, 153, 1, 45, 216, 121, 128, 81, 13, 105,
                    181, 167, 83, 153, 181, 102, 166, 79, 119, 4, 190, 170, 143, 166, 120, 203,
                    213, 124, 150, 250, 140, 149, 86, 70, 153, 118, 73, 75, 66, 157, 129, 182, 11,
                    125, 170, 189, 181, 155, 141, 159, 227, 4, 240, 249, 122, 233, 234, 176, 138,
                    53, 189, 2, 3, 1, 0, 1, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 5, 5, 0,
                    3, 130, 1, 1, 0, 135, 204, 198, 149, 244, 165, 112, 141, 40, 222, 182, 3, 60,
                    16, 116, 237, 165, 205, 179, 6, 248, 16, 35, 72, 40, 109, 2, 17, 52, 212, 198,
                    101, 229, 244, 165, 11, 251, 216, 6, 150, 160, 179, 230, 37, 139, 58, 5, 172,
                    158, 183, 10, 113, 141, 47, 92, 241, 189, 39, 90, 253, 2, 160, 77, 78, 163, 96,
                    30, 173, 134, 211, 117, 244, 247, 110, 186, 95, 144, 169, 57, 237, 115, 22,
                    143, 142, 193, 189, 115, 198, 218, 119, 61, 232, 69, 117, 244, 9, 235, 93, 2,
                    12, 177, 26, 75, 213, 125, 70, 170, 117, 238, 16, 178, 201, 177, 41, 56, 101,
                    112, 123, 199, 231, 147, 231, 219, 16, 189, 129, 163, 117, 15, 26, 186, 108,
                    31, 53, 40, 104, 106, 67, 126, 217, 150, 178, 198, 100, 134, 144, 73, 41, 83,
                    9, 201, 255, 209, 184, 253, 146, 154, 102, 136, 206, 105, 240, 244, 152, 146,
                    149, 136, 115, 163, 139, 105, 205, 222, 107, 21, 120, 99, 69, 184, 56, 205,
                    111, 66, 251, 106, 168, 147, 237, 190, 168, 51, 53, 136, 158, 188, 226, 3, 199,
                    48, 134, 60, 104, 181, 171, 118, 4, 19, 198, 75, 166, 26, 100, 234, 129, 172,
                    17, 248, 222, 76, 14, 215, 79, 76, 68, 52, 93, 242, 1, 115, 103, 9, 17, 76,
                    140, 77, 142, 76, 62, 240, 2, 90, 153, 0, 233, 39, 82, 227, 20, 175, 117, 114,
                    183, 33, 87, 206, 88,
                ])]),
                ..Default::default()
            },
        };

        assert_eq!(jwk, serde_json::from_value(val.clone()).unwrap());
        assert_eq!(val, serde_json::to_value(&jwk).unwrap());

        #[cfg(feature = "rsa")]
        if let Key::Rsa(key) = &jwk.key {
            let pk = ::rsa::RsaPublicKey::try_from(key).unwrap();
            assert_eq!(key, &pk.into());
        } else {
            unreachable!()
        }
    }
}

#[cfg(test)]
mod rfc8037 {
    use jose_jwk::*;

    /// From https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.1
    #[test]
    fn a1() {
        let val = serde_json::json!({
            "kty":"OKP",
            "crv":"Ed25519",
            "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });

        let jwk = Jwk {
            key: Key::Okp(Okp {
                crv: OkpCurves::Ed25519,
                d: Some(
                    vec![
                        157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196,
                        68, 73, 197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
                    ]
                    .into(),
                ),
                x: vec![
                    215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14,
                    225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
                ]
                .into(),
            }),
            prm: Parameters::default(),
        };

        assert_eq!(jwk, serde_json::from_value(val.clone()).unwrap());
        assert_eq!(val, serde_json::to_value(jwk).unwrap());
    }

    /// From https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.2
    #[test]
    fn a2() {
        let val = serde_json::json!({
            "kty":"OKP",
            "crv":"Ed25519",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });

        let jwk = Jwk {
            key: Key::Okp(Okp {
                crv: OkpCurves::Ed25519,
                d: None,
                x: vec![
                    215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14,
                    225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
                ]
                .into(),
            }),
            prm: Parameters::default(),
        };

        assert_eq!(jwk, serde_json::from_value(val.clone()).unwrap());
        assert_eq!(val, serde_json::to_value(jwk).unwrap());
    }

    /// From https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.6
    #[test]
    fn a6() {
        let val = serde_json::json!({
            "kty":"OKP",
            "crv":"X25519",
            "kid":"Bob",
            "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
        });

        let jwk = Jwk {
            key: Key::Okp(Okp {
                crv: OkpCurves::X25519,
                d: None,
                x: vec![
                    222, 158, 219, 125, 123, 125, 193, 180, 211, 91, 97, 194, 236, 228, 53, 55, 63,
                    131, 67, 200, 91, 120, 103, 77, 173, 252, 126, 20, 111, 136, 43, 79,
                ]
                .into(),
            }),
            prm: Parameters {
                kid: Some("Bob".to_string()),
                ..Default::default()
            },
        };

        assert_eq!(jwk, serde_json::from_value(val.clone()).unwrap());
        assert_eq!(val, serde_json::to_value(jwk).unwrap());
    }

    /// From https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.7
    #[test]
    fn a7() {
        let val = serde_json::json!({
            "kty": "OKP",
            "crv": "X448",
            "kid": "Dave",
            "x": "PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk"
        });

        let jwk = Jwk {
            key: Key::Okp(Okp {
                crv: OkpCurves::X448,
                d: None,
                x: vec![
                    62, 183, 168, 41, 176, 205, 32, 245, 188, 252, 11, 89, 155, 111, 236, 207, 109,
                    164, 98, 113, 7, 189, 176, 212, 243, 69, 180, 48, 39, 216, 185, 114, 252, 62,
                    52, 251, 66, 50, 161, 60, 167, 6, 220, 181, 122, 236, 61, 174, 7, 189, 193,
                    198, 123, 243, 54, 9,
                ]
                .into(),
            }),
            prm: Parameters {
                kid: Some("Dave".to_string()),
                ..Default::default()
            },
        };

        assert_eq!(jwk, serde_json::from_value(val.clone()).unwrap());
        assert_eq!(val, serde_json::to_value(jwk).unwrap());
    }
}
