use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::result::Error;

#[inline]
pub fn b64decode(v: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(v)
        .map_err(|e| Error::invalid_value(e.to_string(), "a base64-encoded string"))
}

// Helper function to convert PEM-encoded SubjectPublicKeyInfo into JWK
pub fn pem_spki_to_jwk_string(pem_bytes: &[u8]) -> Result<String, Error> {
    use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
    use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize};
    use elliptic_curve::{PublicKey as EcPublicKey, pkcs8::DecodePublicKey};
    use p256::NistP256;
    use p384::NistP384;
    use p521::NistP521;
    use pem;
    use picky_asn1_x509::{
        AlgorithmIdentifierParameters, EcParameters, PublicKey, SubjectPublicKeyInfo,
    };
    use serde::Serialize;

    #[derive(Serialize, Debug)]
    struct EcJwk {
        pub kty: String,
        pub crv: String,
        pub x: String,
        pub y: String,
    }

    // Returns a pair (X, Y) of Base64Url-encoded strings representing the curve points of the
    // given public key.
    fn extract_ec_point_x_y<C>(ec_pub: EcPublicKey<C>) -> Result<(String, String), Error>
    where
        C: CurveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let point = ec_pub.to_encoded_point(false);
        if let Some(x) = point.x()
            && let Some(y) = point.y()
        {
            let xb64 = URL_SAFE_NO_PAD.encode(x);
            let yb64 = URL_SAFE_NO_PAD.encode(y);
            Ok((xb64, yb64))
        } else {
            Err(Error::Custom(format!(
                "points x and y not populated in encoded point {:?}",
                point
            )))
        }
    }

    let pem = pem::parse(pem_bytes).map_err(Error::custom)?;
    match pem.tag() {
        "PUBLIC KEY" => {
            let contents = pem.contents();
            let spki: SubjectPublicKeyInfo =
                picky_asn1_der::from_bytes(contents).map_err(Error::custom)?;
            match spki.subject_public_key {
                PublicKey::Ec(_) => {
                    if let AlgorithmIdentifierParameters::Ec(EcParameters::NamedCurve(oid)) =
                        spki.algorithm.parameters()
                    {
                        let oid_str: String = oid.0.clone().into();
                        let (crv, x, y) = match oid_str.as_str() {
                            "1.2.840.10045.3.1.7" => {
                                let ec_pub: EcPublicKey<NistP256> =
                                    EcPublicKey::from_public_key_der(contents).unwrap();
                                let (x, y) = extract_ec_point_x_y(ec_pub)?;
                                ("P-256", x, y)
                            }
                            "1.3.132.0.34" => {
                                let ec_pub: EcPublicKey<NistP384> =
                                    EcPublicKey::from_public_key_der(contents).unwrap();
                                let (x, y) = extract_ec_point_x_y(ec_pub)?;
                                ("P-384", x, y)
                            }
                            "1.3.132.0.35" => {
                                let ec_pub: EcPublicKey<NistP521> =
                                    EcPublicKey::from_public_key_der(contents).unwrap();
                                let (x, y) = extract_ec_point_x_y(ec_pub)?;
                                ("P-521", x, y)
                            }
                            c => {
                                return Err(Error::Custom(format!(
                                    "EC curve oid {} is not supported",
                                    c
                                )));
                            }
                        };

                        let jwk = EcJwk {
                            kty: "EC".into(),
                            crv: crv.into(),
                            x,
                            y,
                        };

                        Ok(serde_json::to_string(&jwk).unwrap())
                    } else {
                        Err(Error::Custom(
                            "the EC public key does not contain EC parameters".to_string(),
                        ))
                    }
                }
                _ => Err(Error::Custom("only EC keys supported".to_string())),
            }
        }
        t => Err(Error::Custom(format!(
            "PEM tag {} is not supported - must be PUBLIC KEY (SubjectPublicKeyInfo)",
            t
        ))),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use jsonwebtoken::jwk::Jwk;

    fn pem_to_jwk(pem_bytes: &[u8], expected_jwk: &str) {
        let jwk_converted = pem_spki_to_jwk_string(pem_bytes).unwrap();
        let expected: Jwk =
            serde_json::from_str(expected_jwk).expect("failed to deserialize expected JWK");
        let actual: Jwk =
            serde_json::from_str(&jwk_converted).expect("failed to deserialize actual JWK");
        assert_eq!(actual, expected);
    }

    #[test]
    fn pem_to_jwk_256() {
        let pem_bytes = include_bytes!("../../test/keys/pkey_256.pem");
        let expected_jwk = include_str!("../../test/keys/pkey_256.json");
        pem_to_jwk(pem_bytes, expected_jwk);
    }

    #[test]
    fn pem_to_jwk_384() {
        let pem_bytes = include_bytes!("../../test/keys/pkey_384.pem");
        let expected_jwk = include_str!("../../test/keys/pkey_384.json");
        pem_to_jwk(pem_bytes, expected_jwk);
    }

    #[test]
    fn pem_to_jwk_521() {
        let pem_bytes = include_bytes!("../../test/keys/pkey_521.pem");
        let expected_jwk = include_str!("../../test/keys/pkey_521.json");
        pem_to_jwk(pem_bytes, expected_jwk);
    }
}
