use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::result::Error;
use corim_rs::{
    core::{
        Bytes, CertThumbprintType, CoseAlgorithm, CoseEllipticCurve, CoseKey, CoseKeyOperation,
        CoseKeySetOrKey, CoseKeyType, CoseKty, Digest, HashAlgorithm,
    },
    triples::CryptoKeyTypeChoice,
};
use jsonwebtoken::jwk;

fn jwk_key_ops_to_cose(jwk_op: jwk::KeyOperations) -> Result<CoseKeyOperation, Error> {
    match jwk_op {
        jwk::KeyOperations::Sign => Ok(CoseKeyOperation::Sign),
        jwk::KeyOperations::Verify => Ok(CoseKeyOperation::Verify),
        jwk::KeyOperations::Encrypt => Ok(CoseKeyOperation::Encrypt),
        jwk::KeyOperations::Decrypt => Ok(CoseKeyOperation::Decrypt),
        jwk::KeyOperations::WrapKey => Ok(CoseKeyOperation::WrapKeys),
        jwk::KeyOperations::UnwrapKey => Ok(CoseKeyOperation::UnwrapKeys),
        jwk::KeyOperations::DeriveKey => Ok(CoseKeyOperation::KeyDerive),
        jwk::KeyOperations::DeriveBits => Ok(CoseKeyOperation::KeyDeriveBits),
        op @ jwk::KeyOperations::Other(_) => {
            Err(Error::invalid_value(op, "a valid COSE key operation"))
        }
    }
}

fn jwk_public_key_use_to_cose(key_use: jwk::PublicKeyUse) -> Result<CoseKeyOperation, Error> {
    match key_use {
        jwk::PublicKeyUse::Signature => Ok(CoseKeyOperation::Sign),
        jwk::PublicKeyUse::Encryption => Ok(CoseKeyOperation::Encrypt),
        op @ jwk::PublicKeyUse::Other(_) => {
            Err(Error::invalid_value(op, "a valid COSE key operation"))
        }
    }
}

fn jwk_algorithm_to_cose(alg: jwk::KeyAlgorithm) -> CoseAlgorithm {
    match alg {
        jwk::KeyAlgorithm::HS256 => CoseAlgorithm::Hmac256_256,
        jwk::KeyAlgorithm::HS384 => CoseAlgorithm::Hmac384_384,
        jwk::KeyAlgorithm::HS512 => CoseAlgorithm::Hmac512_512,
        jwk::KeyAlgorithm::ES256 => CoseAlgorithm::ES256,
        jwk::KeyAlgorithm::ES384 => CoseAlgorithm::ES384,
        jwk::KeyAlgorithm::RS256 => CoseAlgorithm::RS256,
        jwk::KeyAlgorithm::RS384 => CoseAlgorithm::RS384,
        jwk::KeyAlgorithm::RS512 => CoseAlgorithm::RS512,
        jwk::KeyAlgorithm::PS256 => CoseAlgorithm::PS256,
        jwk::KeyAlgorithm::PS384 => CoseAlgorithm::PS384,
        jwk::KeyAlgorithm::PS512 => CoseAlgorithm::PS512,
        jwk::KeyAlgorithm::EdDSA => CoseAlgorithm::EdDSA,
        jwk::KeyAlgorithm::RSA1_5 => CoseAlgorithm::RS1,
        jwk::KeyAlgorithm::RSA_OAEP => CoseAlgorithm::RsaesOaepRfc,
        jwk::KeyAlgorithm::RSA_OAEP_256 => CoseAlgorithm::RsaesOaepSha256,
    }
}

fn jwk_ec_curve_to_cose(curve: &jwk::EllipticCurve) -> CoseEllipticCurve {
    match curve {
        jwk::EllipticCurve::P256 => CoseEllipticCurve::P256,
        jwk::EllipticCurve::P384 => CoseEllipticCurve::P384,
        jwk::EllipticCurve::P521 => CoseEllipticCurve::P521,
        jwk::EllipticCurve::Ed25519 => CoseEllipticCurve::Ed25519,
    }
}

/// Convert a JWK key into a CoRIM `CryptoKeyTypeChoice` object wrapping a COSE key.
pub fn jwk_to_crypto_key(jwk: jwk::Jwk) -> Result<CryptoKeyTypeChoice<'static>, Error> {
    if jwk.common.x509_url.is_some() {
        return Err(Error::invalid_value(
            jwk.clone(),
            "cert URL (x5u) JWK field not supported",
        ));
    }

    if jwk.common.x509_sha1_fingerprint.is_some() {
        return Err(Error::invalid_value(
            jwk.clone(),
            "SHA-1 fingerprint (x5t) JWK field not supported",
        ));
    }

    if let Some(fingerprint) = &jwk.common.x509_sha256_fingerprint {
        return Ok(CryptoKeyTypeChoice::CertThumbprint(
            CertThumbprintType::from(Digest {
                alg: HashAlgorithm::Sha256,
                val: Bytes::from(URL_SAFE_NO_PAD.decode(fingerprint).map_err(Error::custom)?),
            }),
        ));
    }

    let mut cose_key = CoseKey::default();

    if let Some(kid) = &jwk.common.key_id {
        cose_key.kid = Some(Bytes::from(kid.clone().as_bytes()));
    }

    if let Some(key_ops) = &jwk.common.key_operations {
        let key_ops: Result<Vec<CoseKeyOperation>, Error> = key_ops
            .iter()
            .map(|op| jwk_key_ops_to_cose(op.clone()))
            .collect();
        cose_key.key_ops = Some(key_ops?);
    } else if let Some(key_use) = &jwk.common.public_key_use {
        cose_key.key_ops = Some(vec![jwk_public_key_use_to_cose(key_use.clone())?]);
    }

    if let Some(alg) = &jwk.common.key_algorithm {
        cose_key.alg = Some(jwk_algorithm_to_cose(*alg))
    }

    match &jwk.algorithm {
        jwk::AlgorithmParameters::EllipticCurve(ec_params) => {
            cose_key.kty = CoseKty::Ec2;
            cose_key.crv = Some(jwk_ec_curve_to_cose(&ec_params.curve));
            cose_key.x = Some(Bytes::from(
                URL_SAFE_NO_PAD
                    .decode(&ec_params.x)
                    .map_err(Error::custom)?,
            ));
            cose_key.y = Some(Bytes::from(
                URL_SAFE_NO_PAD
                    .decode(&ec_params.y)
                    .map_err(Error::custom)?,
            ));
        }
        jwk::AlgorithmParameters::OctetKeyPair(okp_params) => {
            cose_key.kty = CoseKty::Okp;
            cose_key.crv = Some(jwk_ec_curve_to_cose(&okp_params.curve));
            cose_key.x = Some(Bytes::from(
                URL_SAFE_NO_PAD
                    .decode(&okp_params.x)
                    .map_err(Error::custom)?,
            ));
        }
        jwk::AlgorithmParameters::OctetKey(oct_params) => {
            cose_key.kty = CoseKty::Symmetric;
            cose_key.k = Some(Bytes::from(
                URL_SAFE_NO_PAD
                    .decode(&oct_params.value)
                    .map_err(Error::custom)?,
            ));
        }
        jwk::AlgorithmParameters::RSA(_) => {
            return Err(Error::custom("RSA keys are not supported"));
        }
    };

    Ok(CryptoKeyTypeChoice::CoseKey(CoseKeyType::from(
        CoseKeySetOrKey::from(cose_key),
    )))
}
