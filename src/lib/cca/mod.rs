use std::collections::BTreeMap;

use ccatoken::{
    store::{Cpak, ITrustAnchorStore, MemoTrustAnchorStore},
    token::{Evidence, Platform, Realm},
};
use corim_rs::{
    CryptoKeyTypeChoice, EnvironmentMap,
    core::{
        Bytes, Digest, ExtensionValue, HashAlgorithm, Label, RawValueType, RawValueTypeChoice,
        TaggedBytes, TaggedUeidType, Text, UeidType, Ulabel, Uri,
    },
    corim::ProfileTypeChoice,
    triples::{
        ClassIdTypeChoice, ClassMapBuilder, EnvironmentMapBuilder, InstanceIdTypeChoice,
        IntegrityRegisters, MeasurementValuesMapBuilder,
    },
};
use ear::claim::TRUSTWORTHY_INSTANCE;

use crate::authority::jwk_to_crypto_key;
use crate::ect::{CmType, Ect, ElementMap};
use crate::policy::Policy;
use crate::result::Error;
use crate::scheme::Scheme;

pub const PSA_IMPL_ID_TAG: u64 = 600;
pub const PSA_REFVAL_ID_TAG: u64 = 601;
pub const CCA_CONFIG_TAG: u64 = 602;

// Due to how extension are implemented in corim-rs, extension fields are serialized using integers
// (since their string names are not available in CBOR); this means that the evidence claims need
// to use the same values in order for the to match.
pub const SWC_LABEL_LABEL: i64 = 1;
pub const SWC_VERSION_LABEL: i64 = 4;
pub const SWC_SIGNER_ID_LABEL: i64 = 5;
pub const RAW_INT_LABEL: i64 = -1;

pub const LC_UNKNOWN: i64 = 0;
pub const LC_ASSEMBLY_AND_TEST: i64 = 1;
pub const LC_CCA_ROT_PROVISIONING: i64 = 2;
pub const LC_SECURED: i64 = 3;
pub const LC_NON_CCA_PLATFORM_DEBUG: i64 = 4;
pub const LC_RECOVERABLE_CCA_PLATFORM_DEBUG: i64 = 5;
pub const LC_DECOMMISSIONED: i64 = 6;

/// Arm [Confidential Computing
/// Architecture](https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture)
/// attestation scheme. Evidence is composed of plaform and realm components, each evaluated
/// according to its own policy.
#[derive(Debug, Default)]
pub struct CcaScheme;

impl CcaScheme {
    pub fn new() -> Self {
        CcaScheme {}
    }
}

impl Scheme for CcaScheme {
    fn name(&self) -> String {
        "cca".to_string()
    }

    fn profile(&self) -> String {
        "arm-cca".to_string()
    }

    fn match_evidence(&self, evidence: &[u8]) -> bool {
        Evidence::decode(evidence).is_ok()
    }

    fn get_trust_anchor_id<'a>(&self, evidence: &[u8]) -> Result<EnvironmentMap<'a>, Error> {
        let evidence = Evidence::decode(evidence).map_err(Error::custom)?;
        EnvironmentMapBuilder::new()
            .class(
                ClassMapBuilder::default()
                    .class_id(ClassIdTypeChoice::Extension(ExtensionValue::Tag(
                        PSA_IMPL_ID_TAG,
                        Box::new(ExtensionValue::Bytes(Bytes::from(
                            evidence.platform_claims.impl_id.as_slice(),
                        ))),
                    )))
                    .build()
                    .unwrap(),
            )
            .instance(InstanceIdTypeChoice::Ueid(TaggedUeidType::from(
                UeidType::try_from(evidence.platform_claims.inst_id.as_slice())?,
            )))
            .build()
            .map_err(Error::custom)
    }

    fn validate_and_parse_evidence<'a>(
        &self,
        evidence: &[u8],
        trust_anchor: &CryptoKeyTypeChoice<'a>,
    ) -> Result<Vec<Ect<'a>>, Error> {
        let key_bytes: Vec<u8> = match trust_anchor {
            CryptoKeyTypeChoice::Bytes(bytes) => Ok(bytes.into()),
            CryptoKeyTypeChoice::PkixBase64Key(b64key) => {
                let pem_bytes = b64key.as_bytes();
                let jwk_string = crate::util::pem_spki_to_jwk_string(pem_bytes)?;
                Ok(jwk_string.into())
            }
            _ => Err(Error::custom(format!(
                "invalid trust anchor type: {:?}",
                trust_anchor
            ))),
        }?;
        let raw_key = std::str::from_utf8(&key_bytes).map_err(Error::custom)?;

        let evidence = Evidence::decode(evidence).map_err(Error::custom)?;
        let ta_store = create_store(&evidence, raw_key).map_err(Error::custom)?;

        cca_to_ects(evidence, ta_store).map_err(Error::custom)
    }

    fn get_policies(&self) -> Vec<crate::policy::Policy> {
        vec![
            Policy {
                id: "platform".to_string(),
                path: "platform.rego".to_string(),
                text: include_str!("platform.rego").to_string(),
            },
            Policy {
                id: "realm".to_string(),
                path: "realm.rego".to_string(),
                text: include_str!("realm.rego").to_string(),
            },
        ]
    }
}

// there is no way to simply use a key to verify the signature on the Evidence. We need to
// create a store containing the key tying it to the evidence via its implementation and
// instance IDs.
fn create_store(evidence: &Evidence, key: &str) -> Result<MemoTrustAnchorStore, Error> {
    let raw_key: Box<serde_json::value::RawValue> =
        serde_json::from_str(key).map_err(Error::custom)?;

    let store_contents = vec![Cpak {
        raw_pkey: raw_key,
        pkey: None,
        impl_id: evidence.platform_claims.impl_id,
        inst_id: evidence.platform_claims.inst_id,
    }];

    let json = serde_json::to_string(&store_contents).map_err(Error::custom)?;

    let mut store = MemoTrustAnchorStore::new();

    store.load_json(json.as_str()).map_err(Error::custom)?;

    Ok(store)
}

fn cca_to_ects<'a, S: ITrustAnchorStore>(
    mut evidence: Evidence,
    ta_store: S,
) -> Result<Vec<Ect<'a>>, Error> {
    evidence.verify(&ta_store).map_err(Error::custom)?;
    let (plat_tv, realm_tv) = evidence.get_trust_vectors();
    if plat_tv.instance_identity != TRUSTWORTHY_INSTANCE
        || realm_tv.instance_identity != TRUSTWORTHY_INSTANCE
    {
        return Err(Error::SignatureValidation);
    }

    let inst_id = evidence.platform_claims.inst_id;
    let authority = match ta_store.lookup(&inst_id) {
        None => Err(Error::custom("could not find CPAK")),
        Some(cpak) => match cpak.pkey {
            Some(key) => jwk_to_crypto_key(key),
            None => Err(Error::custom("no JWK inside CPAK")),
        },
    }?;

    let mut plat_ect = platform_to_ect(&evidence.platform_claims)?;
    plat_ect.add_authority(authority.clone());

    let mut realm_ect = realm_to_ect(&evidence.realm_claims)?;
    realm_ect.add_authority(authority);

    Ok(vec![plat_ect, realm_ect])
}

fn platform_to_ect<'a>(plat: &Platform) -> Result<Ect<'a>, Error> {
    let mut ect = Ect::new(CmType::Evidence);

    ect.set_environment(
        EnvironmentMapBuilder::default()
            .class(
                ClassMapBuilder::default()
                    .class_id(ClassIdTypeChoice::Extension(ExtensionValue::Tag(
                        PSA_IMPL_ID_TAG,
                        Box::new(ExtensionValue::Bytes(Bytes::from(plat.impl_id.as_slice()))),
                    )))
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap(),
    );

    ect.set_profile(ProfileTypeChoice::Uri(Uri::from(Text::from(
        plat.profile.to_string(),
    ))));

    let plat_hash_alg = HashAlgorithm::try_from(plat.hash_alg.as_str()).map_err(Error::custom)?;

    let cfg_element = ElementMap {
        mkey: Some(corim_rs::triples::MeasuredElementTypeChoice::Extension(
            ExtensionValue::Tag(
                CCA_CONFIG_TAG,
                Box::new(ExtensionValue::Text("cfg v1.0.0".into())),
            ),
        )),
        mval: MeasurementValuesMapBuilder::default()
            .raw(RawValueType {
                raw_value: RawValueTypeChoice::TaggedBytes(TaggedBytes::from(Bytes::from(
                    plat.config.clone(),
                ))),
                raw_value_mask: None,
            })
            .build()
            .map_err(Error::custom)?,
    };

    ect.add_element(cfg_element);

    let lifecycle_elt = ElementMap {
        mkey: Some(corim_rs::triples::MeasuredElementTypeChoice::Tstr(
            "lifecycle".into(),
        )),
        mval: MeasurementValuesMapBuilder::default()
            .add_extension(
                RAW_INT_LABEL.into(),
                ExtensionValue::Int(
                    match plat.lifecycle {
                        0x0000..=0x00ff => Ok(LC_UNKNOWN),
                        0x1000..=0x10ff => Ok(LC_ASSEMBLY_AND_TEST),
                        0x2000..=0x20ff => Ok(LC_CCA_ROT_PROVISIONING),
                        0x3000..=0x30ff => Ok(LC_SECURED),
                        0x4000..=0x40ff => Ok(LC_NON_CCA_PLATFORM_DEBUG),
                        0x5000..=0x50ff => Ok(LC_RECOVERABLE_CCA_PLATFORM_DEBUG),
                        0x6000..=0x60ff => Ok(LC_DECOMMISSIONED),
                        lc => Err(Error::custom(format!("invalid lifecycle value: {}", lc))),
                    }?
                    .into(),
                ),
            )
            .build()
            .map_err(Error::custom)?,
    };

    ect.add_element(lifecycle_elt);

    for sw_comp in plat.sw_components.iter() {
        let mut id_map: BTreeMap<Label, ExtensionValue> = BTreeMap::new();

        if let Some(mtyp) = &sw_comp.mtyp {
            id_map.insert(
                Label::Int(SWC_LABEL_LABEL.into()),
                ExtensionValue::Text(mtyp.clone().into()),
            );
        }

        if let Some(version) = &sw_comp.version {
            id_map.insert(
                Label::Int(SWC_VERSION_LABEL.into()),
                ExtensionValue::Text(version.clone().into()),
            );
        }

        id_map.insert(
            Label::Int(SWC_SIGNER_ID_LABEL.into()),
            ExtensionValue::Bytes(sw_comp.signer_id.clone().into()),
        );

        let element = ElementMap {
            mkey: Some(corim_rs::triples::MeasuredElementTypeChoice::Extension(
                ExtensionValue::Tag(PSA_REFVAL_ID_TAG, Box::new(ExtensionValue::Map(id_map))),
            )),
            mval: MeasurementValuesMapBuilder::default()
                .digest(vec![Digest {
                    alg: match &sw_comp.hash_alg {
                        Some(cca_alg) => {
                            HashAlgorithm::try_from(cca_alg.as_str()).map_err(Error::custom)
                        }
                        None => Ok(plat_hash_alg.clone()),
                    }?,
                    val: sw_comp.mval.clone().into(),
                }])
                .build()
                .map_err(Error::custom)?,
        };

        ect.add_element(element);
    }

    Ok(ect)
}

fn realm_to_ect<'a>(realm: &Realm) -> Result<Ect<'a>, Error> {
    let mut ect = Ect::new(CmType::Evidence);

    ect.set_environment(
        EnvironmentMapBuilder::default()
            .instance(InstanceIdTypeChoice::Bytes(TaggedBytes::from(Bytes::from(
                realm.rim.clone(),
            ))))
            .build()
            .unwrap(),
    );

    ect.set_profile(ProfileTypeChoice::Uri(Uri::from(Text::from(
        realm.profile.to_string(),
    ))));

    let hash_alg = HashAlgorithm::try_from(realm.hash_alg.as_str()).map_err(Error::custom)?;

    let mut regs_map = BTreeMap::from([(
        Ulabel::Text("rim".into()),
        vec![Digest {
            alg: hash_alg.clone(),
            val: Bytes::from(realm.rim.as_slice()),
        }],
    )]);

    for (i, rem) in realm.rem.iter().enumerate() {
        regs_map.insert(
            Ulabel::Text(format!("rem{i}").into()),
            vec![Digest {
                alg: hash_alg.clone(),
                val: Bytes::from(rem.as_slice()),
            }],
        );
    }

    ect.add_element(ElementMap {
        mkey: None,
        mval: MeasurementValuesMapBuilder::default()
            .integrity_registers(IntegrityRegisters(regs_map))
            .build()
            .map_err(Error::custom)?,
    });

    Ok(ect)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn evidence_to_ect() {
        let token = include_bytes!("../../../test/cca/cca-token-01.cbor");
        let raw_key = include_str!("../../../test/cca/pkey.json");

        let scheme = CcaScheme::new();

        let key = CryptoKeyTypeChoice::Bytes(raw_key.as_bytes().into());

        let ects = scheme
            .validate_and_parse_evidence(token.as_slice(), &key)
            .unwrap();
        assert_eq!(ects.len(), 2);
    }
}
