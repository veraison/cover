use std::fmt::Display;

use corim_rs::{
    corim::ProfileTypeChoice,
    triples::{
        CryptoKeyTypeChoice, EnvironmentMap, MeasuredElementTypeChoice, MeasurementValuesMap,
    },
};
use serde::{Deserialize, Serialize, de};

use crate::result::Error;

/// Indicates the intended use/type of contents of an [Ect].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmType {
    ReferenceValues,
    Endorsements,
    Evidence,
    AttestationResults,
    Verifier,
    Policy,
}

impl TryFrom<&str> for CmType {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "reference-values" => Ok(CmType::ReferenceValues),
            "endorsements" => Ok(CmType::Endorsements),
            "evidence" => Ok(CmType::Evidence),
            "attestation-results" => Ok(CmType::AttestationResults),
            "verifier" => Ok(CmType::Verifier),
            "policy" => Ok(CmType::Policy),
            s => Err(Error::invalid_value(
                s.to_string(),
                "a valid conceptual message type name",
            )),
        }
    }
}

impl TryFrom<i64> for CmType {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CmType::ReferenceValues),
            1 => Ok(CmType::Endorsements),
            2 => Ok(CmType::Evidence),
            3 => Ok(CmType::AttestationResults),
            4 => Ok(CmType::Verifier),
            5 => Ok(CmType::Policy),
            n => Err(Error::invalid_value(
                n,
                "an integer 0-5 indicating the conceptual message type",
            )),
        }
    }
}

impl From<&CmType> for i64 {
    fn from(value: &CmType) -> Self {
        match value {
            CmType::ReferenceValues => 0,
            CmType::Endorsements => 1,
            CmType::Evidence => 2,
            CmType::AttestationResults => 3,
            CmType::Verifier => 4,
            CmType::Policy => 5,
        }
    }
}

impl Display for CmType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            CmType::ReferenceValues => "reference-values",
            CmType::Endorsements => "endorsements",
            CmType::Evidence => "evidence",
            CmType::AttestationResults => "attestation-results",
            CmType::Verifier => "verifier",
            CmType::Policy => "policy",
        };

        f.write_str(text)
    }
}

impl Serialize for CmType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            i64::from(self).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for CmType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .as_str()
                .try_into()
                .map_err(de::Error::custom)
        } else {
            i64::deserialize(deserializer)?
                .try_into()
                .map_err(de::Error::custom)
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElementMap<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    pub mval: MeasurementValuesMap<'a>,
}

/// Environment-claims tuple. This associates a set of claims with an environment and keeps track
/// of the authority that originated the claims. [Ect]s are used in several different ways during
/// verification. An [Ect]'s intended use is indicated by the `cm_type` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ect<'a> {
    /// The target environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentMap<'a>>,
    /// The set of elements contained within the target environment.
    #[serde(rename = "element-list", skip_serializing_if = "Option::is_none")]
    pub element_list: Option<Vec<ElementMap<'a>>>,
    /// Authority that issued this ECT
    pub authority: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    /// Conceptual Message Type that identifies the type of Conceptual Message that originated this
    /// Environment-Claims Tuple.
    #[serde(rename = "cm-type")]
    pub cm_type: CmType,
    /// The profile associated with this tuple.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileTypeChoice<'a>>,
}

impl<'a> Ect<'a> {
    pub fn new(cm_type: CmType) -> Self {
        Ect {
            cm_type,
            environment: None,
            authority: None,
            element_list: None,
            profile: None,
        }
    }

    pub fn add_element(&mut self, elt: ElementMap<'a>) {
        if let Some(elt_list) = self.element_list.as_mut() {
            elt_list.push(elt);
        } else {
            self.element_list = Some(vec![elt]);
        }
    }

    pub fn add_authority(&mut self, authority: CryptoKeyTypeChoice<'a>) {
        if let Some(auth_list) = self.authority.as_mut() {
            auth_list.push(authority);
        } else {
            self.authority = Some(vec![authority]);
        }
    }

    pub fn set_environment(&mut self, env: EnvironmentMap<'a>) {
        self.environment = Some(env);
    }

    pub fn set_profile(&mut self, profile: ProfileTypeChoice<'a>) {
        self.profile = Some(profile);
    }
}

/// Allows construction of an [Ect] by chaining method calls.
#[derive(Default)]
pub struct EctBuilder<'a> {
    environment: Option<EnvironmentMap<'a>>,
    element_list: Option<Vec<ElementMap<'a>>>,
    authority: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    cm_type: Option<CmType>,
    profile: Option<ProfileTypeChoice<'a>>,
}

impl<'a> EctBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [CmType] of the [Ect].
    pub fn cm_type(mut self, cm_type: CmType) -> Self {
        self.cm_type = Some(cm_type);
        self
    }

    /// Set the element list of the [Ect].
    pub fn element_list(mut self, element_list: Vec<ElementMap<'a>>) -> Self {
        self.element_list = Some(element_list);
        self
    }

    /// Add an element to the [Ect]'s element list, creating the list if doesn't already exit.
    pub fn add_element(mut self, elt: ElementMap<'a>) -> Self {
        if let Some(elt_list) = self.element_list.as_mut() {
            elt_list.push(elt);
        } else {
            self.element_list = Some(vec![elt]);
        }
        self
    }

    /// Set the authority of the [Ect].
    pub fn authority(mut self, authority: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Add a key to the authority of the [Ect].
    pub fn add_authority(mut self, authority: CryptoKeyTypeChoice<'a>) -> Self {
        if let Some(auth_list) = self.authority.as_mut() {
            auth_list.push(authority);
        } else {
            self.authority = Some(vec![authority]);
        }
        self
    }

    /// Set the environment of the [Ect].
    pub fn environment(mut self, env: EnvironmentMap<'a>) -> Self {
        self.environment = Some(env);
        self
    }

    /// Set the profile of the [Ect].
    pub fn profile(mut self, profile: ProfileTypeChoice<'a>) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Construct the [Ect] from the values set with then [EctBuilder].
    pub fn build(self) -> Result<Ect<'a>, Error> {
        if self.cm_type.is_none() {
            return Err(Error::missing_field("Ect", "cm_type"));
        }

        Ok(Ect {
            cm_type: self.cm_type.unwrap(),
            authority: self.authority,
            environment: self.environment,
            profile: self.profile,
            element_list: self.element_list,
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use super::*;
    use corim_rs::{
        core::{
            Bytes, CertThumbprintType, Digest, ExtensionValue, HashAlgorithm, Label, Text, Uri,
        },
        corim::ProfileTypeChoice,
        numbers::Integer,
        triples::{
            ClassIdTypeChoice, ClassMapBuilder, EnvironmentMapBuilder, MeasurementValuesMapBuilder,
        },
    };

    const PSA_IMPL_ID: u64 = 600;
    const PSA_REFVAL_ID: u64 = 601;
    const PSA_REFVAL_LABEL: Integer = Integer(1);
    const PSA_REFVAL_VERSION: Integer = Integer(4);
    const PSA_REFVAL_SIGNER_ID: Integer = Integer(5);

    #[test]
    fn ect_serialize() {
        let ect: Ect = Ect {
            cm_type: CmType::Endorsements,
            environment: Some(
                EnvironmentMapBuilder::default()
                    .class(
                        ClassMapBuilder::default()
                            .class_id(ClassIdTypeChoice::Extension(ExtensionValue::Tag(
                                PSA_IMPL_ID,
                                Box::new(ExtensionValue::Bytes(Bytes::from(vec![
                                    0x61, 0x63, 0x6d, 0x65, 0x2d, 0x69, 0x6d, 0x70, 0x6c, 0x65,
                                    0x6d, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d,
                                    0x69, 0x64, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                    0x30, 0x31,
                                ]))),
                            )))
                            .layer(0.into())
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            ),
            authority: Some(vec![CryptoKeyTypeChoice::CertThumbprint(
                CertThumbprintType::from(Digest {
                    alg: HashAlgorithm::Sha256,
                    val: Bytes::from([0x01, 0x02, 0x03].as_slice()),
                }),
            )]),
            element_list: Some(vec![ElementMap {
                mkey: Some(MeasuredElementTypeChoice::Extension(ExtensionValue::Tag(
                    PSA_REFVAL_ID,
                    Box::new(ExtensionValue::Map(BTreeMap::from([
                        (
                            Label::Int(PSA_REFVAL_LABEL),
                            ExtensionValue::Text("BL".into()),
                        ),
                        (
                            Label::Int(PSA_REFVAL_VERSION),
                            ExtensionValue::Text("1.2.3".into()),
                        ),
                        (
                            Label::Int(PSA_REFVAL_SIGNER_ID),
                            ExtensionValue::Bytes(Bytes::from(vec![
                                0xac, 0xbb, 0x11, 0xc7, 0xe4, 0xda, 0x21, 0x72, 0x05, 0x52, 0x3c,
                                0xe4, 0xce, 0x1a, 0x24, 0x5a, 0xe1, 0xa2, 0x39, 0xae, 0x3c, 0x6b,
                                0xfd, 0x9e, 0x78, 0x71, 0xf7, 0xe5, 0xd8, 0xba, 0xe8, 0x6b,
                            ])),
                        ),
                    ]))),
                ))),
                mval: MeasurementValuesMapBuilder::default()
                    .digest(vec![Digest {
                        alg: HashAlgorithm::Sha256,
                        val: Bytes::from(vec![
                            0x02, 0x63, 0x82, 0x99, 0x89, 0xb6, 0xfd, 0x95, 0x4f, 0x72, 0xba, 0xaf,
                            0x2f, 0xc6, 0x4b, 0xc2, 0xe2, 0xf0, 0x1d, 0x69, 0x2d, 0x4d, 0xe7, 0x29,
                            0x86, 0xea, 0x80, 0x8f, 0x6e, 0x99, 0x81, 0x3f,
                        ]),
                    }])
                    .build()
                    .unwrap(),
            }]),
            profile: Some(ProfileTypeChoice::Uri(Uri::from(Text::from(
                "http://arm.com/psa/iot/1",
            )))),
        };

        let actual = serde_json::to_string(&ect).unwrap();

        let expected = r#"{"environment":{"class":{"class-id":{"tag":600,"value":"[base64]:YWNtZS1pbXBsZW1lbnRhdGlvbi1pZC0wMDAwMDAwMDE"},"layer":0}},"element-list":[{"mkey":{"tag":601,"value":{"1":"BL","4":"1.2.3","5":"[base64]:rLsRx-TaIXIFUjzkzhokWuGiOa48a_2eeHH35di66Gs"}},"mval":{"digests":["sha-256;AmOCmYm2_ZVPcrqvL8ZLwuLwHWktTecphuqAj26ZgT8"]}}],"authority":[{"type":"cert-thumbprint","value":"sha-256;AQID"}],"cm-type":"endorsements","profile":{"type":"uri","value":"http://arm.com/psa/iot/1"}}"#;

        assert_eq!(actual, expected);
    }

    #[test]
    fn ect_deserialize() {
        let text = std::fs::read_to_string("test/policy/cca-platform/input.json").unwrap();
        let ects: Vec<Ect> = serde_json::from_str(&text).unwrap();

        assert_eq!(ects.len(), 4);
        assert_eq!(ects[0].cm_type, CmType::Evidence);

        let digest = &ects[0].element_list.as_ref().unwrap()[2]
            .mval
            .digests
            .as_ref()
            .unwrap()[0];

        assert_eq!(
            digest,
            &Digest {
                alg: HashAlgorithm::Sha256,
                val: Bytes::from(vec![
                    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b,
                    0x0a, 0x09, 0x08, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x1f, 0x1e,
                    0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
                ]),
            }
        );
    }
}
