use std::collections::HashSet;
use std::fmt::Display;
use std::hash::{Hash, Hasher};

use corim_rs::{
    corim::ProfileTypeChoice,
    triples::{
        CryptoKeyTypeChoice, EnvironmentMap, MeasuredElementTypeChoice, MeasurementMap,
        MeasurementValuesMap,
    },
};
use log::debug;
use serde::{Deserialize, Serialize, de};

use crate::result::Error;

/// Indicates the intended use/type of contents of an [Ect].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmType {
    ReferenceValues,
    Endorsements,
    Evidence,
}

impl TryFrom<&str> for CmType {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "reference-values" => Ok(CmType::ReferenceValues),
            "endorsements" => Ok(CmType::Endorsements),
            "evidence" => Ok(CmType::Evidence),
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
        }
    }
}

impl Display for CmType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            CmType::ReferenceValues => "reference-values",
            CmType::Endorsements => "endorsements",
            CmType::Evidence => "evidence",
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

// helper function to skip serialization of empty vector
fn vec_is_empty_or_none<T>(vec: &Option<Vec<T>>) -> bool {
    vec.as_ref().is_none_or(Vec::is_empty)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElementMap<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    pub mval: MeasurementValuesMap<'a>,
}

// Required for HashSet
impl<'a> Hash for ElementMap<'a> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes).expect("ElementMap should derive Serialize trait");
        bytes.hash(state);
    }
}

impl<'a, 'b> From<&MeasurementMap<'a>> for ElementMap<'b> {
    fn from(value: &MeasurementMap<'a>) -> Self {
        ElementMap {
            mkey: value.mkey.as_ref().map(|k| k.to_fully_owned()),
            mval: value.mval.to_fully_owned(),
        }
    }
}

/// Environment-claims tuple. This associates a set of claims with an environment and keeps track
/// of the authority that originated the claims. [Ect]s are used in several different ways during
/// verification.
/// An [Ect]'s intended use is indicated by the `cmtype` field.
///
/// Top level enum to contain all types of Ects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Ect<'a> {
    Element(ElementEct<'a>),
    Key(KeyEct<'a>),
}

impl<'a> Ect<'a> {
    pub fn as_element_ect(&self) -> Option<&ElementEct<'a>> {
        match self {
            Ect::Element(ect) => Some(ect),
            Ect::Key(_) => None,
        }
    }

    pub fn as_key_ect(&self) -> Option<&KeyEct<'a>> {
        match self {
            Ect::Key(ect) => Some(ect),
            Ect::Element(_) => None,
        }
    }

    /// Merge similar ECTs according to the definition defined in draft-ietf-rats-corim-11.
    pub fn merge_similar_ects(ects: Vec<Self>) -> Vec<Self> {
        let mut element_ects: Vec<ElementEct<'_>> = Vec::with_capacity(ects.len());
        let mut non_element_ects: Vec<Ect<'a>> = Vec::new();

        for ect in ects {
            match ect {
                Ect::Element(element_ect) => element_ects.push(element_ect),
                ect => non_element_ects.push(ect),
            }
        }
        let element_ects_len = element_ects.len();
        let mut merged_element_ects: Vec<ElementEct<'a>> = Vec::with_capacity(element_ects_len);
        for e_ect in element_ects {
            let mut matched = false;

            for existing in &mut merged_element_ects {
                if existing.merge_with(&e_ect) {
                    matched = true;
                    break;
                }
            }

            if !matched {
                merged_element_ects.push(e_ect);
            }
        }
        debug!(
            "{} duplicate Element ECTs are merged",
            element_ects_len - merged_element_ects.len()
        );
        let mut merged: Vec<Ect<'a>> = merged_element_ects.into_iter().map(Ect::Element).collect();
        merged.extend(non_element_ects);
        merged
    }
}

impl<'a> From<ElementEct<'a>> for Ect<'a> {
    fn from(value: ElementEct<'a>) -> Self {
        Ect::Element(value)
    }
}

impl<'a> From<KeyEct<'a>> for Ect<'a> {
    fn from(value: KeyEct<'a>) -> Self {
        Ect::Key(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EctCommon<'a> {
    /// The target environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentMap<'a>>,
    /// Authority that issued this ECT
    #[serde(skip_serializing_if = "vec_is_empty_or_none")]
    pub authority: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    /// The profile associated with this tuple.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileTypeChoice<'a>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ElementEct<'a> {
    #[serde(flatten)]
    pub ect_common: EctCommon<'a>,
    /// The set of elements contained within the target environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub element_list: Option<Vec<ElementMap<'a>>>,
    /// Conceptual Message Type that identifies the type of Conceptual Message that originated this
    /// Environment-Claims Tuple.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmtype: Option<CmType>,
}

impl<'a> ElementEct<'a> {
    pub fn new() -> Self {
        ElementEct::default()
    }

    /// Set type of message, [ElementEct] is representing.
    pub fn cmtype(mut self, cmtype: CmType) -> Self {
        self.cmtype = Some(cmtype);
        self
    }

    /// Set environment Ids inside [ElementEct] for identification
    pub fn environment(mut self, env: EnvironmentMap<'a>) -> Self {
        self.ect_common.environment = Some(env);
        self
    }

    /// Set eat profile of [ElementEct]
    pub fn profile(mut self, profile: ProfileTypeChoice<'a>) -> Self {
        self.ect_common.profile = Some(profile);
        self
    }

    /// Set the authority of the [ElementEct].
    pub fn authority(mut self, authority: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.ect_common.authority = Some(authority);
        self
    }

    /// Insert measured elements into [ElementEct]
    pub fn add_element(&mut self, elt: ElementMap<'a>) {
        if let Some(elt_list) = self.element_list.as_mut() {
            elt_list.push(elt);
        } else {
            self.element_list = Some(vec![elt]);
        }
    }

    /// Add a key to the authority of the [ElementEct].
    pub fn add_authority(&mut self, authority: CryptoKeyTypeChoice<'a>) {
        if let Some(auth_list) = self.ect_common.authority.as_mut() {
            auth_list.push(authority);
        } else {
            self.ect_common.authority = Some(vec![authority]);
        }
    }

    /// Getter method to obtain signig authority (public key) of [ElementEct]
    pub fn get_authority(&self) -> &Option<Vec<CryptoKeyTypeChoice<'a>>> {
        &self.ect_common.authority
    }

    /// Getter method to obtain environment map [ElementEct]
    pub fn get_environment(&self) -> &Option<EnvironmentMap<'a>> {
        &self.ect_common.environment
    }

    /// Getter method to obtain Eat profile of [ElementEct]
    pub fn get_profile(&self) -> &Option<ProfileTypeChoice<'a>> {
        &self.ect_common.profile
    }

    /// Merge Rule:
    /// If two Element ECTs have the same environment, cmtype, authority and profile
    /// then their element-lists are merged. Two element-maps containing duplicate codepoints
    /// and with non-equivalent measurement values MUST NOT be merged. These are effectively
    /// two different acceptable states that need to be processed separately.
    pub fn merge_with(&mut self, other: &Self) -> bool {
        if !self.is_matching(other) {
            return false;
        }

        if other.element_list.as_ref().is_none_or(Vec::is_empty) {
            debug!("other element list is empty, nothing to merge");
            return true;
        };

        match self.element_list.as_mut() {
            // self has no elements — just clone other's list directly
            None => {
                self.element_list = other.element_list.clone();
            }
            Some(self_list) => {
                // cloned() is required because mutuable reference can not be used as
                // immutable which is required for creating hashset.
                let existing: HashSet<ElementMap> = self_list.iter().cloned().collect();

                // Only push elements not already in self
                for other_elt in other.element_list.as_ref().unwrap() {
                    if !existing.contains(other_elt) {
                        self_list.push(other_elt.clone());
                    }
                }
            }
        }
        true
    }

    fn is_matching(&self, other: &Self) -> bool {
        self.get_environment() == other.get_environment()
            && self.cmtype == other.cmtype
            && self.get_authority() == other.get_authority()
            && self.get_profile() == other.get_profile()
    }
}

/// Allows construction of an [ElementEct] by chaining method calls.
#[derive(Default)]
pub struct ElementEctBuilder<'a> {
    ect_common: EctCommon<'a>,
    element_list: Option<Vec<ElementMap<'a>>>,
    cmtype: Option<CmType>,
}

impl<'a> ElementEctBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [CmType] of the [ElementEct].
    pub fn cmtype(mut self, cmtype: CmType) -> Self {
        self.cmtype = Some(cmtype);
        self
    }

    /// Set the environment of the [ElementEct].
    pub fn environment(mut self, env: EnvironmentMap<'a>) -> Self {
        self.ect_common.environment = Some(env);
        self
    }

    /// Set the profile of the [ElementEct].
    pub fn profile(mut self, profile: ProfileTypeChoice<'a>) -> Self {
        self.ect_common.profile = Some(profile);
        self
    }

    /// Set the authority of the [ElementEct].
    pub fn authority(mut self, authority: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.ect_common.authority = Some(authority);
        self
    }

    /// Set the element list of the [ElementEct].
    pub fn element_list(mut self, element_list: Vec<ElementMap<'a>>) -> Self {
        self.element_list = Some(element_list);
        self
    }

    /// Add a key to the authority of the [ElementEct].
    pub fn add_authority(&mut self, authority: CryptoKeyTypeChoice<'a>) {
        if let Some(auth_list) = self.ect_common.authority.as_mut() {
            auth_list.push(authority);
        } else {
            self.ect_common.authority = Some(vec![authority]);
        }
    }

    /// Add an element to the [ElementEct]'s element list, creating the list if doesn't already exit.
    pub fn add_element(&mut self, elt: ElementMap<'a>) {
        if let Some(elt_list) = self.element_list.as_mut() {
            elt_list.push(elt);
        } else {
            self.element_list = Some(vec![elt]);
        }
    }

    /// Construct the [Element-Ect] from the values set with then [ElementEctBuilder].
    pub fn build(self) -> Result<ElementEct<'a>, Error> {
        Ok(ElementEct {
            cmtype: self.cmtype,
            ect_common: self.ect_common,
            element_list: self.element_list,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyType {
    AttestKey,
    IdentityKey,
}

impl TryFrom<&str> for KeyType {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "attest-key" => Ok(Self::AttestKey),
            "identity-key" => Ok(Self::IdentityKey),
            s => Err(Error::invalid_value(
                s.to_string(),
                "a valid KeyType: \"attest-key\" or \"identity-key\"",
            )),
        }
    }
}

impl TryFrom<i64> for KeyType {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AttestKey),
            1 => Ok(Self::IdentityKey),
            n => Err(Error::invalid_value(
                n,
                "an integer 0-1 indicating the key ECT type",
            )),
        }
    }
}

impl From<&KeyType> for i64 {
    fn from(value: &KeyType) -> Self {
        match value {
            KeyType::AttestKey => 0,
            KeyType::IdentityKey => 1,
        }
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            KeyType::AttestKey => "attest-key",
            KeyType::IdentityKey => "identity-key",
        };

        f.write_str(text)
    }
}

impl Serialize for KeyType {
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

impl<'de> Deserialize<'de> for KeyType {
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct KeyEct<'a> {
    #[serde(flatten)]
    pub ect_common: EctCommon<'a>,
    /// The key identifier within the target environment.
    /// "mkey" in comid triple is named as key-id in ECT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<MeasuredElementTypeChoice<'a>>,
    /// The set of keys associated with the environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_list: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    /// The semantic type of the keys in the tuple.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyType>,
}

impl<'a> KeyEct<'a> {
    pub fn new() -> Self {
        KeyEct::default()
    }

    pub fn authority(mut self, authority: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.ect_common.authority = Some(authority);
        self
    }

    pub fn environment(mut self, env: EnvironmentMap<'a>) -> Self {
        self.ect_common.environment = Some(env);
        self
    }

    pub fn profile(mut self, profile: ProfileTypeChoice<'a>) -> Self {
        self.ect_common.profile = Some(profile);
        self
    }

    pub fn key_id(mut self, key_id: MeasuredElementTypeChoice<'a>) -> Self {
        self.key_id = Some(key_id);
        self
    }

    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = Some(key_type);
        self
    }

    pub fn key_list(mut self, key_list: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.key_list = Some(key_list);
        self
    }

    pub fn add_authority(&mut self, authority: CryptoKeyTypeChoice<'a>) {
        if let Some(auth_list) = self.ect_common.authority.as_mut() {
            auth_list.push(authority);
        } else {
            self.ect_common.authority = Some(vec![authority]);
        }
    }

    pub fn add_key(&mut self, key: CryptoKeyTypeChoice<'a>) {
        if let Some(keys) = self.key_list.as_mut() {
            keys.push(key);
        } else {
            self.key_list = Some(vec![key]);
        }
    }

    pub fn get_authority(&self) -> &Option<Vec<CryptoKeyTypeChoice<'a>>> {
        &self.ect_common.authority
    }

    pub fn get_environment(&self) -> &Option<EnvironmentMap<'a>> {
        &self.ect_common.environment
    }

    pub fn get_profile(&self) -> &Option<ProfileTypeChoice<'a>> {
        &self.ect_common.profile
    }
}

#[derive(Default)]
pub struct KeyEctBuilder<'a> {
    ect_common: EctCommon<'a>,
    // "mkey" in comid triple is named as key-id in ECT
    key_id: Option<MeasuredElementTypeChoice<'a>>,
    key_list: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    key_type: Option<KeyType>,
}

impl<'a> KeyEctBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = Some(key_type);
        self
    }

    pub fn authority(mut self, authority: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.ect_common.authority = Some(authority);
        self
    }
    pub fn environment(mut self, env: EnvironmentMap<'a>) -> Self {
        self.ect_common.environment = Some(env);
        self
    }

    pub fn profile(mut self, profile: ProfileTypeChoice<'a>) -> Self {
        self.ect_common.profile = Some(profile);
        self
    }

    pub fn key_id(mut self, key_id: MeasuredElementTypeChoice<'a>) -> Self {
        self.key_id = Some(key_id);
        self
    }

    pub fn key_list(mut self, key_list: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.key_list = Some(key_list);
        self
    }

    pub fn add_authority(&mut self, authority: CryptoKeyTypeChoice<'a>) {
        if let Some(auth_list) = self.ect_common.authority.as_mut() {
            auth_list.push(authority);
        } else {
            self.ect_common.authority = Some(vec![authority]);
        }
    }

    pub fn add_key(&mut self, key: CryptoKeyTypeChoice<'a>) {
        if let Some(keys) = self.key_list.as_mut() {
            keys.push(key);
        } else {
            self.key_list = Some(vec![key]);
        }
    }

    pub fn build(self) -> Result<KeyEct<'a>, Error> {
        Ok(KeyEct {
            ect_common: self.ect_common,
            key_id: self.key_id,
            key_list: self.key_list,
            key_type: self.key_type,
        })
    }
}

// TODO: Implement Domain Membership (M)-ECT and Trust Dependency (T)-ECT

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
    fn element_map_hash() {
        let digest_a = Digest {
            alg: HashAlgorithm::Sha256,
            val: Bytes::from(vec![0x0a, 0x0b, 0x0c]),
        };
        let digest_b = Digest {
            alg: HashAlgorithm::Sha256,
            val: Bytes::from(vec![0x0d, 0x0e, 0x0f]),
        };
        let digest_c = Digest {
            alg: HashAlgorithm::Sha256,
            val: Bytes::from(vec![0x0c, 0x0a, 0x0b]),
        };

        let el_map1 = ElementMap {
            mkey: Some("cca.item".into()),
            mval: MeasurementValuesMapBuilder::default()
                .digest(vec![digest_a.clone()])
                .build()
                .unwrap(),
        };

        let el_map2 = ElementMap {
            mkey: Some("cca.item".into()),
            mval: MeasurementValuesMapBuilder::default()
                .digest(vec![digest_b.clone()])
                .build()
                .unwrap(),
        };
        let el_map3 = ElementMap {
            mkey: Some("cca.other".into()),
            mval: MeasurementValuesMapBuilder::default()
                .digest(vec![digest_b.clone()])
                .build()
                .unwrap(),
        };

        let el_map4 = ElementMap {
            mkey: Some("cca.other".into()),
            mval: MeasurementValuesMapBuilder::default()
                .digest(vec![digest_c.clone()])
                .build()
                .unwrap(),
        };

        let el_list = [el_map1.clone(), el_map2.clone(), el_map3.clone()];

        let el_hashset: HashSet<&ElementMap> = el_list.iter().collect();
        assert!(el_hashset.contains(&el_map1));
        assert!(el_hashset.contains(&el_map2));
        assert!(el_hashset.contains(&el_map3));
        assert!(!el_hashset.contains(&el_map4));
    }

    #[test]
    fn element_ect_serialize() {
        let ect: ElementEct = ElementEct {
            cmtype: Some(CmType::Endorsements),
            ect_common: EctCommon {
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
                profile: Some(ProfileTypeChoice::Uri(Uri::from(Text::from(
                    "http://arm.com/psa/iot/1",
                )))),
            },
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
        };

        let actual = serde_json::to_string(&ect).unwrap();
        println!("{}:", actual);

        let expected = r#"{"environment":{"class":{"class-id":{"tag":600,"value":"[base64]:YWNtZS1pbXBsZW1lbnRhdGlvbi1pZC0wMDAwMDAwMDE"},"layer":0}},"authority":[{"type":"cert-thumbprint","value":"sha-256;AQID"}],"profile":{"type":"uri","value":"http://arm.com/psa/iot/1"},"element-list":[{"mkey":{"tag":601,"value":{"1":"BL","4":"1.2.3","5":"[base64]:rLsRx-TaIXIFUjzkzhokWuGiOa48a_2eeHH35di66Gs"}},"mval":{"digests":["sha-256;AmOCmYm2_ZVPcrqvL8ZLwuLwHWktTecphuqAj26ZgT8"]}}],"cmtype":"endorsements"}"#;

        assert_eq!(actual, expected);
    }

    #[test]
    fn element_ect_deserialize() {
        let text = std::fs::read_to_string("test/policy/cca-platform/input.json").unwrap();
        let ects: Vec<ElementEct> = serde_json::from_str(&text).unwrap();

        assert_eq!(ects.len(), 4);
        assert_eq!(ects[0].cmtype, Some(CmType::Evidence));

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

    #[test]
    fn element_ect_merge_rule() {
        let env = EnvironmentMapBuilder::default()
            .class(
                ClassMapBuilder::default()
                    .class_id(ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3]).into()))
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let profile = ProfileTypeChoice::Uri(Uri::from(Text::from("https://example.test/profile")));
        let authority = vec![CryptoKeyTypeChoice::CertThumbprint(
            CertThumbprintType::from(Digest {
                alg: HashAlgorithm::Sha256,
                val: Bytes::from(vec![0x01, 0x02, 0x03]),
            }),
        )];

        let digest_a = Digest {
            alg: HashAlgorithm::Sha256,
            val: Bytes::from(vec![0x0a, 0x0b, 0x0c]),
        };
        let digest_b = Digest {
            alg: HashAlgorithm::Sha256,
            val: Bytes::from(vec![0x0d, 0x0e, 0x0f]),
        };

        let ect1 = Ect::from(ElementEct {
            ect_common: EctCommon {
                environment: Some(env.clone()),
                authority: Some(authority.clone()),
                profile: Some(profile.clone()),
            },
            element_list: Some(vec![ElementMap {
                mkey: Some("cca.item".into()),
                mval: MeasurementValuesMapBuilder::default()
                    .digest(vec![digest_a.clone()])
                    .build()
                    .unwrap(),
            }]),
            cmtype: Some(CmType::Evidence),
        });

        let ect2 = Ect::from(ElementEct {
            ect_common: EctCommon {
                environment: Some(env.clone()),
                authority: Some(authority.clone()),
                profile: Some(profile.clone()),
            },
            element_list: Some(vec![
                ElementMap {
                    mkey: Some("cca.item".into()),
                    mval: MeasurementValuesMapBuilder::default()
                        .digest(vec![digest_a.clone()])
                        .build()
                        .unwrap(),
                },
                ElementMap {
                    mkey: Some("cca.item".into()),
                    mval: MeasurementValuesMapBuilder::default()
                        .digest(vec![digest_b.clone()])
                        .build()
                        .unwrap(),
                },
                ElementMap {
                    mkey: Some("cca.other".into()),
                    mval: MeasurementValuesMapBuilder::default()
                        .digest(vec![digest_b.clone()])
                        .build()
                        .unwrap(),
                },
            ]),
            cmtype: Some(CmType::Evidence),
        });

        let merged = Ect::merge_similar_ects(vec![ect1, ect2]);

        assert_eq!(merged.len(), 1);
        let merged_ect = &merged[0];
        let items = merged_ect
            .as_element_ect()
            .unwrap()
            .element_list
            .as_ref()
            .unwrap();
        assert_eq!(items.len(), 3);
        assert!(items.iter().any(|i| {
            i.mkey == Some("cca.item".into())
                && i.mval
                    == MeasurementValuesMapBuilder::default()
                        .digest(vec![digest_a.clone()])
                        .build()
                        .unwrap()
        }));
        assert!(items.iter().any(|i| {
            i.mkey == Some("cca.item".into())
                && i.mval
                    == MeasurementValuesMapBuilder::default()
                        .digest(vec![digest_b.clone()])
                        .build()
                        .unwrap()
        }));
        assert!(items.iter().any(|i| {
            i.mkey == Some("cca.other".into())
                && i.mval
                    == MeasurementValuesMapBuilder::default()
                        .digest(vec![digest_b.clone()])
                        .build()
                        .unwrap()
        }));
    }
}
