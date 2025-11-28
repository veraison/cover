use std::collections::BTreeMap;
use std::fmt::Display;
use std::vec::IntoIter;

use corim_rs::{
    AttestKeyTripleRecord, ConciseMidTag, ConciseTagTypeChoice,
    ConditionalEndorsementSeriesTripleRecord, ConditionalEndorsementTripleRecord, Corim,
    CoseKeyOwner, CryptoKeyTypeChoice, EndorsedTripleRecord, ExtensionValue, Label,
    MeasurementValuesMapBuilder, OpensslSigner, ProfileTypeChoice, ReferenceTripleRecord,
};
use serde::{Deserialize, Serialize, de};

use crate::ect::{CmType, Ect, EctBuilder, ElementMap};
use crate::keystore::KeyStore;
use crate::result::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyType {
    AttestKey,
    IdentityKey,
}

impl From<&KeyType> for i64 {
    fn from(value: &KeyType) -> Self {
        match value {
            KeyType::AttestKey => 0,
            KeyType::IdentityKey => 1,
        }
    }
}

impl TryFrom<i64> for KeyType {
    type Error = Error;

    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AttestKey),
            1 => Ok(Self::IdentityKey),
            n => Err(Error::invalid_value(n, "a valid KeyType: 0 or 1")),
        }
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AttestKey => "attest-key",
            Self::IdentityKey => "identity-key",
        })
    }
}

impl TryFrom<&str> for KeyType {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
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

impl Serialize for KeyType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
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
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
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

pub const INTERP_KEYS_EXT_ID: i128 = 65534;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedCryptoKey<'a> {
    pub key: CryptoKeyTypeChoice<'a>,
    #[serde(rename = "key-type")]
    pub key_type: KeyType,
}

impl From<TypedCryptoKey<'_>> for ExtensionValue<'_> {
    fn from(value: TypedCryptoKey) -> Self {
        let mut map: BTreeMap<Label, ExtensionValue> = BTreeMap::new();
        let key_ser = serde_json::to_string(&value.key).unwrap();

        map.insert("key".into(), key_ser.into());
        map.insert("key-type".into(), value.key_type.to_string().into());

        ExtensionValue::Map(map)
    }
}

impl<'a> TryFrom<&ExtensionValue<'a>> for TypedCryptoKey<'a> {
    type Error = Error;

    fn try_from(value: &ExtensionValue<'a>) -> std::result::Result<Self, Self::Error> {
        if let ExtensionValue::Map(map) = value {
            let key_json = map
                .get(&Label::from("key"))
                .ok_or(Error::custom("missing key entry in interp_keys map"))?;

            let key_type_text = map
                .get(&Label::from("key-type"))
                .ok_or(Error::custom("missing key-type entry in interp_keys map"))?;

            let key: CryptoKeyTypeChoice = serde_json::from_str(
                key_json
                    .as_str()
                    .ok_or(Error::custom("invalid key entry"))?,
            )?;

            let key_type: KeyType = KeyType::try_from(
                key_type_text
                    .as_str()
                    .ok_or(Error::custom("invalid key-type entry"))?,
            )?;

            Ok(TypedCryptoKey { key, key_type })
        } else {
            Err(Error::custom(format!("expected map, found {:?}", value)))
        }
    }
}

/// Reference value relation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RvRelation<'a> {
    pub condition: Ect<'a>,
    pub addition: Ect<'a>,
}

impl<'a> RvRelation<'a> {
    pub fn from_reference_triple_record<'b>(
        rvt: &ReferenceTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &Vec<CryptoKeyTypeChoice<'b>>,
    ) -> Result<RvRelation<'a>> {
        let condition: Ect<'a> = EctBuilder::new()
            .cm_type(CmType::ReferenceValues)
            .environment(rvt.ref_env.to_fully_owned())
            .element_list(
                rvt.ref_claims
                    .iter()
                    .map(|e| ElementMap {
                        mkey: e.mkey.as_ref().map(|k| k.to_fully_owned()),
                        mval: e.mval.to_fully_owned(),
                    })
                    .collect(),
            )
            .build()?;

        let addition: Ect<'a> = match profile {
            Some(p) => EctBuilder::new().profile(p.to_fully_owned()),
            None => EctBuilder::new(),
        }
        .cm_type(CmType::ReferenceValues)
        .environment(rvt.ref_env.to_fully_owned())
        .authority(authority.iter().map(|v| v.to_fully_owned()).collect())
        .build()?;

        Ok(RvRelation {
            condition,
            addition,
        })
    }
}

/// Endorsed value relation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvRelation<'a> {
    pub condition: Vec<Ect<'a>>,
    pub addition: Vec<Ect<'a>>,
}

impl<'a> EvRelation<'a> {
    pub fn from_endorsed_triple_record<'b>(
        evt: &EndorsedTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &Vec<CryptoKeyTypeChoice<'b>>,
    ) -> Result<EvRelation<'a>> {
        let condition = EctBuilder::new()
            .cm_type(CmType::Endorsements)
            .environment(evt.condition.to_fully_owned())
            .element_list(
                evt.endorsement
                    .iter()
                    .map(|e| ElementMap {
                        mkey: e.mkey.as_ref().map(|k| k.to_fully_owned()),
                        mval: e.mval.to_fully_owned(),
                    })
                    .collect(),
            )
            .build()?;

        let addition = match profile {
            Some(p) => EctBuilder::new().profile(p.to_fully_owned()),
            None => EctBuilder::new(),
        }
        .cm_type(CmType::Endorsements)
        .environment(evt.condition.to_fully_owned())
        .authority(authority.iter().map(|v| v.to_fully_owned()).collect())
        .build()?;

        Ok(EvRelation {
            condition: vec![condition],
            addition: vec![addition],
        })
    }

    pub fn from_conditional_endorsement_triple_record<'b>(
        cet: &ConditionalEndorsementTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &Vec<CryptoKeyTypeChoice<'b>>,
    ) -> Result<EvRelation<'a>> {
        let condition: Result<Vec<Ect>> = cet
            .conditions
            .iter()
            .map(|cond| {
                EctBuilder::new()
                    .cm_type(CmType::Endorsements)
                    .environment(cond.environment.to_fully_owned())
                    .element_list(
                        cond.claims_list
                            .iter()
                            .map(|e| ElementMap {
                                mkey: e.mkey.as_ref().map(|k| k.to_fully_owned()),
                                mval: e.mval.to_fully_owned(),
                            })
                            .collect(),
                    )
                    .build()
            })
            .collect();

        if let Err(err) = condition {
            return Err(Error::custom(format!("CET condition error: {}", err)));
        }

        let addition: Result<Vec<Ect>> = cet
            .endorsements
            .iter()
            .map(|end| {
                match profile {
                    Some(p) => EctBuilder::new().profile(p.to_fully_owned()),
                    None => EctBuilder::new(),
                }
                .cm_type(CmType::Endorsements)
                .environment(end.condition.to_fully_owned())
                .element_list(
                    end.endorsement
                        .iter()
                        .map(|e| ElementMap {
                            mkey: e.mkey.as_ref().map(|k| k.to_fully_owned()),
                            mval: e.mval.to_fully_owned(),
                        })
                        .collect(),
                )
                .authority(authority.iter().map(|v| v.to_fully_owned()).collect())
                .build()
            })
            .collect();

        if let Err(err) = addition {
            return Err(Error::custom(format!("CET addition error: {}", err)));
        }

        Ok(EvRelation {
            condition: condition.unwrap(),
            addition: addition.unwrap(),
        })
    }

    pub fn from_attest_key_triple_record<'b>(
        akt: &AttestKeyTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &Vec<CryptoKeyTypeChoice<'b>>,
    ) -> Result<EvRelation<'a>> {
        let condition = match &akt.conditions {
            Some(cond) => match &cond.authorized_by {
                Some(auth_by) => EctBuilder::new()
                    .authority(auth_by.iter().map(|c| c.to_fully_owned()).collect()),
                None => EctBuilder::new(),
            },
            None => EctBuilder::new(),
        }
        .cm_type(CmType::Endorsements)
        .environment(akt.environment.to_fully_owned())
        .element_list(
            akt.key_list
                .iter()
                .map(|e| ElementMap {
                    mkey: match &akt.conditions {
                        Some(cond) => cond.mkey.as_ref().map(|k| k.to_fully_owned()),
                        None => None,
                    },
                    mval: MeasurementValuesMapBuilder::new()
                        .add_extension(
                            INTERP_KEYS_EXT_ID,
                            TypedCryptoKey {
                                key: e.to_fully_owned(),
                                key_type: KeyType::AttestKey,
                            }
                            .into(),
                        )
                        .build()
                        .unwrap(),
                })
                .collect(),
        )
        .build()?;

        let addition = match profile {
            Some(p) => EctBuilder::new().profile(p.to_fully_owned()),
            None => EctBuilder::new(),
        }
        .cm_type(CmType::Endorsements)
        .authority(authority.iter().map(|v| v.to_fully_owned()).collect())
        .build()?;

        Ok(EvRelation {
            condition: vec![condition],
            addition: vec![addition],
        })
    }
}

/// Endorsed value series entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvsRelationSeriesEntry<'a> {
    pub selection: Vec<Ect<'a>>,
    pub addition: Vec<Ect<'a>>,
}

/// Endorsed value series relation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvsRelation<'a> {
    pub condition: Vec<Ect<'a>>,
    pub series: Vec<EvsRelationSeriesEntry<'a>>,
}

impl<'a> EvsRelation<'a> {
    pub fn from_conditional_endorsement_series_triple_record<'b>(
        cest: &ConditionalEndorsementSeriesTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &Vec<CryptoKeyTypeChoice<'b>>,
    ) -> Result<EvsRelation<'a>> {
        let condition = EctBuilder::new()
            .cm_type(CmType::Endorsements)
            .environment(cest.condition.environment.to_fully_owned())
            .element_list(
                cest.condition
                    .claims_list
                    .iter()
                    .map(|e| ElementMap {
                        mkey: e.mkey.as_ref().map(|k| k.to_fully_owned()),
                        mval: e.mval.to_fully_owned(),
                    })
                    .collect(),
            )
            .build()?;

        let series: Result<Vec<EvsRelationSeriesEntry>> = cest
            .series
            .iter()
            .map(|csr| {
                let selection: Ect<'a> = EctBuilder::new()
                    .cm_type(CmType::Endorsements)
                    .environment(cest.condition.environment.to_fully_owned())
                    .element_list(
                        csr.selection
                            .iter()
                            .map(|e| ElementMap {
                                mkey: e.mkey.as_ref().map(|k| k.to_fully_owned()),
                                mval: e.mval.to_fully_owned(),
                            })
                            .collect(),
                    )
                    .build()?;

                let addition: Ect<'a> = match profile {
                    Some(p) => EctBuilder::new().profile(p.to_fully_owned()),
                    None => EctBuilder::new(),
                }
                .cm_type(CmType::Endorsements)
                .environment(cest.condition.environment.to_fully_owned())
                .element_list(
                    csr.addition
                        .iter()
                        .map(|e| ElementMap {
                            mkey: e.mkey.as_ref().map(|k| k.to_fully_owned()),
                            mval: e.mval.to_fully_owned(),
                        })
                        .collect(),
                )
                .authority(authority.iter().map(|v| v.to_fully_owned()).collect())
                .build()?;

                Ok(EvsRelationSeriesEntry {
                    selection: vec![selection],
                    addition: vec![addition],
                })
            })
            .collect();

        if let Err(err) = series {
            return Err(Error::custom(format!("CEST series error: {}", err)));
        }

        Ok(EvsRelation {
            condition: vec![condition],
            series: series.unwrap(),
        })
    }
}

/// A store of reference and endorsed values extracted from CoRIMs.
pub trait CorimStore<'a> {
    type RvIter: Iterator<Item = RvRelation<'a>>;
    type EvIter: Iterator<Item = EvRelation<'a>>;
    type EvsIter: Iterator<Item = EvsRelation<'a>>;

    /// Add values from the specified `Corim` to the store.
    fn add(&mut self, corim: &Corim) -> Result<()>;

    /// Add values from the specified CBOR-encoded CoRIM to the store.
    fn add_bytes(&mut self, cbor: &[u8]) -> Result<()> {
        let corim = Corim::from_cbor(cbor)?;
        self.add(&corim)
    }

    /// Iterate over extracted [RvRelation]s.
    fn iter_rv(&self) -> Self::RvIter;

    /// Iterate over extracted [EvRelation]s.
    fn iter_ev(&self) -> Self::EvIter;

    /// Iterate over extracted [EvsRelation]s.
    fn iter_evs(&self) -> Self::EvsIter;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CorimParseResult<'a> {
    #[serde(rename = "rv-list")]
    pub rv_list: Vec<RvRelation<'a>>,
    #[serde(rename = "ev-list")]
    pub ev_list: Vec<EvRelation<'a>>,
    #[serde(rename = "evs-list")]
    pub evs_list: Vec<EvsRelation<'a>>,
}

impl<'a> CorimParseResult<'a> {
    pub fn new() -> Self {
        CorimParseResult {
            rv_list: vec![],
            ev_list: vec![],
            evs_list: vec![],
        }
    }

    pub fn extend(&mut self, other: CorimParseResult<'a>) {
        self.rv_list.extend(other.rv_list);
        self.ev_list.extend(other.ev_list);
        self.evs_list.extend(other.evs_list);
    }

    pub fn append(&mut self, other: &mut CorimParseResult<'a>) {
        self.rv_list.append(other.rv_list.as_mut());
        self.ev_list.append(other.ev_list.as_mut());
        self.evs_list.append(other.evs_list.as_mut());
    }

    pub fn update_from_comid<'b>(
        &mut self,
        comid: &ConciseMidTag<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &Vec<CryptoKeyTypeChoice<'b>>,
    ) -> Result<()> {
        let mut updated = false;

        if let Some(rvts) = &comid.triples.reference_triples {
            for rvt in rvts {
                self.rv_list.push(RvRelation::from_reference_triple_record(
                    rvt, profile, authority,
                )?);
                updated = true;
            }
        }

        if let Some(evts) = &comid.triples.endorsed_triples {
            for evt in evts {
                self.ev_list.push(EvRelation::from_endorsed_triple_record(
                    evt, profile, authority,
                )?);
                updated = true;
            }
        }

        if let Some(cets) = &comid.triples.conditional_endorsement_triples {
            for cet in cets {
                self.ev_list
                    .push(EvRelation::from_conditional_endorsement_triple_record(
                        cet, profile, authority,
                    )?);
                updated = true;
            }
        }

        if let Some(cests) = &comid.triples.conditional_endorsement_series_triples {
            for cest in cests {
                self.evs_list.push(
                    EvsRelation::from_conditional_endorsement_series_triple_record(
                        cest, profile, authority,
                    )?,
                );
                updated = true;
            }
        }

        if let Some(akts) = &comid.triples.attest_key_triples {
            for akt in akts {
                self.ev_list.push(EvRelation::from_attest_key_triple_record(
                    akt, profile, authority,
                )?);
                updated = true;
            }
        }

        match updated {
            true => Ok(()),
            false => Err(Error::custom("no relevant triples found in CoMID")),
        }
    }
}

impl Default for CorimParseResult<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CorimParseResult<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string_pretty(&self).unwrap();
        f.write_str(s.as_str())
    }
}

/// In-memory implementation of [CorimStore].
pub struct MemCorimStore<'a, S: KeyStore> {
    pub items: CorimParseResult<'a>,
    pub keystore: S,
}

impl<S: KeyStore> MemCorimStore<'_, S> {
    pub fn new(keystore: S) -> Self {
        Self {
            items: CorimParseResult::new(),
            keystore,
        }
    }
}

impl<'a, S: KeyStore> CorimStore<'a> for MemCorimStore<'a, S> {
    type RvIter = IntoIter<RvRelation<'a>>;
    type EvIter = IntoIter<EvRelation<'a>>;
    type EvsIter = IntoIter<EvsRelation<'a>>;

    #[allow(clippy::needless_lifetimes)]
    fn add<'b>(&mut self, corim: &Corim<'b>) -> Result<()> {
        if let Some(signed) = corim.as_signed_ref() {
            let key = self.keystore.get(signed.kid.as_slice())?;
            let mut parsed = parse_corim(corim, &key).map_err(|e| {
                Error::Parse(format!("CoRIM \"{}\"", signed.corim_map.id), e.to_string())
            })?;
            self.items.append(&mut parsed);
            Ok(())
        } else {
            Err(Error::custom("unsigned CoRIMs not supported"))
        }
    }

    fn iter_rv(&self) -> Self::RvIter {
        self.items.rv_list.clone().into_iter()
    }

    fn iter_ev(&self) -> Self::EvIter {
        self.items.ev_list.clone().into_iter()
    }

    fn iter_evs(&self) -> Self::EvsIter {
        self.items.evs_list.clone().into_iter()
    }
}

#[allow(clippy::needless_lifetimes)]
pub fn parse_corim<'a, 'b>(corim: &Corim<'a>, key: &[u8]) -> Result<CorimParseResult<'b>> {
    let verifier = OpensslSigner::public_key_from_pem(key)?;
    let authority = vec![CryptoKeyTypeChoice::CoseKey(verifier.to_cose_key().into())];

    if let Corim::Signed(signed) = corim {
        match signed.verify_signature(verifier) {
            Ok(_) => {
                let profile = signed.corim_map.profile.clone();
                let mut result = CorimParseResult::new();

                for tag in &signed.corim_map.tags {
                    if let ConciseTagTypeChoice::Mid(tagged_comid) = tag {
                        result.update_from_comid(tagged_comid.as_ref(), &profile, &authority)?;
                    }
                }

                Ok(result)
            }
            Err(err) => Err(Error::custom(format!(
                "signature verification failed: {}",
                err
            ))),
        }
    } else {
        Err(Error::custom("unsigned CoRIMs not supported"))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keystore::MemKeyStore;

    #[test]
    fn parse_corim_test() {
        let token = include_bytes!("../../test/corim/signed-corim-cca-ref-plat.cbor");
        let token_ta = include_bytes!("../../test/corim/signed-corim-cca-ta.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");

        let mut keystore = MemKeyStore::new();
        keystore.add("key.pub.pem".as_bytes(), key).unwrap();

        let mut store = MemCorimStore::new(keystore);
        store.add_bytes(token.as_slice()).unwrap();
        store.add_bytes(token_ta.as_slice()).unwrap();

        println!("{:?}", store.items);
    }
}
