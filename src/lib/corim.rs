use log::warn;
use std::vec::IntoIter;

use crate::ect::ElementMap;

use chrono::DateTime;
use std::time::{SystemTime, UNIX_EPOCH};

use corim_rs::{
    AttestKeyTripleRecord, ConciseMidTag, ConciseTagTypeChoice, Corim, CoseKeyOwner,
    CryptoKeyTypeChoice, EndorsedTripleRecord, IdentityTripleRecord, MeasurementMap, OpensslSigner,
    ProfileTypeChoice, ReferenceTripleRecord, ValidityMap,
};
use serde::{Deserialize, Serialize};

use crate::ect::{CmType, ElementEct, ElementEctBuilder, KeyEct, KeyEctBuilder, KeyType};
use crate::keystore::KeyStore;
use crate::result::{Error, Result};

/// Helper function to check time validity of Corim.
pub fn is_rim_valid(rim_validity: Option<&ValidityMap>) -> bool {
    let Some(validity) = rim_validity else {
        return true;
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let not_before = validity
        .not_before
        .as_ref()
        .map(|t| t.as_i128() as u64)
        .unwrap_or(0);

    let not_after = validity.not_after.as_i128() as u64;

    if not_before > not_after {
        warn!(
            "Corim validity, Not before: {} is greater than Not After: {}",
            DateTime::from_timestamp(not_before as i64, 0).expect("validity is never none"),
            DateTime::from_timestamp(not_after as i64, 0).expect("validity is never none")
        );
        return false;
    } else if now > not_after {
        warn!(
            "CoRIM expired on: {}",
            DateTime::from_timestamp(not_after as i64, 0).expect("validity is never none")
        );
        return false;
    } else if now < not_before {
        warn!(
            "CoRIM is not active till: {}",
            DateTime::from_timestamp(not_before as i64, 0).expect("validity is never none")
        );
        return false;
    }

    true
}

fn measurementmap_vec_to_elemenetmap_vec<'a, 'b>(
    mms: &Vec<MeasurementMap<'a>>,
) -> Vec<ElementMap<'b>> {
    mms.iter().map(ElementMap::from).collect()
}

/// Reference value relation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RvRelation<'a> {
    pub condition: ElementEct<'a>,
    pub addition: ElementEct<'a>,
}

impl<'a> RvRelation<'a> {
    pub fn from_reference_triple_record<'b>(
        rvt: &ReferenceTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        signer: &[CryptoKeyTypeChoice<'b>],
    ) -> Result<RvRelation<'a>> {
        let condition: ElementEct<'a> = ElementEctBuilder::new()
            .environment(rvt.ref_env.to_fully_owned())
            .element_list(measurementmap_vec_to_elemenetmap_vec(&rvt.ref_claims))
            .build()?;

        let addition: ElementEct<'a> = match profile {
            Some(p) => ElementEctBuilder::new().profile(p.to_fully_owned()),
            None => ElementEctBuilder::new(),
        }
        .cmtype(CmType::ReferenceValues)
        .environment(rvt.ref_env.to_fully_owned())
        .authority(signer.iter().map(|v| v.to_fully_owned()).collect())
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
    pub condition: Vec<ElementEct<'a>>,
    pub addition: Vec<ElementEct<'a>>,
}

impl<'a> EvRelation<'a> {
    pub fn from_endorsed_triple_record<'b>(
        evt: &EndorsedTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        signer: &[CryptoKeyTypeChoice<'b>],
    ) -> Result<EvRelation<'a>> {
        let condition: ElementEct<'a> = ElementEctBuilder::new()
            .environment(evt.condition.to_fully_owned())
            // element list is not used for EV-triples, skipping
            .build()?;

        let addition: ElementEct<'a> = match profile {
            Some(p) => ElementEctBuilder::new().profile(p.to_fully_owned()),
            None => ElementEctBuilder::new(),
        }
        .cmtype(CmType::Endorsements)
        .environment(evt.condition.to_fully_owned())
        .element_list(measurementmap_vec_to_elemenetmap_vec(&evt.endorsement))
        .authority(signer.iter().map(|v| v.to_fully_owned()).collect())
        .build()?;

        Ok(EvRelation {
            condition: vec![condition],
            addition: vec![addition],
        })
    }
}

/// Key relation.
// Key relation condition and addition ECT structure is inferred from \
// transformation function given in corim draft (rev 11) figure 43
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRelation<'a> {
    pub condition: KeyEct<'a>,
    pub addition: KeyEct<'a>,
}

/// Performs a deep copy of triple record conditions with lifetime conversion.
///
/// This helper function creates a fully owned copy of a [TriplesRecordCondition],
/// converting all borrowed references to owned values with the target lifetime `'a`.
fn keytriplerecord_condition_deep_copy<'a>(
    conds: &corim_rs::TriplesRecordCondition,
) -> corim_rs::TriplesRecordCondition<'a> {
    let mut triple_record_conditions = corim_rs::TriplesRecordConditionBuilder::new();
    if let Some(mk) = &conds.mkey {
        triple_record_conditions = triple_record_conditions.mkey(mk.to_fully_owned());
    }

    if let Some(auth_by) = &conds.authorized_by {
        triple_record_conditions = triple_record_conditions
            .authorized_by(auth_by.iter().map(|c| c.to_fully_owned()).collect());
    }
    // Build can not panic since both field can not be empty at the same time.
    triple_record_conditions
        .build()
        .expect("condition is always non-empty")
}

/// Trait for abstracting over different types of key triple records.
///
/// This trait provides a unified interface to extract information from key triple records,
/// i.e. [AttestKeyTripleRecord] and [IdentityTripleRecord]. It allows for
/// generic handling of key-related triples regardless of their specific type.
trait KeyTripleRecord<'a> {
    /// Returns the type of this key triple record (attestation or identity key).
    fn get_key_triple_record_type(&self) -> KeyType;

    /// Returns the environment map associated with this key triple record.
    fn get_key_triple_environment(&self) -> corim_rs::EnvironmentMap<'a>;

    /// Returns the list of cryptographic keys in this record.
    fn get_key_triple_key_list(&self) -> Vec<CryptoKeyTypeChoice<'a>>;

    /// Returns any conditions associated with this key triple record.
    ///
    /// Conditions that must be met for a triple record to be valid.
    fn get_key_triple_conditions(&self) -> Option<corim_rs::TriplesRecordCondition<'a>>;
}

/// Implementation of [KeyTripleRecord] for attestation key triple records.
impl<'a, 'b> KeyTripleRecord<'a> for AttestKeyTripleRecord<'b> {
    fn get_key_triple_record_type(&self) -> KeyType {
        KeyType::AttestKey
    }

    fn get_key_triple_environment(&self) -> corim_rs::EnvironmentMap<'a> {
        self.environment.to_fully_owned()
    }

    fn get_key_triple_key_list(&self) -> Vec<CryptoKeyTypeChoice<'a>> {
        self.key_list.iter().map(|k| k.to_fully_owned()).collect()
    }

    fn get_key_triple_conditions(&self) -> Option<corim_rs::TriplesRecordCondition<'a>> {
        self.conditions
            .as_ref()
            .map(keytriplerecord_condition_deep_copy)
    }
}

/// Implementation of [KeyTripleRecord] for identity key triple records.
impl<'a, 'b> KeyTripleRecord<'a> for IdentityTripleRecord<'b> {
    fn get_key_triple_record_type(&self) -> KeyType {
        KeyType::IdentityKey
    }

    fn get_key_triple_environment(&self) -> corim_rs::EnvironmentMap<'a> {
        self.environment.to_fully_owned()
    }

    fn get_key_triple_key_list(&self) -> Vec<CryptoKeyTypeChoice<'a>> {
        self.key_list.iter().map(|k| k.to_fully_owned()).collect()
    }

    fn get_key_triple_conditions(&self) -> Option<corim_rs::TriplesRecordCondition<'a>> {
        self.conditions
            .as_ref()
            .map(keytriplerecord_condition_deep_copy)
    }
}

impl<'a> KeyRelation<'a> {
    fn from_key_triple_record<T>(
        k: &T,
        profile: &Option<ProfileTypeChoice>,
        verifier: &[CryptoKeyTypeChoice],
    ) -> Result<KeyRelation<'a>>
    where
        T: KeyTripleRecord<'a>,
    {
        // Building Condition ECT
        let mut cond_builder = KeyEctBuilder::new()
            .key_type(k.get_key_triple_record_type())
            .environment(k.get_key_triple_environment())
            .key_list(k.get_key_triple_key_list());

        // Building Addition ECT
        let mut add_builder = KeyEctBuilder::new()
            .key_type(k.get_key_triple_record_type())
            .environment(k.get_key_triple_environment());

        if let Some(triple_conditions) = k.get_key_triple_conditions()
            && let Some(key_id) = triple_conditions.mkey
        {
            cond_builder = cond_builder.key_id(key_id.clone());
            add_builder = add_builder.key_id(key_id);
        }

        if let Some(triple_conditions) = k.get_key_triple_conditions()
            && let Some(authority) = triple_conditions.authorized_by
        {
            cond_builder = cond_builder.authority(authority);
        }

        if let Some(p) = profile {
            add_builder = add_builder.profile(p.to_fully_owned());
        }

        // Adding "verifier's authority" as "addition KeyECT authority"
        add_builder = add_builder.authority(verifier.iter().map(|v| v.to_fully_owned()).collect());

        let condition = cond_builder.build()?;
        let addition = add_builder.build()?;

        Ok(KeyRelation {
            condition,
            addition,
        })
    }

    pub fn from_identity_key_triple_record<'b>(
        ikt: &IdentityTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        signer: &[CryptoKeyTypeChoice<'b>],
    ) -> Result<KeyRelation<'a>> {
        Self::from_key_triple_record(ikt, profile, signer)
    }

    pub fn from_attest_key_triple_record<'b>(
        akt: &AttestKeyTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        signer: &[CryptoKeyTypeChoice<'b>],
    ) -> Result<KeyRelation<'a>> {
        Self::from_key_triple_record(akt, profile, signer)
    }
}

// TODO: Define Domain Membership and Trust Dependency Relations and
// transformation functions to populate defined data structure.

/// A store of reference and endorsed values extracted from CoRIMs.
pub trait CorimStore<'a> {
    type RvIter: Iterator<Item = RvRelation<'a>>;
    type EvIter: Iterator<Item = EvRelation<'a>>;
    type KeyIter: Iterator<Item = KeyRelation<'a>>;

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

    /// Iterate over extracted [KeyRelation]s.
    fn iter_key(&self) -> Self::KeyIter;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CorimParseResult<'a> {
    pub rv_list: Vec<RvRelation<'a>>,
    pub ev_list: Vec<EvRelation<'a>>,
    pub key_list: Vec<KeyRelation<'a>>,
}

impl<'a> CorimParseResult<'a> {
    pub fn new() -> Self {
        CorimParseResult {
            rv_list: vec![],
            ev_list: vec![],
            key_list: vec![],
        }
    }

    pub fn extend(&mut self, other: CorimParseResult<'a>) {
        self.rv_list.extend(other.rv_list);
        self.ev_list.extend(other.ev_list);
        self.key_list.extend(other.key_list);
    }

    pub fn append(&mut self, other: &mut CorimParseResult<'a>) {
        self.rv_list.append(other.rv_list.as_mut());
        self.ev_list.append(other.ev_list.as_mut());
        self.key_list.append(other.key_list.as_mut());
    }

    pub fn update_from_comid<'b>(
        &mut self,
        comid: &ConciseMidTag<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &[CryptoKeyTypeChoice<'b>],
        verifier_authority: &[CryptoKeyTypeChoice<'b>],
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

        if let Some(akts) = &comid.triples.attest_key_triples {
            for akt in akts {
                self.key_list.push(KeyRelation::from_key_triple_record(
                    akt,
                    profile,
                    verifier_authority,
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
        let s = serde_json::to_string_pretty(&self).expect("Input object should be serialisable");
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
    type KeyIter = IntoIter<KeyRelation<'a>>;

    #[allow(clippy::needless_lifetimes)]
    fn add<'b>(&mut self, corim: &Corim<'b>) -> Result<()> {
        // Get cryptographic key for signed corim,
        // for unsigned corims, use verifier's cryptographic key
        let key: Vec<u8> = match corim.as_signed_ref() {
            Some(signed) => self.keystore.get(signed.kid.as_slice())?,
            None => self.keystore.get("verifier-key".as_bytes())?,
        };

        // Fetch verifier's key to use with Key addition Ect
        let verifier_key = self.keystore.get("verifier-key".as_bytes())?;
        let mut parsed = parse_corim(corim, &key, &verifier_key).map_err(|e| {
            Error::Parse(
                format!("CoRIM \"{}\"", corim.as_map_ref().id),
                e.to_string(),
            )
        })?;
        self.items.append(&mut parsed);
        Ok(())
    }

    fn iter_rv(&self) -> Self::RvIter {
        self.items.rv_list.clone().into_iter()
    }

    fn iter_ev(&self) -> Self::EvIter {
        self.items.ev_list.clone().into_iter()
    }

    fn iter_key(&self) -> Self::KeyIter {
        self.items.key_list.clone().into_iter()
    }
}

/// Function to parse corims and add to corim-store.
/// `key` define the authority who signed the corim, for unsigned corim, verifier's authority is used.
/// In case of unsigned corim, `key` and `verifier_key` are same.
#[allow(clippy::needless_lifetimes)]
pub fn parse_corim<'a, 'b>(
    corim: &Corim<'a>,
    key: &[u8],
    verifier_key: &[u8],
) -> Result<CorimParseResult<'b>> {
    let corim_verifier = OpensslSigner::public_key_from_pem(key)?;
    let authority = vec![CryptoKeyTypeChoice::CoseKey(
        corim_verifier.to_cose_key().into(),
    )];

    // key related to Verifier (person using CoVER)
    let verifier = OpensslSigner::public_key_from_pem(verifier_key)?;
    let verifier_authority = vec![CryptoKeyTypeChoice::CoseKey(verifier.to_cose_key().into())];

    let corim_map = match corim {
        Corim::Signed(signed) => match signed.verify_signature(corim_verifier) {
            Ok(_) => &signed.corim_map,
            Err(err) => {
                return Err(Error::custom(format!(
                    "signature verification failed: {}",
                    err
                )));
            }
        },
        Corim::Unsigned(corim_map) => corim_map,
    };

    let profile = corim_map.profile.clone();
    let mut result = CorimParseResult::new();

    for tag in &corim_map.tags {
        if let ConciseTagTypeChoice::Mid(tagged_comid) = tag {
            result.update_from_comid(
                tagged_comid.as_ref(),
                &profile,
                &authority,
                &verifier_authority,
            )?;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keystore::MemKeyStore;
    use corim_rs::triples::EnvironmentMap;

    #[test]
    fn rv_triple_record_creates_condition_and_addition_ects() {
        let corim_bytes = include_bytes!("../../test/corim/signed-corim-cca-plat-rv.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");
        let parsed_corim = Corim::from_cbor(corim_bytes.as_slice()).unwrap();
        let corim_map = &parsed_corim.as_signed().unwrap().corim_map;
        let profile = corim_map.profile.clone();
        let verifier = OpensslSigner::public_key_from_pem(key).unwrap();
        let authority = vec![CryptoKeyTypeChoice::CoseKey(verifier.to_cose_key().into())];

        let env = EnvironmentMap::default();
        let mut rv_triple = ReferenceTripleRecord {
            ref_env: env,
            ref_claims: vec![],
        };
        for tag in &corim_map.tags {
            if let ConciseTagTypeChoice::Mid(tagged_comid) = tag
                && tagged_comid.triples.reference_triples.is_some()
            {
                rv_triple = tagged_comid
                    .as_ref()
                    .triples
                    .reference_triples
                    .clone()
                    .unwrap()
                    .first()
                    .unwrap()
                    .clone();
                break;
            }
        }
        let relation =
            RvRelation::from_reference_triple_record(&rv_triple, &profile, &authority).unwrap();

        assert!(relation.addition.get_profile().is_some());
        assert!(!relation.condition.element_list.as_ref().unwrap().is_empty());
    }

    #[test]
    fn parse_signed_corim() {
        let token = include_bytes!("../../test/corim/signed-corim-cca-plat-rv.cbor");
        let token_ta = include_bytes!("../../test/corim/signed-corim-cca-plat-ta.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");

        let mut keystore = MemKeyStore::new();
        keystore.add("key.pub.pem".as_bytes(), key).unwrap();
        keystore.add("verifier-key".as_bytes(), key).unwrap();

        let mut store = MemCorimStore::new(keystore);
        store.add_bytes(token.as_slice()).unwrap();
        store.add_bytes(token_ta.as_slice()).unwrap();

        assert!(!store.items.rv_list.is_empty());
        assert!(!store.items.key_list.is_empty());
        // Check if addition KeyECT has authority set.
        assert!(
            store
                .items
                .key_list
                .first()
                .unwrap()
                .addition
                .get_authority()
                .is_some()
        );
    }

    #[test]
    fn parse_unsigned_corim() {
        let token = include_bytes!("../../test/corim/corim-cca-plat-rv.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");

        let mut keystore = MemKeyStore::new();
        keystore.add("verifier-key".as_bytes(), key).unwrap();

        let mut store = MemCorimStore::new(keystore);
        store.add_bytes(token.as_slice()).unwrap();
        assert!(!store.items.rv_list.is_empty());
    }
}
