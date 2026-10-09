use log::warn;
use std::vec::IntoIter;

use crate::ect::ElementMap;
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

    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        warn!("System time is before UNIX epoch");
        return false;
    };

    let now = now.as_secs();

    let Some(not_after) = u64::try_from(validity.not_after.as_i128()).ok() else {
        warn!("Invalid CoRIM 'not_after' timestamp");
        return false;
    };

    let not_before = validity
        .not_before
        .as_ref()
        .and_then(|t| u64::try_from(t.as_i128()).ok())
        .unwrap_or(0);

    if not_before > not_after {
        warn!(
            "CoRIM is invalid: 'not_before' ({}) is greater than 'not_after' ({})",
            not_before, not_after
        );
        return false;
    }

    if now > not_after {
        warn!("CoRIM expired at timestamp: {}", not_after);
        return false;
    }

    if now < not_before {
        warn!("CoRIM is not active until timestamp: {}", not_before);
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
        authority: &[CryptoKeyTypeChoice<'b>],
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
    pub condition: Vec<ElementEct<'a>>,
    pub addition: Vec<ElementEct<'a>>,
}

impl<'a> EvRelation<'a> {
    pub fn from_endorsed_triple_record<'b>(
        evt: &EndorsedTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &[CryptoKeyTypeChoice<'b>],
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
        .authority(authority.iter().map(|v| v.to_fully_owned()).collect())
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
    fn get_record_type(&self) -> KeyType;

    /// Returns the environment map associated with this key triple record.
    fn get_environment(&self) -> corim_rs::EnvironmentMap<'a>;

    /// Returns the list of cryptographic keys in this record.
    fn get_key_list(&self) -> Vec<CryptoKeyTypeChoice<'a>>;

    /// Returns any conditions associated with this key triple record.
    ///
    /// Conditions that must be met for a triple record to be valid.
    fn get_conditions(&self) -> Option<corim_rs::TriplesRecordCondition<'a>>;
}

/// Implementation of [KeyTripleRecord] for attestation key triple records.
impl<'a, 'b> KeyTripleRecord<'a> for AttestKeyTripleRecord<'b> {
    fn get_record_type(&self) -> KeyType {
        KeyType::AttestKey
    }

    fn get_environment(&self) -> corim_rs::EnvironmentMap<'a> {
        self.environment.to_fully_owned()
    }

    fn get_key_list(&self) -> Vec<CryptoKeyTypeChoice<'a>> {
        self.key_list.iter().map(|k| k.to_fully_owned()).collect()
    }

    fn get_conditions(&self) -> Option<corim_rs::TriplesRecordCondition<'a>> {
        self.conditions
            .as_ref()
            .map(keytriplerecord_condition_deep_copy)
    }
}

/// Implementation of [KeyTripleRecord] for identity key triple records.
impl<'a, 'b> KeyTripleRecord<'a> for IdentityTripleRecord<'b> {
    fn get_record_type(&self) -> KeyType {
        KeyType::IdentityKey
    }

    fn get_environment(&self) -> corim_rs::EnvironmentMap<'a> {
        self.environment.to_fully_owned()
    }

    fn get_key_list(&self) -> Vec<CryptoKeyTypeChoice<'a>> {
        self.key_list.iter().map(|k| k.to_fully_owned()).collect()
    }

    fn get_conditions(&self) -> Option<corim_rs::TriplesRecordCondition<'a>> {
        self.conditions
            .as_ref()
            .map(keytriplerecord_condition_deep_copy)
    }
}

impl<'a> KeyRelation<'a> {
    fn from_triple_record<T>(
        k: &T,
        profile: &Option<ProfileTypeChoice>,
        verifier_authority: &[CryptoKeyTypeChoice],
    ) -> Result<KeyRelation<'a>>
    where
        T: KeyTripleRecord<'a>,
    {
        // Building Condition ECT
        let mut cond_builder = KeyEctBuilder::new()
            .key_type(k.get_record_type())
            .environment(k.get_environment())
            .key_list(k.get_key_list());

        // Building Addition ECT
        let mut add_builder = KeyEctBuilder::new()
            .key_type(k.get_record_type())
            .environment(k.get_environment());

        let triple_conditions = k.get_conditions();

        if let Some(key_id) = triple_conditions.as_ref().and_then(|c| c.mkey.clone()) {
            cond_builder = cond_builder.key_id(key_id.clone());
            add_builder = add_builder.key_id(key_id);
        }

        if let Some(authority) = triple_conditions.and_then(|c| c.authorized_by) {
            cond_builder = cond_builder.authority(authority);
        }

        if let Some(p) = profile {
            add_builder = add_builder.profile(p.to_fully_owned());
        }

        // Adding "verifier's authority" as "addition KeyECT authority"
        add_builder = add_builder.authority(
            verifier_authority
                .iter()
                .map(|v| v.to_fully_owned())
                .collect(),
        );

        let condition = cond_builder.build()?;
        let addition = add_builder.build()?;

        Ok(KeyRelation {
            condition,
            addition,
        })
    }

    pub fn from_identity_triple_record<'b>(
        ikt: &IdentityTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &[CryptoKeyTypeChoice<'b>],
    ) -> Result<KeyRelation<'a>> {
        Self::from_triple_record(ikt, profile, authority)
    }

    pub fn from_attest_key_triple_record<'b>(
        akt: &AttestKeyTripleRecord<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
        authority: &[CryptoKeyTypeChoice<'b>],
    ) -> Result<KeyRelation<'a>> {
        Self::from_triple_record(akt, profile, authority)
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
    fn iter_keys(&self) -> Self::KeyIter;
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
        corim_profile: &Option<ProfileTypeChoice<'b>>,
        corim_authority: &[CryptoKeyTypeChoice<'b>],
        verifier_authority: &[CryptoKeyTypeChoice<'b>],
    ) -> Result<()> {
        let mut updated = false;

        if let Some(rvts) = &comid.triples.reference_triples {
            for rvt in rvts {
                self.rv_list.push(RvRelation::from_reference_triple_record(
                    rvt,
                    corim_profile,
                    corim_authority,
                )?);
                updated = true;
            }
        }

        if let Some(evts) = &comid.triples.endorsed_triples {
            for evt in evts {
                self.ev_list.push(EvRelation::from_endorsed_triple_record(
                    evt,
                    corim_profile,
                    corim_authority,
                )?);
                updated = true;
            }
        }

        if let Some(akts) = &comid.triples.attest_key_triples {
            for akt in akts {
                self.key_list.push(KeyRelation::from_triple_record(
                    akt,
                    corim_profile,
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
// Field 'verifier_authority' is mandatory because after successfull verification of Keys in
// key-list of Identity/Attest-key triples, claims are asserted with the joint authority
// of the Endorser (CoRIM signer) and the Verifier
pub struct MemCorimStore<'a, S: KeyStore> {
    pub items: CorimParseResult<'a>,
    pub keystore: S,
    pub verifier_authority: Vec<u8>,
}

impl<S: KeyStore> MemCorimStore<'_, S> {
    pub fn new(keystore: S, verifier_authority: Vec<u8>) -> Self {
        Self {
            items: CorimParseResult::new(),
            keystore,
            verifier_authority,
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
        let corim_key: Option<Vec<u8>> = match corim.as_signed_ref() {
            Some(signed) => Some(self.keystore.get(signed.kid.as_slice())?),
            None => None,
        };

        // Fetch verifier's key to use with Key addition Ect
        let mut parsed = parse_corim(corim, corim_key.as_deref(), &self.verifier_authority)
            .map_err(|e| {
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

    fn iter_keys(&self) -> Self::KeyIter {
        self.items.key_list.clone().into_iter()
    }
}

/// Parses a CoRIM and extracts into relevant relations. `corim_key` is the cryptographic
/// public key used to verify a signed CoRIM. For unsigned CoRIMs, `verifier_key` is
/// considered as the CoRIM authority as per
/// [section-4.3 draft-ietf-rats-corim-11](https://datatracker.ietf.org/doc/html/draft-ietf-rats-corim-11#name-signer-authority-of-securel)
#[allow(clippy::needless_lifetimes)]
pub fn parse_corim<'a, 'b>(
    corim: &Corim<'a>,
    corim_key: Option<&[u8]>,
    verifier_key: &[u8],
) -> Result<CorimParseResult<'b>> {
    // key related to Verifier (person using CoVER)
    let verifier = OpensslSigner::public_key_from_pem(verifier_key)?;
    let verifier_authority = vec![CryptoKeyTypeChoice::CoseKey(verifier.to_cose_key().into())];

    let (corim_map, corim_authority) = match corim {
        Corim::Signed(signed) => {
            // None corim_key check is already done earlier, so it will always be Some here
            let corim_verifier = OpensslSigner::public_key_from_pem(corim_key.unwrap())?;
            let corim_authority = vec![CryptoKeyTypeChoice::CoseKey(
                corim_verifier.to_cose_key().into(),
            )];
            signed
                .verify_signature(corim_verifier)
                .map_err(|err| Error::custom(format!("signature verification failed: {}", err)))?;
            (&signed.corim_map, Some(corim_authority))
        }
        Corim::Unsigned(corim_map) => (corim_map.as_ref(), None),
    };

    // For unsigned corim, set verifier authority as corim authority
    let corim_authority = corim_authority.as_deref().unwrap_or(&verifier_authority);

    let corim_profile = corim_map.profile.clone();
    let mut result = CorimParseResult::new();

    for tag in &corim_map.tags {
        if let ConciseTagTypeChoice::Mid(tagged_comid) = tag {
            result.update_from_comid(
                tagged_comid.as_ref(),
                &corim_profile,
                corim_authority,
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
        let corim_key = include_bytes!("../../test/corim/key.pub.pem");
        let parsed_corim = Corim::from_cbor(corim_bytes.as_slice()).unwrap();
        let corim_map = &parsed_corim.as_signed().unwrap().corim_map;
        let profile = corim_map.profile.clone();
        let verifier = OpensslSigner::public_key_from_pem(corim_key).unwrap();
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
    fn parses_signed_corims_into_expected_relations() {
        let key = include_bytes!("../../test/corim/key.pub.pem");

        let mut keystore = MemKeyStore::new();
        keystore.add("key.pub.pem".as_bytes(), key).unwrap();

        let mut store = MemCorimStore::new(keystore, key.to_vec());
        for corim in [
            include_bytes!("../../test/corim/signed-corim-cca-plat-rv.cbor").as_slice(),
            include_bytes!("../../test/corim/signed-corim-cca-plat-ta.cbor").as_slice(),
            include_bytes!("../../test/corim/signed-corim-endval.cbor").as_slice(),
        ] {
            store.add_bytes(corim).unwrap();
        }

        assert!(!store.items.rv_list.is_empty());
        assert!(!store.items.key_list.is_empty());
        assert!(!store.items.ev_list.is_empty());

        assert!(
            store
                .items
                .key_list
                .iter()
                .any(|relation| { relation.condition.key_type == Some(KeyType::AttestKey) })
        );
        // Check if addition KeyECT has authority set.
        assert!(
            store
                .items
                .key_list
                .iter()
                .any(|relation| relation.addition.get_authority().is_some())
        );
    }

    #[test]
    fn parse_unsigned_corim() {
        let token = include_bytes!("../../test/corim/corim-cca-plat-rv.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");

        let keystore = MemKeyStore::new();

        let mut store = MemCorimStore::new(keystore, key.to_vec());
        store.add_bytes(token.as_slice()).unwrap();
        assert!(!store.items.rv_list.is_empty());
    }
}
