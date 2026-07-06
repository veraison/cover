use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{self, Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cmw::{CMW, Indicator, Mime, Monad};
use corim_rs::{ConciseRimTypeChoice, CryptoKeyTypeChoice, EnvironmentMap};
use ear::{Appraisal, EAR_PROFILE, Ear, VerifierID};

use crate::{
    corim::CorimStore,
    ect::{Ect, ElementEct},
    policy::{Policy, appraise},
    result::{Error, Result},
    scheme::Scheme,
};

/// A VerificationResult is produced by the [Verifier] when verifying evidence.
#[derive(Debug)]
pub struct VerificationResult<'a> {
    /// The result of evidence verification in EAR (EAT Attestation Result) format.
    pub ear: Ear,
    /// The ACS containing imputs used in [Policy] evaluation.
    pub acs: Vec<Ect<'a>>,
    /// [Policy] instances evaluated to generate the attestation result.
    pub policies: Vec<Policy>,
}

/// A verifier evaluates evidence using reference values and endorsements extracted from CoRIMs.
pub struct Verifier<'a, S: CorimStore<'a>> {
    /// [CorimStore] containing processed corims.
    pub corims: S,
    /// Supported attestation [Scheme]s.
    pub schemes: HashMap<String, Box<dyn Scheme>>,

    phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a, S: CorimStore<'a>> Verifier<'a, S> {
    /// Create a new Verifier
    pub fn new(corims: S, schemes: HashMap<String, Box<dyn Scheme>>) -> Self {
        Self {
            corims,
            schemes,
            phantom: std::marker::PhantomData,
        }
    }

    /// Attempt to identify the name of the attestation [Scheme] associated with the provided
    /// evidence.
    pub fn match_evidence(&self, evidence: &[u8]) -> Option<&dyn Scheme> {
        for scheme in self.schemes.values() {
            if scheme.match_evidence(evidence) {
                return Some(scheme.as_ref());
            }
        }

        None
    }

    /// Verify evidence according to the [Scheme] identified by the specified name. A nonce, if
    /// specified, will be embedded inside the resulting [Ear].
    pub fn verify(
        &self,
        scheme_name: &str,
        evidence: &[u8],
        nonce: Option<&[u8]>,
    ) -> Result<VerificationResult<'_>> {
        let scheme = self
            .get_scheme(scheme_name)
            .ok_or(Error::scheme_not_found(scheme_name))?;

        let ta_id = scheme.get_trust_anchor_id(evidence)?;

        let trust_anchor = self.get_trust_anchor(&ta_id)?;

        let mut evidence_ects = scheme.validate_and_parse_evidence(evidence, &trust_anchor)?;

        let mut acs = Vec::new();
        acs.append(&mut evidence_ects);

        let mut ref_vals = self.match_reference_values(&acs);
        acs.append(&mut ref_vals);

        let mut ev_vals = self.match_endorsement_values(&acs);
        acs.append(&mut ev_vals);

        acs = Ect::merge_similar_ects(acs);

        let acs_text = serde_json::to_string(&acs)?;
        let policies = scheme.get_policies();

        let mut ear = Ear::new();

        ear.profile = EAR_PROFILE.to_string();
        ear.iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .try_into()?;
        ear.vid = VerifierID {
            build: format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            developer: "https://veraison-project.org".to_string(),
        };
        ear.raw_evidence = Some(CMW::Monad(Monad::new_media_type(
            Mime::from_str("application/eat-cwt").unwrap(),
            evidence.to_vec(),
            Some(Indicator::EVIDENCE),
        )?));
        ear.nonce = match nonce {
            Some(bytes) => Some(URL_SAFE_NO_PAD.encode(bytes).try_into()?),
            None => None,
        };
        ear.submods = policies
            .iter()
            .map(|pol| Ok((pol.id.clone(), appraise(&acs_text, pol)?)))
            .collect::<anyhow::Result<BTreeMap<String, Appraisal>>>()?;
        Ok(VerificationResult { ear, acs, policies })
    }

    /// Add a CoRIM to the verifier's store.
    pub fn add_corim(&mut self, corim: &ConciseRimTypeChoice<'a>) -> Result<()> {
        self.corims.add(corim)
    }

    /// Add CBOR-encoded CoRIM bytes to the verifier's store.
    pub fn add_corim_bytes(&mut self, corim: &'a [u8]) -> Result<()> {
        let corim = ConciseRimTypeChoice::from_cbor(corim)?;
        let supported = self
            .schemes
            .values()
            .any(|scheme| scheme.as_ref().supports_corim(&corim).unwrap_or(false));

        if supported {
            self.corims.add(&corim)
        } else {
            Ok(())
        }
    }

    /// Add an attestation [Scheme] to the verifier.
    pub fn add_scheme(&mut self, scheme: Box<dyn Scheme>) -> Result<()> {
        self.schemes.insert(scheme.name(), scheme);
        Ok(())
    }

    fn match_reference_values(&self, acs: &[Ect<'a>]) -> Vec<Ect<'a>> {
        let mut res: Vec<Ect<'a>> = Vec::new();

        for rv in self.corims.iter_rv() {
            for acs_ect in acs {
                let Some(acs_ect) = acs_ect.as_element_ect() else {
                    continue;
                };

                if !ect_match(&rv.condition, acs_ect) {
                    continue;
                }

                let mut addition = rv.addition.clone();
                addition.element_list = acs_ect.element_list.clone();
                res.push(Ect::from(addition));
            }
        }

        res
    }

    fn match_endorsement_values(&self, act: &[Ect<'a>]) -> Vec<Ect<'a>> {
        let mut res: Vec<Ect<'a>> = Vec::new();

        for ev in self.corims.iter_ev() {
            let mut conditions_match = true;

            for cond in &ev.condition {
                let mut matched = false;

                for acs_ect in act {
                    let Some(acs_ect) = acs_ect.as_element_ect() else {
                        continue;
                    };

                    if ect_match(cond, acs_ect) {
                        matched = true;
                        break;
                    }
                }

                if !matched {
                    conditions_match = false;
                    break;
                }
            }

            if conditions_match {
                for add_ect in &ev.addition {
                    res.push(Ect::from(add_ect.clone()));
                }
            }
        }

        res
    }

    fn get_scheme(&self, name: &str) -> Option<&dyn Scheme> {
        self.schemes.get(name).map(|s| s.as_ref())
    }

    fn get_trust_anchor(&self, id: &EnvironmentMap<'a>) -> Result<CryptoKeyTypeChoice<'a>> {
        let mut found: Option<CryptoKeyTypeChoice> = None;

        for kv in self.corims.iter_key() {
            let cond = kv.condition;
            if cond.get_environment().as_ref().unwrap().matches(id)
                && let Some(elts) = &cond.key_list
            {
                found = elts.first().cloned();
            }
        }

        match found {
            Some(key) => Ok(key),
            None => Err(Error::custom(format!("no trust anchor found for {:?}", id))),
        }
    }
}

fn ect_match(condition: &ElementEct, acs_ect: &ElementEct) -> bool {
    if !condition
        .get_environment()
        .as_ref()
        .unwrap()
        .matches(acs_ect.get_environment().as_ref().unwrap())
    {
        return false;
    }

    for cond_elt in condition.element_list.as_ref().unwrap() {
        let mut elt_matched = false;

        for acs_elt in acs_ect.element_list.as_ref().unwrap() {
            match (&cond_elt.mkey, &acs_elt.mkey) {
                (Some(rv_mkey), Some(acs_mkey)) => {
                    if rv_mkey != acs_mkey {
                        continue;
                    }
                }
                (Some(_), None) => {
                    continue;
                }
                (None, Some(_)) => (),
                (None, None) => (),
            }

            if cond_elt.mval.matches(&acs_elt.mval) {
                elt_matched = true;
                break;
            }
        }

        if !elt_matched {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod test {
    use std::assert_eq;
    use std::collections::HashMap;

    use super::*;
    use crate::cca::CcaScheme;
    use crate::corim::MemCorimStore;
    use crate::keystore::{KeyStore, MemKeyStore};

    #[test]
    fn verifier_test() {
        let corim_rv_plat = include_bytes!("../../test/corim/signed-corim-cca-plat-rv.cbor");
        let corim_rv_realm = include_bytes!("../../test/corim/signed-corim-cca-realm-rv.cbor");
        let corim_ta = include_bytes!("../../test/corim/signed-corim-cca-plat-ta.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");
        let evidence = include_bytes!("../../test/cca/cca-token-01.cbor");

        let mut keystore = MemKeyStore::new();
        keystore.add("key.pub.pem".as_bytes(), key).unwrap();
        keystore.add("verifier-key".as_bytes(), key).unwrap();

        let mut store = MemCorimStore::new(keystore);
        store.add_bytes(corim_rv_plat.as_slice()).unwrap();
        store.add_bytes(corim_rv_realm.as_slice()).unwrap();
        store.add_bytes(corim_ta.as_slice()).unwrap();

        let mut schemes = HashMap::new();
        let cca_scheme: Box<dyn Scheme> = Box::new(CcaScheme::new());
        schemes.insert("cca".to_string(), cca_scheme);

        let verifier = Verifier::new(store, schemes);
        let result = verifier.verify("cca", evidence.as_slice(), None).unwrap();

        for appraisal in result.ear.submods.values() {
            assert_eq!(appraisal.status.to_string(), "affirming");
        }
    }

    #[test]
    fn add_corim_bytes_invalid_profile() {
        let corim_inv_profile =
            include_bytes!("../../test/corim/signed-corim-cca-plat-unsupported-profile.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");
        let mut keystore = MemKeyStore::new();
        keystore.add("key.pub.pem".as_bytes(), key).unwrap();
        let store = MemCorimStore::new(keystore);
        let mut schemes = HashMap::new();
        let cca_scheme: Box<dyn Scheme> = Box::new(CcaScheme::new());
        schemes.insert("arm-cca".to_string(), cca_scheme);
        let mut verifier = Verifier::new(store, schemes);
        let _res = verifier.add_corim_bytes(corim_inv_profile);
        assert_eq!(verifier.corims.items.rv_list.len(), 0);
        assert_eq!(verifier.corims.items.ev_list.len(), 0);
        assert_eq!(verifier.corims.items.key_list.len(), 0);
    }

    #[test]
    fn add_corim_bytes_expired_corim() {
        let corim_inv_profile =
            include_bytes!("../../test/corim/signed-corim-cca-plat-expired-validity.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");
        let mut keystore = MemKeyStore::new();
        keystore.add("key.pub.pem".as_bytes(), key).unwrap();
        let store = MemCorimStore::new(keystore);
        let mut schemes = HashMap::new();
        let cca_scheme: Box<dyn Scheme> = Box::new(CcaScheme::new());
        schemes.insert("arm-cca".to_string(), cca_scheme);
        let mut verifier = Verifier::new(store, schemes);
        let _res = verifier.add_corim_bytes(corim_inv_profile);
        assert_eq!(verifier.corims.items.rv_list.len(), 0);
    }
}
