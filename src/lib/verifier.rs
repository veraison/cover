use std::{
    collections::{BTreeMap, HashMap},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{self, Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use corim_rs::{ConciseRimTypeChoice, CryptoKeyTypeChoice, EnvironmentMap};
use ear::{Appraisal, Ear, Extensions, VerifierID};

use crate::{
    corim::{CorimStore, INTERP_KEYS_EXT_ID, KeyType, TypedCryptoKey},
    ect::Ect,
    policy::{Policy, appraise},
    result::{Error, Result},
    scheme::Scheme,
};

/// A Verification is produced by the [Verifier] when verifying evidence.
#[derive(Debug)]
pub struct Verification<'a> {
    /// The result of evidence verification in EAR (EAT Attestation Result) format.
    pub ear: Ear,
    /// The ACS containing imputs used in [Policy] eveluation.
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
    ) -> Result<Verification> {
        let scheme = self
            .get_scheme(scheme_name)
            .ok_or(Error::scheme_not_found(scheme_name))?;

        let ta_id = scheme.get_trust_anchor_id(evidence)?;

        let trust_anchor = self.get_trust_anchor(&ta_id)?;

        let mut evidence_ects = scheme.validate_and_parse_evidence(evidence, &trust_anchor)?;

        let mut ref_vals = self.match_reference_values(&evidence_ects);

        let mut acs = Vec::new();
        acs.append(&mut evidence_ects);
        acs.append(&mut ref_vals);

        let mut ev_vals = self.match_endorsement_values(&acs);

        acs.append(&mut ev_vals);

        let acs_text = serde_json::to_string(&acs)?;
        let policies = scheme.get_policies();

        let ear = Ear {
            profile: scheme.profile(),
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .try_into()?,
            vid: VerifierID {
                build: format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
                developer: "https://veraison-project.org".to_string(),
            },
            raw_evidence: Some(evidence.into()),
            nonce: match nonce {
                Some(bytes) => Some(URL_SAFE_NO_PAD.encode(bytes).try_into()?),
                None => None,
            },
            submods: policies
                .iter()
                .map(|pol| Ok((pol.id.clone(), appraise(&acs_text, pol)?)))
                .collect::<anyhow::Result<BTreeMap<String, Appraisal>>>()?,
            extensions: Extensions::new(),
        };

        Ok(Verification { ear, acs, policies })
    }

    /// Add a CoRIM to the verifier's store.
    pub fn add_corim(&mut self, corim: &ConciseRimTypeChoice<'a>) -> Result<()> {
        self.corims.add(corim)
    }

    /// Add CBOR-encoded CoRIM bytes to the verifier's store.
    pub fn add_corim_bytes(&mut self, corim: &'a [u8]) -> Result<()> {
        self.corims.add_bytes(corim)
    }

    /// Add an attestation [Scheme] to the verifier.
    pub fn add_scheme(&mut self, scheme: Box<dyn Scheme>) -> Result<()> {
        self.schemes.insert(scheme.name(), scheme);
        Ok(())
    }

    fn match_reference_values(&self, acs: &Vec<Ect<'a>>) -> Vec<Ect<'a>> {
        let mut res: Vec<Ect> = Vec::new();

        for rv in self.corims.iter_rv() {
            for acs_ect in acs {
                if !ect_match(&rv.condition, acs_ect) {
                    continue;
                }

                let mut addition = rv.addition.clone();
                addition.element_list = acs_ect.element_list.clone();
                res.push(addition);
            }
        }

        res
    }

    fn match_endorsement_values(&self, act: &Vec<Ect<'a>>) -> Vec<Ect<'a>> {
        let mut res: Vec<Ect> = Vec::new();

        for ev in self.corims.iter_ev() {
            let mut conditions_match = true;

            for cond in &ev.condition {
                for acs_ect in act {
                    if !ect_match(cond, acs_ect) {
                        conditions_match = false;
                        break;
                    }
                }
            }

            if conditions_match {
                for add_ect in &ev.addition {
                    res.push(add_ect.clone());
                }
            }
        }

        for evs in self.corims.iter_evs() {
            let mut conditions_match = true;

            for cond in &evs.condition {
                for acs_ect in act {
                    if !ect_match(cond, acs_ect) {
                        conditions_match = false;
                        break;
                    }
                }
            }

            if conditions_match {
                for entry in &evs.series {
                    for acs_ect in act {
                        let mut selection_matched = true;
                        for select in &entry.selection {
                            if !ect_match(select, acs_ect) {
                                selection_matched = false;
                                break;
                            }
                        }

                        if selection_matched {
                            for add_ect in &entry.addition {
                                res.push(add_ect.clone());
                            }
                            break;
                        }
                    }
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

        for ev in self.corims.iter_ev() {
            for cond in &ev.condition {
                if cond.environment.as_ref().unwrap() == id {
                    if let Some(elts) = &cond.element_list {
                        for elt in elts {
                            if let Some(exts) = &elt.mval.extensions {
                                if let Some(interp_keys_ext) = exts.get(INTERP_KEYS_EXT_ID.into()) {
                                    let interp_key =
                                        TypedCryptoKey::try_from(interp_keys_ext).unwrap();
                                    if interp_key.key_type == KeyType::AttestKey {
                                        if found.is_some() {
                                            return Err(Error::custom(format!(
                                                "duplicate trust anchor for {:?}",
                                                id
                                            )));
                                        }

                                        found = Some(interp_key.key)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        match found {
            Some(key) => Ok(key),
            None => Err(Error::custom(format!("no trust anchor found for {:?}", id))),
        }
    }
}

fn ect_match(condition: &Ect, acs_ect: &Ect) -> bool {
    if !condition
        .environment
        .as_ref()
        .unwrap()
        .matches(acs_ect.environment.as_ref().unwrap())
    {
        return false;
    }

    // note: sect. 9.4.3 states authorities should be matched here, but it's not clear how given
    // that evidence and reference/endorsement values obviously come from different sources...

    for cond_elt in condition.element_list.as_ref().unwrap() {
        let mut elt_matched = false;

        for act_elt in acs_ect.element_list.as_ref().unwrap() {
            match (&cond_elt.mkey, &act_elt.mkey) {
                (Some(rv_mkey), Some(act_mkey)) => {
                    if rv_mkey != act_mkey {
                        continue;
                    }
                }
                (Some(_), None) => {
                    continue;
                }
                (None, Some(_)) => (),
                (None, None) => (),
            }

            if cond_elt.mval.matches(&act_elt.mval) {
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
    use std::collections::HashMap;

    use super::*;
    use crate::cca::CcaScheme;
    use crate::corim::MemCorimStore;
    use crate::keystore::{KeyStore, MemKeyStore};

    #[test]
    fn verifier_test() {
        let corim_rv_plat = include_bytes!("../../test/corim/signed-corim-cca-ref-plat.cbor");
        let corim_rv_realm = include_bytes!("../../test/corim/signed-corim-cca-ref-realm.cbor");
        let corim_ta = include_bytes!("../../test/corim/signed-corim-cca-ta.cbor");
        let key = include_bytes!("../../test/corim/key.pub.pem");
        let evidence = include_bytes!("../../test/cca/cca-token-01.cbor");

        let mut keystore = MemKeyStore::new();
        keystore.add("key.pub.pem".as_bytes(), key).unwrap();

        let mut store = MemCorimStore::new(keystore);
        store.add_bytes(corim_rv_plat.as_slice()).unwrap();
        store.add_bytes(corim_rv_realm.as_slice()).unwrap();
        store.add_bytes(corim_ta.as_slice()).unwrap();

        let mut schemes = HashMap::new();
        let cca_scheme: Box<dyn Scheme> = Box::new(CcaScheme::new());
        schemes.insert("cca".to_string(), cca_scheme);

        let verifier = Verifier::new(store, schemes);
        let result = verifier.verify("cca", evidence.as_slice(), None).unwrap();

        for (_, appraisal) in &result.ear.submods {
            assert_eq!(appraisal.status.to_string(), "affirming");
        }
    }
}
