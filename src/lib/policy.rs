use std::fs;
use std::io;

use anyhow::Result;
use ear::Appraisal;
use regorus::{Engine, Value};

/// A [Policy] describes how inputs should be evaluated to generated an attestation result.
/// Policy rules are writen using [Rego policy
/// language](https://www.openpolicyagent.org/docs/policy-language).
///
/// # Writing a policy
///
/// A policy must specify package `policy`.
///
/// During appraisal, the engine evaluate queries corresponding to [AR4SI claim name](with hyphens
/// replaced by underscores to make them valid Rego identifiers). These must resolve to a signed 8
/// bit integer values (see AR4SI documentation for what specific values mean when specified  for a
/// claim).
///
/// Additionally, `status` query will be evaluated to overwrite the overall status of the appraisal
/// (by default, this will be determined from individual claims). This must correspond to an 8 bit
/// integer representing an [AR4SI trust
/// tier](https://www.ietf.org/archive/id/draft-ietf-rats-ar4si-09.html#name-trustworthiness-tiers).
///
/// Finally `policy_claims` query will be evaluated. Thus must resolve to a map of any additional
/// claims a policy can choose to add.
///
/// A preamble (see `src/lib/preamble.rego`) specifies default values for all queries, so if a
/// claim is not relevant to a particular policy, it does not need to be defined.
///
/// ## Example policy
///
/// The following is an extract from Arm CCA platform policy that evalues the `configuration` AR4SI
/// claim.
///
/// ```rego
/// package policy
///
/// TAG_PSA_IMPL_ID := 600
/// TAG_CCA_PLAT_CONFIG := 602
///
/// platform contains ect if {
///   ect = input[_]
///   ect.environment.class["class-id"].tag == TAG_PSA_IMPL_ID
/// }
///
/// refvals contains ect if {
///   ect = platform[_]
///   ect["cmtype"] == "reference-values"
/// }
///
/// evidence contains ect if {
///   ect = platform[_]
///   ect["cmtype"] == "evidence"
/// }
///
/// # NOTE: APPROVED_CONFIG and UNSAFE_CONFIG are defined in the preamble
/// configuration := APPROVED_CONFIG if {
///   ref = refvals[_]["element-list"][_]
///   ref.mkey.tag == TAG_CCA_PLAT_CONFIG
///
///   ev = evidence[_]["element-list"][_]
///   ev.mkey.tag == TAG_CCA_PLAT_CONFIG
///
///   ref.mkey.value == ev.mkey.value
///   ref.mval == ev.mval
/// } else := UNSAFE_CONFIG
/// ```
#[derive(Debug, Clone)]
pub struct Policy {
    /// A unique identifier for this policy.
    pub id: String,
    /// A path (e.g file system path) from where the policy originated.
    pub path: String,
    /// Text containing Rego rules.
    pub text: String,
}

impl Policy {
    pub fn new(id: String, path: String, text: String) -> Self {
        Policy { id, path, text }
    }

    pub fn read_from_file(path: &str, id: &str) -> io::Result<Policy> {
        Ok(Policy {
            id: id.to_string(),
            path: path.to_string(),
            text: fs::read_to_string(path)?,
        })
    }
}

const PREAMBLE: &str = include_str!("preamble.rego");

/// Appraise the input, which must be a JSON-serialized ACT, using the provided policy via a
/// Rego-based policy engine.
pub fn appraise(input: &str, policy: &Policy) -> Result<Appraisal> {
    let mut engine = Engine::new();

    engine.add_policy("preamble".to_string(), PREAMBLE.to_string())?;
    engine.add_policy(policy.path.clone(), policy.text.clone())?;
    engine.set_input(Value::from_json_str(input)?);

    let mut appraisal = Appraisal::new();
    appraisal.status = engine
        .eval_rule("data.policy.status".to_string())?
        .as_i8()?
        .try_into()?;
    appraisal.trust_vector.instance_identity.set(
        engine
            .eval_rule("data.policy.instance_identity".to_string())?
            .as_i8()?,
    );
    appraisal.trust_vector.configuration.set(
        engine
            .eval_rule("data.policy.configuration".to_string())?
            .as_i8()?,
    );
    appraisal.trust_vector.executables.set(
        engine
            .eval_rule("data.policy.executables".to_string())?
            .as_i8()?,
    );
    appraisal.trust_vector.file_system.set(
        engine
            .eval_rule("data.policy.file_system".to_string())?
            .as_i8()?,
    );
    appraisal.trust_vector.hardware.set(
        engine
            .eval_rule("data.policy.hardware".to_string())?
            .as_i8()?,
    );
    appraisal.trust_vector.runtime_opaque.set(
        engine
            .eval_rule("data.policy.runtime_opaque".to_string())?
            .as_i8()?,
    );
    appraisal.trust_vector.storage_opaque.set(
        engine
            .eval_rule("data.policy.storage_opaque".to_string())?
            .as_i8()?,
    );
    appraisal.trust_vector.sourced_data.set(
        engine
            .eval_rule("data.policy.sourced_data".to_string())?
            .as_i8()?,
    );
    appraisal.update_status_from_trust_vector();

    Ok(appraisal)
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use ear::Appraisal;
    use test_case::test_case;

    use super::*;

    #[test_case("empty" ; "empty")]
    #[test_case("cca-platform" ; "CCA plaform")]
    #[test_case("cca-realm" ; "CCA realm")]
    #[test_case("added-claims" ; "policy-added claims")]
    fn appraise(name: &str) {
        let path = Path::new("test/policy").join(name);

        let policy =
            Policy::read_from_file(path.join("policy.rego").to_str().unwrap(), name).unwrap();

        let input = fs::read_to_string(path.join("input.json").to_str().unwrap()).unwrap();

        let expected: Appraisal = serde_json::from_str(
            fs::read_to_string(path.join("appraisal.json").to_str().unwrap())
                .unwrap()
                .as_ref(),
        )
        .unwrap();

        let appraisal = super::appraise(&input, &policy).unwrap();

        assert_eq!(appraisal, expected);
    }
}
