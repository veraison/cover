use corim_rs::{CryptoKeyTypeChoice, EnvironmentMap};

use crate::ect::Ect;
use crate::policy::Policy;
use crate::result::Error;

/// Scheme represents a verifier scheme. It handles tasks that require domain-specific knowledge,
/// such as parsing attestation evidence and providing a policy for its appraisal.
pub trait Scheme {
    /// The name of the scheme. Used specify the scheme to the verifier.
    fn name(&self) -> String;
    /// Profile that will be set in the attestation result when this scheme is used.
    fn profile(&self) -> String;
    /// Indicates whether the specified input matches the evidence format expected by the scheme.
    /// This maybe used to "guess" which scheme should be used for evaluating evidence when one is
    /// not identified by name.
    fn match_evidence(&self, evidence: &[u8]) -> bool;
    /// Get trust anchor id from the evidence. This is used to obtain a trust anchor that may be
    /// used to validate the evidence signature.
    fn get_trust_anchor_id<'a>(&self, evidence: &[u8]) -> Result<EnvironmentMap<'a>, Error>;
    /// Validate evidence using provided trust anchor, and parse it into a series of [Ect]s.
    fn validate_and_parse_evidence<'a>(
        &self,
        evidence: &[u8],
        trust_anchor: &CryptoKeyTypeChoice<'a>,
    ) -> Result<Vec<Ect<'a>>, Error>;
    /// Get [Policy] instances associated with the scheme.
    fn get_policies(&self) -> Vec<Policy>;
}
