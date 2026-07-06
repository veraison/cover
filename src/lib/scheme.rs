use log::{debug, info};

use corim_rs::{Corim, CryptoKeyTypeChoice, EnvironmentMap, ProfileTypeChoice};

use crate::corim::is_rim_valid;
use crate::ect::Ect;
use crate::policy::Policy;
use crate::result::Result;

/// Scheme represents a verifier scheme. It handles tasks that require domain-specific knowledge,
/// such as parsing attestation evidence and providing a policy for its appraisal.
pub trait Scheme {
    /// The name of the scheme. Used specify the scheme to the verifier.
    fn name(&self) -> String;

    /// Profile that will be set in the attestation result when this scheme is used.
    fn profile(&self) -> String;

    /// Return supported Corim profiles for endorsements.
    fn get_supported_corim_profiles(&self) -> Vec<String>;

    /// Return true when the CoRIM profile is compatible with this scheme.
    // Scheme not supporting use of Profile in corim do not need to use this method.
    fn supports_profile(&self, profile: Option<&ProfileTypeChoice<'_>>) -> bool {
        let scheme_supported_profiles = self.get_supported_corim_profiles();

        if scheme_supported_profiles.is_empty() && profile.is_none() {
            debug!(
                "Input CoRIM profile field is empty and scheme does not support profile field in Corim CDDL"
            );
            return true;
        }
        let corim_profile = match profile {
            Some(ProfileTypeChoice::Uri(uri)) => uri.to_string(),
            Some(ProfileTypeChoice::Oid(oid)) => oid.to_string(),
            _ => {
                debug!("Extension value not supported");
                return false;
            }
        };

        for p in self.get_supported_corim_profiles() {
            if corim_profile == p {
                return true;
            }
        }
        info!("Unsupported profile \"{}\" ", corim_profile);
        false
    }

    fn supports_corim(&self, corim: &Corim<'_>) -> Result<bool> {
        Ok(self.supports_profile(corim.as_map_ref().profile.as_ref())
            && is_rim_valid(corim.as_map_ref().rim_validity.as_ref()))
    }

    /// Indicates whether the specified input matches the evidence format expected by the scheme.
    /// This maybe used to "guess" which scheme should be used for evaluating evidence when one is
    /// not identified by name.
    fn match_evidence(&self, evidence: &[u8]) -> bool;
    /// Get trust anchor id from the evidence. This is used to obtain a trust anchor that may be
    /// used to validate the evidence signature.
    fn get_trust_anchor_id<'a>(&self, evidence: &[u8]) -> Result<EnvironmentMap<'a>>;
    /// Validate evidence using provided trust anchor, and parse it into a series of [Ect]s.
    fn validate_and_parse_evidence<'a>(
        &self,
        evidence: &[u8],
        trust_anchor: &CryptoKeyTypeChoice<'a>,
    ) -> Result<Vec<Ect<'a>>>;
    /// Get [Policy] instances associated with the scheme.
    fn get_policies(&self) -> Vec<Policy>;
}
