use strum::IntoEnumIterator;
use strum_macros::EnumIter;

/// Arm CCA Platform endorsement Corim profile identifier.
const CCA_CORIM_PLATFORM_PROFILE: &str = "tag:arm.com,2025:endorsements/cca_platform#1.0.0";

/// Arm CCA Realm endorsement Corim profile identifier.
const CCA_CORIM_REALM_PROFILE: &str = "tag:arm.com,2025:endorsements/cca_realm#1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum CcaCorimProfile {
    Platform,
    Realm,
}

impl CcaCorimProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => CCA_CORIM_PLATFORM_PROFILE,
            Self::Realm => CCA_CORIM_REALM_PROFILE,
        }
    }

    pub fn all() -> Vec<String> {
        Self::iter().map(|p| p.to_string()).collect()
    }
}

impl std::fmt::Display for CcaCorimProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for CcaCorimProfile {
    type Error = crate::Error;

    fn try_from(profile: &str) -> Result<Self, Self::Error> {
        match profile {
            CCA_CORIM_PLATFORM_PROFILE => Ok(Self::Platform),
            CCA_CORIM_REALM_PROFILE => Ok(Self::Realm),
            _ => Err(crate::Error::custom(format!(
                "Unrecognised CCA CoRIM profile \"{}\". \
                 Supported profiles: \"{}\", \"{}\"",
                profile, CCA_CORIM_PLATFORM_PROFILE, CCA_CORIM_REALM_PROFILE,
            ))),
        }
    }
}
