use std::{
    fmt::{Debug, Display},
    num::TryFromIntError,
};

use ear::RawValue;

#[derive(Debug)]
pub enum Error {
    InvalidValue(Box<dyn Debug + Sync + Send>, String),
    PolicyClaims(RawValue),
    MissingField(String, String),
    SignatureValidation,
    Parse(String, String),
    KidNotFound(Vec<u8>),
    SchemeNotFound(String),
    Custom(String),
}

#[macro_export]
macro_rules! custom_error {
    ($txt:expr, $($e:expr),*) => {
        Error::custom(format!($txt, $($e),*))
    };
}

impl Error {
    pub fn invalid_value<T>(val: T, expected: &str) -> Error
    where
        T: Sync + Send + Debug + 'static,
    {
        Error::InvalidValue(Box::new(val), expected.to_string())
    }

    pub fn missing_field<T>(obj: T, field: T) -> Error
    where
        T: Display,
    {
        Error::MissingField(obj.to_string(), field.to_string())
    }

    pub fn parse<T>(source: T, cause: T) -> Error
    where
        T: Display,
    {
        Error::Parse(source.to_string(), cause.to_string())
    }

    pub fn scheme_not_found(name: &str) -> Error {
        Error::SchemeNotFound(name.to_string())
    }

    pub fn custom<T>(val: T) -> Error
    where
        T: Display,
    {
        Error::Custom(val.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Error::InvalidValue(value, expected) => {
                format!("invalid value: {:?}, expected {}", *value, expected,)
            }
            Error::PolicyClaims(raw_val) => format!(
                "unexpected policy_claims value (must be a map with string keys): {:?}",
                raw_val,
            ),
            Error::MissingField(obj, field) => {
                format!("missing mandatory field {}.{}", obj, field,)
            }
            Error::SignatureValidation => "signature validation failed".to_string(),
            Error::Parse(src, message) => format!("error parsing {}: {}", src, message,),
            Error::KidNotFound(kid) => format!("kid not found: {:x?}", kid),
            Error::SchemeNotFound(name) => format!("scheme not found: {:x?}", name),
            Error::Custom(message) => message.to_string(),
        };

        f.write_str(&text)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<corim_rs::error::CorimError> for Error {
    fn from(value: corim_rs::error::CorimError) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<corim_rs::error::CoreError> for Error {
    fn from(value: corim_rs::error::CoreError) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(value: serde_json::error::Error) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<anyhow::Error> for Error {
    fn from(value: anyhow::Error) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(value: base64::DecodeError) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<TryFromIntError> for Error {
    fn from(value: TryFromIntError) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<ear::Error> for Error {
    fn from(value: ear::Error) -> Self {
        Self::Custom(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
