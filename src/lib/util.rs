use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::result::Error;

#[inline]
pub fn b64decode(v: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(v)
        .map_err(|e| Error::invalid_value(e.to_string(), "a base64-encoded string"))
}
