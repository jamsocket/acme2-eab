use crate::error::*;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use serde::Deserialize;
use serde::Serialize;

/// This is a identifier for a resource that the ACME server
/// can provision certificates for (a domain).
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Identifier {
  /// The type of identifier.
  pub r#type: String,
  /// The identifier itself.
  pub value: String,
}

pub(crate) fn b64(data: &[u8]) -> String {
  base64::encode_config(data, ::base64::URL_SAFE_NO_PAD)
}

/// Generate a new RSA private key using the specified size,
/// using the system random.
pub fn gen_rsa_private_key(bits: u32) -> Result<PKey<Private>, Error> {
  let rsa = Rsa::generate(bits)?;
  let key = PKey::from_rsa(rsa)?;
  Ok(key)
}
