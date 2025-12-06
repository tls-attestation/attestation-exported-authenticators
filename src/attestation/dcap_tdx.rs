use cmw::Mime;
use std::str::FromStr;
use tdx_quote::Quote;

const TDX_QUOTE_MIME: &str =
    "application/tdx-quote; version=1.0; profile=\"https://trustedcomputinggroup.org/tdx/v1\"";

pub fn tdx_quote_media_type() -> Mime {
    Mime::from_str(TDX_QUOTE_MIME).expect("Failed to parse TDX quote media type")
}

/// Create a mock quote for testing on non-TDX hardware
#[cfg(feature = "mock")]
pub fn generate_quote(input: [u8; 64]) -> Vec<u8> {
    use rand_core::OsRng;
    let attestation_key = tdx_quote::SigningKey::random(&mut OsRng);
    let provisioning_certification_key = tdx_quote::SigningKey::random(&mut OsRng);
    Quote::mock(
        attestation_key.clone(),
        provisioning_certification_key.clone(),
        input,
        b"Mock cert chain".to_vec(),
    )
    .as_bytes()
}

#[cfg(not(feature = "mock"))]
pub fn generate_quote(input: [u8; 64]) -> Vec<u8> {
    configfs_tsm::create_quote(input).unwrap()
}
