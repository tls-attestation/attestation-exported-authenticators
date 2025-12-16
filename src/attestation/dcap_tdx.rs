use cmw::Monad;

use crate::attestation::AttestationGenerationError;

pub fn generate_to_monad(input: [u8; 64]) -> Result<Monad, AttestationGenerationError> {
    Ok(Monad::new_media_type(
        super::tdx_quote_media_type(),
        generate_quote(input)?,
        None,
    )?)
}

/// Create a mock quote for testing on non-TDX hardware
#[cfg(test)]
pub fn generate_quote(input: [u8; 64]) -> Result<Vec<u8>, AttestationGenerationError> {
    use rand_core::OsRng;
    let attestation_key = tdx_quote::SigningKey::random(&mut OsRng);
    let provisioning_certification_key = tdx_quote::SigningKey::random(&mut OsRng);

    Ok(tdx_quote::Quote::mock(
        attestation_key.clone(),
        provisioning_certification_key.clone(),
        input,
        b"Mock cert chain".to_vec(),
    )
    .as_bytes())
}

#[cfg(not(test))]
pub fn generate_quote(input: [u8; 64]) -> Result<Vec<u8>, AttestationGenerationError> {
    Ok(configfs_tsm::create_quote(input)?)
}
