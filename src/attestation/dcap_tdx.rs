use cmw::Monad;

use crate::attestation::{
    AttestationGenerationError, AttestationVerificationError, MultiMeasurements,
};

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

pub async fn validate_attestation(
    input: &[u8],
    expected_input_data: [u8; 64],
) -> Result<MultiMeasurements, AttestationVerificationError> {
    let quote = tdx_quote::Quote::from_bytes(input)?;

    // Check input data
    if quote.report_input_data() != expected_input_data {
        return Err(AttestationVerificationError::InputData);
    }

    // #[cfg(not(feature = "mock"))]
    // quote.verify()?;
    //
    Ok(MultiMeasurements::from_tdx_quote(&quote))
}
