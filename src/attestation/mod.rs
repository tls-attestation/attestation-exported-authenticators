use thiserror::Error;

#[cfg(any(feature = "dcap-tdx", test))]
pub mod dcap_tdx;

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AttestationType {
    None,
    DcapTdx,
}

/// Can generate a local attestation based on attestation type
#[derive(Clone)]
pub struct AttestationGenerator {
    pub attestation_type: AttestationType,
}

impl AttestationGenerator {
    pub fn with_no_attestation() -> Self {
        Self {
            attestation_type: AttestationType::None,
        }
    }

    /// Generate an attestation exchange message
    #[allow(unused_variables)]
    pub async fn generate_attestation(
        &self,
        input_data: [u8; 64],
    ) -> Result<Option<Vec<u8>>, AttestationGenerationError> {
        match self.attestation_type {
            AttestationType::None => Ok(None),
            #[cfg(any(feature = "dcap-tdx", test))]
            AttestationType::DcapTdx => Ok(Some(dcap_tdx::generate_quote(input_data)?)),
            #[cfg(not(any(feature = "dcap-tdx", test)))]
            _ => Err(AttestationGenerationError::AttestationTypeNotSupported),
        }
    }
}

#[derive(Error, Debug)]
pub enum AttestationGenerationError {
    #[cfg(any(feature = "dcap-tdx", test))]
    #[error("TDX quote verification: {0}")]
    Tdx(#[from] tdx_quote::QuoteVerificationError),
    #[error("Quote generation: {0}")]
    QuoteGeneration(#[from] configfs_tsm::QuoteGenerationError),
    #[error("Attestation type not supported")]
    AttestationTypeNotSupported,
}

#[derive(Error, Debug)]
pub enum AttestationVerificationError {
    #[cfg(any(feature = "dcap-tdx", test))]
    #[error("TDX quote verification: {0}")]
    Tdx(#[from] tdx_quote::QuoteVerificationError),
    #[error("Attestation type not supported")]
    AttestationTypeNotSupported,
}
