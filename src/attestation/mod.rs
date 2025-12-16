use cmw::Monad;
use std::str::FromStr;
use tdx_quote::QuoteParseError;
use thiserror::Error;

/// The mime type for DCAP TDX
const TDX_QUOTE_MIME: &str =
    "application/tdx-quote; version=1.0; profile=\"https://trustedcomputinggroup.org/tdx/v1\"";

/// Returns the mime type for DCAP TDX
pub fn tdx_quote_media_type() -> cmw::Mime {
    cmw::Mime::from_str(TDX_QUOTE_MIME).expect("Failed to parse TDX quote media type")
}

#[cfg(any(feature = "dcap-tdx", test))]
pub mod dcap_tdx;

/// The supported attestation types
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AttestationType {
    None,
    DcapTdx,
}

/// Can generate a local attestation based on attestation type
#[derive(Clone, Debug)]
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
    ) -> Result<Option<Monad>, AttestationGenerationError> {
        match self.attestation_type {
            AttestationType::None => Ok(None),
            #[cfg(any(feature = "dcap-tdx", test))]
            AttestationType::DcapTdx => Ok(Some(dcap_tdx::generate_to_monad(input_data)?)),
            #[cfg(not(any(feature = "dcap-tdx", test)))]
            _ => Err(AttestationGenerationError::AttestationTypeNotSupported),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MultiMeasurements {
    DcapTdx {
        mrtd: [u8; 48],
        rtmr0: [u8; 48],
        rtmr1: [u8; 48],
        rtmr2: [u8; 48],
        rtmr3: [u8; 48],
    },
    None,
}

impl MultiMeasurements {
    fn from_tdx_quote(input: &tdx_quote::Quote) -> Self {
        Self::DcapTdx {
            mrtd: input.mrtd(),
            rtmr0: input.rtmr0(),
            rtmr1: input.rtmr1(),
            rtmr2: input.rtmr2(),
            rtmr3: input.rtmr3(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttestationValidator {
    pub accepted_measurements: Vec<MultiMeasurements>,
}

impl AttestationValidator {
    pub fn new_mock_tdx() -> Self {
        Self {
            accepted_measurements: vec![MultiMeasurements::DcapTdx {
                mrtd: [0; 48],
                rtmr0: [0; 48],
                rtmr1: [0; 48],
                rtmr2: [0; 48],
                rtmr3: [0; 48],
            }],
        }
    }

    pub async fn validate_attestation(
        &self,
        monad: Monad,
        expected_input_data: [u8; 64],
    ) -> Result<(), AttestationVerificationError> {
        match monad.type_().as_str() {
            TDX_QUOTE_MIME => {
                let quote = tdx_quote::Quote::from_bytes(&monad.value())?;

                if quote.report_input_data() != expected_input_data {
                    return Err(AttestationVerificationError::InputData);
                }
                let measurements = MultiMeasurements::from_tdx_quote(&quote);

                if self
                    .accepted_measurements
                    .iter()
                    .find(|m| **m == measurements)
                    .is_none()
                {
                    return Err(AttestationVerificationError::MeasurementsNotAccepted);
                }

                // #[cfg(not(feature = "mock"))]
                // quote.verify()?;
            }
            _ => {}
        }
        Ok(())
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
    #[error("Conceptual message wrappers")]
    Cmw(#[from] cmw::Error),
}

#[derive(Error, Debug)]
pub enum AttestationVerificationError {
    #[cfg(any(feature = "dcap-tdx", test))]
    #[error("TDX quote verification: {0}")]
    Tdx(#[from] tdx_quote::QuoteVerificationError),
    #[error("Attestation type not supported")]
    AttestationTypeNotSupported,
    #[error("Quore parse: {0}")]
    QuoteParse(#[from] QuoteParseError),
    #[error("Quote input data does not match exporter")]
    InputData,
    #[error("Measurements not accepted")]
    MeasurementsNotAccepted,
}
