use thiserror::Error;

#[cfg(any(feature = "dcap-tdx", test))]
pub mod dcap_tdx;

#[derive(Debug, Clone, PartialEq)]
pub enum AttestationType {
    None,
    DcapTdx,
}

#[derive(Error, Debug)]
pub enum AttestationVerificationError {
    // #[error("TDX quote verification: {0}")]
    // Tdx(#[from] tdx_quote::error::QuoteVerificationError),
}
