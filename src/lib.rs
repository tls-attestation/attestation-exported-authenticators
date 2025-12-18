pub mod attestation;
pub mod authenticator;
pub mod certificate_request;
mod tls_handshake_messages;

#[cfg(any(feature = "quic", test))]
pub mod quic;

use thiserror::Error;
pub use tls_handshake_messages::{CMWAttestation, Extension, VerificationError};
use x509_parser::error::X509Error;

/// Label used in client authenticator handshake context
pub static EXPORTER_CLIENT_AUTHENTICATOR_HANDSHAKE_CONTEXT: &[u8] =
    b"EXPORTER-client authenticator handshake context";

/// Label used in server authenticator handshake context
pub static EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT: &[u8] =
    b"EXPORTER-server authenticator handshake context";

/// Label used in client authenticator finished message HMAC key
pub static EXPORTER_CLIENT_AUTHENTICATOR_FINISHED_KEY: &[u8] =
    b"EXPORTER-client authenticator finished key";

/// Label used in server authenticator finished message HMAC key
pub static EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY: &[u8] =
    b"EXPORTER-server authenticator finished key";

/// An error when handling a cmw_attestion certificate extension
#[derive(Error, Debug)]
pub enum CmwAttestationCertifcateExtensionError {
    #[error("OID component too large")]
    OIDComponentTooLarge,
    #[error("ASN1 Serialization: {0}")]
    Asn1Serialize(#[from] asn1_rs::SerializeError),
    #[error("X509: {0}")]
    X509(#[from] X509Error),
    #[error("No cmw_attestation extension present")]
    NoCmwExtension,
    #[error("ASN1: {0}")]
    Asn1(#[from] asn1_rs::Error),
    #[error("ASN1: {0}")]
    Asn10(#[from] asn1_rs::Err<asn1_rs::Error>),
    #[error("ASN1 X509: {0}")]
    Asn1X509(#[from] asn1_rs::Err<x509_parser::error::X509Error>),
}

/// An error when encoding a message
#[derive(Error, Debug)]
pub enum EncodeError {
    #[error("Failed to encode {0}")]
    Io(#[from] std::io::Error),
    #[error("Expected at least one certificate")]
    NoCertificate,
    #[error("HMAC: {0}")]
    HMAC(#[from] hmac::digest::InvalidLength),
    #[error("Request context length must be less than 255 bytes")]
    ContextTooLong,
    #[error("Encoded certificate entry is too long to process")]
    CertificateEntryTooLong,
    #[error("Length must be less than 2^24-1 bytes")]
    TooLong,
    #[error("Extension length must be less than 65535 bytes.")]
    ExtensionTooLong,
    #[error("Rustls: {0}")]
    Rustls(rustls::Error),
    #[error("Cannot get crypto provider")]
    NoProvider,
    #[error("No signature scheme available")]
    NoSignatureScheme,
    #[error("CMW error: {0}")]
    CMWError(#[from] cmw::Error),
}

impl From<rustls::Error> for EncodeError {
    fn from(err: rustls::Error) -> Self {
        EncodeError::Rustls(err)
    }
}

/// An error when decoding a message
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Failed to decode {0}")]
    Io(#[from] std::io::Error),
    #[error("Bad length: {0}")]
    BadLength(String),
    #[error("Unexpected signature scheme: {0}")]
    BadSignatureScheme(String),
    #[error("Bad message type")]
    UnknownMessageType,
    #[error("Unexpected message type")]
    UnexpectedMessageType,
    #[error("Extension type not recognized")]
    UnknownExtensionType,
    #[error("CMW error: {0}")]
    CMWError(#[from] cmw::Error),
}
