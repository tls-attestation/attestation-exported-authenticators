pub mod authenticator;
pub mod certificate_request;
mod tls_handshake_messages;

use thiserror::Error;
pub use tls_handshake_messages::Extension;
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

/// Extension type for cmw_attestion extension
// TODO what should this be
pub static CMW_ATTESTATION_EXTENSION_TYPE: [u8; 2] = [0; 2];

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
    #[error("Failed to convert secret key: {0}")]
    PKCS8(#[from] p256::pkcs8::Error),
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
    #[error("Failed to decode DER signature: {0}")]
    P256(#[from] p256::ecdsa::Error),
    #[error("Bad message type")]
    UnknownMessageType,
    #[error("Unexpected message type")]
    UnexpectedMessageType,
}
