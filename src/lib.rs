pub mod authenticator;
pub mod certificate_request;
mod tls_handshake_messages;

// use asn1_rs::{FromDer, Sequence};
// use asn1_rs::{Oid, ToDer};
// use rcgen::CustomExtension;
use thiserror::Error;
// use x509_parser::der_parser::oid;
use x509_parser::error::X509Error;
// use x509_parser::prelude::X509Certificate;

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

/// Returns the OID for the cwm attestation
// TODO #5 replace with the acutal OID for the cwm_attestation extension
// pub fn oid_cmw_attestation() -> Oid<'static> {
//     oid!(1.3.6 .1 .4 .1 .42424242 .1)
// }

/// Given CMW wrapped attestation data create a [CustomExtension]
// pub fn create_cmw_attestation_extension(
//     cmw_wrapped_attestation: &[u8],
// ) -> Result<CustomExtension, CmwAttestationCertifcateExtensionError> {
//     let sequence = Sequence::new(cmw_wrapped_attestation.into());
//
//     Ok(CustomExtension::from_oid_content(
//         &oid_to_u64_vec(&oid_cmw_attestation())?,
//         sequence.to_der_vec()?,
//     ))
// }
//
// /// Given a DER encoded certificate, extract the CMW wrapped attestation data
// pub fn extract_attestation(
//     cert_der: &[u8],
// ) -> Result<Vec<u8>, CmwAttestationCertifcateExtensionError> {
//     let (_, cert) = X509Certificate::from_der(cert_der)?;
//     let extensions = cert.extensions_map()?;
//     let extension = extensions
//         .get(&oid_cmw_attestation())
//         .ok_or(CmwAttestationCertifcateExtensionError::NoCmwExtension)?;
//     let sequence_der = extension.value.to_vec();
//     let (_, sequence) = Sequence::from_der(&sequence_der)?;
//     Ok(sequence.content.to_vec())
// }

// /// Internal helper to format an OID as a Vec<u64>
// fn oid_to_u64_vec(oid: &Oid) -> Result<Vec<u64>, CmwAttestationCertifcateExtensionError> {
//     let iter = oid
//         .iter()
//         .ok_or(CmwAttestationCertifcateExtensionError::OIDComponentTooLarge)?;
//
//     Ok(iter.collect())
// }

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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use rcgen::CertificateParams;
//
//     fn create_cert_der(attestation: Option<&[u8]>) -> Vec<u8> {
//         let keypair = rcgen::KeyPair::generate().unwrap();
//         let mut params = CertificateParams::new(["localhost".to_string()]).unwrap();
//
//         if let Some(attestation) = attestation {
//             params
//                 .custom_extensions
//                 .push(create_cmw_attestation_extension(attestation).unwrap());
//         }
//
//         let cert = params.self_signed(&keypair).unwrap();
//         cert.der().to_vec()
//     }
//
//     #[test]
//     fn extract_attestation_from_cert() {
//         let attestation = b"attestation goes here";
//         let cert_der = create_cert_der(Some(attestation));
//         assert_eq!(extract_attestation(&cert_der).unwrap(), attestation);
//     }
// }
