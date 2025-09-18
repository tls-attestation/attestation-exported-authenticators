//! TLS 1.3 Handshake messages which are used in the exported authenticator
//!
//! ['The illustrated TLS 1.3 Connection'](https://tls13.xargs.org) is a useful resource for these

use std::io::{self, Cursor, Read, Write};

use hmac::{Hmac, Mac};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    pkcs8::DecodePrivateKey,
    EncodedPoint,
};
use rustls::pki_types::PrivateKeyDer;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::prelude::*;

use crate::{certificate_request::CertificateRequest, DecodeError, EncodeError};

/// CertificateVerify message as per
/// https://www.rfc-editor.org/rfc/rfc9261#section-5.2.2
#[derive(Debug, PartialEq, Clone)]
pub struct CertificateVerify {
    signature: Signature,
}

impl CertificateVerify {
    pub fn new(
        certificate: &Certificate,
        private_key: PrivateKeyDer,
        cerificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
    ) -> Result<Self, EncodeError> {
        // TODO check the encoding is PKCS8
        let signing_key = SigningKey::from_pkcs8_der(private_key.secret_der())?;
        let message = Self::create_certificate_verify_message(
            certificate,
            cerificate_request,
            handshake_context_exporter,
        )?;

        Ok(Self {
            signature: signing_key.sign(&message),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut cert_verify_message = Vec::new();

        // SignatureScheme for ecdsa_secp256r1_sha256
        cert_verify_message.extend_from_slice(&[0x04, 0x03]);

        let der_signature = self.signature.to_der();
        let signature_bytes = der_signature.as_bytes();

        // Add length prefix
        cert_verify_message.extend_from_slice(&(signature_bytes.len() as u16).to_be_bytes());

        cert_verify_message.extend_from_slice(signature_bytes);

        cert_verify_message
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        if input.len() < 4 {
            return Err(DecodeError::BadLength(
                "Message too short to be a valid CertificateVerify message".to_string(),
            ));
        }

        let signature_scheme = u16::from_be_bytes([input[0], input[1]]);
        if signature_scheme != 0x0403 {
            return Err(DecodeError::BadSignatureScheme(format!(
                "Unsupported signature scheme: {:x}. Expected ecdsa_secp256r1_sha256 (0x0403)",
                signature_scheme
            )));
        }

        let signature_len = u16::from_be_bytes([input[2], input[3]]) as usize;
        if input.len() < 4 + signature_len {
            return Err(DecodeError::BadLength(
                "Signature length field indicates a length greater than the message size."
                    .to_string(),
            ));
        }

        let signature_bytes = &input[4..4 + signature_len];
        let remaining = &input[4 + signature_len..];

        Ok((
            Self {
                signature: Signature::from_der(signature_bytes)?,
            },
            remaining,
        ))
    }

    /// Verify the signature
    pub fn verify(
        &self,
        certificate: &Certificate,
        cerificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
    ) -> Result<(), VerificationError> {
        // Extract the public key from the certificate
        let certificate_entry = certificate
            .certificate_list
            .iter()
            .next()
            .ok_or(EncodeError::NoCertificate)?;

        if let CertificateType::X509(x509_bytes) = &certificate_entry.certificate_type {
            let (_, cert) = X509Certificate::from_der(&x509_bytes)?;

            let pk_info = &cert.tbs_certificate.subject_pki.parsed()?;
            if let x509_parser::public_key::PublicKey::EC(ec_point) = pk_info {
                let ec_bytes = ec_point.data();
                let encoded_point = EncodedPoint::from_bytes(ec_bytes)
                    .map_err(|_| VerificationError::EncodedPoint)?;
                let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)?;

                let message = CertificateVerify::create_certificate_verify_message(
                    certificate,
                    cerificate_request,
                    handshake_context_exporter,
                )?;

                verifying_key.verify(&message, &self.signature)?;
                Ok(())
            } else {
                Err(VerificationError::NotP256)
            }
        } else {
            Err(VerificationError::NoCertificate)
        }
    }

    /// Static method to create the message to be signed - this is called in both the contrustor and the verify
    /// method
    fn create_certificate_verify_message(
        certificate: &Certificate,
        certificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
    ) -> Result<Vec<u8>, EncodeError> {
        let mut message = Vec::new();

        // The signature is computed using the chosen signature scheme over the concatenation of:
        // - A string that consists of octet 32 (0x20) repeated 64 times
        // - The context string "Exported Authenticator" (which is not NUL-terminated)
        // - A single 0 octet that serves as the separator
        // - The hashed authenticator transcript
        //
        // As per RFC9261 Section 5.5.2
        // https://www.rfc-editor.org/rfc/rfc9261#name-certificateverify

        message.extend_from_slice(&[0x20; 64]);
        message.extend_from_slice(b"Exported Authenticator");
        message.extend_from_slice(&[0; 1]);

        let authentictor_transcript = {
            // The authenticator transcript is the hash of the concatenated Handshake Context,
            // authenticator request (if present), and Certificate message:
            //
            // Hash(Handshake Context || authenticator request || Certificate)
            let mut hasher = Sha256::new();
            hasher.update(handshake_context_exporter);
            hasher.update(certificate_request.encode());
            hasher.update(certificate.encode()?);

            hasher.finalize()
        };
        message.extend_from_slice(&authentictor_transcript);
        Ok(message)
    }
}

/// The Finished message which is:
///
/// HMAC(Finished MAC Key, Hash(Handshake Context || authenticator request || Certificate || CertificateVerify))
// TODO this should be wrapped in a HandshakeMessage with type (0x14) and length (3 bytes)
#[derive(Debug, PartialEq, Clone)]
pub struct Finished {
    hmac: Vec<u8>,
}

impl Finished {
    pub fn new(
        certificate: &Certificate,
        certificate_verify: &CertificateVerify,
        certificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
        finished_key_exporter: &[u8; 32],
    ) -> Result<Self, EncodeError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(finished_key_exporter)?;

        mac.update(handshake_context_exporter);
        mac.update(&certificate_request.encode());
        mac.update(&certificate.encode()?);
        mac.update(&certificate_verify.encode());

        let hmac = mac.finalize();
        Ok(Self {
            hmac: hmac.into_bytes().to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.hmac.clone()
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            hmac: input.to_vec(),
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum CertificateType {
    X509(Vec<u8>),
    RawPublicKey(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone)]
pub struct CertificateEntry {
    pub certificate_type: CertificateType,
    pub extensions: Vec<u8>,
}

impl CertificateEntry {
    pub fn from_cert_der(cert_der: Vec<u8>) -> Self {
        Self {
            certificate_type: CertificateType::X509(cert_der),
            extensions: Default::default(), // TODO
        }
    }

    #[allow(dead_code)]
    pub fn from_raw_public_key(raw_public_key: Vec<u8>) -> Self {
        Self {
            certificate_type: CertificateType::RawPublicKey(raw_public_key),
            extensions: Default::default(), // TODO
        }
    }

    pub fn as_cert_der(&self) -> Result<Vec<u8>, String> {
        match &self.certificate_type {
            CertificateType::X509(cert_der) => Ok(cert_der.to_vec()),
            _ => Err("No X509 Cerificate".to_string()),
        }
    }

    /// Encode a certificate message with length prefix
    pub fn encode(&self) -> Vec<u8> {
        let mut certificate_entry_bytes = Vec::new();
        let mut cursor = Cursor::new(&mut certificate_entry_bytes);

        match &self.certificate_type {
            CertificateType::X509(cert_der) => {
                // Write the 24-bit length prefix for the DER certificate data.
                let der_cert_len = cert_der.len();
                assert!(der_cert_len < 0x00FFFFFF, "Certificate data too large");
                let len_bytes = [
                    (der_cert_len >> 16) as u8,
                    (der_cert_len >> 8) as u8,
                    der_cert_len as u8,
                ];
                cursor
                    .write_all(&len_bytes)
                    .expect("Failed to write certificate length");

                // Write the actual DER certificate data.
                cursor
                    .write_all(&cert_der)
                    .expect("Failed to write certificate data");
            }
            _ => {
                todo!()
            }
        }

        // Write the 16-bit length prefix for extensions - currently empty
        let extensions_len_bytes: [u8; 2] = [0x00, 0x00];
        cursor
            .write_all(&extensions_len_bytes)
            .expect("Failed to write extensions length");

        certificate_entry_bytes
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), io::Error> {
        // Read the 3-byte length prefix for the certificate
        if input.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Input too short for certificate length prefix",
            ));
        }
        let cert_len_bytes = &input[0..3];
        let cert_len = ((cert_len_bytes[0] as usize) << 16)
            | ((cert_len_bytes[1] as usize) << 8)
            | (cert_len_bytes[2] as usize);
        let mut offset = 3;

        // Read the certificate data based on the length
        if input.len() < offset + cert_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Input too short for certificate data",
            ));
        }
        let cert_der = input[offset..offset + cert_len].to_vec();
        offset += cert_len;

        // For this specific implementation, we assume the certificate type is X509
        let certificate_type = CertificateType::X509(cert_der);

        // Read the 2-byte length prefix for extensions
        if input.len() < offset + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Input too short for extensions length prefix",
            ));
        }
        let extensions_len_bytes = &input[offset..offset + 2];
        let extensions_len =
            ((extensions_len_bytes[0] as usize) << 8) | (extensions_len_bytes[1] as usize);
        offset += 2;

        // Read the extensions data based on the length
        if input.len() < offset + extensions_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Input too short for extensions data",
            ));
        }
        let extensions = input[offset..offset + extensions_len].to_vec();
        offset += extensions_len;

        let entry = CertificateEntry {
            certificate_type,
            extensions,
        };

        let remaining = &input[offset..];
        Ok((entry, remaining))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Certificate {
    pub certificate_request_context: Vec<u8>,
    pub certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut certificate_list_bytes = Vec::new();
        let mut cursor = Cursor::new(&mut certificate_list_bytes);

        let context_len = self.certificate_request_context.len();
        if context_len > 255 {
            return Err(EncodeError::ContextTooLong);
        }
        cursor.write_all(&[context_len as u8])?;
        cursor.write_all(&self.certificate_request_context)?;

        // TODO here we just take the first cert in the list, but we should iterate over all of
        // them
        let encoded_cert_entry = self
            .certificate_list
            .iter()
            .next()
            .ok_or(EncodeError::NoCertificate)?
            .encode();

        // Write the 24-bit length prefix for the combined certificate entries
        let certificate_entry_len = encoded_cert_entry.len();
        if certificate_entry_len > 0x00FFFFFF {
            return Err(EncodeError::CertificateEntryTooLong);
        };
        let len_bytes = [
            (certificate_entry_len >> 16) as u8,
            (certificate_entry_len >> 8) as u8,
            certificate_entry_len as u8,
        ];
        cursor.write_all(&len_bytes)?;

        // Write the `CertificateEntry` bytes
        cursor.write_all(&encoded_cert_entry)?;

        Ok(certificate_list_bytes)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let mut cursor = Cursor::new(input);

        // Read context
        let mut context_len_bytes = [0; 1];
        cursor.read_exact(&mut context_len_bytes)?;
        let context_len: usize = context_len_bytes[0].into();

        let mut certificate_request_context = vec![0u8; context_len];
        cursor.read_exact(&mut certificate_request_context)?;

        // Read the 3-byte length prefix for the certificate list
        let mut cert_list_len_bytes = [0u8; 3];
        cursor.read_exact(&mut cert_list_len_bytes)?;
        let cert_list_len = ((cert_list_len_bytes[0] as usize) << 16)
            | ((cert_list_len_bytes[1] as usize) << 8)
            | (cert_list_len_bytes[2] as usize);

        // Read the certificate list bytes
        let mut cert_list_data = vec![0u8; cert_list_len];
        cursor.read_exact(&mut cert_list_data)?;

        // Decode the single CertificateEntry from the list data and get the remaining bytes
        let (certificate_entry, _remaining) = CertificateEntry::decode(&cert_list_data)?;
        let certificate_list = vec![certificate_entry];

        // // Ensure there are no leftover bytes within the certificate list data itself
        // if !remaining_in_list.is_empty() {
        //     return Err(io::Error::new(
        //         io::ErrorKind::InvalidData,
        //         "Unexpected bytes in certificate list",
        //     ));
        // }

        let offset = 1 + context_len + 3 + cert_list_len;
        let remaining_after_list = &input[offset..];

        Ok((
            Certificate {
                certificate_request_context,
                certificate_list,
            },
            remaining_after_list,
        ))
    }
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Signature verification: {0}")]
    Io(#[from] p256::ecdsa::Error),
    #[error("No X509 certificate")]
    NoCertificate,
    #[error("Encode: {0}")]
    Encode(#[from] EncodeError),
    #[error("Only P256 signatures currently supported")]
    NotP256,
    #[error("Could not verify Finished message")]
    BadFinished,
    #[error("ASN1 X509: {0}")]
    Asn1X509(#[from] asn1_rs::Err<X509Error>),
    #[error("X509: {0}")]
    X509(#[from] X509Error),
    #[error("Failed to convert encoded point")]
    EncodedPoint,
}

#[cfg(test)]
mod tests {
    use rcgen::CertificateParams;

    use super::*;

    fn create_cert_der(keypair: &rcgen::KeyPair) -> Vec<u8> {
        let params = CertificateParams::new(["localhost".to_string()]).unwrap();
        let cert = params.self_signed(keypair).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn encode_decode_certificate_entry() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let entry = CertificateEntry::from_cert_der(cert_der.clone());
        let encoded = entry.encode();
        let (decoded_entry, remaining) = CertificateEntry::decode(&encoded).unwrap();

        if let CertificateType::X509(decoded_cert) = decoded_entry.certificate_type {
            assert_eq!(cert_der, decoded_cert);
        } else {
            panic!("Decoded certificate type is not X509");
        }

        assert!(remaining.is_empty());
    }

    #[test]
    fn encode_decode_certificate() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let entry = CertificateEntry::from_cert_der(cert_der.clone());

        let certificate = Certificate {
            certificate_request_context: b"context".to_vec(),
            certificate_list: vec![entry],
        };

        let encoded = certificate.encode().unwrap();
        let (decoded_cert, remaining) = Certificate::decode(&encoded).unwrap();

        assert_eq!(certificate, decoded_cert);
        assert!(remaining.is_empty());
    }

    #[test]
    fn encode_decode_certificate_verify() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);

        let entry = CertificateEntry::from_cert_der(cert_der.clone());

        let certificate = Certificate {
            certificate_request_context: Default::default(),
            certificate_list: vec![entry],
        };

        let encoded = certificate.encode().unwrap();
        let (decoded_cert, _) = Certificate::decode(&encoded).unwrap();

        assert_eq!(certificate, decoded_cert);
    }
}
