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
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::certificate_request::CertificateRequest;

/// An Authenticator as per RFC9261 Exported Authenticators
#[derive(Debug, PartialEq, Clone)]
pub struct Authenticator {
    certificate: Certificate,
    certificate_verify: CertificateVerify,
    finished: Finished,
}

impl Authenticator {
    pub fn new(
        certificate: CertificateDer,
        private_key: PrivateKeyDer,
        certificate_request: &CertificateRequest,
        // The Handshake Context is an exporter value that is derived using the label "EXPORTER-client authenticator handshake context" or "EXPORTER-server authenticator handshake context" for authenticators sent by the client or server, respectively.
        handshake_context_exporter: [u8; 64],
        // The Finished MAC Key is an exporter value derived using the label "EXPORTER-client authenticator finished key" or "EXPORTER-server authenticator finished key" for authenticators sent by the client or server, respectively.
        finished_key_exporter: [u8; 32],
    ) -> Self {
        let certificate = certificate.to_vec();
        let certificate = Certificate {
            certificate_request_context: Default::default(),
            certificate_list: vec![CertificateEntry::from_cert_der(certificate.to_vec())],
        };

        let certificate_verify = CertificateVerify::new(
            &certificate,
            private_key,
            &certificate_request,
            &handshake_context_exporter,
        );

        let finished = Finished::new(
            &certificate,
            &certificate_verify,
            certificate_request,
            &handshake_context_exporter,
            &finished_key_exporter,
        );

        Self {
            certificate,
            certificate_verify,
            finished,
        }
    }

    /// Serialize to bytes
    /// Certificate || CertificateVerify || Finished
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&self.certificate.encode());
        output.extend_from_slice(&self.certificate_verify.encode());
        output.extend_from_slice(&self.finished.encode());
        output
    }

    /// Deserialize from bytes
    pub fn decode(input: &[u8]) -> Result<Self, ()> {
        let (certificate, input) = Certificate::decode(&input).unwrap();
        let (certificate_verify, input) = CertificateVerify::decode(&input).unwrap();
        Ok(Self {
            certificate,
            certificate_verify,
            finished: Finished::decode(input),
        })
    }

    pub fn cert_der(&self) -> Result<Vec<u8>, String> {
        match self.certificate.certificate_list.iter().next() {
            Some(certificate_entry) => certificate_entry.as_cert_der(),
            None => Err("No ceritficate".to_string()),
        }
    }

    pub fn verify(
        &self,
        certificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
        finished_key_exporter: &[u8; 32],
    ) -> Result<(), String> {
        let finished_check = Finished::new(
            &self.certificate,
            &self.certificate_verify,
            certificate_request,
            handshake_context_exporter,
            finished_key_exporter,
        );
        if finished_check != self.finished {
            return Err("Could not verify Finished message".to_string());
        }

        self.certificate_verify.verify(
            &self.certificate,
            certificate_request,
            handshake_context_exporter,
        )
    }
}

/// CertificateVerify message as per
/// https://www.rfc-editor.org/rfc/rfc9261#section-5.2.2
#[derive(Debug, PartialEq, Clone)]
struct CertificateVerify {
    signature: Signature,
}

impl CertificateVerify {
    fn new(
        certificate: &Certificate,
        private_key: PrivateKeyDer,
        cerificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
    ) -> Self {
        // TODO check the encoding is PKCS8
        let signing_key = SigningKey::from_pkcs8_der(private_key.secret_der()).unwrap();
        let message = Self::create_certificate_verify_message(
            certificate,
            cerificate_request,
            handshake_context_exporter,
        );

        Self {
            signature: signing_key.sign(&message),
        }
    }

    fn encode(&self) -> Vec<u8> {
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

    fn decode(input: &[u8]) -> Result<(Self, &[u8]), String> {
        if input.len() < 4 {
            return Err("Message too short to be a valid CertificateVerify message.".to_string());
        }

        let signature_scheme = u16::from_be_bytes([input[0], input[1]]);
        if signature_scheme != 0x0403 {
            return Err(format!(
                "Unsupported signature scheme: {:x}. Expected ecdsa_secp256r1_sha256 (0x0403).",
                signature_scheme
            ));
        }

        let signature_len = u16::from_be_bytes([input[2], input[3]]) as usize;
        if input.len() < 4 + signature_len {
            return Err(
                "Signature length field indicates a length greater than the message size."
                    .to_string(),
            );
        }

        let signature_bytes = &input[4..4 + signature_len];
        let remaining = &input[4 + signature_len..];

        Ok((
            Self {
                signature: Signature::from_der(signature_bytes)
                    .map_err(|e| format!("Failed to decode DER signature: {:?}", e))?,
            },
            remaining,
        ))
    }

    /// Verify the signature
    fn verify(
        &self,
        certificate: &Certificate,
        cerificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
    ) -> Result<(), String> {
        // Extract the public key from the certificate
        let certificate_entry = certificate.certificate_list.iter().next().unwrap();
        if let CertificateType::X509(x509_bytes) = &certificate_entry.certificate_type {
            let (_, cert) = X509Certificate::from_der(&x509_bytes).unwrap();

            let pk_info = &cert.tbs_certificate.subject_pki.parsed().unwrap();
            if let x509_parser::public_key::PublicKey::EC(ec_point) = pk_info {
                let ec_bytes = ec_point.data();
                let encoded_point = EncodedPoint::from_bytes(ec_bytes).unwrap();
                let verifying_key = VerifyingKey::from_encoded_point(&encoded_point).unwrap();

                let message = CertificateVerify::create_certificate_verify_message(
                    certificate,
                    cerificate_request,
                    handshake_context_exporter,
                );
                verifying_key
                    .verify(&message, &self.signature)
                    .map_err(|e| e.to_string())
            } else {
                Err("Public key is not P256".to_string())
            }
        } else {
            Err("No X509 Certificate".to_string())
        }
    }

    /// Static method to create the message to be signed - this is called in both the contrustor and the verify
    /// method
    fn create_certificate_verify_message(
        certificate: &Certificate,
        certificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
    ) -> Vec<u8> {
        let mut message = Vec::new();

        // The signature is computed using the chosen signature scheme over the concatenation of:
        // - A string that consists of octet 32 (0x20) repeated 64 times
        // - The context string "Exported Authenticator" (which is not NUL-terminated)
        // - A single 0 octet that serves as the separator
        // - The hashed authenticator transcript

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
            hasher.update(certificate.encode());

            hasher.finalize()
        };
        message.extend_from_slice(&authentictor_transcript);
        message
    }
}

/// The Finished message which is:
///
/// HMAC(Finished MAC Key, Hash(Handshake Context || authenticator request || Certificate || CertificateVerify))
// TODO this should be wrapped in a HandshakeMessage with type (0x14) and length (3 bytes)
#[derive(Debug, PartialEq, Clone)]
struct Finished {
    hmac: Vec<u8>,
}

impl Finished {
    fn new(
        certificate: &Certificate,
        certificate_verify: &CertificateVerify,
        certificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
        finished_key_exporter: &[u8; 32],
    ) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(finished_key_exporter).unwrap();

        mac.update(handshake_context_exporter);
        mac.update(&certificate_request.encode());
        mac.update(&certificate.encode());
        mac.update(&certificate_verify.encode());

        let hmac = mac.finalize();
        Self {
            hmac: hmac.into_bytes().to_vec(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        self.hmac.clone()
    }

    fn decode(input: &[u8]) -> Self {
        Self {
            hmac: input.to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
enum CertificateType {
    X509(Vec<u8>),
    RawPublicKey(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone)]
struct CertificateEntry {
    certificate_type: CertificateType,
    extensions: Vec<u8>,
}

impl CertificateEntry {
    fn from_cert_der(cert_der: Vec<u8>) -> Self {
        Self {
            certificate_type: CertificateType::X509(cert_der),
            extensions: Default::default(), // TODO
        }
    }

    #[allow(dead_code)]
    fn from_raw_public_key(raw_public_key: Vec<u8>) -> Self {
        Self {
            certificate_type: CertificateType::RawPublicKey(raw_public_key),
            extensions: Default::default(), // TODO
        }
    }

    fn as_cert_der(&self) -> Result<Vec<u8>, String> {
        match &self.certificate_type {
            CertificateType::X509(cert_der) => Ok(cert_der.to_vec()),
            _ => Err("No X509 Cerificate".to_string()),
        }
    }

    // Encode for a certificate message with length prefix
    fn encode(&self) -> Vec<u8> {
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

    fn decode(input: &[u8]) -> Result<(Self, &[u8]), io::Error> {
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
struct Certificate {
    pub certificate_request_context: Vec<u8>,
    pub certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    fn encode(&self) -> Vec<u8> {
        let mut certificate_list_bytes = Vec::new();
        let mut cursor = Cursor::new(&mut certificate_list_bytes);

        let encoded_cert_entry = self.certificate_list.iter().next().unwrap().encode();

        // Write the 24-bit length prefix for the combined certificate entries
        let certificate_entry_len = encoded_cert_entry.len();
        assert!(
            certificate_entry_len < 0x00FFFFFF,
            "Certificate list too large"
        );
        let len_bytes = [
            (certificate_entry_len >> 16) as u8,
            (certificate_entry_len >> 8) as u8,
            certificate_entry_len as u8,
        ];
        cursor
            .write_all(&len_bytes)
            .expect("Failed to write certificate list length");

        // Write the `CertificateEntry` bytes
        cursor
            .write_all(&encoded_cert_entry)
            .expect("Failed to write certificate entry");

        // TODO add request context
        certificate_list_bytes
    }

    fn decode(input: &[u8]) -> Result<(Self, &[u8]), io::Error> {
        let mut cursor = Cursor::new(input);

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
        let (certificate_entry, remaining_in_list) = CertificateEntry::decode(&cert_list_data)?;
        let certificate_list = vec![certificate_entry];

        // Ensure there are no leftover bytes within the certificate list data itself
        if !remaining_in_list.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected bytes in certificate list",
            ));
        }

        // TODO add context here
        let certificate_request_context = Vec::new();

        let offset = 3 + cert_list_len;
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

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};
    use rcgen::CertificateParams;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;

    fn create_cert_der(keypair: &rcgen::KeyPair) -> Vec<u8> {
        let params = CertificateParams::new(["localhost".to_string()]).unwrap();
        let cert = params.self_signed(keypair).unwrap();
        cert.der().to_vec()
    }

    fn create_certificate_request() -> CertificateRequest {
        let mut context = [0u8; 32];
        OsRng.fill_bytes(&mut context);

        CertificateRequest {
            certificate_request_context: context.to_vec(),
            extensions: b"cmw_attestation".to_vec(), // TODO
        }
    }

    #[test]
    fn encode_decode_authenticator() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let private_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der()));

        let certificate_request = create_certificate_request();

        let handshake_context_exporter = [0; 64];
        let finished_key_exporter = [0; 32];

        let authenticator = Authenticator::new(
            cert_der.into(),
            private_key_der,
            &certificate_request,
            handshake_context_exporter,
            finished_key_exporter,
        );

        let encoded = authenticator.encode();

        assert_eq!(authenticator, Authenticator::decode(&encoded).unwrap());

        authenticator
            .verify(
                &certificate_request,
                &handshake_context_exporter,
                &finished_key_exporter,
            )
            .unwrap();
    }

    #[test]
    fn encode_decode_certificate_entry() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let entry = CertificateEntry::from_cert_der(cert_der.clone());
        let encoded = entry.encode();
        let (decoded_entry, _) = CertificateEntry::decode(&encoded).unwrap();

        if let CertificateType::X509(decoded_cert) = decoded_entry.certificate_type {
            assert_eq!(cert_der, decoded_cert);
        } else {
            panic!("Decoded certificate type is not X509");
        }
    }

    #[test]
    fn encode_decode_certificate() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let entry = CertificateEntry::from_cert_der(cert_der.clone());

        let certificate = Certificate {
            certificate_request_context: Default::default(),
            certificate_list: vec![entry],
        };

        let encoded = certificate.encode();
        let (decoded_cert, _) = Certificate::decode(&encoded).unwrap();

        assert_eq!(certificate, decoded_cert);
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

        let encoded = certificate.encode();
        let (decoded_cert, _) = Certificate::decode(&encoded).unwrap();

        assert_eq!(certificate, decoded_cert);
    }
}
