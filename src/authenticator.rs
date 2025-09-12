use std::io::{self, Cursor, Read, Write};

use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

/// An Authenticator as per RFC9261 Exported Authenticators
#[derive(Debug, PartialEq, Clone)]
pub struct Authenticator {
    certificate: Certificate,
    certificate_verify: Vec<u8>,
    finished: Vec<u8>,
}

impl Authenticator {
    pub fn new(certificate: CertificateDer, private_key: PrivateKeyDer) -> Self {
        // TODO#4 this should be encoded as a cert chain with length prefix:
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2
        let certificate = certificate.to_vec();
        let certificate = Certificate {
            certificate_request_context: Default::default(),
            certificate_list: vec![CertificateEntry::from_cert_der(certificate.to_vec())],
        };

        // TODO#4 this should be the signature
        // https://www.rfc-editor.org/rfc/rfc9261#section-5.2.2
        // TODO check the encoding is PKCS8
        let signing_key = SigningKey::from_pkcs8_der(private_key.secret_der()).unwrap();

        // The signature is computed using the chosen signature scheme over the concatenation of:
        // a string that consists of octet 32 (0x20) repeated 64 times,
        // the context string "Exported Authenticator" (which is not NUL-terminated),
        // a single 0 octet that serves as the separator,
        //  and the hashed authenticator transcript.
        //
        //  The authenticator transcript is the hash of the concatenated
        //  Handshake Context, authenticator request (if present), and
        //  Certificate message:
        //
        // Hash(Handshake Context || authenticator request || Certificate)
        let mut hasher = Sha256::new();
        hasher.update(&certificate.encode());
        let message = hasher.finalize();
        let signature: Signature = signing_key.sign(&message);

        let certificate_verify = signature.to_vec();

        // TODO#4 this should be:
        // Finished = HMAC(Finished MAC Key, Hash(Handshake Context ||
        //      authenticator request || Certificate || CertificateVerify))
        let finished = Default::default();

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
        output.extend_from_slice(&self.certificate_verify);
        output.extend_from_slice(&self.finished);
        output
    }

    /// Deserialize from bytes
    pub fn decode(input: Vec<u8>) -> Result<Self, ()> {
        // TODO this should actually parse all values
        let (certificate, input) = Certificate::decode(&input).unwrap();
        Ok(Self {
            certificate,
            certificate_verify: input.to_vec(), // TODO parse this with length prefix
            finished: Default::default(),
        })
    }

    pub fn cert_der(&self) -> Result<Vec<u8>, String> {
        match self.certificate.certificate_list.iter().next() {
            Some(certificate_entry) => certificate_entry.as_cert_der(),
            None => Err("No ceritficate".to_string()),
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
    use rcgen::CertificateParams;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;

    fn create_cert_der(keypair: &rcgen::KeyPair) -> Vec<u8> {
        let params = CertificateParams::new(["localhost".to_string()]).unwrap();
        let cert = params.self_signed(keypair).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn encode_decode_authenticator() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let private_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der()));

        let authenticator = Authenticator::new(cert_der.into(), private_key_der);

        let encoded = authenticator.encode();

        assert_eq!(authenticator, Authenticator::decode(encoded).unwrap());
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
}
