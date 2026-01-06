//! TLS 1.3 Handshake messages which are used in the exported authenticator
//!
//! ['The illustrated TLS 1.3 Connection'](https://tls13.xargs.org) is a useful resource for these

use std::io::{Cursor, Read, Write};

use cmw::{Monad, CMW};
use hmac::{Hmac, Mac};
use rustls::{crypto::CryptoProvider, pki_types::PrivateKeyDer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use webpki::RawPublicKeyEntity;
use x509_parser::prelude::*;

use crate::{certificate_request::CertificateRequest, DecodeError, EncodeError};

/// Represents the different possible handshake message types
// Dead code allowed because not all variants are constructed
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(u8)]
enum HandshakeMessageType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl TryFrom<u8> for HandshakeMessageType {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HandshakeMessageType::ClientHello),
            2 => Ok(HandshakeMessageType::ServerHello),
            11 => Ok(HandshakeMessageType::Certificate),
            15 => Ok(HandshakeMessageType::CertificateVerify),
            20 => Ok(HandshakeMessageType::Finished),
            _ => Err(DecodeError::UnknownMessageType),
        }
    }
}

/// A HandShakeMessage wrapper as per RFC8448
struct HandShakeMessage {
    /// Which of the handshake messages this is
    handshake_type: HandshakeMessageType,
    /// The encoded handshake message
    payload: Vec<u8>,
}

impl HandShakeMessage {
    fn new_certificate(payload: Vec<u8>) -> Self {
        Self {
            handshake_type: HandshakeMessageType::Certificate,
            payload,
        }
    }

    fn new_certificate_verify(payload: Vec<u8>) -> Self {
        Self {
            handshake_type: HandshakeMessageType::CertificateVerify,
            payload,
        }
    }

    fn new_finished(payload: Vec<u8>) -> Self {
        Self {
            handshake_type: HandshakeMessageType::Finished,
            payload,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut output = Vec::new();
        output.extend_from_slice(&[self.handshake_type.clone() as u8]);
        let payload_length = usize_to_uint24_bytes(self.payload.len())?;
        output.extend_from_slice(&payload_length);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let mut cursor = Cursor::new(input);

        let mut handshake_type_byte = [0];
        cursor.read_exact(&mut handshake_type_byte)?;
        let handshake_type = handshake_type_byte[0].try_into()?;

        let mut length_bytes = [0u8; 3];
        cursor.read_exact(&mut length_bytes)?;
        let payload_length = uint24_bytes_to_usize(length_bytes);

        let mut payload = vec![0u8; payload_length];
        cursor.read_exact(&mut payload)?;

        let current_position = cursor.position() as usize;
        let remaining = &input[current_position..];

        Ok((
            Self {
                handshake_type,
                payload,
            },
            remaining,
        ))
    }
}

/// CertificateVerify message as per
/// https://www.rfc-editor.org/rfc/rfc9261#section-5.2.2
#[derive(Debug, PartialEq, Clone)]
pub struct CertificateVerify {
    signing_scheme: rustls::SignatureScheme,
    signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn new(
        provider: &CryptoProvider,
        certificate: &Certificate,
        private_key: PrivateKeyDer,
        cerificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
    ) -> Result<Self, EncodeError> {
        let signing_key = provider
            .key_provider
            .load_private_key(private_key.clone_key())?;

        let supported_schemes = provider
            .signature_verification_algorithms
            .supported_schemes();

        let signer = signing_key
            .choose_scheme(&supported_schemes)
            .ok_or(EncodeError::NoSignatureScheme)?;

        let message = Self::create_certificate_verify_message(
            certificate,
            cerificate_request,
            handshake_context_exporter,
        )?;

        Ok(Self {
            signature: signer.sign(&message)?,
            signing_scheme: signer.scheme(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut cert_verify_message = Vec::new();

        cert_verify_message.extend_from_slice(&self.signing_scheme.to_array());

        cert_verify_message.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());

        cert_verify_message.extend_from_slice(&self.signature);

        let handshake_message = HandShakeMessage::new_certificate_verify(cert_verify_message);
        handshake_message.encode()
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (handshake_message, remaining) = HandShakeMessage::decode(input)?;
        let input = handshake_message.payload;
        if handshake_message.handshake_type != HandshakeMessageType::CertificateVerify {
            return Err(DecodeError::UnexpectedMessageType);
        }

        if input.len() < 4 {
            return Err(DecodeError::BadLength(
                "Message too short to be a valid CertificateVerify message".to_string(),
            ));
        }

        let signature_scheme = u16::from_be_bytes([input[0], input[1]]);
        if signature_scheme != 0x0403 {
            return Err(DecodeError::BadSignatureScheme(format!(
                "Unsupported signature scheme: {signature_scheme:x}. Expected ecdsa_secp256r1_sha256 (0x0403)"
            )));
        }

        let signature_len = u16::from_be_bytes([input[2], input[3]]) as usize;
        if input.len() < 4 + signature_len {
            return Err(DecodeError::BadLength(
                "Signature length field indicates a length greater than the message size."
                    .to_string(),
            ));
        }

        let signature = &input[4..4 + signature_len];
        // let remaining = &input[4 + signature_len..];

        Ok((
            Self {
                signature: signature.to_vec(),
                signing_scheme: signature_scheme.into(),
            },
            remaining,
        ))
    }

    /// Verify the signature
    pub fn verify(
        &self,
        provider: &CryptoProvider,
        certificate: &Certificate,
        cerificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
    ) -> Result<(), VerificationError> {
        // Extract the public key from the certificate
        let certificate_entry = certificate
            .certificate_list
            .first()
            .ok_or(EncodeError::NoCertificate)?;

        if let CertificateType::X509(x509_bytes) = &certificate_entry.certificate_type {
            let (_, cert) = X509Certificate::from_der(x509_bytes)?;

            let spki: rustls::pki_types::SubjectPublicKeyInfoDer =
                cert.tbs_certificate.subject_pki.raw.into();

            let public_key: RawPublicKeyEntity = (&spki).try_into()?;

            let message = CertificateVerify::create_certificate_verify_message(
                certificate,
                cerificate_request,
                handshake_context_exporter,
            )?;

            let schemes = provider.signature_verification_algorithms.mapping;

            let scheme = schemes
                .iter()
                .find(|(s, _)| *s == self.signing_scheme)
                .ok_or(VerificationError::NoSignatureScheme)?
                .1
                .first()
                .ok_or(VerificationError::NoSignatureScheme)?;

            public_key.verify_signature(*scheme, &message, &self.signature)?;

            Ok(())
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
        mac.update(&certificate_verify.encode()?);

        let hmac = mac.finalize();
        Ok(Self {
            hmac: hmac.into_bytes().to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let handshake_message = HandShakeMessage::new_finished(self.hmac.clone());
        handshake_message.encode()
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (handshake_message, remaining) = HandShakeMessage::decode(input)?;
        if handshake_message.handshake_type != HandshakeMessageType::Finished {
            return Err(DecodeError::UnexpectedMessageType);
        }

        Ok((
            Self {
                hmac: handshake_message.payload,
            },
            remaining,
        ))
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
    pub extensions: Vec<Extension>,
}

impl CertificateEntry {
    pub fn from_cert_der(cert_der: Vec<u8>, extensions: Vec<Extension>) -> Self {
        Self {
            certificate_type: CertificateType::X509(cert_der),
            extensions,
        }
    }

    #[allow(dead_code)]
    pub fn from_raw_public_key(raw_public_key: Vec<u8>, extensions: Vec<Extension>) -> Self {
        Self {
            certificate_type: CertificateType::RawPublicKey(raw_public_key),
            extensions,
        }
    }

    pub fn as_cert_der(&self) -> Result<Vec<u8>, String> {
        match &self.certificate_type {
            CertificateType::X509(cert_der) => Ok(cert_der.to_vec()),
            _ => Err("No X509 Cerificate".to_string()),
        }
    }

    /// Encode a certificate message with length prefix
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut certificate_entry_bytes = Vec::new();
        let mut cursor = Cursor::new(&mut certificate_entry_bytes);

        let cert_data = match &self.certificate_type {
            CertificateType::X509(cert_der) => cert_der,
            CertificateType::RawPublicKey(raw_public_key) => raw_public_key,
        };

        // Write the 24-bit length prefix for the certificate data
        let cert_data_len = cert_data.len();
        if cert_data_len > 0x00FFFFFF {
            return Err(EncodeError::CertificateEntryTooLong);
        }
        let len_bytes = [
            (cert_data_len >> 16) as u8,
            (cert_data_len >> 8) as u8,
            cert_data_len as u8,
        ];
        cursor.write_all(&len_bytes)?;

        // Write the actual certificate data
        cursor.write_all(cert_data)?;

        let mut encoded_extensions = Vec::new();

        for extension in self.extensions.iter() {
            encoded_extensions.extend_from_slice(&extension.encode()?);
        }

        if encoded_extensions.len() > 0xFFFF {
            return Err(EncodeError::ExtensionTooLong);
        }
        let u16_length = encoded_extensions.len() as u16;
        cursor.write_all(&u16_length.to_be_bytes())?;

        cursor.write_all(&encoded_extensions)?;

        Ok(certificate_entry_bytes)
    }

    /// Decode, assuming certificate is given as x509
    /// In the context of exported authenticators, this is generally what is used
    pub fn decode_x509(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Self::decode(input, true)
    }

    #[allow(dead_code)]
    /// Decode, assuming certificate is given as a raw public key
    pub fn decode_raw_public_key(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        Self::decode(input, false)
    }

    fn decode(input: &[u8], is_x509: bool) -> Result<(Self, &[u8]), DecodeError> {
        // Read the 3-byte length prefix for the certificate
        if input.len() < 3 {
            return Err(DecodeError::BadLength(
                "Input too short for certificate length prefix".to_string(),
            ));
        }
        let cert_len_bytes = &input[0..3];
        let cert_len = ((cert_len_bytes[0] as usize) << 16)
            | ((cert_len_bytes[1] as usize) << 8)
            | (cert_len_bytes[2] as usize);
        let mut offset = 3;

        // Read the certificate data based on the length
        if input.len() < offset + cert_len {
            return Err(DecodeError::BadLength(
                "Input too short for certificate data".to_string(),
            ));
        }
        let cert_data = input[offset..offset + cert_len].to_vec();
        offset += cert_len;

        let certificate_type = if is_x509 {
            CertificateType::X509(cert_data)
        } else {
            CertificateType::RawPublicKey(cert_data)
        };

        // Read the 2-byte length prefix for extensions
        if input.len() < offset + 2 {
            return Err(DecodeError::BadLength(
                "Input too short for extensions length prefix".to_string(),
            ));
        }
        let extensions_len_bytes = &input[offset..offset + 2];
        let extensions_len =
            ((extensions_len_bytes[0] as usize) << 8) | (extensions_len_bytes[1] as usize);
        offset += 2;

        // Read the extensions data based on the length
        if input.len() < offset + extensions_len {
            return Err(DecodeError::BadLength(
                "Input too short for extensions data".to_string(),
            ));
        }
        let mut encoded_extensions = &input[offset..offset + extensions_len];
        offset += extensions_len;

        let mut extensions = Vec::new();
        while !encoded_extensions.is_empty() {
            let (extension, remaining) = Extension::decode(encoded_extensions)?;
            extensions.push(extension);
            encoded_extensions = remaining;
        }

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
        let mut certificate_bytes = Vec::new();
        let mut cursor = Cursor::new(&mut certificate_bytes);

        let context_len = self.certificate_request_context.len();
        if context_len > 255 {
            return Err(EncodeError::ContextTooLong);
        }
        cursor.write_all(&[context_len as u8])?;
        cursor.write_all(&self.certificate_request_context)?;

        let certificate_list_bytes = {
            let mut certificate_list_bytes = Vec::new();
            let mut cursor = Cursor::new(&mut certificate_list_bytes);
            for cert in self.certificate_list.iter() {
                let encoded_cert_entry = cert.encode()?;

                // Write the `CertificateEntry` bytes
                cursor.write_all(&encoded_cert_entry)?;
            }
            certificate_list_bytes
        };

        // Write the 24-bit length prefix for the combined certificate entries
        let certificate_entry_len = certificate_list_bytes.len();
        if certificate_entry_len > 0x00FFFFFF {
            return Err(EncodeError::CertificateEntryTooLong);
        };
        let len_bytes = [
            (certificate_entry_len >> 16) as u8,
            (certificate_entry_len >> 8) as u8,
            certificate_entry_len as u8,
        ];
        cursor.write_all(&len_bytes)?;

        cursor.write_all(&certificate_list_bytes)?;

        let handshake_message = HandShakeMessage::new_certificate(certificate_bytes);
        handshake_message.encode()
    }

    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (handshake_message, remaining) = HandShakeMessage::decode(input)?;
        if handshake_message.handshake_type != HandshakeMessageType::Certificate {
            return Err(DecodeError::UnexpectedMessageType);
        }

        let mut cursor = Cursor::new(handshake_message.payload);

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

        // Decode the CertificateEntrys from the list data
        let mut certificate_list = Vec::new();
        while !cert_list_data.is_empty() {
            let (certificate_entry, remaining) = CertificateEntry::decode_x509(&cert_list_data)?;
            certificate_list.push(certificate_entry);
            cert_list_data = remaining.to_vec();
        }

        Ok((
            Certificate {
                certificate_request_context,
                certificate_list,
            },
            remaining,
        ))
    }
}

/// Represents an extension as given in a [CertificateEntry]
#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data: Vec<u8>,
}

impl Extension {
    /// Create a `attestation_cmw` extension with the given payload
    pub fn new_attestation_cmw(data: Vec<u8>) -> Self {
        Self {
            extension_type: ExtensionType::CMWAttestation,
            extension_data: data,
        }
    }

    /// Serialize to bytes
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut extension_bytes = Vec::new();
        let mut cursor = Cursor::new(&mut extension_bytes);

        cursor.write_all(&(self.extension_type.clone() as u16).to_be_bytes())?;

        if self.extension_data.len() > 0xFFFF {
            return Err(EncodeError::ExtensionTooLong);
        }

        let u16_length = self.extension_data.len() as u16;

        cursor.write_all(&u16_length.to_be_bytes())?;
        cursor.write_all(&self.extension_data)?;

        Ok(extension_bytes)
    }

    /// Deserialize from bytes
    pub fn decode(input: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let mut cursor = Cursor::new(input);

        let mut extension_type_val = [0; 2];
        cursor.read_exact(&mut extension_type_val)?;

        let extension_type = ExtensionType::try_from(u16::from_be_bytes(extension_type_val))?;

        let mut length_bytes = [0; 2];
        cursor.read_exact(&mut length_bytes)?;
        let length = u16::from_be_bytes(length_bytes);

        let mut extension_data = vec![0u8; length.into()];
        cursor.read_exact(&mut extension_data)?;

        let mut remaining = Vec::new();
        cursor.read_to_end(&mut remaining)?;

        let position = cursor.position() as usize;
        let remaining = &input[position..];

        Ok((
            Self {
                extension_type,
                extension_data,
            },
            remaining,
        ))
    }
}

#[repr(u16)]
#[derive(Debug, PartialEq, Clone)]
pub enum ExtensionType {
    ServerName = 0x0000,
    MaxFragmentLength = 0x0001,
    StatusRequest = 0x0005,
    SupportedGroups = 0x000a,
    SignatureAlgorithms = 0x000d,
    UseSrtp = 0x000e,
    Heartbeat = 0x000f,
    ApplicationLayerProtocolNegotiation = 0x0010,
    SignedCertificateTimestamp = 0x0012,
    ClientCertificateType = 0x0013,
    ServerCertificateType = 0x0014,
    Padding = 0x0015,
    PreSharedKey = 0x0029,
    EarlyData = 0x002a,
    SupportedVersions = 0x002b,
    Cookie = 0x002c,
    PskKeyExchangeModes = 0x002d,
    CertificateAuthorities = 0x002f,
    OidFilters = 0x0030,
    PostHandshakeAuth = 0x0031,
    SignatureAlgorithmsCert = 0x0032,
    KeyShare = 0x0033,
    CMWAttestation = 0xffff,
}

impl TryFrom<u16> for ExtensionType {
    type Error = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(ExtensionType::ServerName),
            0x0001 => Ok(ExtensionType::MaxFragmentLength),
            0x0005 => Ok(ExtensionType::StatusRequest),
            0x000a => Ok(ExtensionType::SupportedGroups),
            0x000d => Ok(ExtensionType::SignatureAlgorithms),
            0x000e => Ok(ExtensionType::UseSrtp),
            0x000f => Ok(ExtensionType::Heartbeat),
            0x0010 => Ok(ExtensionType::ApplicationLayerProtocolNegotiation),
            0x0012 => Ok(ExtensionType::SignedCertificateTimestamp),
            0x0013 => Ok(ExtensionType::ClientCertificateType),
            0x0014 => Ok(ExtensionType::ServerCertificateType),
            0x0015 => Ok(ExtensionType::Padding),
            0x0029 => Ok(ExtensionType::PreSharedKey),
            0x002a => Ok(ExtensionType::EarlyData),
            0x002b => Ok(ExtensionType::SupportedVersions),
            0x002c => Ok(ExtensionType::Cookie),
            0x002d => Ok(ExtensionType::PskKeyExchangeModes),
            0x002f => Ok(ExtensionType::CertificateAuthorities),
            0x0030 => Ok(ExtensionType::OidFilters),
            0x0031 => Ok(ExtensionType::PostHandshakeAuth),
            0x0032 => Ok(ExtensionType::SignatureAlgorithmsCert),
            0x0033 => Ok(ExtensionType::KeyShare),
            0xffff => Ok(ExtensionType::CMWAttestation),
            _ => Err(DecodeError::UnknownExtensionType),
        }
    }
}

/// CMW Attestation extension contents
///
/// Corresponds to the CMWAttestation structure defined in
/// section 3 of draft-fossati-seat-expat.
#[derive(Debug, PartialEq, Clone)]
pub struct CMWAttestation(CMW);

impl CMWAttestation {
    /// Create a new extension from a CMW
    pub fn new(cmw: CMW) -> Self {
        Self(cmw)
    }

    /// Get the inner CMW
    pub fn cmw(self) -> CMW {
        self.0
    }

    /// Get the inner Monad CMW, or return an error if it is not a Monad
    pub fn monad_cmw(self) -> Result<Monad, DecodeError> {
        match self.0 {
            CMW::Monad(m) => Ok(m),
            _ => Err(DecodeError::CMWError(cmw::Error::Unexpected(
                "Not a monad CMW".into(),
            ))),
        }
    }

    /// Get the inner Collection CMW, or return an error if it is not a Collection
    pub fn collection_cmw(self) -> Result<cmw::Collection, DecodeError> {
        match self.0 {
            CMW::Collection(c) => Ok(c),
            _ => Err(DecodeError::CMWError(cmw::Error::Unexpected(
                "Not a collection CMW".into(),
            ))),
        }
    }

    /// Encode the CMW Attestation extension data to CBOR
    pub fn encode_cbor(&self) -> Result<Vec<u8>, EncodeError> {
        let marshalled_cmw = self.0.marshal_cbor()?;
        let len: u16 = marshalled_cmw
            .len()
            .try_into()
            .map_err(|_| EncodeError::TooLong)?;

        let mut result = Vec::new();
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&marshalled_cmw);
        Ok(result)
    }

    /// Decode the CMW Attestation extension data
    pub fn decode_cbor(input: &[u8]) -> Result<Self, DecodeError> {
        // Read the two byte big endian length prefix
        // then call CMW::unmarshal_cbor on the remaining bytes
        if input.len() < 2 {
            return Err(DecodeError::BadLength(
                "Input too short for CMW length prefix".to_string(),
            ));
        }
        let len = u16::from_be_bytes([input[0], input[1]]) as usize;
        if input.len() < 2 + len {
            return Err(DecodeError::BadLength(
                "Input too short for CMW data".to_string(),
            ));
        }
        let cbor_data = &input[2..2 + len];
        let cmw = CMW::unmarshal_cbor(cbor_data)?;
        Ok(Self(cmw))
    }
}

/// An error when verifying a [CertificateVerify]
#[derive(Error, Debug)]
pub enum VerificationError {
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
    #[error("WebPKI: {0}")]
    WebPki(webpki::Error),
    #[error("No signature scheme available")]
    NoSignatureScheme,
    #[error("Cannot get crypto provider")]
    NoProvider,
}

impl From<webpki::Error> for VerificationError {
    fn from(err: webpki::Error) -> Self {
        VerificationError::WebPki(err)
    }
}

/// Helper for creating uint24 for length prefix
fn usize_to_uint24_bytes(value: usize) -> Result<[u8; 3], EncodeError> {
    if value > 0xFFFFFF {
        return Err(EncodeError::TooLong);
    }
    let full_bytes = (value as u32).to_be_bytes();
    Ok([full_bytes[1], full_bytes[2], full_bytes[3]])
}

/// Helper for decoding uint24 for length prefix
fn uint24_bytes_to_usize(bytes: [u8; 3]) -> usize {
    let full_bytes: [u8; 4] = [0u8, bytes[0], bytes[1], bytes[2]];
    let value = u32::from_be_bytes(full_bytes);
    value as usize
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

    fn hex_string_to_bytes(hex_string: &str) -> Vec<u8> {
        let cleaned_hex = hex_string.split_whitespace().collect::<String>();
        hex::decode(cleaned_hex).unwrap()
    }

    #[test]
    fn decode_certificate() {
        // Test data from RFC8448
        let cert_hex = r#"0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
        01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
        86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
        72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
        0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
        03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
        0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
        82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
        d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
        1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
        4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
        80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
        ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
        01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
        03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
        01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
        72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
        e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
        51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
        c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
        1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
        96 12 29 ac 91 87 b4 2b 4d e1 00 00"#;
        let cert_bytes = hex_string_to_bytes(cert_hex);

        let (_decoded_entry, remaining) = Certificate::decode(&cert_bytes).unwrap();

        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_certificate_verify() {
        // Test data from RFC8448
        let certificate_verify_hex = r#"0f 00 00 4b 04 03 00 47 30 45 02
         21 00 d7 a4 d3 4b d5 4f 55 fe e1 a8 96 25 67 8c 3d d5 e5 f6 0d
         ac 73 ec 94 0c 5c 7b 93 04 a0 20 84 a9 02 20 28 9f 59 5e d4 88
         b9 ac 68 9a 3d 19 2b 1a 8b b3 8f 34 af 78 74 c0 59 c9 80 6a 1f
         38 26 93 53 e8"#;
        let cert_bytes = hex_string_to_bytes(certificate_verify_hex);

        let (_certificate_verify, remaining) = CertificateVerify::decode(&cert_bytes).unwrap();

        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_finished() {
        // Test data from RFC8448
        let finished_hex = r#"14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a
         c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce
         61"#;

        let finished_bytes = hex_string_to_bytes(finished_hex);

        let (_decoded, remaining) = Finished::decode(&finished_bytes).unwrap();

        assert!(remaining.is_empty());
    }

    #[test]
    fn encode_decode_certificate_entry() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let extensions = vec![Extension {
            extension_type: ExtensionType::CMWAttestation,
            extension_data: b"foo".to_vec(),
        }];
        let entry = CertificateEntry::from_cert_der(cert_der.clone(), extensions);
        let encoded = entry.encode().unwrap();
        let (decoded_entry, remaining) = CertificateEntry::decode_x509(&encoded).unwrap();

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
        let entry = CertificateEntry::from_cert_der(cert_der.clone(), Vec::new());

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
    fn encode_decode_certificate_with_chain() {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let entry0 = CertificateEntry::from_cert_der(cert_der.clone(), Vec::new());

        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert_der = create_cert_der(&keypair);
        let entry1 = CertificateEntry::from_cert_der(cert_der.clone(), Vec::new());

        let certificate = Certificate {
            certificate_request_context: b"context".to_vec(),
            certificate_list: vec![entry0, entry1],
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

        let entry = CertificateEntry::from_cert_der(cert_der.clone(), Vec::new());

        let certificate = Certificate {
            certificate_request_context: Default::default(),
            certificate_list: vec![entry],
        };

        let encoded = certificate.encode().unwrap();
        let (decoded_cert, _) = Certificate::decode(&encoded).unwrap();

        assert_eq!(certificate, decoded_cert);
    }
}
