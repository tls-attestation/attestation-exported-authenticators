use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

use crate::{
    certificate_request::CertificateRequest,
    tls_handshake_messages::{
        Certificate, CertificateEntry, CertificateVerify, Extension, Finished, VerificationError,
    },
    DecodeError, EncodeError, CMW_ATTESTATION_EXTENSION_TYPE,
};

/// An Authenticator as per RFC9261 Exported Authenticators
#[derive(Debug, PartialEq, Clone)]
pub struct Authenticator {
    certificate: Certificate,
    certificate_verify: CertificateVerify,
    finished: Finished,
}

impl Authenticator {
    pub fn new(
        certificate_chain: Vec<CertificateDer>,
        private_key: PrivateKeyDer,
        extensions: Vec<Extension>,
        certificate_request: &CertificateRequest,
        handshake_context_exporter: [u8; 64],
        finished_key_exporter: [u8; 32],
    ) -> Result<Self, EncodeError> {
        // Add the extensions to the leaf certificate
        let certificate_list = certificate_chain
            .into_iter()
            .enumerate()
            .map(|(index, cert)| {
                let exts = if index == 0 {
                    extensions.clone()
                } else {
                    Vec::new()
                };
                CertificateEntry::from_cert_der(cert.to_vec(), exts)
            })
            .collect();

        let certificate = Certificate {
            certificate_request_context: certificate_request.certificate_request_context.clone(),
            certificate_list,
        };

        let certificate_verify = CertificateVerify::new(
            &certificate,
            private_key,
            certificate_request,
            &handshake_context_exporter,
        )?;

        let finished = Finished::new(
            &certificate,
            &certificate_verify,
            certificate_request,
            &handshake_context_exporter,
            &finished_key_exporter,
        )?;

        Ok(Self {
            certificate,
            certificate_verify,
            finished,
        })
    }

    /// Create a new authenticator with a cmw_attestation extension.
    /// Takes an encoded CMW message.
    pub fn new_with_cmw_attestation(
        certificate_chain: Vec<CertificateDer>,
        private_key: PrivateKeyDer,
        cmw_attestation: Vec<u8>,
        certificate_request: &CertificateRequest,
        handshake_context_exporter: [u8; 64],
        finished_key_exporter: [u8; 32],
    ) -> Result<Self, EncodeError> {
        Self::new(
            certificate_chain,
            private_key,
            vec![Extension::new_attestation_cmw(cmw_attestation)],
            certificate_request,
            handshake_context_exporter,
            finished_key_exporter,
        )
    }

    /// Serialize to bytes
    /// Certificate || CertificateVerify || Finished
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut output = Vec::new();
        output.extend_from_slice(&self.certificate.encode()?);
        output.extend_from_slice(&self.certificate_verify.encode()?);
        output.extend_from_slice(&self.finished.encode()?);
        Ok(output)
    }

    /// Deserialize from bytes
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let (certificate, input) = Certificate::decode(input)?;
        let (certificate_verify, input) = CertificateVerify::decode(input)?;
        let (finished, _input) = Finished::decode(input)?;
        Ok(Self {
            certificate,
            certificate_verify,
            finished,
        })
    }

    pub fn cert_der(&self) -> Result<Vec<u8>, String> {
        match self.certificate.certificate_list.first() {
            Some(certificate_entry) => certificate_entry.as_cert_der(),
            None => Err("No certificate".to_string()),
        }
    }

    pub fn verify(
        &self,
        certificate_request: &CertificateRequest,
        handshake_context_exporter: &[u8; 64],
        finished_key_exporter: &[u8; 32],
    ) -> Result<(), VerificationError> {
        let finished_check = Finished::new(
            &self.certificate,
            &self.certificate_verify,
            certificate_request,
            handshake_context_exporter,
            finished_key_exporter,
        )?;

        if finished_check != self.finished {
            return Err(VerificationError::BadFinished);
        }

        self.certificate_verify.verify(
            &self.certificate,
            certificate_request,
            handshake_context_exporter,
        )
    }

    /// Get extensions from the leaf certificate
    pub fn extensions(&self) -> Result<Vec<Extension>, AuthenticatorError> {
        match self.certificate.certificate_list.first() {
            Some(certificate_entry) => Ok(certificate_entry.extensions.clone()),
            None => Err(AuthenticatorError::NoCertificate),
        }
    }

    /// Get a cwm_attestation extension if present
    pub fn get_attestation_cmw_extension(&self) -> Result<Vec<u8>, AuthenticatorError> {
        for extension in self.extensions()? {
            if extension.extension_type == CMW_ATTESTATION_EXTENSION_TYPE {
                return Ok(extension.extension_data);
            }
        }
        Err(AuthenticatorError::NoExtension)
    }
}

#[derive(Error, Debug)]
pub enum AuthenticatorError {
    #[error("Authenticator has no certificate")]
    NoCertificate,
    #[error("Requested extension not present")]
    NoExtension,
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
            vec![cert_der.into()],
            private_key_der,
            Vec::new(), // extensions
            &certificate_request,
            handshake_context_exporter,
            finished_key_exporter,
        )
        .unwrap();

        let encoded = authenticator.encode().unwrap();

        assert_eq!(authenticator, Authenticator::decode(&encoded).unwrap());

        authenticator
            .verify(
                &certificate_request,
                &handshake_context_exporter,
                &finished_key_exporter,
            )
            .unwrap();
    }
}
