use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{
    certificate_request::CertificateRequest,
    tls_handshake_messages::{Certificate, CertificateEntry, CertificateVerify, Finished},
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
}
