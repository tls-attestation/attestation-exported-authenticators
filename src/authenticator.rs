use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, PartialEq, Clone)]
pub struct Authenticator {
    certificate: Vec<u8>,
    certificate_verify: Vec<u8>,
    finished: Vec<u8>,
}

impl Authenticator {
    pub fn new(certificate: CertificateDer, _private_key: PrivateKeyDer) -> Self {
        // TODO this should be encoded as a cert chain with length prefix:
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2
        let certificate = certificate.to_vec();

        // TODO this should be the signature
        // https://www.rfc-editor.org/rfc/rfc9261#section-5.2.2
        let certificate_verify = Default::default();

        // TODO this should be:
        // Finished = HMAC(Finished MAC Key, Hash(Handshake Context ||
        //      authenticator request || Certificate || CertificateVerify))
        let finished = Default::default();

        Self {
            certificate,
            certificate_verify,
            finished,
        }
    }

    /// Certificate || CertificateVerify || Finished
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&self.certificate);
        output.extend_from_slice(&self.certificate_verify);
        output.extend_from_slice(&self.finished);
        output
    }

    pub fn decode(_input: Vec<u8>) -> Result<Self, ()> {
        todo!()
    }
}
