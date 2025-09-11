use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// An Authenticator as per RFC9261 Exported Authenticators
#[derive(Debug, PartialEq, Clone)]
pub struct Authenticator {
    pub certificate: Vec<u8>,
    certificate_verify: Vec<u8>,
    finished: Vec<u8>,
}

impl Authenticator {
    pub fn new(certificate: CertificateDer, _private_key: PrivateKeyDer) -> Self {
        // TODO#4 this should be encoded as a cert chain with length prefix:
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2
        let certificate = certificate.to_vec();

        // TODO#4 this should be the signature
        // https://www.rfc-editor.org/rfc/rfc9261#section-5.2.2
        let certificate_verify = Default::default();

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
        output.extend_from_slice(&self.certificate);
        output.extend_from_slice(&self.certificate_verify);
        output.extend_from_slice(&self.finished);
        output
    }

    /// Deserialize from bytes
    pub fn decode(input: Vec<u8>) -> Result<Self, ()> {
        // TODO this should actually parse all values
        Ok(Self {
            certificate: input,
            certificate_verify: Default::default(),
            finished: Default::default(),
        })
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
}
