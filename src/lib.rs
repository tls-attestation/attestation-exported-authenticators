pub mod authenticator;
pub mod certificate_request;

use asn1_rs::{FromDer, Sequence};
use asn1_rs::{Oid, ToDer};
use rcgen::CustomExtension;
use x509_parser::der_parser::oid;
use x509_parser::prelude::X509Certificate;

pub fn oid_cwm_attestation() -> Oid<'static> {
    oid!(1.3.6 .1 .4 .1 .42424242 .1)
}

pub fn create_custom_extension(attestation: &[u8]) -> CustomExtension {
    let sequence = Sequence::new(attestation.into());

    CustomExtension::from_oid_content(
        &oid_to_u64_vec(&oid_cwm_attestation()).unwrap(),
        sequence.to_der_vec().unwrap(),
    )
}

pub fn extract_attestation(cert_der: &[u8]) -> Vec<u8> {
    let (_, cert) = X509Certificate::from_der(cert_der).unwrap();
    let extensions = cert.extensions_map().unwrap();
    let extension = extensions.get(&oid_cwm_attestation()).unwrap();
    let sequence_der = extension.value.to_vec();
    let (_, sequence) = Sequence::from_der(&sequence_der).unwrap();
    sequence.content.to_vec()
}

fn oid_to_u64_vec(oid: &Oid) -> Result<Vec<u64>, String> {
    let iter = oid
        .iter()
        .ok_or_else(|| "OID component is too large to fit in u64".to_string())?;

    Ok(iter.collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::CertificateParams;

    fn create_cert_der(attestation: Option<&[u8]>) -> Vec<u8> {
        let keypair = rcgen::KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(["localhost".to_string()]).unwrap();

        if let Some(attestation) = attestation {
            params
                .custom_extensions
                .push(create_custom_extension(attestation));
        }

        let cert = params.self_signed(&keypair).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn extract_attestation_from_cert() {
        let attestation = b"attestation goes here";
        let cert_der = create_cert_der(Some(attestation));
        assert_eq!(extract_attestation(&cert_der), attestation);
    }
}
