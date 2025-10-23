//! Helper functions for integration tests
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, ServerConfig,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use std::sync::Arc;

/// Create a self-signed certificate and keypair
pub fn generate_certificate_chain() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .expect("Failed to generate self-signed certificate");

    let certs = vec![CertificateDer::from(cert_key.cert)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert_key.signing_key.serialize_der(),
    ));
    (certs, key)
}

/// Setup a quinn endpoint as a client only
pub fn create_quinn_client(remote_cert_chain: &Vec<CertificateDer<'static>>) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(remote_cert_chain[0].clone()).unwrap();

    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
        .unwrap(),
    ));

    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();

    client_endpoint.set_default_client_config(client_config);
    client_endpoint
}

/// Create a TLS configuration, optionally specifying a remote certificate chain and client authentication
fn create_tls_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    remote_cert_chain: Option<&Vec<CertificateDer<'static>>>,
    client_auth: bool,
) -> (rustls::ServerConfig, Option<rustls::ClientConfig>) {
    let (tls_server_config_builder, tls_client_config) =
        if let Some(remote_cert_chain) = remote_cert_chain {
            let (client_verifier, root_store) =
                client_verifier_from_remote_cert(remote_cert_chain[0].clone());

            let server_config_builder = if client_auth {
                rustls::ServerConfig::builder().with_client_cert_verifier(client_verifier)
            } else {
                rustls::ServerConfig::builder().with_no_client_auth()
            };

            let client_config = if client_auth {
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_client_auth_cert(certificate_chain.clone(), key.clone_key())
                    .unwrap()
            } else {
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            };

            (server_config_builder, Some(client_config))
        } else {
            (rustls::ServerConfig::builder().with_no_client_auth(), None)
        };

    let tls_server_config = tls_server_config_builder
        .with_single_cert(certificate_chain.clone(), key)
        .expect("Failed to create rustls server config");

    (tls_server_config, tls_client_config)
}

/// Setup a quinn server, with optional remote ceritifcate and client authentication
pub fn create_quinn_server(
    certificate_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    remote_cert_chain: Option<&Vec<CertificateDer<'static>>>,
    client_auth: bool,
) -> quinn::Endpoint {
    let (tls_server_config, tls_client_config) =
        create_tls_config(certificate_chain, key, remote_cert_chain, client_auth);

    let server_config = ServerConfig::with_crypto(Arc::<QuicServerConfig>::new(
        tls_server_config.try_into().unwrap(),
    ));
    let mut quic_server =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();

    if let Some(tls_client_config) = tls_client_config {
        let client_config = ClientConfig::new(Arc::<QuicClientConfig>::new(
            tls_client_config.try_into().unwrap(),
        ));
        quic_server.set_default_client_config(client_config);
    }
    quic_server
}

/// Generate two quinn servers, configurated for mutual attestation
pub fn create_quinn_servers(
    alice_certificate_chain: Vec<CertificateDer<'static>>,
    alice_key: PrivateKeyDer<'static>,
    bob_certificate_chain: Vec<CertificateDer<'static>>,
    bob_key: PrivateKeyDer<'static>,
) -> (quinn::Endpoint, quinn::Endpoint) {
    let alice = create_quinn_server(
        alice_certificate_chain.clone(),
        alice_key,
        Some(&bob_certificate_chain),
        true,
    );
    let bob = create_quinn_server(
        bob_certificate_chain,
        bob_key,
        Some(&alice_certificate_chain),
        true,
    );
    (alice, bob)
}

/// Given a server ceritificate, return a client verifier which will accept it
fn client_verifier_from_remote_cert(
    cert: CertificateDer<'static>,
) -> (
    Arc<dyn rustls::server::danger::ClientCertVerifier>,
    rustls::RootCertStore,
) {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert).unwrap();

    (
        WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
            .build()
            .unwrap(),
        root_store,
    )
}
