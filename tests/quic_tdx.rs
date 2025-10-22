use attestation_exported_authenticators::{
    authenticator::Authenticator, certificate_request::CertificateRequest,
    create_cmw_attestation_extension, extract_attestation,
    EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY, EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, Endpoint, ServerConfig,
};
use rand_core::{OsRng, RngCore};
use rcgen::CertificateParams;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use std::{error::Error, sync::Arc};
use tdx_quote::Quote;

/// Given an incoming connection, accept a [CertificateRequest] and respond with an attestation [Authenticator]
async fn handle_connection_server(conn: &quinn::Connection, keypair: PrivateKeyDer<'static>) {
    // Wait for a bidirectional stream to be opened by the client
    let (mut send_stream, mut recv_stream) = conn.accept_bi().await.unwrap();

    // Read and deserialize a CertificateRequest from the client
    let cert_request_serialized = recv_stream.read_to_end(1024).await.unwrap();
    let cert_request = CertificateRequest::decode(&cert_request_serialized).unwrap();

    // Now we prepare an authenticator with an attestation using exported key material (based
    // on given context) as input
    let mut keying_material = [0u8; 64];
    conn.export_keying_material(
        &mut keying_material,
        b"label", // TODO #8
        &cert_request.certificate_request_context,
    )
    .unwrap();

    // Generate a TDX quote using the exported keying material as input
    let quote = generate_quote(keying_material);

    // TODO#1 here we should wrap the quote in a RATS Conceptual Messages Wrapper (CMW)

    let rcgen_keypair: rcgen::KeyPair = (&keypair).try_into().unwrap();
    let cert_der = create_cert_der(&rcgen_keypair, Some(&quote));

    let mut handshake_context_exporter = [0u8; 64];
    conn.export_keying_material(
        &mut handshake_context_exporter,
        EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
        &cert_request.certificate_request_context,
    )
    .unwrap();

    let mut finished_key_exporter = [0u8; 32];
    conn.export_keying_material(
        &mut finished_key_exporter,
        EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY,
        &cert_request.certificate_request_context,
    )
    .unwrap();

    let authenticator = Authenticator::new(
        cert_der.into(),
        keypair,
        &cert_request,
        handshake_context_exporter,
        finished_key_exporter,
    )
    .unwrap();

    send_stream
        .write_all(&authenticator.encode().unwrap())
        .await
        .unwrap();
    send_stream.finish().unwrap(); // Close the send side of the stream
}

/// Given an outgoing connection, make a [CertificateRequest] and read and verify an attestation [Authenticator]
async fn handle_connection_client(conn: &quinn::Connection) {
    let (mut send_stream, mut recv_stream) = conn.open_bi().await.unwrap();

    let mut context = [0u8; 32];
    OsRng.fill_bytes(&mut context);

    let cert_request = CertificateRequest {
        certificate_request_context: context.to_vec(),
        extensions: b"cmw_attestation".to_vec(), // TODO #14
    };
    send_stream.write_all(&cert_request.encode()).await.unwrap();
    send_stream.finish().unwrap();

    // Prepare keying material which we will use for checking the quote input data
    let mut keying_material = [0u8; 64];
    conn.export_keying_material(
        &mut keying_material,
        b"label", // TODO #8
        &cert_request.certificate_request_context,
    )
    .unwrap();

    // Wait for a response from the server.
    let response = recv_stream.read_to_end(65535).await.unwrap();

    let authenticator = Authenticator::decode(&response).unwrap();

    let mut handshake_context_exporter = [0u8; 64];
    conn.export_keying_material(
        &mut handshake_context_exporter,
        EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
        &cert_request.certificate_request_context,
    )
    .unwrap();

    let mut finished_key_exporter = [0u8; 32];
    conn.export_keying_material(
        &mut finished_key_exporter,
        EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY,
        &cert_request.certificate_request_context,
    )
    .unwrap();

    assert!(authenticator
        .verify(
            &cert_request,
            &handshake_context_exporter,
            &finished_key_exporter
        )
        .is_ok());

    let quote_bytes = extract_attestation(&authenticator.cert_der().unwrap()).unwrap();

    let quote = Quote::from_bytes(&quote_bytes).unwrap();

    assert_eq!(quote.report_input_data(), keying_material);
}

#[tokio::test]
async fn demonstrate_with_quic_and_tdx() {
    let keypair = rcgen::KeyPair::generate().unwrap();
    let (server_config, client_config) = generate_certs(&keypair).unwrap();

    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let incoming_conn = server.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();

        let private_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der()));
        handle_connection_server(&conn, private_key_der).await;

        conn.closed().await;
    });

    let client_handle = tokio::spawn(async move {
        let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();

        client_endpoint.set_default_client_config(client_config);

        // Connect to the server
        let conn = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        handle_connection_client(&conn).await
    });

    // Wait for both the client and server tasks to finish.
    let (res1, res2) = tokio::join! {
        server_handle,
        client_handle,
    };

    res1.unwrap();
    res2.unwrap();
}

#[tokio::test]
async fn mutual_attestation_with_quic_and_tdx() {
    let (alice_cert, alice_key) = generate_certificate_chain();
    let (bob_cert, bob_key) = generate_certificate_chain();
    let ((alice_server_config, alice_client_config), (bob_server_config, bob_client_config)) =
        generate_tls_config_with_client_auth(
            alice_cert,
            alice_key.clone_key(),
            bob_cert,
            bob_key.clone_key(),
        );

    let mut alice_server =
        Endpoint::server(alice_server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    alice_server.set_default_client_config(alice_client_config);
    let alice_server_addr = alice_server.local_addr().unwrap();

    let mut bob_server =
        Endpoint::server(bob_server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    bob_server.set_default_client_config(bob_client_config);
    let bob_server_addr = bob_server.local_addr().unwrap();

    let alice_server_clone = alice_server.clone();
    let alice_server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let incoming_conn = alice_server_clone.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();

        handle_connection_server(&conn, alice_key).await;

        conn.closed().await;
    });

    let bob_server_clone = bob_server.clone();
    let bob_server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let incoming_conn = bob_server_clone.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();

        handle_connection_server(&conn, bob_key).await;

        conn.closed().await;
    });

    let alice_client_handle = tokio::spawn(async move {
        // Connect to bob
        let conn = alice_server
            .connect(bob_server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        handle_connection_client(&conn).await
    });

    let bob_client_handle = tokio::spawn(async move {
        // Connect to alice
        let conn = bob_server
            .connect(alice_server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        handle_connection_client(&conn).await
    });

    // Wait for both the client and server tasks to finish.
    let (res1, res2, res3, res4) = tokio::join! {
        alice_server_handle,
        alice_client_handle,
        bob_server_handle,
        bob_client_handle,
    };

    res1.unwrap();
    res2.unwrap();
    res3.unwrap();
    res4.unwrap();
}

/// A helper to generate TLS configuration
fn generate_certs(
    keypair: &rcgen::KeyPair,
) -> Result<(ServerConfig, ClientConfig), Box<dyn Error>> {
    let key = keypair.serialize_der();

    let cert = create_cert_der(keypair, None);

    let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone()));
    let server_config = ServerConfig::with_single_cert(vec![cert.clone().into()], private_key_der)?;

    let cert_der = CertificateDer::from(cert.clone());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;

    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
        .unwrap(),
    ));

    Ok((server_config, client_config))
}

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

pub fn generate_tls_config_with_client_auth(
    alice_certificate_chain: Vec<CertificateDer<'static>>,
    alice_key: PrivateKeyDer<'static>,
    bob_certificate_chain: Vec<CertificateDer<'static>>,
    bob_key: PrivateKeyDer<'static>,
) -> ((ServerConfig, ClientConfig), (ServerConfig, ClientConfig)) {
    let (alice_client_verifier, alice_root_store) =
        client_verifier_from_remote_cert(bob_certificate_chain[0].clone());

    let alice_server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(alice_client_verifier)
        .with_single_cert(alice_certificate_chain.clone(), alice_key.clone_key())
        .expect("Failed to create rustls server config");

    let alice_client_config = rustls::ClientConfig::builder()
        .with_root_certificates(alice_root_store)
        .with_client_auth_cert(alice_certificate_chain.clone(), alice_key)
        .unwrap();

    let (bob_client_verifier, bob_root_store) =
        client_verifier_from_remote_cert(alice_certificate_chain[0].clone());

    let bob_server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(bob_client_verifier)
        .with_single_cert(bob_certificate_chain.clone(), bob_key.clone_key())
        .expect("Failed to create rustls server config");

    let bob_client_config = rustls::ClientConfig::builder()
        .with_root_certificates(bob_root_store)
        .with_client_auth_cert(bob_certificate_chain, bob_key)
        .unwrap();

    (
        (
            ServerConfig::with_crypto(Arc::<QuicServerConfig>::new(
                alice_server_config.try_into().unwrap(),
            )),
            ClientConfig::new(Arc::<QuicClientConfig>::new(
                alice_client_config.try_into().unwrap(),
            )),
        ),
        (
            ServerConfig::with_crypto(Arc::<QuicServerConfig>::new(
                bob_server_config.try_into().unwrap(),
            )),
            ClientConfig::new(Arc::<QuicClientConfig>::new(
                bob_client_config.try_into().unwrap(),
            )),
        ),
    )
}

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

/// Create a self-signed TLS certificate with the given keypair, adding an attestation_cmw
/// extension if the data is given
fn create_cert_der(keypair: &rcgen::KeyPair, attestation_cmw: Option<&[u8]>) -> Vec<u8> {
    let mut params = CertificateParams::new(["localhost".to_string()]).unwrap();

    if let Some(attestation) = attestation_cmw {
        params
            .custom_extensions
            .push(create_cmw_attestation_extension(attestation).unwrap());
    }

    let cert = params.self_signed(keypair).unwrap();
    cert.der().to_vec()
}

/// Create a mock quote for testing on non-TDX hardware
#[cfg(feature = "mock")]
fn generate_quote(input: [u8; 64]) -> Vec<u8> {
    let attestation_key = tdx_quote::SigningKey::random(&mut OsRng);
    let provisioning_certification_key = tdx_quote::SigningKey::random(&mut OsRng);
    Quote::mock(
        attestation_key.clone(),
        provisioning_certification_key.clone(),
        input,
        b"Mock cert chain".to_vec(),
    )
    .as_bytes()
}

#[cfg(not(feature = "mock"))]
fn generate_quote(input: [u8; 64]) -> Vec<u8> {
    configfs_tsm::create_quote(input).unwrap()
}
