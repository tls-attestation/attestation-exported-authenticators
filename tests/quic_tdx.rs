mod helpers;

use std::str::FromStr;

use cmw::{Mime, Monad, CMW};
use helpers::{
    create_quinn_client, create_quinn_server, create_quinn_servers, generate_certificate_chain,
};

use attestation_exported_authenticators::{
    authenticator::Authenticator, certificate_request::ClientCertificateRequest, CMWAttestation,
    EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY, EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
};
use rand_core::{OsRng, RngCore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tdx_quote::Quote;

/// Given an incoming connection, accept a [ClientCertificateRequest] and respond with an attestation [Authenticator]
async fn handle_connection_server(
    conn: &quinn::Connection,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) {
    // Wait for a bidirectional stream to be opened by the client
    let (mut send_stream, mut recv_stream) = conn.accept_bi().await.unwrap();

    // Read and deserialize a CertificateRequest from the client
    let cert_request_serialized = recv_stream.read_to_end(1024).await.unwrap();
    let cert_request = ClientCertificateRequest::decode(&cert_request_serialized).unwrap();

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

    let tdx_quote_media_type = Mime::from_str(
        "application/tdx-quote; version=1.0; profile=\"https://trustedcomputinggroup.org/tdx/v1\"",
    )
    .expect("Failed to parse TDX quote media type");
    let cmw = Monad::new_media_type(tdx_quote_media_type, quote, None)
        .expect("Failed to create Monad CMW");

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

    let authenticator = Authenticator::new_with_cmw_attestation(
        certificate_chain,
        private_key,
        CMWAttestation::new(CMW::Monad(cmw)),
        cert_request,
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

    let cert_request = ClientCertificateRequest {
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
            cert_request,
            &handshake_context_exporter,
            &finished_key_exporter
        )
        .is_ok());

    let cmw_attestation_extension = authenticator.get_attestation_cmw_extension().unwrap();
    let cmw = cmw_attestation_extension
        .monad_cmw()
        .expect("Expected a Monad CMW");

    let quote_bytes = cmw.value();

    let quote = Quote::from_bytes(&quote_bytes).unwrap();

    assert_eq!(quote.report_input_data(), keying_material);
}

#[tokio::test]
async fn demonstrate_with_quic_and_tdx() {
    let (cert_chain, keypair) = generate_certificate_chain();
    let server = create_quinn_server(cert_chain.clone(), keypair.clone_key(), None, false);

    let server_addr = server.local_addr().unwrap();

    let cert_chain_clone = cert_chain.clone();
    let server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let incoming_conn = server.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();

        handle_connection_server(&conn, cert_chain_clone, keypair).await;

        conn.closed().await;
    });

    let client_endpoint = create_quinn_client(&cert_chain);

    let client_handle = tokio::spawn(async move {
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

    let (alice_server, bob_server) = create_quinn_servers(
        alice_cert.clone(),
        alice_key.clone_key(),
        bob_cert.clone(),
        bob_key.clone_key(),
    );

    let alice_server_addr = alice_server.local_addr().unwrap();
    let bob_server_addr = bob_server.local_addr().unwrap();

    let alice_server_clone = alice_server.clone();
    let cert_chain_clone = alice_cert.clone();
    let alice_server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let incoming_conn = alice_server_clone.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();

        handle_connection_server(&conn, cert_chain_clone, alice_key).await;

        conn.closed().await;
    });

    let bob_server_clone = bob_server.clone();
    let bob_cert_chain_clone = bob_cert.clone();
    let bob_server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let incoming_conn = bob_server_clone.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();

        handle_connection_server(&conn, bob_cert_chain_clone, bob_key).await;

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

    // Wait for all tasks to finish.
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
