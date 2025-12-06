mod helpers;

use helpers::{
    create_quinn_client, create_quinn_server, create_quinn_servers, generate_certificate_chain,
};

use attestation_exported_authenticators::quic::{AttestedQuic, TlsServer};

#[tokio::test]
async fn demonstrate_with_quic_and_tdx() {
    let (cert_chain, keypair) = generate_certificate_chain();
    let quinn_server = create_quinn_server(cert_chain.clone(), keypair.clone_key(), None, false);
    let server = AttestedQuic {
        endpoint: quinn_server,
        tls_server: Some(TlsServer {
            certificate_chain: cert_chain.clone(),
            private_key: keypair,
        }),
    };

    let server_addr = server.endpoint.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let conn = server.accept().await.unwrap();

        conn.closed().await;
    });

    let client_endpoint = create_quinn_client(&cert_chain);
    let client = AttestedQuic {
        endpoint: client_endpoint,
        tls_server: None,
    };

    let client_handle = tokio::spawn(async move {
        // Connect to the server
        let _conn = client.connect(server_addr, "localhost").await;
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

    let (alice_quinn_server, bob_quinn_server) = create_quinn_servers(
        alice_cert.clone(),
        alice_key.clone_key(),
        bob_cert.clone(),
        bob_key.clone_key(),
    );

    let alice_server = AttestedQuic {
        endpoint: alice_quinn_server,
        tls_server: Some(TlsServer {
            certificate_chain: alice_cert,
            private_key: alice_key,
        }),
    };

    let bob_server = AttestedQuic {
        endpoint: bob_quinn_server,
        tls_server: Some(TlsServer {
            certificate_chain: bob_cert,
            private_key: bob_key,
        }),
    };

    let alice_server_addr = alice_server.endpoint.local_addr().unwrap();
    let bob_server_addr = bob_server.endpoint.local_addr().unwrap();

    let alice_server_clone = alice_server.clone();
    let alice_server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let conn = alice_server_clone.accept().await.unwrap();

        conn.closed().await;
    });

    let bob_server_clone = bob_server.clone();
    let bob_server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let conn = bob_server_clone.accept().await.unwrap();

        conn.closed().await;
    });

    let alice_client_handle = tokio::spawn(async move {
        // Connect to bob
        let _conn = alice_server.connect(bob_server_addr, "localhost").await;
    });

    let bob_client_handle = tokio::spawn(async move {
        // Connect to alice
        let _conn = bob_server.connect(alice_server_addr, "localhost").await;
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
