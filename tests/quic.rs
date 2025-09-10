use attestation_exported_authenticators::{
    authenticator::Authenticator, certificate_request::CertificateRequest,
};
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint, ServerConfig};
use rand_core::{OsRng, RngCore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{error::Error, sync::Arc};
use tdx_quote::Quote;

#[tokio::test]
async fn quic() {
    let (server_config, client_config, cert_der, key_der) = generate_certs().unwrap();

    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        // Wait for an incoming connection from the client
        let incoming_conn = server.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();

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
            b"label",
            &cert_request.certificate_request_context,
        )
        .unwrap();

        let attestation_key = tdx_quote::SigningKey::random(&mut OsRng);
        let provisioning_certification_key = tdx_quote::SigningKey::random(&mut OsRng);

        // Generate a mock TDX quote using the exported keying material as input
        let quote = Quote::mock(
            attestation_key.clone(),
            provisioning_certification_key.clone(),
            keying_material,
            b"Mock cert chain".to_vec(),
        );

        let cert_der = CertificateDer::from(cert_der);
        let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        // TODO here we should:
        // - Wrap the quote in a RATS Conceptual Messages Wrapper (CMW)
        // - Add the CMW to the cerificate as a `cmw_attestation` extension
        // - Create an authenticator
        // - Create a CertificateVerify message (by signing the certificate)
        // - Create a Finished message

        let _authenticator = Authenticator::new(cert_der, private_key_der);

        send_stream.write_all(&quote.as_bytes()).await.unwrap();
        send_stream.finish().unwrap(); // Close the send side of the stream

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

        let (mut send_stream, mut recv_stream) = conn.open_bi().await.unwrap();

        let mut context = [0u8; 32];
        OsRng.fill_bytes(&mut context);

        let cert_request = CertificateRequest {
            certificate_request_context: context.to_vec(),
            extensions: b"bar".to_vec(),
        };
        send_stream.write_all(&cert_request.encode()).await.unwrap();
        send_stream.finish().unwrap();

        let mut keying_material = [0u8; 64];
        conn.export_keying_material(
            &mut keying_material,
            b"label",
            &cert_request.certificate_request_context,
        )
        .unwrap();

        // Wait for a response from the server.
        let response = recv_stream.read_to_end(65535).await.unwrap();
        let quote = Quote::from_bytes(&response).unwrap();

        assert_eq!(quote.report_input_data(), keying_material);
    });

    // Wait for both the client and server tasks to finish.
    let (_res1, _res2) = tokio::join! {
        server_handle,
        client_handle,
    };
}

/// A helper to generate TLS configuration
fn generate_certs() -> Result<(ServerConfig, ClientConfig, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let certified_key = rcgen::generate_simple_self_signed(["localhost".to_string()])?;
    let key = certified_key.signing_key.serialize_der();
    let cert = certified_key.cert.der();

    let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone()));
    let server_config = ServerConfig::with_single_cert(vec![cert.clone()], private_key_der)?;

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

    Ok((server_config, client_config, cert.to_vec(), key))
}
