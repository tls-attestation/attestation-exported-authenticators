use std::net::SocketAddr;

use attestation_exported_authenticators::{
    authenticator::Authenticator, certificate_request::CertificateRequest,
    create_cmw_attestation_extension, extract_attestation,
    EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY, EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
};
use quinn::ClientConfig;
use rand_core::{OsRng, RngCore};
use rcgen::CertificateParams;
use rustls::pki_types::PrivateKeyDer;
use tdx_quote::Quote;

pub struct AttestedQuic {
    pub endpoint: quinn::Endpoint,
    // TODO this should be a certificate
    keypair: PrivateKeyDer<'static>,
}

impl AttestedQuic {
    /// Accept and attest an incoming connection
    pub async fn accept(&self) -> quinn::Connection {
        let incoming_conn = self.endpoint.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();

        self.handle_connection_server(&conn).await;

        conn
    }

    pub async fn connect(&self, server_addr: SocketAddr, server_name: &str) -> quinn::Connection {
        let conn = self
            .endpoint
            .connect(server_addr, server_name)
            .unwrap()
            .await
            .unwrap();

        self.handle_connection_client(&conn).await;

        conn
    }

    pub async fn connect_with(
        &self,
        config: ClientConfig,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> quinn::Connection {
        let conn = self
            .endpoint
            .connect_with(config, server_addr, server_name)
            .unwrap()
            .await
            .unwrap();

        self.handle_connection_client(&conn).await;

        conn
    }

    /// Given an incoming connection, accept a [CertificateRequest] and respond with an attestation [Authenticator]
    async fn handle_connection_server(&self, conn: &quinn::Connection) {
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

        let rcgen_keypair: rcgen::KeyPair = (&self.keypair).try_into().unwrap();
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
            self.keypair.clone_key(),
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
    async fn handle_connection_client(&self, conn: &quinn::Connection) {
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

// TODO this should take a certificate, not a keypair
pub fn create_cert_der(keypair: &rcgen::KeyPair, attestation_cmw: Option<&[u8]>) -> Vec<u8> {
    let mut params = CertificateParams::new(["localhost".to_string()]).unwrap();

    if let Some(attestation) = attestation_cmw {
        params
            .custom_extensions
            .push(create_cmw_attestation_extension(attestation).unwrap());
    }

    let cert = params.self_signed(keypair).unwrap();
    cert.der().to_vec()
}
