use std::net::SocketAddr;

use attestation_exported_authenticators::{
    authenticator::Authenticator, certificate_request::CertificateRequest,
    EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY, EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
};
use quinn::ClientConfig;
use rand_core::{OsRng, RngCore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tdx_quote::Quote;

pub struct TlsServer {
    pub certificate_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl Clone for TlsServer {
    fn clone(&self) -> Self {
        Self {
            certificate_chain: self.certificate_chain.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

#[derive(Clone)]
pub struct AttestedQuic {
    pub endpoint: quinn::Endpoint,
    pub tls_server: Option<TlsServer>,
}

impl AttestedQuic {
    /// Accept and attest an incoming connection
    pub async fn accept(&self) -> Option<quinn::Connection> {
        if let Some(tls_server) = &self.tls_server {
            let incoming_conn = self.endpoint.accept().await.unwrap();
            let conn = incoming_conn.await.unwrap();

            Self::handle_connection_server(&conn, tls_server).await;
            Some(conn)
        } else {
            None
        }
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

    async fn handle_connection_server(conn: &quinn::Connection, tls_server: &TlsServer) {
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
            tls_server.certificate_chain.clone(),
            tls_server.private_key.clone_key(),
            quote,
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

        let quote_bytes = authenticator.get_attestation_cmw_extension().unwrap();

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
