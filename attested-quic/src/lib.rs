use std::net::SocketAddr;

use attestation_exported_authenticators::{
    authenticator::Authenticator, certificate_request::CertificateRequest,
    EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY, EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
};
use quinn::ClientConfig;
use rand_core::{OsRng, RngCore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tdx_quote::Quote;
use thiserror::Error;

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
    pub async fn accept(&self) -> Result<quinn::Connection, Error> {
        if let Some(tls_server) = &self.tls_server {
            let incoming_conn = self.endpoint.accept().await.ok_or(Error::EndpointClosed)?;
            let conn = incoming_conn.await?;

            Self::handle_connection_server(&conn, tls_server).await?;
            Ok(conn)
        } else {
            Err(Error::NoServer)
        }
    }

    pub async fn connect(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection, Error> {
        let conn = self.endpoint.connect(server_addr, server_name)?.await?;

        self.handle_connection_client(&conn).await?;

        Ok(conn)
    }

    pub async fn connect_with(
        &self,
        config: ClientConfig,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection, Error> {
        let conn = self
            .endpoint
            .connect_with(config, server_addr, server_name)?
            .await?;

        self.handle_connection_client(&conn).await?;

        Ok(conn)
    }

    async fn handle_connection_server(
        conn: &quinn::Connection,
        tls_server: &TlsServer,
    ) -> Result<(), Error> {
        // Wait for a bidirectional stream to be opened by the client
        let (mut send_stream, mut recv_stream) = conn.accept_bi().await?;

        // Read and deserialize a CertificateRequest from the client
        let cert_request_serialized = recv_stream.read_to_end(1024).await?;
        let cert_request = CertificateRequest::decode(&cert_request_serialized)?;

        // Now we prepare an authenticator with an attestation using exported key material (based
        // on given context) as input
        let mut keying_material = [0u8; 64];
        conn.export_keying_material(
            &mut keying_material,
            b"label", // TODO #8
            &cert_request.certificate_request_context,
        )?;

        // Generate a TDX quote using the exported keying material as input
        let quote = generate_quote(keying_material);

        // TODO#1 here we should wrap the quote in a RATS Conceptual Messages Wrapper (CMW)

        let mut handshake_context_exporter = [0u8; 64];
        conn.export_keying_material(
            &mut handshake_context_exporter,
            EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
            &cert_request.certificate_request_context,
        )?;

        let mut finished_key_exporter = [0u8; 32];
        conn.export_keying_material(
            &mut finished_key_exporter,
            EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY,
            &cert_request.certificate_request_context,
        )?;

        let authenticator = Authenticator::new_with_cmw_attestation(
            tls_server.certificate_chain.clone(),
            tls_server.private_key.clone_key(),
            quote,
            &cert_request,
            handshake_context_exporter,
            finished_key_exporter,
        )?;

        send_stream.write_all(&authenticator.encode()?).await?;
        send_stream.finish()?; // Close the send side of the stream
        Ok(())
    }

    /// Given an outgoing connection, make a [CertificateRequest] and read and verify an attestation [Authenticator]
    async fn handle_connection_client(&self, conn: &quinn::Connection) -> Result<(), Error> {
        let (mut send_stream, mut recv_stream) = conn.open_bi().await?;

        let mut context = [0u8; 32];
        OsRng.fill_bytes(&mut context);

        let cert_request = CertificateRequest {
            certificate_request_context: context.to_vec(),
            extensions: b"cmw_attestation".to_vec(), // TODO #14
        };
        send_stream.write_all(&cert_request.encode()).await?;
        send_stream.finish()?;

        // Prepare keying material which we will use for checking the quote input data
        let mut keying_material = [0u8; 64];
        conn.export_keying_material(
            &mut keying_material,
            b"label", // TODO #8
            &cert_request.certificate_request_context,
        )?;

        // Wait for a response from the server.
        let response = recv_stream.read_to_end(65535).await?;

        let authenticator = Authenticator::decode(&response)?;

        let mut handshake_context_exporter = [0u8; 64];
        conn.export_keying_material(
            &mut handshake_context_exporter,
            EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
            &cert_request.certificate_request_context,
        )?;

        let mut finished_key_exporter = [0u8; 32];
        conn.export_keying_material(
            &mut finished_key_exporter,
            EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY,
            &cert_request.certificate_request_context,
        )?;

        authenticator.verify(
            &cert_request,
            &handshake_context_exporter,
            &finished_key_exporter,
        )?;

        let quote_bytes = authenticator.get_attestation_cmw_extension()?;

        let quote = Quote::from_bytes(&quote_bytes)?;

        if quote.report_input_data() != keying_material {
            return Err(Error::KeyMaterialMismatch);
        }

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cannot accept connection as no TLS Server configuration is present")]
    NoServer,
    #[error("Cannot accept connection as QUIC endpoint is closed")]
    EndpointClosed,
    #[error("Connection: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),
    #[error("Connect: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),
    #[error("Read to end: {0}")]
    ReadToEnd(#[from] quinn::ReadToEndError),
    #[error("Encode: {0}")]
    Encode(#[from] attestation_exported_authenticators::EncodeError),
    #[error("Decode: {0}")]
    Decode(#[from] attestation_exported_authenticators::DecodeError),
    #[error("Export keying material: {0}")]
    ExportKeyingMaterial(String),
    #[error("Closed stream: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("Quinn write: {0}")]
    QuinnWrite(#[from] quinn::WriteError),
    #[error("Authenticator: {0}")]
    Authenticator(#[from] attestation_exported_authenticators::authenticator::AuthenticatorError),
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] tdx_quote::QuoteParseError),
    #[error("Authenticator verification: {0}")]
    AuthenticatorVerification(#[from] attestation_exported_authenticators::VerificationError),
    #[error("Exported keying material does not match quote input")]
    KeyMaterialMismatch,
}

impl From<quinn::crypto::ExportKeyingMaterialError> for Error {
    fn from(err: quinn::crypto::ExportKeyingMaterialError) -> Self {
        Self::ExportKeyingMaterial(format!("{err:?}"))
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
