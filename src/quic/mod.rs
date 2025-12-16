#[cfg(test)]
mod test_helpers;

use std::net::SocketAddr;

use crate::{
    attestation::{AttestationGenerator, AttestationValidator},
    authenticator::Authenticator,
    certificate_request::CertificateRequest,
    CMWAttestation, EXPORTER_SERVER_AUTHENTICATOR_FINISHED_KEY,
    EXPORTER_SERVER_AUTHENTICATOR_HANDSHAKE_CONTEXT,
};
use cmw::CMW;
use quinn::ClientConfig;
use rand_core::{OsRng, RngCore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tdx_quote::Quote;
use thiserror::Error;

/// Details of a TLS server, or TLS client with client authentication
pub struct TlsServer {
    /// DER-encoded TLS certificate chain
    pub certificate_chain: Vec<CertificateDer<'static>>,
    /// Associated private key
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

/// An attested QUIC endpoint (server or client)
#[derive(Clone)]
pub struct AttestedQuic {
    pub endpoint: quinn::Endpoint,
    pub tls_server: Option<TlsServer>,
    pub attestation_generator: AttestationGenerator,
    pub attestation_validator: AttestationValidator,
}

impl AttestedQuic {
    /// Accept an incoming connection, do an attestation exchange, then return the
    /// [quinn::Connection] if succesful
    pub async fn accept(&self) -> Result<quinn::Connection, Error> {
        if let Some(tls_server) = &self.tls_server {
            let incoming_conn = self.endpoint.accept().await.ok_or(Error::EndpointClosed)?;
            let conn = incoming_conn.await?;

            self.handle_connection_server(&conn, tls_server).await?;
            Ok(conn)
        } else {
            Err(Error::NoServer)
        }
    }

    /// Connect to a remote peer, do an attestation exchange, and return the [quinn::Connection] if
    /// succesful
    pub async fn connect(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection, Error> {
        let conn = self.endpoint.connect(server_addr, server_name)?.await?;

        self.handle_connection_client(&conn).await?;

        Ok(conn)
    }

    /// Connect to a remote peer with given [ClientConfig], do an attestion exchange, and return
    /// the [quinn::Connection] if succesful
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

    /// Do an attestation exchange with an incoming connection
    ///
    /// This means accepting a [CertificateRequest] and responding with an [Authenticator]
    async fn handle_connection_server(
        &self,
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

        let evidence = self
            .attestation_generator
            .generate_attestation(keying_material)
            .await?
            .unwrap();

        // // Generate a TDX quote using the exported keying material as input
        // let quote = dcap_tdx::generate_quote(keying_material)?;

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
            CMWAttestation::new(CMW::Monad(evidence)),
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

        let cmw_attestation_extension = authenticator.get_attestation_cmw_extension()?;
        let cmw = cmw_attestation_extension.monad_cmw()?;

        let _ = self
            .attestation_validator
            .validate_attestation(cmw, keying_material)
            .await?;

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
    Encode(#[from] crate::EncodeError),
    #[error("Decode: {0}")]
    Decode(#[from] crate::DecodeError),
    #[error("Export keying material: {0}")]
    ExportKeyingMaterial(String),
    #[error("Closed stream: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("Quinn write: {0}")]
    QuinnWrite(#[from] quinn::WriteError),
    #[error("Authenticator: {0}")]
    Authenticator(#[from] crate::authenticator::AuthenticatorError),
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] tdx_quote::QuoteParseError),
    #[error("Authenticator verification: {0}")]
    AuthenticatorVerification(#[from] crate::VerificationError),
    #[error("Exported keying material does not match quote input")]
    KeyMaterialMismatch,
    #[error("Conceptual Message Wrappers: {0}")]
    Cmw(#[from] cmw::Error),
    #[error("Attestation generation: {0}")]
    AttestationGeneration(#[from] crate::attestation::AttestationGenerationError),
    #[error("Attestation verification: {0}")]
    AttestationVerification(#[from] crate::attestation::AttestationVerificationError),
}

impl From<quinn::crypto::ExportKeyingMaterialError> for Error {
    fn from(err: quinn::crypto::ExportKeyingMaterialError) -> Self {
        Self::ExportKeyingMaterial(format!("{err:?}"))
    }
}

#[cfg(test)]
mod test {

    use super::test_helpers::{
        create_quinn_client, create_quinn_server, create_quinn_servers, generate_certificate_chain,
    };

    use crate::{
        attestation::{AttestationGenerator, AttestationType, AttestationValidator},
        quic::{AttestedQuic, TlsServer},
    };

    #[tokio::test]
    async fn demonstrate_with_quic_and_tdx() {
        let (cert_chain, keypair) = generate_certificate_chain();
        let quinn_server =
            create_quinn_server(cert_chain.clone(), keypair.clone_key(), None, false);
        let server = AttestedQuic {
            attestation_validator: AttestationValidator {},
            attestation_generator: AttestationGenerator {
                attestation_type: AttestationType::DcapTdx,
            },
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
            attestation_validator: AttestationValidator {},
            attestation_generator: AttestationGenerator {
                attestation_type: AttestationType::None,
            },
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
            attestation_validator: AttestationValidator {},
            attestation_generator: AttestationGenerator {
                attestation_type: AttestationType::DcapTdx,
            },
            endpoint: alice_quinn_server,
            tls_server: Some(TlsServer {
                certificate_chain: alice_cert,
                private_key: alice_key,
            }),
        };

        let bob_server = AttestedQuic {
            attestation_validator: AttestationValidator {},
            attestation_generator: AttestationGenerator {
                attestation_type: AttestationType::DcapTdx,
            },
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
}
