use crate::{tls_handshake_messages::Extension, DecodeError, EncodeError};
use std::io::Read;

/// A CertificateRequest message as per RFC9261 Exported Authenticators
#[derive(Debug, PartialEq, Clone)]
pub struct CertificateRequest {
    /// Context used to link the response to this request
    pub certificate_request_context: Vec<u8>,
    /// The serialized extensions
    pub extensions: Vec<Extension>,
}

impl CertificateRequest {
    pub fn new_with_cmw_extension(certificate_request_context: Vec<u8>) -> Self {
        Self {
            certificate_request_context,
            extensions: vec![Extension::new_attestation_cmw(Vec::new())],
        }
    }

    /// Serialize to bytes
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        // Handshake type: A 1 byte value for CertificateRequest (0x0D).
        let mut encoded_message = vec![0x0D];

        // Encode the extensions
        let mut encoded_extensions = Vec::new();

        for extension in self.extensions.iter() {
            encoded_extensions.extend_from_slice(&extension.encode()?);
        }

        if encoded_extensions.len() > 0xFFFF {
            return Err(EncodeError::ExtensionTooLong);
        }

        // Handshake message length: A 3-byte value for the total length of the payload
        // + extensions (2 byte length + content)
        let payload_length =
            1 + self.certificate_request_context.len() + 2 + encoded_extensions.len();

        // Ensure the payload length fits within 3 bytes.
        let length_bytes = (payload_length as u32).to_be_bytes();
        encoded_message.extend_from_slice(&length_bytes[1..]); // Use the last 3 bytes.

        // Encode the certificate_request_context
        // The length is a 1 byte value
        encoded_message.push(self.certificate_request_context.len() as u8);
        encoded_message.extend_from_slice(&self.certificate_request_context);

        let u16_length = encoded_extensions.len() as u16;

        encoded_message.extend_from_slice(&u16_length.to_be_bytes());
        encoded_message.extend_from_slice(&encoded_extensions);

        Ok(encoded_message)
    }

    /// Deserialize from bytes
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut cursor = std::io::Cursor::new(data);

        // Read and verify the handshake type (1 byte)
        let mut msg_type_buf = [0u8; 1];
        cursor.read_exact(&mut msg_type_buf)?;
        if msg_type_buf[0] != 0x0D {
            return Err(DecodeError::UnknownMessageType);
        }

        // Read the handshake message length (3 bytes)
        let mut length_buf = [0u8; 3];
        cursor.read_exact(&mut length_buf)?;

        let payload_length =
            ((length_buf[0] as u32) << 16) | ((length_buf[1] as u32) << 8) | (length_buf[2] as u32);

        // Check if the reported length matches the remaining data.
        if payload_length as usize != cursor.get_ref().len() - cursor.position() as usize {
            return Err(DecodeError::BadLength(
                "Reported length does not match remaining data".to_string(),
            ));
        }

        // Read the certificate_request_context length (1 byte) and data
        let mut context_len_buf = [0u8; 1];
        cursor.read_exact(&mut context_len_buf)?;

        let context_length = context_len_buf[0] as usize;
        if (cursor.position() as usize + context_length) > cursor.get_ref().len() {
            return Err(DecodeError::BadLength(
                "Reported length does not match remaining data".to_string(),
            ));
        }
        let context_start = cursor.position() as usize;
        cursor.set_position(cursor.position() + context_length as u64);
        let certificate_request_context =
            data[context_start..context_start + context_length].to_vec();

        // Read the extensions length (2 bytes) and data
        let mut ext_len_buf = [0u8; 2];
        cursor.read_exact(&mut ext_len_buf)?;

        let extensions_length = ((ext_len_buf[0] as u16) << 8) | (ext_len_buf[1] as u16);
        let extensions_length = extensions_length as usize;

        if (cursor.position() as usize + extensions_length) > cursor.get_ref().len() {
            return Err(DecodeError::BadLength(
                "Reported length does not match remaining data".to_string(),
            ));
        }
        let extensions_start = cursor.position() as usize;
        let mut encoded_extensions = &data[extensions_start..extensions_start + extensions_length];

        let mut extensions = Vec::new();
        while !encoded_extensions.is_empty() {
            let (extension, remaining) = Extension::decode(encoded_extensions)?;
            extensions.push(extension);
            encoded_extensions = remaining;
        }

        Ok(CertificateRequest {
            certificate_request_context,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_certificate_request() {
        let cert_request = CertificateRequest::new_with_cmw_extension(b"foo".to_vec());

        let encoded = cert_request.encode().unwrap();
        assert_eq!(encoded.len(), 1 + 3 + 1 + 3 + 2 + 4);

        let decoded = CertificateRequest::decode(&encoded).unwrap();
        assert_eq!(cert_request, decoded);
    }
}
