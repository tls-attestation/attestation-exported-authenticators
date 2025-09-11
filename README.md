## `attestation-exported-authenticators`

This is a WIP experimental implementation of [Remote Attestation with Exported Authenticators](https://datatracker.ietf.org/doc/html/draft-fossati-tls-exported-attestation-02).

It includes a test which demonstrates using it with QUIC (for transport) and Intel TDX (as confidential compute platform): [tests/quic_tdx.rs](tests/quic_tdx.rs).

There are currently still some key parts missing:
- [Authenticator](src/authenticator.rs) is missing length-prefixing and construction of the `CertificateVerify` and `Finished` messages
- Should use RATS conceptual messages wrapper: [veraison/rust-cmw](https://github.com/veraison/rust-cmw [draft-ietf-rats-msg-wrap](https://datatracker.ietf.org/doc/draft-ietf-rats-msg-wrap)
