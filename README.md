## `attestation-exported-authenticators`

This is an experimental implementation of the draft IETF standard [Remote Attestation with Exported Authenticators](https://datatracker.ietf.org/doc/html/draft-fossati-seat-expat).

This is a remote-attested TLS protocol based on post-handshake attestation. This means that the attestation evidence is provided after a standard TLS handshake is complete. This is in contrast to some other remote-attested TLS protocols which include the evidence during the TLS handshake, either through x509 certificate extensions or TLS handshake message extensions.

Evidence is requested and provided using the Exported Authenticators ([RFC9261](https://datatracker.ietf.org/doc/rfc9261)) protocol. This is a standardized way to request and provide a certificate which is bound to the TLS channel by using exported keying material [RFC5705](https://datatracker.ietf.org/doc/rfc5705). Arbitrary application data can be included through x509 certificate extensions.

In order to provide the evidence in a self-describing, platform agnostic way it is given as a [RATS conceptual messages wrapper](https://datatracker.ietf.org/doc/draft-ietf-rats-msg-wrap). This implementation uses the [veraison/rust-cmw](https://github.com/veraison/rust-cmw) crate.

The protocol supports server-side, client-side, and mutual attestation, meaning either or both client and server can provide evidence.

A test is included which demonstrates using this with QUIC (for transport) and Intel TDX (as confidential compute platform): [tests/quic_tdx.rs](tests/quic_tdx.rs).

By default, this test will use mock quotes so that the test will run on non-TDX hardware. To run the test with production quotes on TDX hardware, disable the 'mock' feature by running:

```
cargo test --no-default-features
```

This work is supported in part by the Cypherpunk fellowship](https://cypherpunk.camp/#fellowship) program.
