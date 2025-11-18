## `attestation-exported-authenticators`

This is a WIP implementation of the draft IETF standard [Remote Attestation with Exported Authenticators](https://datatracker.ietf.org/doc/html/draft-fossati-seat-expat).

It uses the [veraison/rust-cmw](https://github.com/veraison/rust-cmw) implementation of [RATS conceptual messages wrapper](https://datatracker.ietf.org/doc/draft-ietf-rats-msg-wrap).

It includes a test which demonstrates using it with QUIC (for transport) and Intel TDX (as confidential compute platform): [tests/quic_tdx.rs](tests/quic_tdx.rs).

By default, this test will use mock quotes so that the test will run on non-TDX hardware. To run the test with production quotes on TDX hardware, disable the 'mock' feature by running:

```
cargo test --no-default-features
```

