# Typescript `did:peer`

This is a typescript implementation of the [did:peer](https://identity.foundation/peer-did-method-spec) method.

> Currently it more correctly aligns with the python [peerdid](https://github.com/sicpa-dlab/peer-did-python) implementation of the method. Work is required to update the `did:peer` method to be conformant with [did-core](https://www.w3.org/TR/did-core/) and since this was created to interoperate with other `did:peer` didcomm participants interoperability has been chosen over spec correctness.

## Assumptions and limitations

- Only static layers 1, 2a, 2b are supported
- Only X25519 keys are supported for key agreement
- Only Ed25519 keys are supported for authentication
- Supported verification materials (input and in the resolved DID Document)
  - [x] 2020 verification materials (Ed25519VerificationKey2020 and X25519KeyAgreementKey2020) with multibase base58 (publicKeyMultibase) public key encoding.
  - [ ] JWK (JsonWebKey2020) using JWK (publicKeyJwk) public key encoding
        2018/2019 verification materials (Ed25519VerificationKey2018 and X25519KeyAgreementKey2019)
  - [ ] using base58 (publicKeyBase58) public key encoding.


