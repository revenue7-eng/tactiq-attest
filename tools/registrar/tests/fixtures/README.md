# Registrar test fixtures

## makecred/

- `ek-test.pk8`, `ek-test.pub.pem`: a throwaway RSA-2048 key standing in for an
  EK. The private half is here so the tests can open blobs in software.
- `name.bin`: a 34-byte TPM name (`000b` and 32 random bytes).
- `secret.bin`: 32 random bytes.
- `tools.blob`: made by tpm2-tools 5.6 with
  `tpm2_makecredential -T none -G rsa -u ek-test.pub.pem -s secret.bin -n <name hex> -o tools.blob`.
  The test that opens it is what ties `makecred.rs` to the reference tooling.

## chain/

A synthetic three-link chain with the TCG EK certificate profile (empty
subject, critical subjectAltName with the TPM manufacturer, model and version
attributes, extended key usage 2.23.133.8.1), generated with OpenSSL from
`ca.cnf`. The private keys were deleted after signing.

- `root.der`, `int.der`, `ek.der`: the valid chain, 10 years from 25 Sep 2026.
- `int-nosign.der`: the intermediate without keyCertSign.
- `ek-noeku.der`: the EK certificate without the TCG extended key usage.
- `ek-unknown-critical.der`: the EK certificate with an unknown critical extension.

The real Infineon chain of the bench SLB9670 is not a fixture; see the ignored
test `infineon_chain_from_env` in `src/chain.rs`.
