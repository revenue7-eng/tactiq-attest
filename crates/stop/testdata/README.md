Test fixtures for `release.rs`, made with openssl so the tests check the
operator's actual tool, not only the Rust signer.

- `operator.pub.pem`: a throwaway P-256 public key
  (`openssl ecparam -name prime256v1 -genkey -noout | openssl ec -pubout`).
  Its private half was discarded after signing; it is no key in use.
- `p384.pub.pem`: a P-384 public key, which the service must refuse.
- `release`, `release.sig`: a release for TACTIQ-BENCH-001 at epoch 8128,
  signed with `openssl dgst -sha256 -sign`.
