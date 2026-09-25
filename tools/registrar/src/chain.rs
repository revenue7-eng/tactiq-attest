//! EK certificate chain: exactly three links, EK <- intermediate <- pinned root.
//!
//! This is deliberately narrower than RFC 5280 path validation, and says so:
//!
//!   * the path is given, not built: one intermediate, one root, no search;
//!   * every certificate is signed with sha256WithRSAEncryption (the Infineon
//!     OPTIGA RSA chain); any other algorithm is refused, not skipped;
//!   * each issuer name equals the next subject name byte for byte (DER);
//!   * each signature verifies under the next certificate's key, the root's
//!     under its own;
//!   * each certificate is within its validity period at the time given; the
//!     periods are not required to nest (the SLB9670 EK certificate predates the
//!     re-issued CA 034 certificate that signs it);
//!   * both CAs carry basicConstraints cA=TRUE and keyUsage keyCertSign; the EK
//!     certificate is not a CA and carries the TCG EK extended key usage;
//!   * a critical extension this module does not interpret is a refusal;
//!   * no revocation, no policy processing, no name constraints (a CA carrying
//!     critical nameConstraints is refused by the rule above).
//!
//! Whether the root is the right root is not decided here: the caller pins it
//! and the registration record names its SHA-256 (DDR-005 boundary C).

use std::time::Duration;

use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::Certificate;

const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const EXT_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const EXT_KEY_USAGE: &str = "2.5.29.15";
const EXT_SUBJECT_ALT_NAME: &str = "2.5.29.17";
const EXT_EXT_KEY_USAGE: &str = "2.5.29.37";
/// tcg-kp-EKCertificate (TCG EK Credential Profile).
const TCG_KP_EK_CERTIFICATE: &str = "2.23.133.8.1";

/// Critical extensions whose meaning this module enforces or, for the SAN,
/// knows to carry only the TPM manufacturer, model and version.
const UNDERSTOOD_CRITICAL: &[&str] =
    &[EXT_BASIC_CONSTRAINTS, EXT_KEY_USAGE, EXT_SUBJECT_ALT_NAME, EXT_EXT_KEY_USAGE];

pub struct Chain {
    /// The EK public key, from the EK certificate.
    pub ek_public: RsaPublicKey,
    pub root_sha256: [u8; 32],
}

fn parse(der: &[u8], what: &str) -> Result<Certificate, String> {
    Certificate::from_der(der).map_err(|e| format!("{what}: not a DER certificate ({e})"))
}

fn rsa_key(c: &Certificate, what: &str) -> Result<RsaPublicKey, String> {
    let spki = c.tbs_certificate.subject_public_key_info.to_der().map_err(|e| format!("{what}: {e}"))?;
    RsaPublicKey::from_public_key_der(&spki).map_err(|e| format!("{what}: not an RSA key ({e})"))
}

fn check_alg(c: &Certificate, what: &str) -> Result<(), String> {
    let outer = c.signature_algorithm.oid.to_string();
    let inner = c.tbs_certificate.signature.oid.to_string();
    if outer != SHA256_WITH_RSA || inner != SHA256_WITH_RSA {
        return Err(format!("{what}: signature algorithm {outer}/{inner}, only sha256WithRSAEncryption accepted"));
    }
    Ok(())
}

fn check_signed_by(c: &Certificate, issuer_key: &RsaPublicKey, what: &str) -> Result<(), String> {
    let tbs = c.tbs_certificate.to_der().map_err(|e| format!("{what}: {e}"))?;
    let sig_bytes = c
        .signature
        .as_bytes()
        .ok_or_else(|| format!("{what}: signature has unused bits"))?;
    let sig = Signature::try_from(sig_bytes).map_err(|e| format!("{what}: {e}"))?;
    VerifyingKey::<Sha256>::new(issuer_key.clone())
        .verify(&tbs, &sig)
        .map_err(|_| format!("{what}: signature does not verify under its issuer's key"))
}

fn check_issued_by(c: &Certificate, issuer: &Certificate, what: &str) -> Result<(), String> {
    let a = c.tbs_certificate.issuer.to_der().map_err(|e| format!("{what}: {e}"))?;
    let b = issuer.tbs_certificate.subject.to_der().map_err(|e| format!("{what}: {e}"))?;
    if a != b {
        return Err(format!(
            "{what}: issuer `{}` is not the next certificate's subject `{}`",
            c.tbs_certificate.issuer, issuer.tbs_certificate.subject
        ));
    }
    Ok(())
}

fn check_time(c: &Certificate, at: Duration, what: &str) -> Result<(), String> {
    let v = &c.tbs_certificate.validity;
    let nb = v.not_before.to_unix_duration();
    let na = v.not_after.to_unix_duration();
    if at < nb || at > na {
        return Err(format!("{what}: not valid at the registration time (valid {} to {})", v.not_before, v.not_after));
    }
    Ok(())
}

struct Ext {
    basic: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    eku: Option<ExtendedKeyUsage>,
}

fn extensions(c: &Certificate, what: &str) -> Result<Ext, String> {
    let mut e = Ext { basic: None, key_usage: None, eku: None };
    for x in c.tbs_certificate.extensions.iter().flatten() {
        let id = x.extn_id.to_string();
        let v = x.extn_value.as_bytes();
        match id.as_str() {
            EXT_BASIC_CONSTRAINTS => {
                e.basic = Some(BasicConstraints::from_der(v).map_err(|er| format!("{what}: basicConstraints {er}"))?)
            }
            EXT_KEY_USAGE => e.key_usage = Some(KeyUsage::from_der(v).map_err(|er| format!("{what}: keyUsage {er}"))?),
            EXT_EXT_KEY_USAGE => {
                e.eku = Some(ExtendedKeyUsage::from_der(v).map_err(|er| format!("{what}: extKeyUsage {er}"))?)
            }
            _ => {}
        }
        if x.critical && !UNDERSTOOD_CRITICAL.contains(&id.as_str()) {
            return Err(format!("{what}: critical extension {id} is not understood"));
        }
    }
    Ok(e)
}

fn check_ca(c: &Certificate, what: &str) -> Result<(), String> {
    let e = extensions(c, what)?;
    if !e.basic.map(|b| b.ca).unwrap_or(false) {
        return Err(format!("{what}: not a CA (basicConstraints cA is not TRUE)"));
    }
    if !e.key_usage.map(|k| k.0.contains(KeyUsages::KeyCertSign)).unwrap_or(false) {
        return Err(format!("{what}: keyUsage does not include keyCertSign"));
    }
    Ok(())
}

fn check_ek_leaf(c: &Certificate) -> Result<(), String> {
    let e = extensions(c, "EK certificate")?;
    if e.basic.map(|b| b.ca).unwrap_or(false) {
        return Err("EK certificate: marked as a CA".into());
    }
    let is_ek = e.eku.map(|u| u.0.iter().any(|o| o.to_string() == TCG_KP_EK_CERTIFICATE)).unwrap_or(false);
    if !is_ek {
        return Err(format!("EK certificate: extended key usage lacks {TCG_KP_EK_CERTIFICATE} (tcg-kp-EKCertificate)"));
    }
    Ok(())
}

/// Check the chain at `at` (time since the Unix epoch). Returns the EK public
/// key from the EK certificate and the SHA-256 of the root certificate.
pub fn verify(ek_der: &[u8], int_der: &[u8], root_der: &[u8], at: Duration) -> Result<Chain, String> {
    let ek = parse(ek_der, "EK certificate")?;
    let int = parse(int_der, "intermediate")?;
    let root = parse(root_der, "root")?;

    for (c, w) in [(&ek, "EK certificate"), (&int, "intermediate"), (&root, "root")] {
        check_alg(c, w)?;
        check_time(c, at, w)?;
    }

    let root_key = rsa_key(&root, "root")?;
    let int_key = rsa_key(&int, "intermediate")?;
    let ek_key = rsa_key(&ek, "EK certificate")?;

    check_issued_by(&root, &root, "root")?;
    check_signed_by(&root, &root_key, "root")?;
    check_ca(&root, "root")?;

    check_issued_by(&int, &root, "intermediate")?;
    check_signed_by(&int, &root_key, "intermediate")?;
    check_ca(&int, "intermediate")?;

    check_issued_by(&ek, &int, "EK certificate")?;
    check_signed_by(&ek, &int_key, "EK certificate")?;
    check_ek_leaf(&ek)?;

    use rsa::traits::PublicKeyParts;
    if ek_key.size() != 256 {
        return Err(format!("EK certificate: RSA key of {} bits, want 2048", ek_key.size() * 8));
    }

    Ok(Chain { ek_public: ek_key, root_sha256: Sha256::digest(root_der).into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(n: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/chain/{n}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    /// 2026-10-01T00:00:00Z, inside every synthetic certificate's validity.
    const AT: Duration = Duration::from_secs(1_790_812_800);

    fn ok(ek: &str, int: &str, root: &str) -> Result<Chain, String> {
        verify(&fx(ek), &fx(int), &fx(root), AT)
    }

    #[test]
    fn synthetic_ek_profile_chain_verifies() {
        let c = ok("ek.der", "int.der", "root.der").unwrap();
        assert_eq!(c.root_sha256, <[u8; 32]>::from(Sha256::digest(fx("root.der"))));
    }

    #[test]
    fn a_flipped_bit_in_any_signature_is_refused() {
        for (i, n) in ["ek.der", "int.der", "root.der"].iter().enumerate() {
            let mut v = [fx("ek.der"), fx("int.der"), fx("root.der")];
            let last = v[i].len() - 1; // the signature is the last field
            v[i][last] ^= 1;
            let e = verify(&v[0], &v[1], &v[2], AT).map(|_| ()).unwrap_err();
            assert!(e.contains("signature"), "{n}: {e}");
        }
    }

    #[test]
    fn links_out_of_order_are_refused() {
        assert!(ok("ek.der", "root.der", "root.der").is_err());
        assert!(ok("int.der", "int.der", "root.der").is_err());
        assert!(ok("ek.der", "int.der", "int.der").is_err());
    }

    #[test]
    fn outside_validity_is_refused() {
        let late = Duration::from_secs(2_524_608_000); // 2050-01-01
        let early = Duration::from_secs(1_577_836_800); // 2020-01-01
        for at in [late, early] {
            let e = verify(&fx("ek.der"), &fx("int.der"), &fx("root.der"), at).map(|_| ()).unwrap_err();
            assert!(e.contains("not valid"), "{e}");
        }
    }

    #[test]
    fn ca_without_key_cert_sign_is_refused() {
        let e = ok("ek.der", "int-nosign.der", "root.der").map(|_| ()).unwrap_err();
        assert!(e.contains("keyCertSign") || e.contains("signature"), "{e}");
    }

    #[test]
    fn leaf_without_ek_usage_is_refused() {
        let e = ok("ek-noeku.der", "int.der", "root.der").map(|_| ()).unwrap_err();
        assert!(e.contains("tcg-kp-EKCertificate"), "{e}");
    }

    #[test]
    fn unknown_critical_extension_is_refused() {
        let e = ok("ek-unknown-critical.der", "int.der", "root.der").map(|_| ()).unwrap_err();
        assert!(e.contains("not understood"), "{e}");
    }

    /// The real Infineon OPTIGA RSA chain of a bench SLB9670. The certificates
    /// are not in the repository (DDR-005 decision 6 publishes an EK
    /// certificate with a signed record, not as a test fixture). Run with
    ///   TACTIQ_EK_CHAIN_DIR=<dir with ek.der mfr034.crt root.crt> \
    ///     cargo test -- --ignored infineon
    #[test]
    #[ignore]
    fn infineon_chain_from_env() {
        let d = std::env::var("TACTIQ_EK_CHAIN_DIR").expect("TACTIQ_EK_CHAIN_DIR");
        let r = |n: &str| std::fs::read(format!("{d}/{n}")).unwrap();
        let c = verify(&r("ek.der"), &r("mfr034.crt"), &r("root.crt"), AT).unwrap();
        use rsa::traits::PublicKeyParts;
        assert_eq!(c.ek_public.size(), 256);
    }
}
