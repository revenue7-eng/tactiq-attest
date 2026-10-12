//! Revocation of the EK chain, checked against the CRLs of its two CAs.
//!
//! The registrar does not fetch anything. The CRLs are fetched beforehand from
//! the distribution points named in the certificates (the EK certificate names
//! the CRL of its issuing CA, the issuing CA names the CRL of the root) and
//! given as files; their bytes go into the record, so a reader re-checks the
//! same CRLs. Each CRL must
//!
//!   * be signed with sha256WithRSAEncryption, by the key of the CA that issued
//!     the certificate being checked, whose keyUsage includes cRLSign;
//!   * name that CA as its issuer, byte for byte (DER);
//!   * be current at the time given: thisUpdate at or before it, nextUpdate
//!     present and at or after it;
//!   * carry no critical CRL extension (none is understood here);
//!   * not list the serial number of the certificate being checked.
//!
//! The time given is the chain check time of the registration, so a record
//! states that the chain was not revoked by the CRLs current when it was
//! checked, and keeps those CRLs with their own thisUpdate and nextUpdate.
//! Delta CRLs and indirect CRLs are out of scope; a CRL that needs them is
//! refused by the critical-extension rule or by the issuer rule.

use std::time::Duration;

use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::KeyUsages;
use x509_cert::Certificate;

use crate::chain;

const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

/// What a checked CRL contributes to the record.
pub struct Checked {
    pub this_update_unix: u64,
    pub next_update_unix: u64,
}

/// Check that `subject`, issued by `issuer`, is not revoked by `crl_der` at
/// `at` (time since the Unix epoch).
pub fn check(
    crl_der: &[u8],
    subject: &Certificate,
    issuer: &Certificate,
    issuer_key: &RsaPublicKey,
    at: Duration,
    what: &str,
) -> Result<Checked, String> {
    let crl = CertificateList::from_der(crl_der).map_err(|e| format!("{what}: not a DER CRL ({e})"))?;
    let tbs = &crl.tbs_cert_list;

    let outer = crl.signature_algorithm.oid.to_string();
    let inner = tbs.signature.oid.to_string();
    if outer != SHA256_WITH_RSA || inner != SHA256_WITH_RSA {
        return Err(format!("{what}: signature algorithm {outer}/{inner}, only sha256WithRSAEncryption accepted"));
    }

    let a = tbs.issuer.to_der().map_err(|e| format!("{what}: {e}"))?;
    let b = issuer.tbs_certificate.subject.to_der().map_err(|e| format!("{what}: {e}"))?;
    if a != b {
        return Err(format!(
            "{what}: CRL issuer `{}` is not the issuing CA `{}`",
            tbs.issuer, issuer.tbs_certificate.subject
        ));
    }

    let ku = chain::extensions(issuer, what)?.key_usage;
    if !ku.map(|k| k.0.contains(KeyUsages::CRLSign)).unwrap_or(false) {
        return Err(format!("{what}: the issuing CA's keyUsage does not include cRLSign"));
    }

    let tbs_der = tbs.to_der().map_err(|e| format!("{what}: {e}"))?;
    let sig_bytes = crl.signature.as_bytes().ok_or_else(|| format!("{what}: signature has unused bits"))?;
    let sig = Signature::try_from(sig_bytes).map_err(|e| format!("{what}: {e}"))?;
    VerifyingKey::<Sha256>::new(issuer_key.clone())
        .verify(&tbs_der, &sig)
        .map_err(|_| format!("{what}: CRL signature does not verify under the issuing CA's key"))?;

    let this = tbs.this_update.to_unix_duration();
    let next = tbs
        .next_update
        .as_ref()
        .ok_or_else(|| format!("{what}: CRL has no nextUpdate"))?
        .to_unix_duration();
    if at < this || at > next {
        return Err(format!(
            "{what}: CRL not current at the chain check time (thisUpdate {}, nextUpdate {})",
            tbs.this_update,
            tbs.next_update.as_ref().unwrap()
        ));
    }

    for x in tbs.crl_extensions.iter().flatten() {
        if x.critical {
            return Err(format!("{what}: critical CRL extension {} is not understood", x.extn_id));
        }
    }

    let serial = subject.tbs_certificate.serial_number.as_bytes();
    for r in tbs.revoked_certificates.iter().flatten() {
        if r.serial_number.as_bytes() == serial {
            return Err(format!("{what}: the certificate is REVOKED (serial {})", hex::encode(serial)));
        }
    }

    Ok(Checked { this_update_unix: this.as_secs(), next_update_unix: next.as_secs() })
}

/// The EK chain against both CRLs: the EK certificate against the CRL of its
/// issuing CA, the issuing CA against the CRL of the root.
pub fn check_chain(
    ek_der: &[u8],
    int_der: &[u8],
    root_der: &[u8],
    ek_crl: &[u8],
    int_crl: &[u8],
    at: Duration,
) -> Result<(Checked, Checked), String> {
    let ek = chain::parse(ek_der, "EK certificate")?;
    let int = chain::parse(int_der, "intermediate")?;
    let root = chain::parse(root_der, "root")?;
    let int_key = chain::rsa_key(&int, "intermediate")?;
    let root_key = chain::rsa_key(&root, "root")?;
    let e = check(ek_crl, &ek, &int, &int_key, at, "EK CRL")?;
    let i = check(int_crl, &int, &root, &root_key, at, "intermediate CRL")?;
    Ok((e, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(n: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/crl/{n}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// 1 Oct 2026, inside the validity of the fixture CRLs.
    const AT: Duration = Duration::from_secs(1_790_812_800);

    fn run(ek_crl: &str, int_crl: &str, at: Duration) -> Result<(Checked, Checked), String> {
        check_chain(&fx("ek.der"), &fx("int.der"), &fx("root.der"), &fx(ek_crl), &fx(int_crl), at)
    }

    #[test]
    fn current_empty_crls_pass() {
        let (e, i) = run("int-empty.crl", "root-empty.crl", AT).unwrap();
        assert!(e.this_update_unix <= AT.as_secs() && AT.as_secs() <= e.next_update_unix);
        assert!(i.this_update_unix <= AT.as_secs() && AT.as_secs() <= i.next_update_unix);
    }

    #[test]
    fn revoked_ek_is_refused() {
        let e = run("int-revokes-ek.crl", "root-empty.crl", AT).err().unwrap();
        assert!(e.contains("REVOKED"), "{e}");
    }

    #[test]
    fn revoked_intermediate_is_refused() {
        let e = run("int-empty.crl", "root-revokes-int.crl", AT).err().unwrap();
        assert!(e.contains("intermediate CRL") && e.contains("REVOKED"), "{e}");
    }

    #[test]
    fn crl_from_another_key_is_refused() {
        let e = run("int-other-key.crl", "root-empty.crl", AT).err().unwrap();
        assert!(e.contains("does not verify") || e.contains("issuer"), "{e}");
    }

    #[test]
    fn swapped_crls_are_refused() {
        let e = run("root-empty.crl", "int-empty.crl", AT).err().unwrap();
        assert!(e.contains("CRL issuer"), "{e}");
    }

    #[test]
    fn crl_outside_its_window_is_refused() {
        // 1 Jan 2030: after nextUpdate of every fixture CRL.
        let e = run("int-empty.crl", "root-empty.crl", Duration::from_secs(1_893_456_000)).err().unwrap();
        assert!(e.contains("not current"), "{e}");
    }

    /// The real Infineon chain of the bench SLB9670 with the CRLs fetched from
    /// Infineon. Not a fixture: run with
    /// `INFINEON_DIR=<dir with ek.der, mfr034.der, root.der, mfr034.crl, root.crl> cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn infineon_crls_from_env() {
        let d = std::env::var("INFINEON_DIR").expect("INFINEON_DIR");
        let r = |n: &str| std::fs::read(format!("{d}/{n}")).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        check_chain(&r("ek.der"), &r("mfr034.der"), &r("root.der"), &r("mfr034.crl"), &r("root.crl"), now).unwrap();
    }
}
