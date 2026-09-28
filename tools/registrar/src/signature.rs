//! Signature of a registration record (DDR-005 decision 6).
//!
//! A record is signed as a file, over its exact bytes, by the
//! `Registration Signer` leaf under the release root. The container is the one
//! the RIM uses (tactiq-os RELEASE_INTEGRITY.md, RIM signature): CMS SignedData
//! (RFC 5652), detached, DER, SHA-256, no signed attributes, carrying the
//! signer certificate and the Signing CA certificate. It is made with
//!
//!     openssl cms -sign -binary -noattr -md sha256 -in registration.json \
//!         -signer reg-signer.pem -inkey reg-signer.key.pem \
//!         -certfile signing-ca.pem -outform DER -out registration.json.p7s
//!
//! This check is as narrow as `chain.rs` and says so:
//!
//!   * exactly one signer, identified by issuer and serial number;
//!   * no encapsulated content and no signed attributes: the signature is
//!     RSASSA-PKCS1-v1_5 with SHA-256 over the record bytes themselves;
//!   * the path is leaf <- Signing CA <- release root, the Signing CA taken
//!     from the container, the root given by the caller and never from it;
//!   * every certificate sha256WithRSAEncryption, within its validity at the
//!     time given, the CAs with cA=TRUE and keyCertSign;
//!   * the leaf is not a CA, has digitalSignature, and its extended key usage
//!     is exactly the registration purpose OID, critical. `openssl cms -verify
//!     -purpose any` does not look at the EKU, so without this check a RIM
//!     signature under the same root would pass as a registration signature.

use std::time::Duration;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::{Digest, Sha256};
use x509_cert::ext::pkix::KeyUsages;
use x509_cert::Certificate;

use crate::chain;

/// The registration purpose, gen-pki.sh `regsigner` / `regsigner-prod`.
pub const REG_EKU_OID: &str = "2.25.205994972697553183157730487844756597568";

const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const ID_DATA: &str = "1.2.840.113549.1.7.1";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const EXT_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const EXT_KEY_USAGE: &str = "2.5.29.15";
const EXT_EXT_KEY_USAGE: &str = "2.5.29.37";

pub struct Signer {
    pub leaf_subject: String,
    pub leaf_serial: String,
    pub signing_ca_subject: String,
    /// SHA-256 of the release root certificate (DER), as `openssl x509
    /// -fingerprint -sha256` prints it without the colons.
    pub root_sha256: String,
}

/// Accept a certificate as PEM or DER, returning DER.
pub fn cert_der(bytes: &[u8], what: &str) -> Result<Vec<u8>, String> {
    if bytes.starts_with(b"-----BEGIN") {
        use der::DecodePem;
        let c = Certificate::from_pem(bytes).map_err(|e| format!("{what}: not a PEM certificate ({e})"))?;
        c.to_der().map_err(|e| format!("{what}: {e}"))
    } else {
        Ok(bytes.to_vec())
    }
}

fn check_time(c: &Certificate, at: Duration, what: &str) -> Result<(), String> {
    let v = &c.tbs_certificate.validity;
    if at < v.not_before.to_unix_duration() || at > v.not_after.to_unix_duration() {
        return Err(format!("{what}: not valid now (valid {} to {})", v.not_before, v.not_after));
    }
    Ok(())
}

/// DER of an OBJECT IDENTIFIER in dotted form. `const-oid`, under `der` and
/// `x509-cert`, holds arcs in 32 bits, and a `2.25.<uuid>` OID has a 128-bit
/// arc, so the purpose OID is compared as bytes rather than decoded.
fn oid_der(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u128> = dotted.split('.').map(|a| a.parse().expect("numeric arc")).collect();
    let mut body = Vec::new();
    let mut push = |mut v: u128| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        body.extend(tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    let mut out = vec![0x06, body.len() as u8];
    out.extend(body);
    out
}

/// The extension value a Registration Signer carries: SEQUENCE { REG_EKU_OID }.
fn expected_eku_value() -> Vec<u8> {
    let oid = oid_der(REG_EKU_OID);
    let mut v = vec![0x30, oid.len() as u8];
    v.extend(oid);
    v
}

fn check_leaf(c: &Certificate) -> Result<(), String> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let w = "signer certificate";
    let (mut basic, mut key_usage, mut eku) = (None, None, None);
    for x in c.tbs_certificate.extensions.iter().flatten() {
        let id = x.extn_id.to_string();
        let v = x.extn_value.as_bytes();
        match id.as_str() {
            EXT_BASIC_CONSTRAINTS => {
                basic = Some(BasicConstraints::from_der(v).map_err(|e| format!("{w}: basicConstraints {e}"))?)
            }
            EXT_KEY_USAGE => key_usage = Some(KeyUsage::from_der(v).map_err(|e| format!("{w}: keyUsage {e}"))?),
            EXT_EXT_KEY_USAGE => eku = Some((v.to_vec(), x.critical)),
            _ if x.critical => return Err(format!("{w}: critical extension {id} is not understood")),
            _ => {}
        }
    }
    if basic.map(|b| b.ca).unwrap_or(false) {
        return Err(format!("{w}: marked as a CA"));
    }
    if !key_usage.map(|k| k.0.contains(KeyUsages::DigitalSignature)).unwrap_or(false) {
        return Err(format!("{w}: keyUsage lacks digitalSignature"));
    }
    match eku {
        Some((v, true)) if v == expected_eku_value() => Ok(()),
        Some((_, false)) => Err(format!("{w}: extended key usage is not critical")),
        Some(_) => Err(format!("{w}: extended key usage is not exactly {REG_EKU_OID} (Registration Signer)")),
        None => Err(format!("{w}: no extended key usage, want exactly {REG_EKU_OID}")),
    }
}

/// Verify `p7s` (DER) as a detached signature over `record` by a Registration
/// Signer under `root_der`, with certificate validity judged at `at`.
pub fn verify(record: &[u8], p7s: &[u8], root_der: &[u8], at: Duration) -> Result<Signer, String> {
    let ci = ContentInfo::from_der(p7s).map_err(|e| format!("signature: not a DER CMS ContentInfo ({e})"))?;
    if ci.content_type.to_string() != ID_SIGNED_DATA {
        return Err(format!("signature: content type {}, want SignedData", ci.content_type));
    }
    let sd: SignedData = ci.content.decode_as().map_err(|e| format!("signature: SignedData {e}"))?;
    if sd.encap_content_info.econtent_type.to_string() != ID_DATA {
        return Err(format!("signature: encapsulated type {}, want id-data", sd.encap_content_info.econtent_type));
    }
    if sd.encap_content_info.econtent.is_some() {
        return Err("signature: content is embedded; a record signature is detached".into());
    }
    let signers: Vec<_> = sd.signer_infos.0.iter().collect();
    if signers.len() != 1 {
        return Err(format!("signature: {} signers, want exactly one", signers.len()));
    }
    let si = signers[0];
    if si.signed_attrs.is_some() {
        return Err("signature: signed attributes present; sign with -noattr (the signature covers the record bytes)".into());
    }
    if si.digest_alg.oid.to_string() != SHA256 {
        return Err(format!("signature: digest {}, want SHA-256", si.digest_alg.oid));
    }
    let sig_alg = si.signature_algorithm.oid.to_string();
    if sig_alg != RSA_ENCRYPTION && sig_alg != SHA256_WITH_RSA {
        return Err(format!("signature: algorithm {sig_alg}, want RSA PKCS#1 v1.5"));
    }
    let SignerIdentifier::IssuerAndSerialNumber(ias) = &si.sid else {
        return Err("signature: signer identified by key identifier; want issuer and serial number".into());
    };

    let certs: Vec<&Certificate> = sd
        .certificates
        .as_ref()
        .map(|s| {
            s.0.iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(c) => Some(c),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let leaf = certs
        .iter()
        .find(|c| c.tbs_certificate.issuer == ias.issuer && c.tbs_certificate.serial_number == ias.serial_number)
        .ok_or("signature: the signer certificate is not in the container")?;
    let sca = certs
        .iter()
        .find(|c| c.tbs_certificate.subject == leaf.tbs_certificate.issuer)
        .ok_or("signature: the Signing CA certificate is not in the container")?;
    let root = chain::parse(root_der, "release root")?;

    for (c, w) in [(*leaf, "signer certificate"), (*sca, "Signing CA"), (&root, "release root")] {
        chain::check_alg(c, w)?;
        check_time(c, at, w)?;
    }
    let root_key = chain::rsa_key(&root, "release root")?;
    let sca_key = chain::rsa_key(sca, "Signing CA")?;
    let leaf_key = chain::rsa_key(leaf, "signer certificate")?;

    chain::check_issued_by(&root, &root, "release root")?;
    chain::check_signed_by(&root, &root_key, "release root")?;
    chain::check_ca(&root, "release root")?;
    chain::check_issued_by(sca, &root, "Signing CA")?;
    chain::check_signed_by(sca, &root_key, "Signing CA")?;
    chain::check_ca(sca, "Signing CA")?;
    chain::check_issued_by(leaf, sca, "signer certificate")?;
    chain::check_signed_by(leaf, &sca_key, "signer certificate")?;
    check_leaf(leaf)?;

    let sig = Signature::try_from(si.signature.as_bytes()).map_err(|e| format!("signature: {e}"))?;
    VerifyingKey::<Sha256>::new(leaf_key)
        .verify(record, &sig)
        .map_err(|_| "signature: does not verify over the record bytes".to_string())?;

    Ok(Signer {
        leaf_subject: leaf.tbs_certificate.subject.to_string(),
        leaf_serial: hex::encode(leaf.tbs_certificate.serial_number.as_bytes()),
        signing_ca_subject: sca.tbs_certificate.subject.to_string(),
        root_sha256: hex::encode(Sha256::digest(root_der)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(n: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/signature/{n}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    /// 1 Oct 2026, inside every fixture certificate's validity.
    const AT: Duration = Duration::from_secs(1_790_812_800);

    fn run(record: &str, p7s: &str, root: &str) -> Result<Signer, String> {
        verify(&fx(record), &fx(p7s), &cert_der(&fx(root), "root").unwrap(), AT)
    }

    #[test]
    fn registration_signer_signature_verifies() {
        let s = run("record.json", "record.json.p7s", "root.pem").unwrap();
        assert!(s.leaf_subject.contains("Registration Signer"), "{}", s.leaf_subject);
    }

    #[test]
    fn a_changed_record_is_refused() {
        let e = run("record-changed.json", "record.json.p7s", "root.pem").err().unwrap();
        assert!(e.contains("does not verify"), "{e}");
    }

    #[test]
    fn a_rim_signer_signature_is_refused() {
        let e = run("record.json", "record.json.rim.p7s", "root.pem").err().unwrap();
        assert!(e.contains("extended key usage"), "{e}");
    }

    #[test]
    fn another_root_is_refused() {
        let e = run("record.json", "record.json.p7s", "other-root.pem").err().unwrap();
        assert!(e.contains("Signing CA"), "{e}");
    }

    #[test]
    fn signed_attributes_are_refused() {
        let e = run("record.json", "record.json.attrs.p7s", "root.pem").err().unwrap();
        assert!(e.contains("signed attributes"), "{e}");
    }

    #[test]
    fn embedded_content_is_refused() {
        let e = run("record.json", "record.json.embedded.p7s", "root.pem").err().unwrap();
        assert!(e.contains("embedded"), "{e}");
    }

    #[test]
    fn purpose_oid_encoding_matches_openssl() {
        // The EKU extension value of the fixture leaf, as OpenSSL wrote it.
        let from_openssl = hex::decode("301606146982b5f99892c497b283e9a6e6e094e589a4d640").unwrap();
        assert_eq!(expected_eku_value(), from_openssl);
        assert_eq!(oid_der("2.5.29.37"), [0x06, 0x03, 0x55, 0x1d, 0x25]);
    }

    #[test]
    fn expired_certificates_are_refused() {
        let late = Duration::from_secs(AT.as_secs() + 20 * 365 * 86_400);
        let e = verify(&fx("record.json"), &fx("record.json.p7s"), &cert_der(&fx("root.pem"), "root").unwrap(), late)
            .err()
            .unwrap();
        assert!(e.contains("not valid now"), "{e}");
    }
}
