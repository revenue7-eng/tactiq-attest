//! `TPM2_MakeCredential` in software (TPM 2.0 Part 1, "Credential Protection").
//!
//! The registrar has the EK public key from the EK certificate, never from the
//! device (DDR-005 decision 2), and the name of the AK the device presented. It
//! produces a blob that only a TPM holding the EK private key opens, and only
//! while an object with exactly that name is loaded in it.
//!
//! For an RSA EK with nameAlg SHA-256 and a symmetric AES-128-CFB (the default
//! TCG EK template):
//!
//!   seed            32 random bytes
//!   encryptedSecret RSA-OAEP(SHA-256, label "IDENTITY\0")(seed)
//!   symKey          KDFa(SHA-256, seed, "STORAGE", name, "", 128)
//!   encIdentity     AES-128-CFB(symKey, IV = 0)(TPM2B_DIGEST(secret))
//!   hmacKey         KDFa(SHA-256, seed, "INTEGRITY", "", "", 256)
//!   integrityHMAC   HMAC-SHA256(hmacKey, encIdentity || name)
//!   credentialBlob  TPM2B_ID_OBJECT(TPM2B_DIGEST(integrityHMAC) || encIdentity)
//!
//! The file layout is the one `tpm2_makecredential` writes and
//! `tpm2_activatecredential` reads, so a blob from this tool can be opened on
//! the bench with stock tpm2-tools before the agent has registration commands.

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;

/// Magic and version of the tpm2-tools credential file.
pub const FILE_MAGIC: u32 = 0xBADC_C0DE;
pub const FILE_VERSION: u32 = 1;

pub const SECRET_LEN: usize = 32;
const SEED_LEN: usize = 32;
/// The OAEP label includes the terminating zero octet.
const LABEL_IDENTITY: &[u8] = b"IDENTITY\0";

/// KDFa with HMAC-SHA256 (TPM 2.0 Part 1, 11.4.10.2). `label` is given without
/// its terminating zero; the zero octet is added here, as the specification
/// requires for a label passed as a string.
pub fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::with_capacity(bytes + 32);
    let mut counter: u32 = 0;
    while out.len() < bytes {
        counter += 1;
        let mut m = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
        m.update(&counter.to_be_bytes());
        m.update(label);
        m.update(&[0u8]);
        m.update(context_u);
        m.update(context_v);
        m.update(&bits.to_be_bytes());
        out.extend_from_slice(&m.finalize().into_bytes());
    }
    out.truncate(bytes);
    out
}

fn tpm2b(v: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(2 + v.len());
    o.extend_from_slice(&(v.len() as u16).to_be_bytes());
    o.extend_from_slice(v);
    o
}

/// Make the credential blob for `name` (a TPM name, nameAlg first) and
/// `secret`, encrypted to `ek`. Returns the tpm2-tools credential file bytes.
pub fn make_credential(
    ek: &RsaPublicKey,
    name: &[u8],
    secret: &[u8; SECRET_LEN],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>, String> {
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed);
    make_credential_with_seed(ek, name, secret, &seed, rng)
}

/// As `make_credential` with the seed supplied. Separate so that the symmetric
/// part can be tested against a known seed; the OAEP step still draws its own
/// randomness from `rng`.
pub fn make_credential_with_seed(
    ek: &RsaPublicKey,
    name: &[u8],
    secret: &[u8; SECRET_LEN],
    seed: &[u8; SEED_LEN],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>, String> {
    let enc_seed = ek
        .encrypt(rng, Oaep::new_with_label::<Sha256, _>(label_str()), seed)
        .map_err(|e| format!("RSA-OAEP: {e}"))?;

    let (enc_identity, integrity) = protect(seed, name, secret);

    let mut id_object = tpm2b(&integrity);
    id_object.extend_from_slice(&enc_identity);

    let mut f = Vec::new();
    f.extend_from_slice(&FILE_MAGIC.to_be_bytes());
    f.extend_from_slice(&FILE_VERSION.to_be_bytes());
    f.extend_from_slice(&tpm2b(&id_object));
    f.extend_from_slice(&tpm2b(&enc_seed));
    Ok(f)
}

/// The OAEP label as the `rsa` crate wants it: a `String`. "IDENTITY\0" is
/// valid UTF-8, including the zero octet.
fn label_str() -> String {
    String::from_utf8(LABEL_IDENTITY.to_vec()).expect("ASCII label")
}

/// The symmetric half: encIdentity and integrityHMAC from seed, name, secret.
fn protect(seed: &[u8], name: &[u8], secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sym_key = kdfa(seed, b"STORAGE", name, &[], 128);
    let mut enc_identity = tpm2b(secret);
    Aes128CfbEnc::new_from_slices(&sym_key, &[0u8; 16])
        .expect("16-byte key and IV")
        .encrypt(&mut enc_identity);

    let hmac_key = kdfa(seed, b"INTEGRITY", &[], &[], 256);
    let mut m = HmacSha256::new_from_slice(&hmac_key).expect("HMAC key");
    m.update(&enc_identity);
    m.update(name);
    (enc_identity, m.finalize().into_bytes().to_vec())
}

/// The parts of a tpm2-tools credential file, checked for layout only. The
/// fields are read by the software activation in tests; outside tests the
/// parse is the check.
#[cfg_attr(not(test), allow(dead_code))]
pub struct CredentialFile<'a> {
    pub integrity: &'a [u8],
    pub enc_identity: &'a [u8],
    pub enc_seed: &'a [u8],
}

pub fn parse_file(b: &[u8]) -> Result<CredentialFile<'_>, String> {
    fn take<'a>(b: &mut &'a [u8], n: usize, what: &str) -> Result<&'a [u8], String> {
        if b.len() < n {
            return Err(format!("credential file: short {what}"));
        }
        let (h, t) = b.split_at(n);
        *b = t;
        Ok(h)
    }
    fn u16be(b: &mut &[u8], what: &str) -> Result<usize, String> {
        let h = take(b, 2, what)?;
        Ok(u16::from_be_bytes([h[0], h[1]]) as usize)
    }
    let mut r = b;
    let magic = u32::from_be_bytes(take(&mut r, 4, "magic")?.try_into().unwrap());
    let version = u32::from_be_bytes(take(&mut r, 4, "version")?.try_into().unwrap());
    if magic != FILE_MAGIC || version != FILE_VERSION {
        return Err(format!("credential file: magic {magic:#010x} version {version}"));
    }
    let id_len = u16be(&mut r, "TPM2B_ID_OBJECT size")?;
    let mut id = take(&mut r, id_len, "TPM2B_ID_OBJECT")?;
    let hmac_len = u16be(&mut id, "integrityHMAC size")?;
    let integrity = take(&mut id, hmac_len, "integrityHMAC")?;
    let enc_identity = id;
    let seed_len = u16be(&mut r, "TPM2B_ENCRYPTED_SECRET size")?;
    let enc_seed = take(&mut r, seed_len, "encryptedSecret")?;
    if !r.is_empty() {
        return Err(format!("credential file: {} trailing bytes", r.len()));
    }
    if integrity.len() != 32 || enc_identity.len() != 2 + SECRET_LEN {
        return Err(format!(
            "credential file: integrityHMAC {} bytes, encIdentity {} bytes",
            integrity.len(),
            enc_identity.len()
        ));
    }
    Ok(CredentialFile { integrity, enc_identity, enc_seed })
}

/// `TPM2_ActivateCredential` in software, for tests only: what the TPM does
/// with the EK private key. It lets the tests check this module against blobs
/// made by `tpm2_makecredential` without a TPM.
#[cfg(test)]
pub fn activate_in_software(
    ek_priv: &rsa::RsaPrivateKey,
    name: &[u8],
    file: &[u8],
) -> Result<Vec<u8>, String> {
    use aes::cipher::AsyncStreamCipher as _;
    type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;
    let c = parse_file(file)?;
    let seed = ek_priv
        .decrypt(Oaep::new_with_label::<Sha256, _>(label_str()), c.enc_seed)
        .map_err(|e| format!("OAEP: {e}"))?;
    let hmac_key = kdfa(&seed, b"INTEGRITY", &[], &[], 256);
    let mut m = HmacSha256::new_from_slice(&hmac_key).unwrap();
    m.update(c.enc_identity);
    m.update(name);
    m.verify_slice(c.integrity).map_err(|_| "integrity HMAC mismatch (wrong name or EK)".to_string())?;
    let sym_key = kdfa(&seed, b"STORAGE", name, &[], 128);
    let mut id = c.enc_identity.to_vec();
    Aes128CfbDec::new_from_slices(&sym_key, &[0u8; 16]).unwrap().decrypt(&mut id);
    let n = u16::from_be_bytes([id[0], id[1]]) as usize;
    if n != id.len() - 2 {
        return Err("identity size mismatch".into());
    }
    Ok(id[2..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;

    fn fx(n: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/makecred/{n}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    fn test_key() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::from_pkcs8_der(&fx("ek-test.pk8")).unwrap()
    }

    /// A blob written by tpm2_makecredential (tpm2-tools 5.6) for a known name
    /// and secret opens with this module's KDF and layout. This is what ties the
    /// module to the reference tooling without a TPM in CI.
    #[test]
    fn opens_a_blob_made_by_tpm2_tools() {
        let name = fx("name.bin");
        let got = activate_in_software(&test_key(), &name, &fx("tools.blob")).unwrap();
        assert_eq!(got, fx("secret.bin"));
    }

    #[test]
    fn blob_made_here_round_trips_and_has_the_tools_layout() {
        let k = test_key();
        let name = fx("name.bin");
        let secret: [u8; 32] = fx("secret.bin").try_into().unwrap();
        let blob = make_credential(&k.to_public_key(), &name, &secret, &mut rand_core::OsRng).unwrap();
        assert_eq!(blob.len(), fx("tools.blob").len());
        assert_eq!(&blob[..12], &fx("tools.blob")[..12], "magic, version, TPM2B_ID_OBJECT size");
        assert_eq!(activate_in_software(&k, &name, &blob).unwrap(), secret);
    }

    #[test]
    fn another_name_does_not_open_the_blob() {
        let k = test_key();
        let name = fx("name.bin");
        let secret = [7u8; 32];
        let blob = make_credential(&k.to_public_key(), &name, &secret, &mut rand_core::OsRng).unwrap();
        let mut other = name.clone();
        let last = other.len() - 1;
        other[last] ^= 1;
        assert!(activate_in_software(&k, &other, &blob).is_err());
    }

    #[test]
    fn layout_errors_are_refused() {
        let good = fx("tools.blob");
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        assert!(parse_file(&bad_magic).is_err());
        assert!(parse_file(&good[..good.len() - 1]).is_err());
        let mut long = good.clone();
        long.push(0);
        assert!(parse_file(&long).is_err());
    }
}
