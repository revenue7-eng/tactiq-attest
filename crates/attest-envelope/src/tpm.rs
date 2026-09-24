//! TPM wire structures for envelope v2 (DDR-004 decision 8).
//!
//! Two structures, parsed from the bytes tpm2-tools writes:
//!
//!   * `TPMS_ATTEST` of type `TPM_ST_ATTEST_QUOTE`, the object the AK signs;
//!   * `TPM2B_PUBLIC` of an ECC key, the AK public area a verifier trusts.
//!
//! Same rules as the rest of this crate: pure parsing over bytes, no I/O, no
//! crypto verification, no trust decision. Which attributes make a key an AK
//! is decided by the verifier (`attest-appraise`), not here. Every length is
//! checked against the bytes remaining before it is read, the parse is exact
//! (trailing bytes are refused), and nothing is allocated per field.
//!
//! Plain Rust with no TSS dependency, so the verifier keeps building for
//! `wasm32-unknown-unknown` (DDR-003 boundary F).

use sha2::{Digest, Sha256};

use crate::MSG_LEN;

/// `TPM_GENERATED_VALUE`: every structure the TPM signs itself starts with it,
/// and a restricted key refuses to sign external data that does.
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
/// `TPM_ST_ATTEST_QUOTE`.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ECC_NIST_P256: u16 = 0x0003;

/// `TPMA_OBJECT` bits used by the verifier's AK rule.
pub mod attr {
    pub const FIXED_TPM: u32 = 1 << 1;
    pub const FIXED_PARENT: u32 = 1 << 4;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    pub const RESTRICTED: u32 = 1 << 16;
    pub const DECRYPT: u32 = 1 << 17;
    pub const SIGN: u32 = 1 << 18;
}

/// `qualifyingData` for the quote over one canonical message: SHA-256 of the
/// 93 bytes. One function for both sides, so prover and verifier agree by
/// construction.
pub fn qualifying_data(msg: &[u8]) -> Result<[u8; 32], String> {
    if msg.len() != MSG_LEN {
        return Err(format!("bad message length: {} (want {})", msg.len(), MSG_LEN));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(msg));
    Ok(out)
}

struct Rd<'a> {
    b: &'a [u8],
    what: &'static str,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize, field: &str) -> Result<&'a [u8], String> {
        if self.b.len() < n {
            return Err(format!("{}: truncated at {field} (need {n}, have {})", self.what, self.b.len()));
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self, f: &str) -> Result<u8, String> { Ok(self.take(1, f)?[0]) }
    fn u16(&mut self, f: &str) -> Result<u16, String> {
        let s = self.take(2, f)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self, f: &str) -> Result<u32, String> {
        let s = self.take(4, f)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self, f: &str) -> Result<u64, String> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8, f)?);
        Ok(u64::from_be_bytes(a))
    }
    /// A TPM2B: u16 size, then that many bytes.
    fn tpm2b(&mut self, f: &str) -> Result<&'a [u8], String> {
        let n = self.u16(f)? as usize;
        self.take(n, f)
    }
    fn end(&self) -> Result<(), String> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(format!("{}: {} trailing byte(s)", self.what, self.b.len()))
        }
    }
}

/// `TPMS_CLOCK_INFO`. Parsed and carried, not appraised in v2 (DDR-004 boundary D).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}

/// A parsed `TPMS_ATTEST` of type quote. Fields borrow from the input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Quote<'a> {
    /// `qualifiedSigner`: the TPM name of the key that signed.
    pub qualified_signer: &'a [u8],
    /// `extraData`: the caller's qualifying data, as echoed by the TPM.
    pub extra_data: &'a [u8],
    pub clock_info: ClockInfo,
    pub firmware_version: u64,
    /// `TPML_PCR_SELECTION`, one entry per bank: (hash alg, select bitmap).
    /// Kept as the raw list; the verifier decides what it accepts.
    pub pcr_banks: PcrBanks<'a>,
    /// `pcrDigest`: hash of the selected PCR values, computed by the TPM.
    pub pcr_digest: &'a [u8],
}

/// Raw `TPML_PCR_SELECTION` body, iterated without allocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PcrBanks<'a> {
    count: u32,
    body: &'a [u8],
}

impl<'a> PcrBanks<'a> {
    pub fn count(&self) -> u32 { self.count }

    /// Iterate (hash_alg, bitmap). The body was fully validated at parse time,
    /// so iteration cannot fail.
    pub fn iter(&self) -> impl Iterator<Item = (u16, &'a [u8])> + 'a {
        let mut b = self.body;
        (0..self.count).map(move |_| {
            let alg = u16::from_be_bytes([b[0], b[1]]);
            let n = b[2] as usize;
            let bits = &b[3..3 + n];
            b = &b[3 + n..];
            (alg, bits)
        })
    }
}

/// Upper bound on banks in one selection. A TPM has a handful; this only stops
/// a hostile count from making the validation loop long.
const MAX_BANKS: u32 = 16;

impl<'a> Quote<'a> {
    /// Parse `TPMS_ATTEST` bytes exactly as `tpm2_quote -m` writes them.
    ///
    /// Refuses anything that is not a quote: wrong magic, wrong type, short or
    /// trailing bytes. Magic and type are checked here, but they mean nothing
    /// until the signature over these bytes has verified (DDR-004 boundary A);
    /// that ordering is the verifier's job.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        let mut r = Rd { b: bytes, what: "TPMS_ATTEST" };
        let magic = r.u32("magic")?;
        if magic != TPM_GENERATED_VALUE {
            return Err(format!("TPMS_ATTEST: magic {magic:#010x}, want {TPM_GENERATED_VALUE:#010x}"));
        }
        let ty = r.u16("type")?;
        if ty != TPM_ST_ATTEST_QUOTE {
            return Err(format!("TPMS_ATTEST: type {ty:#06x}, want {TPM_ST_ATTEST_QUOTE:#06x} (quote)"));
        }
        let qualified_signer = r.tpm2b("qualifiedSigner")?;
        let extra_data = r.tpm2b("extraData")?;
        let clock_info = ClockInfo {
            clock: r.u64("clock")?,
            reset_count: r.u32("resetCount")?,
            restart_count: r.u32("restartCount")?,
            safe: match r.u8("safe")? {
                0 => false,
                1 => true,
                v => return Err(format!("TPMS_ATTEST: safe = {v}, want 0 or 1")),
            },
        };
        let firmware_version = r.u64("firmwareVersion")?;

        let count = r.u32("pcrSelect.count")?;
        if count > MAX_BANKS {
            return Err(format!("TPMS_ATTEST: {count} PCR banks, limit {MAX_BANKS}"));
        }
        let body_start = r.b;
        for _ in 0..count {
            r.u16("pcrSelect.hash")?;
            let n = r.u8("pcrSelect.sizeofSelect")? as usize;
            r.take(n, "pcrSelect.pcrSelect")?;
        }
        let body = &body_start[..body_start.len() - r.b.len()];
        let pcr_digest = r.tpm2b("pcrDigest")?;
        r.end()?;

        Ok(Quote {
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version,
            pcr_banks: PcrBanks { count, body },
            pcr_digest,
        })
    }
}

/// A parsed ECC `TPMT_PUBLIC`, from the `TPM2B_PUBLIC` that `tpm2_create -u`
/// and `tpm2_readpublic -o` write.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EccPublic<'a> {
    /// The `TPMT_PUBLIC` bytes, the input to the TPM name.
    pub tpmt: &'a [u8],
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: &'a [u8],
    /// Symmetric algorithm of the key; `TPM_ALG_NULL` for a signing key.
    pub symmetric: u16,
    /// Signing scheme and its hash; (`TPM_ALG_NULL`, 0) when none is set.
    pub scheme: u16,
    pub scheme_hash: u16,
    pub curve: u16,
    /// KDF scheme; `TPM_ALG_NULL` for a signing key.
    pub kdf: u16,
    pub x: &'a [u8],
    pub y: &'a [u8],
}

impl<'a> EccPublic<'a> {
    /// Parse a `TPM2B_PUBLIC` (u16 size, then exactly that `TPMT_PUBLIC`).
    /// Only ECC keys are accepted; anything else is refused, not skipped.
    pub fn parse_tpm2b(bytes: &'a [u8]) -> Result<Self, String> {
        let mut outer = Rd { b: bytes, what: "TPM2B_PUBLIC" };
        let tpmt = outer.tpm2b("size")?;
        outer.end()?;

        let mut r = Rd { b: tpmt, what: "TPMT_PUBLIC" };
        let ty = r.u16("type")?;
        if ty != TPM_ALG_ECC {
            return Err(format!("TPMT_PUBLIC: type {ty:#06x}, want ECC {TPM_ALG_ECC:#06x}"));
        }
        let name_alg = r.u16("nameAlg")?;
        let attributes = r.u32("objectAttributes")?;
        let auth_policy = r.tpm2b("authPolicy")?;
        let symmetric = r.u16("symmetric.algorithm")?;
        if symmetric != TPM_ALG_NULL {
            r.u16("symmetric.keyBits")?;
            r.u16("symmetric.mode")?;
        }
        let scheme = r.u16("scheme.scheme")?;
        let scheme_hash = if scheme != TPM_ALG_NULL { r.u16("scheme.hashAlg")? } else { 0 };
        let curve = r.u16("curveID")?;
        let kdf = r.u16("kdf.scheme")?;
        if kdf != TPM_ALG_NULL {
            r.u16("kdf.hashAlg")?;
        }
        let x = r.tpm2b("unique.x")?;
        let y = r.tpm2b("unique.y")?;
        r.end()?;

        Ok(EccPublic { tpmt, name_alg, attributes, auth_policy, symmetric, scheme, scheme_hash, curve, kdf, x, y })
    }

    /// The TPM name: `nameAlg || H_nameAlg(TPMT_PUBLIC)`. Only sha256 is
    /// supported; any other name algorithm is refused rather than guessed.
    pub fn name(&self) -> Result<[u8; 34], String> {
        if self.name_alg != TPM_ALG_SHA256 {
            return Err(format!("nameAlg {:#06x} not supported (sha256 only)", self.name_alg));
        }
        let mut out = [0u8; 34];
        out[..2].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out[2..].copy_from_slice(&Sha256::digest(self.tpmt));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote_bytes(extra: &[u8], banks: &[(u16, &[u8])], digest: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        v.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        v.extend_from_slice(&34u16.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x0B]);
        v.extend_from_slice(&[0xAA; 32]);
        v.extend_from_slice(&(extra.len() as u16).to_be_bytes());
        v.extend_from_slice(extra);
        v.extend_from_slice(&7u64.to_be_bytes());
        v.extend_from_slice(&3u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.push(1);
        v.extend_from_slice(&0x2019_1023u64.to_be_bytes());
        v.extend_from_slice(&(banks.len() as u32).to_be_bytes());
        for (alg, bits) in banks {
            v.extend_from_slice(&alg.to_be_bytes());
            v.push(bits.len() as u8);
            v.extend_from_slice(bits);
        }
        v.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        v.extend_from_slice(digest);
        v
    }

    #[test]
    fn parses_a_single_bank_quote_of_swtpm_size() {
        let b = quote_bytes(&[0x11; 32], &[(TPM_ALG_SHA256, &[0xff, 0x03, 0x00])], &[0x22; 32]);
        assert_eq!(b.len(), 145, "same size as the swtpm quote over sha256:0..9");
        let q = Quote::parse(&b).unwrap();
        assert_eq!(q.extra_data, &[0x11; 32]);
        assert_eq!(q.pcr_digest, &[0x22; 32]);
        assert_eq!(q.clock_info, ClockInfo { clock: 7, reset_count: 3, restart_count: 1, safe: true });
        let banks: Vec<_> = q.pcr_banks.iter().collect();
        assert_eq!(banks, vec![(TPM_ALG_SHA256, &[0xff, 0x03, 0x00][..])]);
    }

    #[test]
    fn refuses_wrong_magic_and_wrong_type() {
        let mut b = quote_bytes(&[], &[(TPM_ALG_SHA256, &[1, 0, 0])], &[0; 32]);
        b[0] = 0;
        assert!(Quote::parse(&b).unwrap_err().contains("magic"));
        let mut b = quote_bytes(&[], &[(TPM_ALG_SHA256, &[1, 0, 0])], &[0; 32]);
        b[5] = 0x17; // 0x8017, certify
        assert!(Quote::parse(&b).unwrap_err().contains("type"));
    }

    #[test]
    fn refuses_truncation_and_trailing_bytes() {
        let b = quote_bytes(&[1; 32], &[(TPM_ALG_SHA256, &[1, 0, 0])], &[0; 32]);
        for n in 0..b.len() {
            assert!(Quote::parse(&b[..n]).is_err(), "prefix of {n} bytes must not parse");
        }
        let mut long = b.clone();
        long.push(0);
        assert!(Quote::parse(&long).unwrap_err().contains("trailing"));
    }

    #[test]
    fn refuses_hostile_bank_count() {
        let mut b = quote_bytes(&[], &[], &[0; 32]);
        // count sits after magic(4) type(2) signer(2+34) extra(2) clock(17) fw(8)
        let off = 4 + 2 + 36 + 2 + 17 + 8;
        b[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Quote::parse(&b).is_err());
    }

    #[test]
    fn qualifying_data_requires_a_canonical_message() {
        assert!(qualifying_data(&[0; MSG_LEN]).is_ok());
        assert!(qualifying_data(&[0; MSG_LEN - 1]).is_err());
    }
}
