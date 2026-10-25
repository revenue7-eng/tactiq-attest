//! attest-stop: the body of the agent stop service's evidence sections.
//!
//! `attest-envelope` frames a bundle and assigns two tags to the stop service:
//! `TAG_STOP_STATE` (0x0004) and `TAG_VERIFIER_NONCE` (0x0005). It does not
//! know what the bodies mean, by design. This crate does, and both sides use
//! it: `tactiq-stop` builds the bodies on the device, and whoever checks the
//! device parses them. One codec on both sides, for the same reason the
//! envelope is one crate.
//!
//! What a stop record says
//! -----------------------
//! The record is signed indirectly: its section sits in the evidence bundle,
//! `evidence_hash` in the 93-byte message is SHA-256 of that bundle, and the
//! TPM quote's qualifying data is SHA-256 of the message. The quote also
//! carries the PCR digest, so a verifier learns from one signature which
//! measured build answered, and what it answered.
//!
//! ```text
//! status:  version(1) || kind=0x02(1) || state(1) || reserved=0(1) || stop_epoch_be(8) || policy_digest(32)                      = 44 bytes
//! refusal: version(1) || kind=0x01(1) || state(1) || reserved=0(1) || stop_epoch_be(8) || policy_digest(32) || request_digest(32) = 76 bytes
//! ```
//!
//! * `kind` says why the record exists: a refusal of one call, or an answer
//!   to a status question.
//! * `state` is the gateway's admission state when the record was made.
//! * `stop_epoch` is the value of the stop service's TPM counter at that
//!   moment. What advances it is the service's rule, not this codec's; the
//!   codec only carries the number so a verifier can compare two records.
//! * `policy_digest` is SHA-256 of the gateway policy the service enforces.
//! * `request_digest` (refusals only) is SHA-256 of the refused request as the
//!   service saw it, so a refusal cannot be presented as being about another
//!   call.
//!
//! Rules the parser enforces, each tested
//! --------------------------------------
//! * Exact length for the kind. Not a minimum.
//! * `0x00` and `0xFF` are never valid in `kind` or `state`, for the reason the
//!   envelope forbids tags `0x0000` and `0xFFFF`: zeroed memory and erased
//!   flash must not parse as a plausible record.
//! * `reserved` must be zero, so it can be given a meaning later without old
//!   records becoming ambiguous.
//! * A refusal with `state = running` is refused. The stop service refuses a
//!   call only because the gateway is stopped; a refusal claiming otherwise
//!   is not something this service produces.
//! * The nonce section is between 16 and 64 bytes. Shorter is guessable,
//!   longer buys nothing and is refused rather than truncated.
//!
//! No state, no I/O, no trust decision: whether a record is fresh enough,
//! whether its epoch is acceptable and whether its policy is the expected
//! one are the verifier's decisions.
//!
//! Digests both sides compute
//! --------------------------
//! * `request_digest` = SHA-256(`"tactiq-stop/request/v1\0"` || method ||
//!   `\0` || path || `\0` || body), over the request as the gateway handed it
//!   to the service.
//! * The NV certify's qualifying data = SHA-256(`"tactiq-stop/certify/v1\0"`
//!   || stop record body || nonce), with an empty nonce when there is none.
//!   The TPM-signed counter value is thereby tied to this one record (and to
//!   the verifier's challenge), so it cannot be lifted into another.
//! * The quote's qualifying data = SHA-256(`"tactiq-stop/quote/v1\0"` ||
//!   msg). An agent envelope's quote uses SHA-256(msg) alone, so a stop
//!   receipt can never pass as an agent envelope, or the reverse.
//!
//! What a valid receipt does and does not prove
//! --------------------------------------------
//! It proves that a TPM holding the device's AK, on a device booted into the
//! measured build named by the quoted PCRs, signed this record, and that the
//! TPM itself read the named NV index at the value in the record. It does
//! not by itself prove which process on that device asked for the
//! signatures: any process allowed to use the AK could. Tying the answer to
//! the stop service is the job of the key's authorization and of the
//! operating system's policy, not of this format. A verifier must also pin
//! the stop counter's index name (recorded at registration), or a certify of
//! some other counter would pass.
//!
//! Receipt
//! -------
//! What the service hands out (403 body to the gateway, file for `status`):
//!
//! ```text
//! "TQSR" || version=0x01 || len_be32 || msg(93) || len_be32 || quote_attest
//!        || len_be32 || quote_sig || len_be32 || bundle
//! ```
//!
//! The bundle carries the stop record (0x0004), the NV certify (0x0006) and,
//! for a challenged status, the nonce (0x0005). The quote's qualifying data is
//! SHA-256 of `msg`, as for every envelope.

use sha2::{Digest, Sha256};

/// The only version this codec knows. A record with any other value is
/// refused, not guessed at.
pub const STOP_RECORD_VERSION: u8 = 0x01;

/// Common head: version, kind, state, reserved, stop_epoch, policy_digest.
pub const HEAD_LEN: usize = 1 + 1 + 1 + 1 + 8 + 32;
/// Exact body length of a status record.
pub const STATUS_LEN: usize = HEAD_LEN;
/// Exact body length of a refusal record.
pub const REFUSAL_LEN: usize = HEAD_LEN + 32;

/// Accepted length of a verifier nonce, inclusive.
pub const NONCE_MIN: usize = 16;
pub const NONCE_MAX: usize = 64;

const KIND_REFUSAL: u8 = 0x01;
const KIND_STATUS: u8 = 0x02;
const STATE_RUNNING: u8 = 0x01;
const STATE_STOPPED: u8 = 0x02;

/// Admission state of the gateway when the record was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Running,
    Stopped,
}

impl State {
    fn to_byte(self) -> u8 {
        match self {
            State::Running => STATE_RUNNING,
            State::Stopped => STATE_STOPPED,
        }
    }

    fn from_byte(b: u8) -> Result<Self, String> {
        match b {
            STATE_RUNNING => Ok(State::Running),
            STATE_STOPPED => Ok(State::Stopped),
            other => Err(format!("stop record: state byte 0x{other:02x} is not valid")),
        }
    }
}

/// Why the record exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One call was refused; `request_digest` names it.
    Refusal { request_digest: [u8; 32] },
    /// An answer to a status question.
    Status,
}

/// A parsed or to-be-built stop record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopRecord {
    pub kind: Kind,
    pub state: State,
    pub stop_epoch: u64,
    pub policy_digest: [u8; 32],
}

impl StopRecord {
    /// Encode the section body. Refuses the one combination the parser would
    /// refuse, so the service cannot emit what a verifier must reject.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if matches!(self.kind, Kind::Refusal { .. }) && self.state == State::Running {
            return Err("stop record: a refusal must carry state = stopped".into());
        }
        let mut out = Vec::with_capacity(REFUSAL_LEN);
        out.push(STOP_RECORD_VERSION);
        out.push(match self.kind {
            Kind::Refusal { .. } => KIND_REFUSAL,
            Kind::Status => KIND_STATUS,
        });
        out.push(self.state.to_byte());
        out.push(0x00);
        out.extend_from_slice(&self.stop_epoch.to_be_bytes());
        out.extend_from_slice(&self.policy_digest);
        if let Kind::Refusal { request_digest } = self.kind {
            out.extend_from_slice(&request_digest);
        }
        Ok(out)
    }

    /// Parse a section body. Every rule in the module documentation is
    /// checked here; nothing is repaired.
    pub fn parse(body: &[u8]) -> Result<Self, String> {
        if body.len() < HEAD_LEN {
            return Err(format!(
                "stop record: {} bytes, shorter than the {HEAD_LEN}-byte head",
                body.len()
            ));
        }
        if body[0] != STOP_RECORD_VERSION {
            return Err(format!("stop record: unknown version 0x{:02x}", body[0]));
        }
        let state = State::from_byte(body[2])?;
        if body[3] != 0x00 {
            return Err(format!("stop record: reserved byte is 0x{:02x}, must be zero", body[3]));
        }
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&body[4..12]);
        let mut policy_digest = [0u8; 32];
        policy_digest.copy_from_slice(&body[12..HEAD_LEN]);
        let kind = match body[1] {
            KIND_STATUS => {
                if body.len() != STATUS_LEN {
                    return Err(format!(
                        "stop record: status is exactly {STATUS_LEN} bytes, got {}",
                        body.len()
                    ));
                }
                Kind::Status
            }
            KIND_REFUSAL => {
                if body.len() != REFUSAL_LEN {
                    return Err(format!(
                        "stop record: refusal is exactly {REFUSAL_LEN} bytes, got {}",
                        body.len()
                    ));
                }
                if state != State::Stopped {
                    return Err("stop record: refusal with state = running".into());
                }
                let mut request_digest = [0u8; 32];
                request_digest.copy_from_slice(&body[HEAD_LEN..REFUSAL_LEN]);
                Kind::Refusal { request_digest }
            }
            other => return Err(format!("stop record: kind byte 0x{other:02x} is not valid")),
        };
        Ok(StopRecord {
            kind,
            state,
            stop_epoch: u64::from_be_bytes(epoch),
            policy_digest,
        })
    }
}

/// Check a verifier nonce section body: length only. The bytes themselves
/// are the verifier's; this crate never interprets them.
pub fn check_nonce(body: &[u8]) -> Result<(), String> {
    if body.len() < NONCE_MIN || body.len() > NONCE_MAX {
        return Err(format!(
            "verifier nonce: {} bytes, must be {NONCE_MIN}..={NONCE_MAX}",
            body.len()
        ));
    }
    Ok(())
}

/// SHA-256 of the request, domain-separated. See the module documentation.
pub fn request_digest(method: &str, path: &str, body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tactiq-stop/request/v1\0");
    h.update(method.as_bytes());
    h.update(b"\0");
    h.update(path.as_bytes());
    h.update(b"\0");
    h.update(body);
    h.finalize().into()
}

/// Qualifying data for the stop service's quote over its message.
pub fn stop_quote_qualifying(msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tactiq-stop/quote/v1\0");
    h.update(msg);
    h.finalize().into()
}

/// Qualifying data for the NV certify of the stop counter.
pub fn certify_qualifying(record_body: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tactiq-stop/certify/v1\0");
    h.update(record_body);
    h.update(nonce);
    h.finalize().into()
}

/// Upper bounds on the parts of a certify section and a receipt. A TPMS_ATTEST
/// and an ECDSA P-256 signature are far below these; the bounds exist so a
/// length field is never trusted as an allocation size.
pub const ATTEST_MAX: usize = 2048;
pub const SIG_MAX: usize = 512;
pub const BUNDLE_MAX: usize = 64 * 1024;

/// Body of a `TAG_TPM_NV_CERTIFY` section: the TPM's attestation structure
/// and the AK signature over it.
///
/// ```text
/// len_be16 || attest || len_be16 || sig
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvCertify {
    pub attest: Vec<u8>,
    pub sig: Vec<u8>,
}

impl NvCertify {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.attest.is_empty() || self.attest.len() > ATTEST_MAX {
            return Err(format!("nv certify: attest is {} bytes", self.attest.len()));
        }
        if self.sig.is_empty() || self.sig.len() > SIG_MAX {
            return Err(format!("nv certify: signature is {} bytes", self.sig.len()));
        }
        let mut out = Vec::with_capacity(4 + self.attest.len() + self.sig.len());
        out.extend_from_slice(&(self.attest.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.attest);
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        Ok(out)
    }

    pub fn parse(body: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(body);
        let attest = r.take16(ATTEST_MAX, "nv certify attest")?.to_vec();
        let sig = r.take16(SIG_MAX, "nv certify signature")?.to_vec();
        r.finish("nv certify")?;
        Ok(NvCertify { attest, sig })
    }
}

const RECEIPT_MAGIC: &[u8; 4] = b"TQSR";
const RECEIPT_VERSION: u8 = 0x01;

/// A signed answer from the stop service. See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub msg: Vec<u8>,
    pub quote_attest: Vec<u8>,
    pub quote_sig: Vec<u8>,
    pub bundle: Vec<u8>,
}

/// Width of the canonical message, repeated here so this crate stays free of
/// a dependency on `attest-envelope`; a test pins it to the envelope's value.
pub const RECEIPT_MSG_LEN: usize = 93;

impl Receipt {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.msg.len() != RECEIPT_MSG_LEN {
            return Err(format!("receipt: message is {} bytes, expected {RECEIPT_MSG_LEN}", self.msg.len()));
        }
        for (name, v, max) in [
            ("quote attest", &self.quote_attest, ATTEST_MAX),
            ("quote signature", &self.quote_sig, SIG_MAX),
            ("bundle", &self.bundle, BUNDLE_MAX),
        ] {
            if v.is_empty() || v.len() > max {
                return Err(format!("receipt: {name} is {} bytes", v.len()));
            }
        }
        let mut out = Vec::new();
        out.extend_from_slice(RECEIPT_MAGIC);
        out.push(RECEIPT_VERSION);
        for v in [&self.msg, &self.quote_attest, &self.quote_sig, &self.bundle] {
            out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            out.extend_from_slice(v);
        }
        Ok(out)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 5 || &bytes[..4] != RECEIPT_MAGIC {
            return Err("receipt: missing TQSR magic".into());
        }
        if bytes[4] != RECEIPT_VERSION {
            return Err(format!("receipt: unknown version 0x{:02x}", bytes[4]));
        }
        let mut r = Reader::new(&bytes[5..]);
        let msg = r.take32(RECEIPT_MSG_LEN, "receipt message")?.to_vec();
        if msg.len() != RECEIPT_MSG_LEN {
            return Err(format!("receipt: message is {} bytes, expected {RECEIPT_MSG_LEN}", msg.len()));
        }
        let quote_attest = r.take32(ATTEST_MAX, "receipt quote attest")?.to_vec();
        let quote_sig = r.take32(SIG_MAX, "receipt quote signature")?.to_vec();
        let bundle = r.take32(BUNDLE_MAX, "receipt bundle")?.to_vec();
        r.finish("receipt")?;
        Ok(Receipt { msg, quote_attest, quote_sig, bundle })
    }
}

/// Length-prefixed reader: every length is checked against the bound and
/// against the bytes left before anything is sliced; empty parts are refused.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }

    fn take(&mut self, n: usize, max: usize, what: &str) -> Result<&'a [u8], String> {
        if n == 0 || n > max {
            return Err(format!("{what}: length {n} outside 1..={max}"));
        }
        if n > self.b.len() {
            return Err(format!("{what}: length {n} exceeds the {} bytes left", self.b.len()));
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }

    fn take16(&mut self, max: usize, what: &str) -> Result<&'a [u8], String> {
        if self.b.len() < 2 {
            return Err(format!("{what}: truncated length"));
        }
        let n = u16::from_be_bytes([self.b[0], self.b[1]]) as usize;
        self.b = &self.b[2..];
        self.take(n, max, what)
    }

    fn take32(&mut self, max: usize, what: &str) -> Result<&'a [u8], String> {
        if self.b.len() < 4 {
            return Err(format!("{what}: truncated length"));
        }
        let n = u32::from_be_bytes([self.b[0], self.b[1], self.b[2], self.b[3]]) as usize;
        self.b = &self.b[4..];
        self.take(n, max, what)
    }

    fn finish(&self, what: &str) -> Result<(), String> {
        if !self.b.is_empty() {
            return Err(format!("{what}: {} trailing bytes", self.b.len()));
        }
        Ok(())
    }
}

/// `TPM_GENERATED_VALUE`: every TPM-produced attestation starts with it.
pub const TPM_GENERATED: u32 = 0xFF54_4347;
/// `TPM_ST_ATTEST_NV`.
pub const ST_ATTEST_NV: u16 = 0x8014;

/// The fields of a `TPMS_ATTEST` of type `TPM_ST_ATTEST_NV` that a check of
/// the stop counter needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvCertifyInfo {
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub index_name: Vec<u8>,
    pub offset: u16,
    pub contents: Vec<u8>,
}

/// Parse a `TPMS_ATTEST` produced by `TPM2_NV_Certify` (TPM 2.0 Part 2,
/// 10.12.8 and 10.12.13):
///
/// ```text
/// magic(4) || type(2) || qualifiedSigner(TPM2B) || extraData(TPM2B)
///          || clockInfo(17) || firmwareVersion(8)
///          || indexName(TPM2B) || offset(2) || nvContents(TPM2B)
/// ```
///
/// Exact: every byte is consumed or the structure is refused. The signature
/// over it is not checked here; that needs the AK and is the verifier's.
pub fn parse_nv_certify_info(attest: &[u8]) -> Result<NvCertifyInfo, String> {
    let mut r = Be::new(attest);
    if r.u32()? != TPM_GENERATED {
        return Err("nv certify: not a TPM-generated structure".into());
    }
    let t = r.u16()?;
    if t != ST_ATTEST_NV {
        return Err(format!("nv certify: type 0x{t:04x}, expected 0x{ST_ATTEST_NV:04x}"));
    }
    let qualified_signer = r.tpm2b()?.to_vec();
    let extra_data = r.tpm2b()?.to_vec();
    r.skip(17)?; // clockInfo: clock(8) resetCount(4) restartCount(4) safe(1)
    r.skip(8)?; // firmwareVersion
    let index_name = r.tpm2b()?.to_vec();
    let offset = r.u16()?;
    let contents = r.tpm2b()?.to_vec();
    if !r.b.is_empty() {
        return Err(format!("nv certify: {} trailing bytes", r.b.len()));
    }
    Ok(NvCertifyInfo { qualified_signer, extra_data, index_name, offset, contents })
}

/// Check that a certify says what the record says: bound to `qualifying`,
/// over the expected index, the whole 8-byte counter from offset 0, at the
/// record's epoch. Used by the service before it hands out a receipt, and
/// by any verifier.
pub fn check_counter_certify(
    attest: &[u8],
    qualifying: &[u8; 32],
    index_name: &[u8],
    stop_epoch: u64,
) -> Result<(), String> {
    let i = parse_nv_certify_info(attest)?;
    if i.extra_data != qualifying {
        return Err("nv certify: bound to a different record or nonce".into());
    }
    if i.index_name != index_name {
        return Err("nv certify: certifies a different NV index".into());
    }
    if i.offset != 0 || i.contents.len() != 8 {
        return Err(format!(
            "nv certify: covers {} bytes at offset {}, expected 8 at 0",
            i.contents.len(),
            i.offset
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&i.contents);
    let v = u64::from_be_bytes(b);
    if v != stop_epoch {
        return Err(format!("nv certify: the TPM read {v}, the record says {stop_epoch}"));
    }
    Ok(())
}

/// Big-endian reader for TPM structures.
struct Be<'a> {
    b: &'a [u8],
}

impl<'a> Be<'a> {
    fn new(b: &'a [u8]) -> Self {
        Be { b }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.b.len() {
            return Err(format!("nv certify: needs {n} bytes, {} left", self.b.len()));
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.take(n).map(|_| ())
    }
    fn u16(&mut self) -> Result<u16, String> {
        let h = self.take(2)?;
        Ok(u16::from_be_bytes([h[0], h[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let h = self.take(4)?;
        Ok(u32::from_be_bytes([h[0], h[1], h[2], h[3]]))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Build a `TPM_ST_ATTEST_NV` structure the way a TPM lays it out. For tests
/// on both sides of the format; a real one comes from the TPM.
#[doc(hidden)]
pub fn build_nv_certify_info_for_tests(info: &NvCertifyInfo) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&TPM_GENERATED.to_be_bytes());
    o.extend_from_slice(&ST_ATTEST_NV.to_be_bytes());
    for part in [&info.qualified_signer, &info.extra_data] {
        o.extend_from_slice(&(part.len() as u16).to_be_bytes());
        o.extend_from_slice(part);
    }
    o.extend_from_slice(&[0x11; 17]);
    o.extend_from_slice(&[0x22; 8]);
    o.extend_from_slice(&(info.index_name.len() as u16).to_be_bytes());
    o.extend_from_slice(&info.index_name);
    o.extend_from_slice(&info.offset.to_be_bytes());
    o.extend_from_slice(&(info.contents.len() as u16).to_be_bytes());
    o.extend_from_slice(&info.contents);
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(state: State) -> StopRecord {
        StopRecord { kind: Kind::Status, state, stop_epoch: 7, policy_digest: [0x11; 32] }
    }

    fn refusal() -> StopRecord {
        StopRecord {
            kind: Kind::Refusal { request_digest: [0x22; 32] },
            state: State::Stopped,
            stop_epoch: 7,
            policy_digest: [0x11; 32],
        }
    }

    #[test]
    fn status_round_trips_at_exact_length() {
        for s in [State::Running, State::Stopped] {
            let b = status(s).encode().unwrap();
            assert_eq!(b.len(), STATUS_LEN);
            assert_eq!(StopRecord::parse(&b).unwrap(), status(s));
        }
    }

    #[test]
    fn refusal_round_trips_at_exact_length() {
        let b = refusal().encode().unwrap();
        assert_eq!(b.len(), REFUSAL_LEN);
        assert_eq!(StopRecord::parse(&b).unwrap(), refusal());
    }

    #[test]
    fn layout_is_pinned() {
        // Offsets are wire format: pin them so a refactor cannot move a field.
        let b = refusal().encode().unwrap();
        assert_eq!(&b[..4], &[STOP_RECORD_VERSION, 0x01, 0x02, 0x00]);
        assert_eq!(&b[4..12], &7u64.to_be_bytes());
        assert_eq!(&b[12..44], &[0x11; 32]);
        assert_eq!(&b[44..76], &[0x22; 32]);
    }

    #[test]
    fn length_is_exact_not_a_minimum() {
        let mut b = status(State::Stopped).encode().unwrap();
        b.push(0);
        assert!(StopRecord::parse(&b).is_err());
        let mut r = refusal().encode().unwrap();
        r.pop();
        assert!(StopRecord::parse(&r).is_err());
        assert!(StopRecord::parse(&r[..HEAD_LEN - 1]).is_err());
    }

    #[test]
    fn zero_fill_and_erased_flash_do_not_parse() {
        for len in [STATUS_LEN, REFUSAL_LEN] {
            assert!(StopRecord::parse(&vec![0x00; len]).is_err());
            assert!(StopRecord::parse(&vec![0xFF; len]).is_err());
        }
    }

    #[test]
    fn forbidden_kind_and_state_bytes_are_refused() {
        for bad in [0x00u8, 0xFF, 0x03] {
            let mut b = status(State::Stopped).encode().unwrap();
            b[1] = bad;
            assert!(StopRecord::parse(&b).is_err(), "kind 0x{bad:02x}");
            let mut b = status(State::Stopped).encode().unwrap();
            b[2] = bad;
            assert!(StopRecord::parse(&b).is_err(), "state 0x{bad:02x}");
        }
    }

    #[test]
    fn unknown_version_is_refused() {
        let mut b = status(State::Stopped).encode().unwrap();
        b[0] = 0x02;
        assert!(StopRecord::parse(&b).is_err());
    }

    #[test]
    fn reserved_byte_must_be_zero() {
        let mut b = status(State::Stopped).encode().unwrap();
        b[3] = 0x01;
        assert!(StopRecord::parse(&b).is_err());
    }

    #[test]
    fn refusal_while_running_is_refused_both_ways() {
        let r = StopRecord { state: State::Running, ..refusal() };
        assert!(r.encode().is_err());
        let mut b = refusal().encode().unwrap();
        b[2] = 0x01;
        assert!(StopRecord::parse(&b).is_err());
    }

    #[test]
    fn status_and_refusal_cannot_be_swapped_by_the_kind_byte() {
        // A refusal with its kind byte flipped is the wrong length for a
        // status, and the reverse: one byte cannot turn one into the other.
        let mut r = refusal().encode().unwrap();
        r[1] = 0x02;
        assert!(StopRecord::parse(&r).is_err());
        let mut s = status(State::Stopped).encode().unwrap();
        s[1] = 0x01;
        assert!(StopRecord::parse(&s).is_err());
    }

    #[test]
    fn nonce_length_bounds() {
        assert!(check_nonce(&[0u8; NONCE_MIN - 1]).is_err());
        assert!(check_nonce(&[0u8; NONCE_MIN]).is_ok());
        assert!(check_nonce(&[0u8; NONCE_MAX]).is_ok());
        assert!(check_nonce(&[0u8; NONCE_MAX + 1]).is_err());
    }

    #[test]
    fn digests_are_domain_separated_and_input_sensitive() {
        let a = request_digest("POST", "/mcp", b"{}");
        assert_ne!(a, request_digest("POST", "/mcp", b"{ }"));
        assert_ne!(a, request_digest("GET", "/mcp", b"{}"));
        // The separator keeps method and path from sliding into each other.
        assert_ne!(request_digest("PO", "ST/mcp", b""), request_digest("POST", "/mcp", b""));
        let rec = status(State::Stopped).encode().unwrap();
        assert_ne!(certify_qualifying(&rec, b""), certify_qualifying(&rec, &[0u8; 16]));
        assert_ne!(certify_qualifying(&rec, b""), request_digest("", "", &rec));
    }

    #[test]
    fn nv_certify_round_trips_and_refuses_bad_lengths() {
        let c = NvCertify { attest: vec![1; 100], sig: vec![2; 64] };
        let b = c.encode().unwrap();
        assert_eq!(NvCertify::parse(&b).unwrap(), c);
        let mut t = b.clone();
        t.push(0);
        assert!(NvCertify::parse(&t).is_err(), "trailing byte");
        assert!(NvCertify::parse(&b[..b.len() - 1]).is_err(), "truncated");
        assert!(NvCertify::parse(&[0, 0, 0, 0]).is_err(), "empty parts");
        assert!(NvCertify { attest: vec![], sig: vec![1] }.encode().is_err());
    }

    fn receipt() -> Receipt {
        Receipt {
            msg: vec![7; RECEIPT_MSG_LEN],
            quote_attest: vec![1; 120],
            quote_sig: vec![2; 64],
            bundle: vec![3; 300],
        }
    }

    #[test]
    fn receipt_round_trips() {
        let b = receipt().encode().unwrap();
        assert_eq!(&b[..5], b"TQSR\x01");
        assert_eq!(Receipt::parse(&b).unwrap(), receipt());
    }

    #[test]
    fn receipt_refuses_wrong_magic_version_length_and_trailing() {
        let b = receipt().encode().unwrap();
        let mut m = b.clone();
        m[0] = b'X';
        assert!(Receipt::parse(&m).is_err());
        let mut v = b.clone();
        v[4] = 0x02;
        assert!(Receipt::parse(&v).is_err());
        let mut t = b.clone();
        t.push(0);
        assert!(Receipt::parse(&t).is_err());
        assert!(Receipt::parse(&b[..b.len() - 1]).is_err());
        assert!(Receipt { msg: vec![0; 92], ..receipt() }.encode().is_err());
        // A length field larger than the bound is refused before slicing.
        let mut big = b.clone();
        big[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Receipt::parse(&big).is_err());
    }

    fn info(epoch: u64, qd: [u8; 32]) -> NvCertifyInfo {
        NvCertifyInfo {
            qualified_signer: vec![0x00, 0x0b, 0xAA, 0xBB],
            extra_data: qd.to_vec(),
            index_name: vec![0x00, 0x0b, 0x01, 0x02],
            offset: 0,
            contents: epoch.to_be_bytes().to_vec(),
        }
    }

    #[test]
    fn nv_certify_info_round_trips() {
        let i = info(5, [7; 32]);
        let b = build_nv_certify_info_for_tests(&i);
        assert_eq!(parse_nv_certify_info(&b).unwrap(), i);
    }

    #[test]
    fn nv_certify_info_refuses_wrong_magic_type_trailing_truncated() {
        let b = build_nv_certify_info_for_tests(&info(5, [7; 32]));
        let mut m = b.clone();
        m[0] = 0;
        assert!(parse_nv_certify_info(&m).is_err());
        let mut t = b.clone();
        t[4..6].copy_from_slice(&0x8018u16.to_be_bytes()); // a quote, not an NV certify
        assert!(parse_nv_certify_info(&t).is_err());
        let mut x = b.clone();
        x.push(0);
        assert!(parse_nv_certify_info(&x).is_err());
        assert!(parse_nv_certify_info(&b[..b.len() - 1]).is_err());
    }

    #[test]
    fn counter_certify_must_match_every_field() {
        let qd = [7u8; 32];
        let name = [0x00, 0x0b, 0x01, 0x02];
        let ok = build_nv_certify_info_for_tests(&info(5, qd));
        assert!(check_counter_certify(&ok, &qd, &name, 5).is_ok());
        assert!(check_counter_certify(&ok, &qd, &name, 6).is_err(), "value moved");
        assert!(check_counter_certify(&ok, &[8; 32], &name, 5).is_err(), "other record");
        assert!(check_counter_certify(&ok, &qd, &[0x00, 0x0b, 0x09], 5).is_err(), "other index");
        let off = build_nv_certify_info_for_tests(&NvCertifyInfo { offset: 1, ..info(5, qd) });
        assert!(check_counter_certify(&off, &qd, &name, 5).is_err(), "offset");
        let short = build_nv_certify_info_for_tests(&NvCertifyInfo { contents: vec![5], ..info(5, qd) });
        assert!(check_counter_certify(&short, &qd, &name, 5).is_err(), "partial read");
    }

    #[test]
    fn stop_quote_qualifying_differs_from_a_plain_digest() {
        let m = [3u8; RECEIPT_MSG_LEN];
        let plain: [u8; 32] = Sha256::digest(m).into();
        assert_ne!(stop_quote_qualifying(&m), plain);
    }
}
