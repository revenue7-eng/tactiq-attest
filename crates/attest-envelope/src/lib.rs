//! attest-envelope — the canonical attestation envelope, and nothing else.
//!
//! ```text
//! device_id(16) || counter_be(8) || pcr_selection(5) || pcr_hash(32) || evidence_hash(32)  = 93 bytes
//! ```
//!
//! Why this is its own crate
//! -------------------------
//! The envelope has to exist on both sides of the protocol: the prover builds
//! it, the verifier parses it. Everything else in `attest-core` — the trust
//! store, the high-water mark, the durable write — runs only in the appliance.
//!
//! Those two halves have different disclosure profiles. The prover ships on
//! every customer device, so the wire format is recoverable from the binary or
//! from the wire regardless of what the repository says; treating it as secret
//! buys nothing. The verifier does not ship, and can stay closed. Splitting the
//! crate along that line lets the device-side build be reproducible from
//! sources an auditor can obtain, which is what `LAYERS.lock` in tactiq-os
//! claims of every other build input, without opening the verifier.
//!
//! The split costs nothing in safety: prover and verifier still share one
//! codec, byte for byte, because it is literally the same crate. A duplicated
//! codec is the failure this arrangement exists to prevent — the earlier
//! documents described this envelope as `device_id + counter + pcr_hash +
//! timestamp` signed with Ed25519, and neither half was true of the code.
//!
//! This crate holds no state, performs no I/O, and makes no trust decision. It
//! is pure serialisation over bytes.
//!
//! The evidence field (§8 item 1, DDR-002 decision 5 boundary D)
//! ------------------------------------------------------------
//! `evidence_hash` is `SHA-256` over the evidence bundle that travels alongside
//! the envelope. Only the *digest* rides inside the signed area; the bundle
//! itself does not, so the signed message keeps a fixed width and this crate
//! keeps its exact-length parser.
//!
//! Since decision 6 (§8 item 5) this crate also knows the bundle's *framing* —
//! the tag/len section container defined below — but still not its *meaning*.
//! Which tags a verifier requires, how tags map to evidence kinds, and how a
//! section body is appraised belong to gate 3 in `verifier-rats` (§8 items
//! 5/6). Binding and framing are wire-format concerns; interpretation is not.
//!
//! `evidence_digest` is taken over the framed bundle bytes exactly as
//! transported. There is no canonical re-encoding: two bundles that differ in
//! section order or in duplicate sections are different bundles with different
//! digests, and that is intended (decision 6: no canonicalisation).
//!
//! There is no "no evidence" sentinel. A device with no sub-attesters has an
//! empty bundle, and the digest of an empty bundle is a perfectly ordinary
//! digest. That keeps the field total: the verifier always hashes what it was
//! handed and always compares, with no special case to forget.

use sha2::{Digest, Sha256};

pub const DEVICE_ID_LEN: usize = 16;
pub const PCR_HASH_LEN: usize = 32;
pub const COUNTER_LEN: usize = 8;

/// PCR-selection, canonical opaque encoding (mirrors TPMS_PCR_SELECTION):
///   alg_id (u16, big-endian) || pcr_bitmap (3 bytes, TPM bit order: PCR n -> byte n/8, bit n%8)
/// e.g. sha256 over PCRs 0..7  =>  00 0B FF 00 00.
///
/// Nothing here interprets these bytes. They are covered by the signature
/// (gate 1) and handed downstream opaque. Interpretation — comparison against
/// the reference set's expected selection, BEFORE the digest, boundary A of
/// DDR-001 — belongs to gate 3 in verifier-rats.
pub const PCR_SELECTION_LEN: usize = 5;

/// SHA-256 over the evidence bundle. Width is the digest size, not a policy.
pub const EVIDENCE_HASH_LEN: usize = 32;

/// Canonical signed message =
///   device_id(16) || counter_be(8) || pcr_selection(5) || pcr_hash(32) || evidence_hash(32)
pub const MSG_LEN: usize =
    DEVICE_ID_LEN + COUNTER_LEN + PCR_SELECTION_LEN + PCR_HASH_LEN + EVIDENCE_HASH_LEN;

/// Digest of an evidence bundle, as committed to by the signed envelope.
///
/// One function, called by both sides: the prover to build the field, the
/// verifier to check it. Same reason `build_canonical` takes the digest of
/// `pcr_state` itself instead of trusting the caller — agreement by
/// construction rather than by convention.
pub fn evidence_digest(bundle: &[u8]) -> [u8; EVIDENCE_HASH_LEN] {
    let mut out = [0u8; EVIDENCE_HASH_LEN];
    out.copy_from_slice(&Sha256::digest(bundle));
    out
}

#[derive(Debug, Clone)]
pub struct AttestationMessage {
    pub device_id: [u8; DEVICE_ID_LEN],
    pub counter: u64,
    pub pcr_selection: [u8; PCR_SELECTION_LEN],
    pub pcr_hash: [u8; PCR_HASH_LEN],
    /// SHA-256 of the evidence bundle carried alongside this envelope. Verified
    /// against the bundle in gate 1 (`RejectReason::EvidenceBindingFail`).
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
}

impl AttestationMessage {
    /// Parse the canonical signed bytes. device_id and counter are read FROM the
    /// signed region, so they cannot be altered without breaking the signature.
    ///
    /// The length check is exact, not a minimum: a fixed layout is what keeps
    /// this parser small enough to read in one sitting, which for code inside
    /// the TCB is worth more than extensibility.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != MSG_LEN {
            return Err(format!("bad message length: {} (want {})", bytes.len(), MSG_LEN));
        }
        let mut device_id = [0u8; DEVICE_ID_LEN];
        device_id.copy_from_slice(&bytes[0..DEVICE_ID_LEN]);
        let mut ctr = [0u8; COUNTER_LEN];
        ctr.copy_from_slice(&bytes[DEVICE_ID_LEN..DEVICE_ID_LEN + COUNTER_LEN]);
        let counter = u64::from_be_bytes(ctr); // TPM NV counter is big-endian
        let sel_off = DEVICE_ID_LEN + COUNTER_LEN;
        let mut pcr_selection = [0u8; PCR_SELECTION_LEN];
        pcr_selection.copy_from_slice(&bytes[sel_off..sel_off + PCR_SELECTION_LEN]);
        let hash_off = sel_off + PCR_SELECTION_LEN;
        let mut pcr_hash = [0u8; PCR_HASH_LEN];
        pcr_hash.copy_from_slice(&bytes[hash_off..hash_off + PCR_HASH_LEN]);
        let ev_off = hash_off + PCR_HASH_LEN;
        let mut evidence_hash = [0u8; EVIDENCE_HASH_LEN];
        evidence_hash.copy_from_slice(&bytes[ev_off..]);
        Ok(Self { device_id, counter, pcr_selection, pcr_hash, evidence_hash })
    }

    pub fn device_id_str(&self) -> String {
        device_id_display(&self.device_id)
    }
}

/// The payload gate 3 appraises, extracted from an already signature-verified
/// message. Every field either rode inside the signed area or was verified
/// against it, so none can be altered without breaking gate 1. Deliberately
/// minimal: `counter` is NOT here — freshness is fully adjudicated by gate 2
/// upstream, and carrying it would pre-design for downstream consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedMessage {
    pub device_id: [u8; DEVICE_ID_LEN],
    pub pcr_selection: [u8; PCR_SELECTION_LEN],
    pub pcr_hash: [u8; PCR_HASH_LEN],
    /// The evidence bundle, verbatim, AFTER gate 1 verified it hashes to the
    /// signed `evidence_hash`. The bytes themselves ride here — not the digest,
    /// which has done its job by this point and would be dead weight.
    ///
    /// It lives inside `AttestedMessage`, and therefore inside `Passed` only,
    /// for the same reason `pcr_hash` does: gate 3 must be structurally unable
    /// to appraise a bundle from a rejected message. Handing the bundle to
    /// `finalize` as a separate argument would restore that possibility and make
    /// the invariant disciplinary again (DDR-002, decision 5 boundary D).
    ///
    /// Empty for a device with no sub-attesters — the honest edge-profile state.
    pub evidence: Vec<u8>,
}

/// Render a device_id as a trimmed display string (drops NUL padding).
pub fn device_id_display(id: &[u8; DEVICE_ID_LEN]) -> String {
    String::from_utf8_lossy(id)
        .trim_end_matches('\0')
        .trim_end()
        .to_string()
}

/// Hex form of a device_id, used for on-disk filenames by the verifier's
/// durable store. Kept here with its inverse so the two cannot drift.
pub fn id_to_hex(id: &[u8; DEVICE_ID_LEN]) -> String {
    hex::encode(id)
}

pub fn hex_to_id(s: &str) -> Option<[u8; DEVICE_ID_LEN]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != DEVICE_ID_LEN { return None; }
    let mut id = [0u8; DEVICE_ID_LEN];
    id.copy_from_slice(&bytes);
    Some(id)
}

/// Encode the canonical opaque PCR-selection bytes on the prover side.
/// `alg_id` is the TPM algorithm id (sha256 = 0x000B), `bitmap` is the 3-byte
/// TPM PCR bitmap.
pub fn encode_pcr_selection(alg_id: u16, bitmap: [u8; 3]) -> [u8; PCR_SELECTION_LEN] {
    let a = alg_id.to_be_bytes();
    [a[0], a[1], bitmap[0], bitmap[1], bitmap[2]]
}

/// Build the canonical message. `pcr_state` is the raw selected-PCR contents and
/// `evidence` the raw bundle; both digests are taken here rather than by the
/// caller, so prover and verifier agree on them by construction instead of by
/// convention. Pass an empty slice for a device with no sub-attesters.
pub fn build_canonical(
    device_id: &str,
    counter: u64,
    pcr_selection: &[u8; PCR_SELECTION_LEN],
    pcr_state: &[u8],
    evidence: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MSG_LEN);
    let mut id = [0u8; DEVICE_ID_LEN];
    let b = device_id.as_bytes();
    id[..b.len().min(DEVICE_ID_LEN)].copy_from_slice(&b[..b.len().min(DEVICE_ID_LEN)]);
    out.extend_from_slice(&id);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(pcr_selection);
    let pcr_hash = Sha256::digest(pcr_state);
    out.extend_from_slice(&pcr_hash);
    out.extend_from_slice(&evidence_digest(evidence));
    out
}

// ---------------------------------------------------------------------------
// Evidence bundle container (DDR-002 decision 6, §8 item 5)
// ---------------------------------------------------------------------------
//
// A bundle is a concatenation of sections, each:
//
//     tag (u16, big-endian) || len (u32, big-endian) || body (len bytes)
//
// Tag registry. The space is public and extensible by construction
// (decision 6 boundary B): a tag unknown to a verifier parses fine and is
// appraised as `EvidenceUnrecognized` downstream, never as a parse error.
//
//     0x0000            forbidden, never assigned
//     0x0001            TPM quote
//     0x0002            GPU attestation
//     0x0003            CPU TEE report
//     0x0004..=0xFEFF   unassigned, public registry
//     0xFF00..=0xFFFE   private / experimental, never publicly registered
//     0xFFFF            forbidden, never assigned
//
// The two forbidden values are load-bearing, not decoration. A zeroed buffer
// would otherwise parse as `tag=0, len=0` — a legitimate-looking empty-ish
// bundle — and an empty bundle IS legitimate (boundary A), so zero-fill would
// pass silently. Erased NOR flash reads back 0xFF and is the same failure from
// the other end. Both patterns must die in the parser, as container refusal
// (boundary C), not arrive at appraisal.
//
// Duplicate tags are legal on the wire (two TPMs on one board is a real
// configuration); collapsing them into a set is the verifier's mapping step,
// not the codec's business.
//
// A section's claimed `len` is validated against the bytes actually remaining
// BEFORE anything is read, and is never used as an allocation size — bodies
// are subslices of the input, this parser allocates nothing per section.

/// Fixed section header width: tag(2) + len(4).
pub const SECTION_HEADER_LEN: usize = 6;

/// Assigned tags. The `tag -> EvidenceKind` mapping lives in `verifier-rats`
/// and uses these constants; the numeric values are wire format and live here.
pub const TAG_TPM_QUOTE: u16 = 0x0001;
pub const TAG_GPU_ATTEST: u16 = 0x0002;
pub const TAG_CPU_TEE: u16 = 0x0003;
/// Private/experimental range, inclusive. Never publicly registered.
pub const TAG_PRIVATE_MIN: u16 = 0xFF00;
pub const TAG_PRIVATE_MAX: u16 = 0xFFFE;

/// 0x0000 (zeroed memory) and 0xFFFF (erased flash) are refused in the parser
/// and in the builder, permanently.
pub fn tag_forbidden(tag: u16) -> bool {
    tag == 0x0000 || tag == 0xFFFF
}

/// One parsed section: the tag and its body, borrowed from the bundle bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section<'a> {
    pub tag: u16,
    pub body: &'a [u8],
}

/// Iterator over the sections of a bundle. Yields `Err` once at the first
/// malformation and then fuses: a bundle is either fully parseable or refused,
/// there is no "the valid prefix" (boundary C).
pub struct Sections<'a> {
    rest: &'a [u8],
    offset: usize,
    failed: bool,
}

/// Iterate the sections of `bundle`. An empty bundle yields no sections and no
/// error — the legitimate no-sub-attesters state (boundary A).
pub fn sections(bundle: &[u8]) -> Sections<'_> {
    Sections { rest: bundle, offset: 0, failed: false }
}

impl<'a> Iterator for Sections<'a> {
    type Item = Result<Section<'a>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < SECTION_HEADER_LEN {
            self.failed = true;
            return Some(Err(format!(
                "truncated section header at offset {}: {} byte(s) left, want {}",
                self.offset,
                self.rest.len(),
                SECTION_HEADER_LEN
            )));
        }
        let tag = u16::from_be_bytes([self.rest[0], self.rest[1]]);
        if tag_forbidden(tag) {
            self.failed = true;
            return Some(Err(format!(
                "forbidden tag 0x{tag:04X} at offset {}",
                self.offset
            )));
        }
        let len =
            u32::from_be_bytes([self.rest[2], self.rest[3], self.rest[4], self.rest[5]]) as usize;
        let after_header = &self.rest[SECTION_HEADER_LEN..];
        if len > after_header.len() {
            self.failed = true;
            return Some(Err(format!(
                "section 0x{tag:04X} at offset {} claims {} byte(s), {} remain",
                self.offset,
                len,
                after_header.len()
            )));
        }
        let (body, rest) = after_header.split_at(len);
        self.rest = rest;
        self.offset += SECTION_HEADER_LEN + len;
        Some(Ok(Section { tag, body }))
    }
}

/// Parse a whole bundle atomically: all sections, or the first error and
/// nothing. This is the verifier's entry point — a refused container must not
/// degrade into `presented = []` (boundary C vs boundary A).
pub fn parse_bundle(bundle: &[u8]) -> Result<Vec<Section<'_>>, String> {
    let mut out = Vec::new();
    for s in sections(bundle) {
        out.push(s?);
    }
    Ok(out)
}

/// Build a bundle on the prover side. Rejects what the parser would refuse,
/// so both sides agree by construction — same reason `build_canonical` takes
/// digests itself.
pub fn build_bundle(sections: &[(u16, &[u8])]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for &(tag, body) in sections {
        if tag_forbidden(tag) {
            return Err(format!("forbidden tag 0x{tag:04X}"));
        }
        if body.len() > u32::MAX as usize {
            return Err(format!(
                "section 0x{tag:04X} body of {} bytes exceeds u32 length field",
                body.len()
            ));
        }
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel_sha256_0_7() -> [u8; PCR_SELECTION_LEN] {
        encode_pcr_selection(0x000B, [0xFF, 0x00, 0x00])
    }

    #[test]
    fn message_roundtrip() {
        let sel = sel_sha256_0_7();
        let m = build_canonical("device-A", 42, &sel, b"pcr-state", b"bundle");
        assert_eq!(m.len(), MSG_LEN);
        let parsed = AttestationMessage::parse(&m).unwrap();
        assert_eq!(parsed.counter, 42);
        assert_eq!(parsed.device_id_str(), "device-A");
        assert_eq!(parsed.pcr_selection, sel);
        assert_eq!(parsed.evidence_hash, evidence_digest(b"bundle"));
    }

    #[test]
    fn length_is_exact_not_minimum() {
        let sel = sel_sha256_0_7();
        let mut m = build_canonical("device-A", 1, &sel, b"x", b"");
        assert!(AttestationMessage::parse(&m).is_ok());
        m.push(0);
        assert!(AttestationMessage::parse(&m).is_err());
        m.truncate(MSG_LEN - 1);
        assert!(AttestationMessage::parse(&m).is_err());
    }

    #[test]
    fn empty_bundle_is_an_ordinary_digest_not_a_sentinel() {
        // No "absent" encoding: the empty bundle hashes like any other input, so
        // the verifier's compare has no special case. Guards against anyone
        // later introducing an all-zero sentinel, which a forged bundle could
        // trivially claim.
        let d = evidence_digest(b"");
        assert_ne!(d, [0u8; EVIDENCE_HASH_LEN]);
        let sel = sel_sha256_0_7();
        let m = build_canonical("device-A", 1, &sel, b"x", b"");
        assert_eq!(AttestationMessage::parse(&m).unwrap().evidence_hash, d);
    }

    #[test]
    fn evidence_hash_occupies_the_signed_tail() {
        // The field rides INSIDE the signed area: pin its offset so a layout
        // change cannot silently move it out from under the signature.
        let sel = sel_sha256_0_7();
        let m = build_canonical("device-A", 1, &sel, b"x", b"bundle");
        assert_eq!(&m[MSG_LEN - EVIDENCE_HASH_LEN..], &evidence_digest(b"bundle"));
    }

    // ---- bundle container (decision 6) ----

    #[test]
    fn bundle_roundtrip_preserves_order_and_bytes() {
        let b = build_bundle(&[
            (TAG_TPM_QUOTE, b"quote-bytes".as_slice()),
            (TAG_GPU_ATTEST, b"".as_slice()),
            (TAG_CPU_TEE, b"tee".as_slice()),
        ])
        .unwrap();
        let s = parse_bundle(&b).unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!((s[0].tag, s[0].body), (TAG_TPM_QUOTE, b"quote-bytes".as_slice()));
        assert_eq!((s[1].tag, s[1].body), (TAG_GPU_ATTEST, b"".as_slice()));
        assert_eq!((s[2].tag, s[2].body), (TAG_CPU_TEE, b"tee".as_slice()));
    }

    #[test]
    fn empty_bundle_is_zero_sections_not_an_error() {
        // Boundary A: the no-sub-attesters state is legitimate.
        assert_eq!(parse_bundle(b"").unwrap(), vec![]);
        assert_eq!(sections(b"").count(), 0);
    }

    #[test]
    fn unknown_tags_parse_as_sections() {
        // Boundary B: extensible by construction. Unknown-to-us is not
        // malformed; public-unassigned and private ranges both parse.
        let b = build_bundle(&[(0x0004, b"x".as_slice()), (TAG_PRIVATE_MIN, b"y".as_slice())]).unwrap();
        let s = parse_bundle(&b).unwrap();
        assert_eq!(s[0].tag, 0x0004);
        assert_eq!(s[1].tag, TAG_PRIVATE_MIN);
    }

    #[test]
    fn zeroed_buffer_is_container_refusal_not_empty_bundle() {
        // tag 0x0000 forbidden: a zero-filled buffer must not parse as a
        // pile of empty sections, because empty-ish is legitimate (boundary A)
        // and zero-fill would otherwise pass silently.
        assert!(parse_bundle(&[0u8; 6]).is_err());
        assert!(parse_bundle(&[0u8; 60]).is_err());
    }

    #[test]
    fn erased_flash_buffer_is_container_refusal() {
        // tag 0xFFFF forbidden: erased NOR reads back 0xFF.
        assert!(parse_bundle(&[0xFFu8; 6]).is_err());
        assert!(parse_bundle(&[0xFFu8; 60]).is_err());
    }

    #[test]
    fn truncation_is_refusal_of_the_whole_container() {
        // Boundary C: refused container, not "the valid prefix".
        let b = build_bundle(&[
            (TAG_TPM_QUOTE, b"quote".as_slice()),
            (TAG_CPU_TEE, b"tee".as_slice()),
        ])
        .unwrap();
        assert!(parse_bundle(&b[..b.len() - 1]).is_err()); // body cut
        assert!(parse_bundle(&b[..b.len() - 4]).is_err()); // header cut
    }

    #[test]
    fn overlong_len_fails_against_remaining_bytes_before_any_read() {
        // Boundary F: len is checked against what remains; it is never an
        // allocation size. 0xFFFFFFFF on a tiny buffer must simply refuse.
        let mut b = TAG_TPM_QUOTE.to_be_bytes().to_vec();
        b.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        b.extend_from_slice(b"short");
        let err = parse_bundle(&b).unwrap_err();
        assert!(err.contains("4294967295"), "unexpected error text: {err}");
    }

    #[test]
    fn duplicate_tags_are_legal_on_the_wire() {
        // Boundary E: two TPMs on one board is a real configuration.
        // Collapsing into a set is the verifier's mapping step, not the codec's.
        let b = build_bundle(&[
            (TAG_TPM_QUOTE, b"tpm-0".as_slice()),
            (TAG_TPM_QUOTE, b"tpm-1".as_slice()),
        ])
        .unwrap();
        let s = parse_bundle(&b).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].tag, s[1].tag);
        assert_ne!(s[0].body, s[1].body);
    }

    #[test]
    fn builder_refuses_what_the_parser_refuses() {
        assert!(build_bundle(&[(0x0000, b"".as_slice())]).is_err());
        assert!(build_bundle(&[(0xFFFF, b"".as_slice())]).is_err());
    }

    #[test]
    fn sections_iterator_fuses_after_first_error() {
        // One error, then silence — no resynchronisation on garbage.
        let mut b = build_bundle(&[(TAG_TPM_QUOTE, b"ok".as_slice())]).unwrap();
        b.extend_from_slice(&[0x00, 0x00]); // forbidden tag, then nothing
        let items: Vec<_> = sections(&b).collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
    }

    #[test]
    fn digest_is_over_transported_bytes_no_canonicalisation() {
        // Decision 6: no canonical re-encoding. Order matters, duplicates
        // matter, the digest commits to the bytes as they rode.
        let ab = build_bundle(&[(TAG_TPM_QUOTE, b"a".as_slice()), (TAG_CPU_TEE, b"b".as_slice())]).unwrap();
        let ba = build_bundle(&[(TAG_CPU_TEE, b"b".as_slice()), (TAG_TPM_QUOTE, b"a".as_slice())]).unwrap();
        assert_ne!(evidence_digest(&ab), evidence_digest(&ba));
    }

    #[test]
    fn id_hex_roundtrip() {
        let id = *b"device-A\0\0\0\0\0\0\0\0";
        assert_eq!(hex_to_id(&id_to_hex(&id)), Some(id));
        assert_eq!(hex_to_id("nothex"), None);
        assert_eq!(hex_to_id("00"), None); // wrong width
    }
}
