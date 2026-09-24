//! Gate 1: authenticity and evidence binding (DDR-003, decision 7), with the
//! quote path of envelope v2 (DDR-004).
//!
//! Stateless given the device's trust entry.
//!
//! Two envelope forms, one gate:
//!
//!   * v1: `.msg` signed directly by a legacy key (`TrustEntry::Legacy`). The
//!     PCR claim is whatever the prover assembled; `Binding::SelfSigned`.
//!   * v2: `.msg` committed to by a `TPM2_Quote` from an attestation key
//!     (`TrustEntry::Ak`); the signature is over the `TPMS_ATTEST`, and the
//!     TPM's own `pcrDigest` must equal the message's `pcr_hash`;
//!     `Binding::TpmQuote`.
//!
//! The pairing is fixed by the trust entry, never by what the envelope offers:
//! an AK entry with no quote is refused (DDR-004 decision 5, no downgrade),
//! and a quote under a legacy entry is refused (a key that is not restricted
//! can sign a forged `TPMS_ATTEST`).
//!
//! The output is [`Authenticated`], whose fields are private: the only way to
//! obtain one is to pass this gate. Gate 3 ([`crate::appraise`]) accepts nothing
//! else, so "gate 3 never sees an unbound bundle or an unverified state" holds
//! for every caller, including callers outside this workspace (DDR-003
//! boundary A).

use attest_envelope::tpm::{self, attr, ClockInfo, EccPublic, Quote};
use attest_envelope::{evidence_digest, AttestationMessage, DEVICE_ID_LEN, PCR_HASH_LEN, PCR_SELECTION_LEN};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;

use crate::verdict::Reason;

/// Gate 1 failure classes. A strict subset of [`Reason`]; kept separate so a
/// caller mapping into its own taxonomy can match exhaustively.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gate1Reject {
    /// the message is not the canonical fixed-length layout.
    Malformed,
    /// the key lookup returned no key for this device_id.
    UnknownDevice,
    /// the signature did not decode, or did not verify over the signed area.
    SignatureFail,
    /// the signature verified, but the bundle does not hash to the signed
    /// `evidence_hash`.
    EvidenceBindingFail,
    /// v2: the quote verified under the AK but does not commit to this message
    /// (`extraData`, PCR selection or `pcrDigest`), or the envelope
    /// form does not match the trust entry (DDR-004 decisions 5 and 9).
    QuoteBindingFail,
}

impl From<Gate1Reject> for Reason {
    fn from(r: Gate1Reject) -> Reason {
        match r {
            Gate1Reject::Malformed => Reason::Malformed,
            Gate1Reject::UnknownDevice => Reason::UnknownDevice,
            Gate1Reject::SignatureFail => Reason::SignatureFail,
            Gate1Reject::EvidenceBindingFail => Reason::EvidenceBindingFail,
            Gate1Reject::QuoteBindingFail => Reason::QuoteBindingFail,
        }
    }
}

/// Why gate 1 refused, with enough context for a diagnostic line.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Gate1Error {
    /// `None` when the message did not parse, so no device_id is known.
    pub device_id: Option<[u8; DEVICE_ID_LEN]>,
    pub reason: Gate1Reject,
    pub detail: String,
}

/// An envelope that passed gate 1. Fields are private and there is no public
/// constructor: holding a value of this type is the proof that the signature
/// verified under the device's key and the bundle is bound to it.
///
/// ```compile_fail
/// // Not constructible outside gate 1.
/// let a = attest_appraise::Authenticated {
///     device_id: [0; 16], counter: 0, pcr_selection: [0; 5],
///     pcr_hash: [0; 32], evidence: Vec::new(),
/// };
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Authenticated {
    device_id: [u8; DEVICE_ID_LEN],
    counter: u64,
    pcr_selection: [u8; PCR_SELECTION_LEN],
    pcr_hash: [u8; PCR_HASH_LEN],
    evidence: Vec<u8>,
    binding: Binding,
    quote_meta: Option<QuoteMeta>,
}

/// How the PCR claim in an authenticated envelope was bound (DDR-004
/// decision 6). Any L3 claim requires `TpmQuote`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Binding {
    /// v1: the prover read the PCRs and signed its own message. Proves the
    /// message came from the key holder, not that the TPM measured the values.
    SelfSigned,
    /// v2: the TPM quoted the PCRs under a restricted AK and the quote commits
    /// to this message.
    TpmQuote,
}

/// Quote fields carried verbatim and not appraised in v2 (DDR-004 boundary D).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QuoteMeta {
    pub clock_info: ClockInfo,
    pub firmware_version: u64,
}

/// An attestation key accepted as a v2 trust entry (DDR-004 decision 4).
///
/// The only constructor checks the public area, so holding an `AkKey` means the
/// key is restricted, signs only, never leaves its TPM, and was generated
/// inside it. There is no way to get the verifying key back out: the v1 path
/// cannot be handed an AK by mistake.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AkKey {
    vk: VerifyingKey,
    name: [u8; 34],
}

/// Attributes an AK must carry, and the one it must not.
const AK_REQUIRED: u32 = attr::FIXED_TPM
    | attr::FIXED_PARENT
    | attr::SENSITIVE_DATA_ORIGIN
    | attr::RESTRICTED
    | attr::SIGN;

impl AkKey {
    /// Accept an AK from its `TPM2B_PUBLIC` bytes, as `tpm2_readpublic -o`
    /// writes them. The rule is derived from the public area, never from a
    /// flag on the trust entry.
    pub fn from_tpm2b_public(bytes: &[u8]) -> Result<Self, String> {
        let p = EccPublic::parse_tpm2b(bytes)?;
        if p.attributes & AK_REQUIRED != AK_REQUIRED {
            return Err(format!(
                "not an AK: attributes {:#010x} lack {:#010x} (fixedTPM, fixedParent, sensitiveDataOrigin, restricted, sign)",
                p.attributes,
                AK_REQUIRED & !p.attributes
            ));
        }
        if p.attributes & attr::DECRYPT != 0 {
            return Err("not an AK: key also decrypts".into());
        }
        if p.symmetric != tpm::TPM_ALG_NULL || p.kdf != tpm::TPM_ALG_NULL {
            return Err("not an AK: symmetric or KDF scheme set on a signing key".into());
        }
        if p.scheme != tpm::TPM_ALG_ECDSA || p.scheme_hash != tpm::TPM_ALG_SHA256 {
            return Err(format!(
                "not an AK: scheme {:#06x}/{:#06x}, want ECDSA/SHA-256",
                p.scheme, p.scheme_hash
            ));
        }
        if p.curve != tpm::TPM_ECC_NIST_P256 {
            return Err(format!("not an AK: curve {:#06x}, want NIST P-256", p.curve));
        }
        if p.x.len() > 32 || p.y.len() > 32 {
            return Err("not an AK: point coordinate longer than 32 bytes".into());
        }
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x[32 - p.x.len()..].copy_from_slice(p.x);
        y[32 - p.y.len()..].copy_from_slice(p.y);
        let point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
        let vk = VerifyingKey::from_encoded_point(&point).map_err(|e| format!("not an AK: point: {e}"))?;
        Ok(AkKey { vk, name: p.name()? })
    }

    /// TPM name of the AK, `sha256 alg id || SHA-256(TPMT_PUBLIC)`. Not the
    /// quote's `qualifiedSigner` (that is the qualified name). Used by AK
    /// registration against the EK, which works on the name.
    pub fn name(&self) -> &[u8; 34] { &self.name }
}

/// What the verifier holds for one device.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TrustEntry {
    /// v1 key, trusted as given (PEM). Accepts v1 envelopes only.
    Legacy(VerifyingKey),
    /// v2 attestation key. Accepts v2 envelopes only.
    Ak(AkKey),
}

impl Authenticated {
    pub fn device_id(&self) -> &[u8; DEVICE_ID_LEN] { &self.device_id }
    /// The counter from the signed area, as signed. This crate does not
    /// interpret it.
    pub fn counter(&self) -> u64 { self.counter }
    pub fn pcr_selection(&self) -> &[u8; PCR_SELECTION_LEN] { &self.pcr_selection }
    pub fn pcr_hash(&self) -> &[u8; PCR_HASH_LEN] { &self.pcr_hash }
    /// The bundle, verbatim, verified to hash to the signed `evidence_hash`.
    pub fn evidence(&self) -> &[u8] { &self.evidence }
    /// How the PCR claim was bound. L3 requires [`Binding::TpmQuote`].
    pub fn binding(&self) -> Binding { self.binding }
    /// Quote metadata for v2 envelopes, `None` for v1. Not appraised.
    pub fn quote_meta(&self) -> Option<QuoteMeta> { self.quote_meta }
}

/// Run gate 1 over one v1 envelope under a legacy key.
///
/// Kept for v1 callers; equivalent to [`authenticate_envelope`] with no quote
/// and a [`TrustEntry::Legacy`] lookup. It can never accept an AK, because an
/// [`AkKey`] does not yield a `VerifyingKey`.
pub fn authenticate<F>(
    msg_bytes: &[u8],
    sig_bytes: &[u8],
    evidence: &[u8],
    key_for: F,
) -> Result<Authenticated, Gate1Error>
where
    F: FnOnce(&[u8; DEVICE_ID_LEN]) -> Option<VerifyingKey>,
{
    authenticate_envelope(msg_bytes, None, sig_bytes, evidence, |id| key_for(id).map(TrustEntry::Legacy))
}

/// Run gate 1 over one envelope, v1 (`attest = None`) or v2 (`attest =
/// Some(TPMS_ATTEST bytes)`).
///
/// Order, each step load-bearing (DDR-004 decision 3):
/// 1. parse the fixed layout (device_id is read from the signed area);
/// 2. `entry_for(device_id)`; `None` refuses as `UnknownDevice`;
/// 3. the envelope form must match the entry: AK with quote, legacy without;
/// 4. v2: parse `TPMS_ATTEST` (magic, type quote), refusal is `Malformed`;
/// 5. verify ECDSA P-256 over SHA-256 of the signed object (`.msg` for v1,
///    `.attest` for v2), DER or raw r||s;
/// 6. v2 only, after step 5: `extraData`, selection, `pcrDigest` against the
///    message, refusal is `QuoteBindingFail`;
/// 7. only then compare the bundle digest with the signed `evidence_hash`.
///    Before step 5 holds, every compared field is attacker-chosen and the
///    comparison would prove nothing (DDR-002 decision 5 boundary D, DDR-004
///    boundary A).
pub fn authenticate_envelope<F>(
    msg_bytes: &[u8],
    attest: Option<&[u8]>,
    sig_bytes: &[u8],
    evidence: &[u8],
    entry_for: F,
) -> Result<Authenticated, Gate1Error>
where
    F: FnOnce(&[u8; DEVICE_ID_LEN]) -> Option<TrustEntry>,
{
    let msg = AttestationMessage::parse(msg_bytes).map_err(|e| Gate1Error {
        device_id: None,
        reason: Gate1Reject::Malformed,
        detail: e,
    })?;
    let refuse = |reason, detail: String| Gate1Error { device_id: Some(msg.device_id), reason, detail };

    let entry = entry_for(&msg.device_id).ok_or_else(|| {
        refuse(Gate1Reject::UnknownDevice, "unknown device (not in trust store)".into())
    })?;

    let (vk, signed, quote) = match (&entry, attest) {
        (TrustEntry::Legacy(vk), None) => (*vk, msg_bytes, None),
        (TrustEntry::Ak(ak), Some(a)) => {
            let q = Quote::parse(a).map_err(|e| refuse(Gate1Reject::Malformed, e))?;
            (ak.vk, a, Some(q))
        }
        (TrustEntry::Ak(_), None) => {
            return Err(refuse(
                Gate1Reject::QuoteBindingFail,
                "v1 envelope for an attestation key: an AK is accepted only with a quote (DDR-004 decision 5)".into(),
            ))
        }
        (TrustEntry::Legacy(_), Some(_)) => {
            return Err(refuse(
                Gate1Reject::QuoteBindingFail,
                "quote presented under a legacy key: only a restricted AK makes a quote meaningful".into(),
            ))
        }
    };

    // DER (variable) or fixed r||s (64 bytes): a TPM emits DER; accept either.
    let sig = Signature::from_der(sig_bytes)
        .or_else(|_| Signature::from_slice(sig_bytes))
        .map_err(|e| refuse(Gate1Reject::SignatureFail, format!("malformed signature: {e}")))?;
    // ECDSA over SHA-256(signed), matching `tpm2_sign` / `tpm2_quote -g sha256`.
    if vk.verify(signed, &sig).is_err() {
        return Err(refuse(Gate1Reject::SignatureFail, "signature verification failed".into()));
    }

    let quote_meta = match quote {
        Some(q) => {
            let bind = |d: String| refuse(Gate1Reject::QuoteBindingFail, d);
            // `qualifiedSigner` is NOT compared. It holds the AK's qualified
            // name, a hash over the whole parent chain, which the AK public
            // area alone cannot reproduce. The signature verified under the AK
            // above is what proves the signer.
            let qd = tpm::qualifying_data(msg_bytes).map_err(bind)?;
            if q.extra_data != qd.as_slice() {
                return Err(bind("quote extraData is not SHA-256 of this message".into()));
            }
            let mut banks = q.pcr_banks.iter();
            let (alg, bits) = match (q.pcr_banks.count(), banks.next()) {
                (1, Some(b)) => b,
                (n, _) => return Err(bind(format!("quote covers {n} PCR banks, want exactly 1"))),
            };
            let want_alg = u16::from_be_bytes([msg.pcr_selection[0], msg.pcr_selection[1]]);
            if alg != want_alg || bits != &msg.pcr_selection[2..] {
                return Err(bind("quote PCR selection differs from the message's pcr_selection".into()));
            }
            if q.pcr_digest != msg.pcr_hash.as_slice() {
                return Err(bind("quote pcrDigest differs from the message's pcr_hash".into()));
            }
            Some(QuoteMeta { clock_info: q.clock_info, firmware_version: q.firmware_version })
        }
        None => None,
    };

    if evidence_digest(evidence) != msg.evidence_hash {
        return Err(refuse(
            Gate1Reject::EvidenceBindingFail,
            format!(
                "evidence binding: bundle of {} byte(s) does not hash to the signed digest",
                evidence.len()
            ),
        ));
    }

    Ok(Authenticated {
        device_id: msg.device_id,
        counter: msg.counter,
        pcr_selection: msg.pcr_selection,
        pcr_hash: msg.pcr_hash,
        evidence: evidence.to_vec(),
        binding: if quote_meta.is_some() { Binding::TpmQuote } else { Binding::SelfSigned },
        quote_meta,
    })
}
