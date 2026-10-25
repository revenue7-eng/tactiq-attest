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
}
