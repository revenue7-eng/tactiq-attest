# tactiq-attest

The device side of TactiQ attestation: the canonical envelope format, and the
agent that produces it from a TPM.

```
device_id(16) || counter_be(8) || pcr_selection(5) || pcr_hash(32) || evidence_hash(32)  = 93 bytes
```

The TPM quotes the selected PCRs with a restricted ECDSA P-256 attestation key
(AK), and the quote's qualifying data is SHA-256 of this message. The verifier
checks the AK signature over the quote, then that the quote commits to the
message and that the TPM's own PCR digest equals `pcr_hash`. Each cycle writes
`<stem>.msg`, `<stem>.attest` (the quote) and `<stem>.sig` (over `.attest`).
The verifier trusts the AK by its public area; binding that AK to the TPM's
endorsement key is a separate step and not part of this format.

Freshness comes from a TPM NV monotonic counter, not from a server nonce, a
clock, or a network round trip, which is what lets a device attest after
months offline.

The message is a fixed 93 bytes and stays 93 bytes however much evidence
the device collected, because what rides in it is a digest of the evidence
bundle rather than the bundle. The parser enforces that length exactly, not as
a minimum.

## What is here

| Crate | What it does |
|---|---|
| `attest-envelope` | The wire format: the signed message, and the tag/len container for the evidence bundle it commits to. Parse, build, encode the PCR selection. No state, no I/O, no trust decision. |
| `attest-stop` | Formats of the stop service: the stop record (tag `0x0004`), the verifier nonce (`0x0005`), the NV certify section (`0x0006`) with a parser for the TPM's `TPM_ST_ATTEST_NV` structure, and the receipt container. Parse, build and check, exact lengths, no state. |
| `attest-tpm` | Every TPM call the device binaries make, in one crate. Shells out to `tpm2-tools` today. |
| `prover` | `tactiq-agent`: provisions an identity, then produces one signed envelope per cycle. |
| `stop` | `tactiq-stop`: the agent stop service. Answers agentgateway's `extAuthz` before every tool call; the stop state is the parity of a TPM NV counter, and every refusal carries a receipt with the AK quote over the boot PCRs and the TPM's own `NV_Certify` of that counter, checked on the device before it is handed out. A stop is lifted only by the operator's release, a record naming the device and the next epoch, signed with the operator's key (ECDSA P-256, `openssl dgst -sha256 -sign`), whose public half is on the device's dm-verity root; stopping needs nothing. Not yet closed: the AK is shared with the agent, and a release image has no operator channel. See the service's own documentation. |
| `tools/stop-verify` | `tactiq-stop-verify`: the check of a stop receipt away from the device, offline. `nonce` draws a challenge; `check` verifies a receipt from `tactiq-stop status <nonce>` (or a 403 body) under the device's registered AK, against the PCR reference of the accepted build: both TPM signatures, the binding of quote, record, certify and nonce, the stop counter's name computed from its definition. It says whether the agent is stopped and on whose word: an odd counter is the TPM's, an even one is the stop service's finding on the operator's release. The check is `attest_appraise::verify_stop_receipt`, stateless; the tool reads files and prints. Its own workspace, like the registrar. |

## The evidence bundle

`evidence_hash` is SHA-256 over a bundle of sections, each framed as
`tag(u16, big-endian) || len(u32, big-endian) || body`. Assigned tags are
`0x0001` TPM quote, `0x0002` GPU attestation, `0x0003` CPU TEE, `0x0004` agent
stop state, `0x0005` verifier nonce and `0x0006` TPM NV certify (bodies
defined in `attest-stop`), with
`0xFF00`-`0xFFFE` reserved for private use.

Four properties of that container are load-bearing rather than stylistic:

`0x0000` and `0xFFFF` are permanently forbidden. A zero-filled buffer would
otherwise parse as a legitimate-looking empty section, and erased NOR flash
reads back all ones, which is the same failure from the other direction. Both
must refuse rather than pass silently.

A tag a verifier does not know parses as a section and is carried through. The
space is extensible by construction, so adding a new evidence kind does not
break an older verifier.

Duplicate tags are legal on the wire. Two TPMs on one board is a real
configuration, not an error to reject in the codec.

A section's claimed `len` is validated against the bytes actually remaining
before anything is read, and is never used as an allocation size.

The digest is taken over the bundle bytes exactly as they were transported. No
canonicalisation, so section order is part of what is signed.

## What is not here

The verifier. Signature checking, the anti-replay high-water mark, the durable
write, the reference-value appraisal and the trust store are a separate,
closed component that runs in the Custinel appliance. Which tags a verifier
requires, and how a tag maps to an evidence kind, are its decisions, not the
codec's.

That split is deliberate. The envelope has to exist on both sides, and the
agent ships on every device, so the format is recoverable from a binary or from
the wire no matter what this repository says. Keeping it closed would buy
nothing and cost the ability to audit what runs on your own hardware. The
verifier never leaves the appliance, so it stays where it is.

## Design notes worth reading before changing anything

**The signing key is not sealed to a PCR policy.** A device whose state has
changed must still be able to sign. If it could not, the verifier would see
silence, indistinguishable from a device that is powered off, instead of a
signed attestation of a state it does not recognise. The verifier draws a hard
line between "attested something we have not enrolled" and "signature did not
verify", and quarantines on one while alarming on the other. A sealed signing
key collapses that distinction. See `attest-tpm/src/lib.rs`.

**Identity and key live and die together.** The device id sits next to the
public key in `/data/tactiq/keys`, not in the image: the same image is flashed
to every unit, so an identity carried there would be identical fleet-wide. The
verifier maps device id to public key, so if one were regenerated without the
other, a routine provisioning desync would arrive at the verifier looking
exactly like a forgery. The agent therefore refuses to run on a partial state
rather than repairing it. See `prover/src/state.rs`.

**The counter value is taken before the measurement.** A crash in between
burns a counter value, which is harmless, because the verifier requires
strictly greater, not consecutive. The reverse order would let two envelopes
describe different states under one counter value. The TPM counter itself
advances once per agent start, as an epoch, not once per envelope (DDR-006).

**The envelope is built by `attest-envelope`, never by hand.** Prover and
verifier share one codec because it is one crate. Earlier design documents in
this project described the envelope as `device_id + counter + pcr_hash +
timestamp` signed with Ed25519; neither half was true of the code. A shared
codec makes that class of drift impossible rather than merely unlikely.

## TPM access

`attest-tpm` shells out to `tpm2-tools`. This is a deliberate first
step, not the end state: the command sequence matches the harness that
validated the protocol, and it behaves identically against swtpm and a discrete
chip, so the agent could be finished before hardware arrived.

Consequence to be aware of: while this is in use, an image shipping the agent
needs `tpm2-tools`, not just the `libtss2` runtime. Every TPM call lives in that
one crate so that swapping to `tss-esapi`, which removes the dependency, touches
nothing else.

## Building

```sh
cargo build --release
cargo test
```

The agent needs a TPM. For development, swtpm works:

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/tpm \
  --ctrl type=tcp,port=2321 --server type=tcp,port=2320 \
  --flags not-need-init,startup-clear --daemon
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2320"

tactiq-agent provision device-A
tactiq-agent attest
```

End-to-end harnesses that judge the agent's output against a verifier live with
the verifier, since they need both sides.

## Status

Alpha. Exercised against a discrete TPM (Infineon SLB9670 over SPI) as well as
swtpm. Two properties remain unproven and require a deliberate test: that the
NV counter cannot be rolled back across a power cycle, and that the private key
is genuinely non-exportable. Running on a discrete chip makes them testable,
which a software TPM keeping its state in a file cannot; neither has been
measured.

## License

Apache-2.0.
