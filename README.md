# tactiq-attest

The device side of TactiQ attestation: the canonical envelope format, and the
agent that produces it from a TPM.

```
device_id(16) || counter_be(8) || pcr_selection(5) || pcr_hash(32) || evidence_hash(32)  = 93 bytes
```

Signed with ECDSA P-256 inside the TPM. Freshness comes from a TPM NV monotonic
counter, not from a server nonce, a clock, or a network round trip, which is
what lets a device attest after months offline.

The signed message is a fixed 93 bytes and stays 93 bytes however much evidence
the device collected, because what rides in it is a digest of the evidence
bundle rather than the bundle. The parser enforces that length exactly, not as
a minimum.

## What is here

| Crate | What it does |
|---|---|
| `attest-envelope` | The wire format: the signed message, and the tag/len container for the evidence bundle it commits to. Parse, build, encode the PCR selection. No state, no I/O, no trust decision. |
| `prover` | `tactiq-agent`: provisions an identity, then produces one signed envelope per cycle. |

## The evidence bundle

`evidence_hash` is SHA-256 over a bundle of sections, each framed as
`tag(u16, big-endian) || len(u32, big-endian) || body`. Assigned tags are
`0x0001` TPM quote, `0x0002` GPU attestation, `0x0003` CPU TEE, with
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
key collapses that distinction. See `prover/src/tpm.rs`.

**Identity and key live and die together.** The device id sits next to the
public key in `/data/tactiq/keys`, not in the image: the same image is flashed
to every unit, so an identity carried there would be identical fleet-wide. The
verifier maps device id to public key, so if one were regenerated without the
other, a routine provisioning desync would arrive at the verifier looking
exactly like a forgery. The agent therefore refuses to run on a partial state
rather than repairing it. See `prover/src/state.rs`.

**The counter advances before the measurement is taken.** A crash in between
burns a counter value, which is harmless, because the verifier requires
strictly greater, not consecutive. The reverse order would let two envelopes
describe different states under one counter value.

**The envelope is built by `attest-envelope`, never by hand.** Prover and
verifier share one codec because it is one crate. Earlier design documents in
this project described the envelope as `device_id + counter + pcr_hash +
timestamp` signed with Ed25519; neither half was true of the code. A shared
codec makes that class of drift impossible rather than merely unlikely.

## TPM access

`prover/src/tpm.rs` shells out to `tpm2-tools`. This is a deliberate first
step, not the end state: the command sequence matches the harness that
validated the protocol, and it behaves identically against swtpm and a discrete
chip, so the agent could be finished before hardware arrived.

Consequence to be aware of: while this is in use, an image shipping the agent
needs `tpm2-tools`, not just the `libtss2` runtime. Every TPM call lives in that
one file so that swapping to `tss-esapi`, which removes the dependency, touches
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
