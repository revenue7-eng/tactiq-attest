# Envelopes you can check yourself

Twenty-one attestation envelopes of `tactiq-agent` from a Radxa ROCK 5A bench
board, `TACTIQ-BENCH-001` (Infineon SLB9670 TPM), taken on 18 November 2026,
and everything needed to check them away from the device, offline, with the
open tool in this repository.

The board was running an EV charging station stack (EVerest) on a TactiQ OS
development image, slot B. Each envelope was sent from the station over
OCPP 2.0.1 `DataTransfer` to a test CSMS on the bench and appraised there by a
verifier outside the station. The files here are those envelopes, as received.

## Files

| File | What it is |
|---|---|
| `envelopes/<counter>.msg` | The 93-byte signed message: device id, counter, PCR selection, PCR digest, evidence hash. |
| `envelopes/<counter>.attest` | The `TPMS_ATTEST` of the TPM quote over PCR 0 to 9, qualifying data SHA-256 of the message. |
| `envelopes/<counter>.sig` | The AK signature over `.attest`. |
| `TACTIQ-BENCH-001.ak.pub` | The board's attestation key as `TPM2B_PUBLIC`, from the verifier's trust directory of the run. |
| `TACTIQ-BENCH-001.pcr-ref.json` | The expected PCR values of the image that answered (`tactiq-pcr-reference/2`, made by `mk-pcr-reference.py`). PCR 1 differs per slot. |
| `tampered/137690611729.*` | The first envelope with one byte of `.attest` flipped. It must be refused. |
| `SHA256SUMS` | Sums of every file above. |

No envelope carries an evidence bundle (`.tag`); the signed evidence hash is
the hash of an empty bundle, and the check verifies that.

## Check them

From the root of this repository:

```
cargo build --release --manifest-path tools/envelope-verify/Cargo.toml
```

```
cd docs/envelope-sample
```

```
sha256sum -c SHA256SUMS
```

```
for m in envelopes/*.msg; do s=${m%.msg}; printf '%s  ' "$(basename $s)"; ../../tools/envelope-verify/target/release/tactiq-envelope-verify check "$s" --ak TACTIQ-BENCH-001.ak.pub --device TACTIQ-BENCH-001 --pcr-ref TACTIQ-BENCH-001.pcr-ref.json --slot B | grep VERDICT; done
```

Expected: `VERDICT     ACCEPT` on each of the 21 lines.

```
../../tools/envelope-verify/target/release/tactiq-envelope-verify check tampered/137690611729 --ak TACTIQ-BENCH-001.ak.pub --device TACTIQ-BENCH-001 --pcr-ref TACTIQ-BENCH-001.pcr-ref.json --slot B
```

Expected: `refused at  signature, quote and bundle checks: signature verification failed`
and `VERDICT     REJECT SignatureFail`.

Both results were obtained on 18 November 2026 with the tool as merged in
`da96af0`.

## What an ACCEPT here says

Each envelope was signed through a TPM quote under this AK; the quote commits
to the message; the message's PCR digest is the quoted one; and the quoted
PCR 0 to 9 are those the reference gives for slot B.

## What it does not say

- That an envelope is the board's latest. Freshness needs the highest counter
  already accepted from the device. That is state a verifier keeps over time,
  and this stateless check does not have it. The counters here only increase,
  which you can read in the file names, but the tool does not judge that.
- That the AK belongs to this board. The key was taken from the verifier's
  trust directory of the run, not from a signed registration record. Checked
  against itself, it proves only that the envelopes and the key go together.
  `tools/registrar` verifies an AK against the device's signed registration
  record.
- That the image is a release. It is a development image, signed with the
  development FIT key (`fit_key_name_hint`: `dev-fit`); the development keys of
  tactiq-os are public on purpose.
- Anything about the station after boot. The PCRs cover the boot chain up to
  the kernel, its devicetree and the dm-verity root hash in its command line;
  runtime behaviour is outside them.

## What the image was built from

- TactiQ OS, a development build, with its development keys.
- `meta-everest` of the EVerest project, at tag `2026.10.0-rc2`
  (github.com/EVerest/EVerest).
- `meta-tactiq-everest-demo`, our layer for this bench: the station's
  configuration and the module that sends envelopes over OCPP
  `DataTransfer`. It is not published, so the image cannot be rebuilt from
  public sources today. What can be repeated is the check of the envelopes
  above, and the recomputation of the reference from its inputs.

The reference records the digests of its inputs (`inputs.fitImage`,
`inputs.u-boot.itb`) and the command that recomputes it from those files
(`recompute`). The envelopes do not depend on this repository: the format is
`attest-envelope`, and any implementation of the same check should reach the
same verdicts.
