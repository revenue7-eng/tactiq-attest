# A stop receipt you can check yourself

Answers of `tactiq-stop` from a Radxa ROCK 5A bench board, `TACTIQ-BENCH-001`,
and everything needed to check them away from the device, offline, without
trusting this repository's word for the key.

There are two, made on two versions of the stop counter. `cnt` (2 November
2026) is the current one and is checked with the verifier on `main`. `loto3`
(28 October 2026) was made before the counter moved off the TPM owner
hierarchy (#29) and is checked with the verifier of that version, `b9874bf`;
see "The earlier receipt" below.

The question it answers is the fifth of Imran Siddique's in "Who checks the
kill switch?" (20 October 2026): how does someone check, today, that the agent
is still stopped? Here the verifier picks a nonce, the device answers it with
two TPM signatures, and the check runs on the verifier's machine.

## Files

| File | What it is |
|---|---|
| `nonce-cnt-20261102.txt` | The challenge, 32 bytes in hex, drawn on the verifier's PC with `tactiq-stop-verify nonce` before the board was asked. |
| `receipt-cnt-20261102.tqsr` | The board's answer: `tactiq-stop status <nonce>`, carried back on a USB drive. A TQSR receipt: the stop record, the TPM's `NV_Certify` of the stop counter and the AK quote over PCR 0, 1 and 8. |
| `pcr-ref-cnt-20261102.json` | The expected PCR values of the build that answered (development image `cnt`, built from tactiq-os `8fa65ff`, merged as `c48a8cb`, with tactiq-attest `101b7a7`, slot B), made by `mk-pcr-reference.py`. |
| `nonce-loto3.txt`, `receipt-loto3.tqsr`, `pcr-ref-op1-20261028.json` | The earlier receipt, the same kinds of file (development image `op1`, slot A). |

sha256:

```
9dc5c0c669937473a7e431794f0576f44585ed5939ed935fb4ee6cf19fba783a  receipt-cnt-20261102.tqsr
725582e9c98d921def40cdbada33ad3701f2bed4450a95aa4dea909ca9a180b2  nonce-cnt-20261102.txt
3ba34156533337defd8a8d29f5554f1f86853fbae87430feac3a75a922f38446  pcr-ref-cnt-20261102.json
4915c4b5ec936bf5a34e19cace937c24fa19e89b66f0095f6ba61e5442b1d10a  receipt-loto3.tqsr
8c0a4c81beaf9e24ea61380ec46bab49c9c652fbdb7db3158c78e753670618c6  nonce-loto3.txt
6aa5396063dc414c4f23a0a2e305076ca6c1a7138be5aa3e500b1ef4187933f5  pcr-ref-op1-20261028.json
```

The AK is not in this directory. You take it from the device's signed
registration record, published with TactiQ OS v2.1.0-rc14.

## Run it

You need Rust, OpenSSL and tpm2-tools (for the release script only).

1. The AK registration, from the release:

   ```
   curl -sSLO https://github.com/revenue7-eng/tactiq-os/releases/download/v2.1.0-rc14/verify-l3-rc14.sh
   bash verify-l3-rc14.sh
   ```

   The script downloads the release files, checks them against the release
   `SHA256SUMS` and checks the registration record's signature, the EK chain
   to Infineon and the AK name in the record. Expect `FAIL: 0`. The lines
   that matter here are `record CMS`, `record signer is the leaf` and
   `AK name equals record`.

2. The AK public area, out of the signed record:

   ```
   curl -sSLO https://github.com/revenue7-eng/tactiq-os/releases/download/v2.1.0-rc14/l3-evidence-rc14.tar.gz
   curl -sSLO https://github.com/revenue7-eng/tactiq-os/releases/download/v2.1.0-rc14/release-root-r2.pem
   tar -xzf l3-evidence-rc14.tar.gz
   (cd tools/registrar && cargo build --release)
   tools/registrar/target/release/tactiq-registrar verify \
     --record l3-evidence-rc14/registration-TACTIQ-BENCH-001-rc14.json \
     --root l3-evidence-rc14/infineon-root.crt \
     --sig l3-evidence-rc14/registration-TACTIQ-BENCH-001-rc14.json.p7s \
     --release-root release-root-r2.pem \
     --emit-ak ak.pub
   ```

   `release-root-r2.pem` must have the sha256 fingerprint
   `8E:10:04:1E:BB:FC:CB:A0:36:62:1B:2E:45:36:87:D2:9A:50:D7:15:65:F2:99:CB:41:28:B4:CE:B9:65:FF:E8`
   (`openssl x509 -in release-root-r2.pem -noout -fingerprint -sha256`).

3. The receipt:

   ```
   (cd tools/stop-verify && cargo build --release)
   tools/stop-verify/target/release/tactiq-stop-verify check docs/stop-sample/receipt-cnt-20261102.tqsr \
     --ak ak.pub --device TACTIQ-BENCH-001 \
     --pcr-ref docs/stop-sample/pcr-ref-cnt-20261102.json --slot B \
     --nonce $(cat docs/stop-sample/nonce-cnt-20261102.txt)
   ```

   Expected:

   ```
   ak          name 000b35c0941662473b6dc78ce636d83dfcaf1bbdfa68bb69121dd9b3c0b414df0a0a
   build       PCR 0, 1, 8 equal to pcr-ref-cnt-20261102.json, slot B
   fresh       yes: answers nonce a652bb3f03696b4888dac0caa71d53ed726f203733fa06cb78f2b5f519ba9f44
   kind        status answer
   counter     8145 (odd), read and signed by the TPM
   policy      sha256 60e962b74b1bf258d0fe5f21b25cccfb288c9b6f7ab71550dd385b3ebe92063a
   basis       the counter is odd, as the TPM read it; in the build named above every call is refused at an odd counter
   VERDICT     STOPPED
   ```

   Exit 0 is stopped, 2 running, 1 refused.

4. The check must be able to fail. Each of these gives `VERDICT REFUSED`:
   another nonce (`--nonce $(tools/stop-verify/target/release/tactiq-stop-verify nonce)`),
   the other slot (`--slot A`), another device id, or one byte of the receipt
   changed.

## The earlier receipt

`receipt-loto3.tqsr` was made on 28 October 2026 with the stop counter of
that version, an index the owner hierarchy writes. Since `3c57e1f` (#29) the
counter is defined with other attributes (auth write, auth read, no owner
bits) so that the owner authorization can be closed, and its TPM name changed
with them. The verifier on `main` computes the name of the new index, so it
refuses this receipt with `certifies a different NV index`, and the verifier at
`b9874bf` refuses `receipt-cnt-20261102.tqsr` the same way. Each refusal is
correct: a receipt is checked with the verifier of the version that made it.

```
git worktree add ../tactiq-attest-b9874bf b9874bf
(cd ../tactiq-attest-b9874bf/tools/stop-verify && cargo build --release)
../tactiq-attest-b9874bf/tools/stop-verify/target/release/tactiq-stop-verify check docs/stop-sample/receipt-loto3.tqsr \
  --ak ak.pub --device TACTIQ-BENCH-001 \
  --pcr-ref docs/stop-sample/pcr-ref-op1-20261028.json --slot A \
  --nonce $(cat docs/stop-sample/nonce-loto3.txt)
```

Expected: `counter 8129 (odd)`, `build ... slot A`, `VERDICT STOPPED`; with
another nonce, `--slot B`, another device id or one byte changed,
`VERDICT REFUSED`.

Between the two receipts the board's counters were recreated with the new
attributes. The stop counter was 8129 before and is 8145 after: a counter
defined again starts above the highest value a deleted counter held, so the
change cannot take the stop back to an earlier epoch.

## What a pass shows

- The TPM whose EK chains to Infineon, holding the AK registered in the signed
  record, read the stop counter at 8145 and signed that value (`NV_Certify`),
  bound to the stop record and to your nonce. An odd counter is a stop: the
  stop service refuses every tool call through the gateway while it is odd.
  An even counter lets calls through only with an operator's signed release
  for this device and that value; without one it is still a stop.
- The same AK quoted PCR 0, 1 and 8 equal to the reference. PCR 1 covers the
  kernel's devicetree, whose command line carries the dm-verity root hash of
  the root filesystem, where the gateway, the stop service and their SELinux
  policy live.
- The answer came after your nonce existed. A receipt from before cannot
  answer it.

## What it does not show

- **When, within the window.** The nonce bounds the start; the end is when the
  receipt reached the verifier. The board has no network and no real-time
  clock, so it went by USB drive, minutes and not seconds, and dates on the
  board's files mean nothing. A verifier who needs a tighter bound sets it by
  its own clock.
- **The build is ours to name.** The reference was made by us from a
  development image that is not published, so you can check that the board
  ran the build this file names, not what is in that build. It is a
  development image: a release image carries no gateway yet, because it has
  no operator channel.
- **The boot loader is the root.** SPL measures the rest and is not itself
  measured or verified until the SoC's OTP key is fused, which it is not on
  this board. A replaced SPL could extend the same values.
- **Who can write the counter.** It is written with its own empty
  authorization, so any process with TPM access can trip it, which is the
  lockout rule, and nothing short of the operator's release makes an even
  counter pass calls. On this board the TPM owner authorization is still
  empty, so the owner can delete and define the index again; that ends at a
  higher value with no release, which is a stop. Closing the owner is done at
  provisioning and is not done here.
- **Which process asked.** The AK is also the agent's. The receipt proves what
  the TPM read; it does not prove that the stop service, and not another
  process with TPM access, asked for it. For a stop this is the safe side: an
  odd counter is the TPM's value, whoever asked.
- **A call already running.** The stop is checked when a call is admitted. A
  call admitted before the trip was not measured; we expect it to finish.
- **The plant.** The receipt shows the gateway refusing. That a command did
  not reach equipment is a separate observation, not made here.
- **Ongoing.** This is one answer to one challenge. The mechanism answers as
  often as it is asked; nobody asks it on a schedule yet.
