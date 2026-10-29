# A stop receipt you can check yourself

One answer of `tactiq-stop` from a Radxa ROCK 5A bench board, `TACTIQ-BENCH-001`,
and everything needed to check it away from the device, offline, without
trusting this repository's word for the key.

The question it answers is the fifth of Imran Siddique's in "Who checks the
kill switch?" (20 October 2026): how does someone check, today, that the agent
is still stopped? Here the verifier picks a nonce, the device answers it with
two TPM signatures, and the check runs on the verifier's machine.

## Files

| File | What it is |
|---|---|
| `nonce-loto3.txt` | The challenge, 32 bytes in hex, drawn on the verifier's PC with `tactiq-stop-verify nonce` before the board was asked. |
| `receipt-loto3.tqsr` | The board's answer: `tactiq-stop status <nonce>`, carried back on a USB drive. A TQSR receipt: the stop record, the TPM's `NV_Certify` of the stop counter and the AK quote over PCR 0, 1 and 8. |
| `pcr-ref-op1-20261028.json` | The expected PCR values of the build that answered (development image `op1`, slot A), made by `mk-pcr-reference.py`. |

sha256:

```
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
   tools/stop-verify/target/release/tactiq-stop-verify check docs/stop-sample/receipt-loto3.tqsr \
     --ak ak.pub --device TACTIQ-BENCH-001 \
     --pcr-ref docs/stop-sample/pcr-ref-op1-20261028.json --slot A \
     --nonce $(cat docs/stop-sample/nonce-loto3.txt)
   ```

   Expected:

   ```
   ak          name 000b35c0941662473b6dc78ce636d83dfcaf1bbdfa68bb69121dd9b3c0b414df0a0a
   build       PCR 0, 1, 8 equal to pcr-ref-op1-20261028.json, slot A
   fresh       yes: answers nonce 6d341edaec7ca318b51aa39e8a96e10b6a4c150001205d08dfafde0290a2aeb7
   kind        status answer
   counter     8129 (odd), read and signed by the TPM
   policy      sha256 60e962b74b1bf258d0fe5f21b25cccfb288c9b6f7ab71550dd385b3ebe92063a
   basis       the counter is odd, as the TPM read it; in the build named above every call is refused at an odd counter
   VERDICT     STOPPED
   ```

   Exit 0 is stopped, 2 running, 1 refused.

4. The check must be able to fail. Each of these gives `VERDICT REFUSED`:
   another nonce (`--nonce $(tools/stop-verify/target/release/tactiq-stop-verify nonce)`),
   the other slot (`--slot B`), another device id, or one byte of the receipt
   changed.

## What a pass shows

- The TPM whose EK chains to Infineon, holding the AK registered in the signed
  record, read the stop counter at 8129 and signed that value (`NV_Certify`),
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
