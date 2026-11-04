# DDR-007: A stop that held between two receipts, by the TPM clock

Status: accepted, implemented; run on swtpm and on the bench board. Takes up
the item DDR-006 left for a later record: appraising `clockInfo` of
`TPMS_ATTEST`. Does not change the receipt format (`TQSR` v1) or the stop
service.

## Context

A stop receipt (`docs/stop-sample`) answers whether the agent is stopped at
the moment the verifier asks. A plant's safety team or an auditor also asks
whether it stayed stopped: that nothing lifted the stop between two checks.
Two receipts with the same odd counter come close, but on their own they do
not exclude a reboot in between, after which any build may have run with the
counter still odd, and the board then rebooted into the reference build
before the second check.

Reproduced on swtpm with `tactiq-stop` of this tree: two status receipts
with a `Shutdown(CLEAR)` and `Startup(CLEAR)` between them both give
`VERDICT STOPPED` at counter 1; the TPM signed `resetCount` 2 in the first
and 3 in the second, and no check read it.

Also found: `verify_stop_receipt` took the counter from the certify and the
build from the quote without asking whether the two were made in one TPM
boot. A receipt whose certify was made before a `Shutdown(STATE)` and
`Startup(STATE)` and whose quote was made after it passed the check of
`main` (`mix-yes` in the fixtures).

Both signatures already carry what is needed. The AK is in the endorsement
hierarchy (DDR-005 decision 3), so the TPM reports `resetCount` and
`restartCount` in the clear. On the bench board the published receipts show
it: `receipt-loto3` has `resetCount` 368, `receipt-cnt-20261102` 377, and
in each the certify and the quote carry the same counts.

## Decisions

1. **`clockInfo` of the NV certify is parsed and kept.** `attest-stop`
   reads it into `TpmClock` (clock, resetCount, restartCount, safe) instead
   of skipping 17 bytes, and refuses a `safe` byte other than 0 or 1.

2. **One receipt is one TPM boot.** `verify_stop_receipt` refuses a receipt
   whose certify and quote differ in `resetCount` or `restartCount`, and
   returns the certify's clock in `StopFinding`.

3. **An interval check, `verify_stop_interval`.** Each receipt passes
   `verify_stop_receipt` against the same AK, device and reference build,
   each with its own nonce. Then: the nonces differ; both counters are odd
   (an even counter without a release is the service's word, not the TPM's);
   the counter is equal at both ends; `resetCount` and `restartCount` are
   equal at both ends; the second clock is greater. `tactiq-stop-verify
   interval` runs it.

Why these suffice: the TPM only increments the counter, and both a lift
and a new trip increment it, so an equal value means neither happened. A
counter deleted and defined again starts above every value the chip has
held (observed in DDR-006 and in `docs/stop-sample`), so it cannot return to
the same value. Within one boot a PCR only moves forward by extend, so both
quotes equal to the reference means the reference build ran throughout.

## Rejected

- **Comparing only the counter.** Misses the reboot, the case above.
- **Wall time from the device.** The device has no trusted clock off the
  network; the TPM clock is the one the TPM signs.
- **Requiring `safe`.** Within one boot the clock does not go back, and
  `resetCount` already rules out the case `safe` guards.

## Limits

- The TPM clock counts milliseconds while the TPM is powered and can be
  moved forward by the owner or platform (`TPM2_ClockSet`), never back.
  `held_ms` can therefore be more than the time that passed. Until the
  owner authorization is set and kept off the device, a process with the
  empty owner auth can move it.
- The interval proves the gateway's rule held, not that no command reached
  a process: that needs an observation of the process itself.
- The AK is shared with `tactiq-agent`: a pass proves the device and its
  measured build, not which process asked for the signatures.

## Verification

Unit tests in `attest-stop`: the clock is read at its offset, a bad `safe`
byte is refused, `same_boot` needs both counts.

`crates/attest-appraise/tests/stop_interval_swtpm.rs`, on receipts made by
`tactiq-stop` against swtpm 0.7.3 and tpm2-tools 5.6
(`fixtures/stop/interval/make.sh`):

| Pair | Result |
|---|---|
| `s1`, `s2`: one boot, counter 1 | held, 2063 ms of TPM clock |
| `s2`, `s1` | refused: not later |
| `s1` with its own nonce given for `s2` | refused: same challenge |
| `s2`, `rs`: restart between | refused: restartCount 0 then 1 |
| `rs`, `rb`: reset between | refused: resetCount 1 then 2 |
| `m0`, `m2`: counter 1 then 3 | refused: moved |
| `m2`, `ev`: counter 4 | refused: even |
| `s1`, `s2` with one byte changed | refused: signature |
| `mix-no` alone | passes |
| `mix-yes` alone | refused: two boots in one receipt |

Each receipt of a refused pair passes `verify_stop_receipt` on its own, so
every refusal is the interval check's. The verifier of `main` before this
change gives `VERDICT STOPPED` for `mix-yes` and for `rb`.

The published board receipt `docs/stop-sample/receipt-cnt-20261102.tqsr`
still gives `VERDICT STOPPED` with this verifier.

### On the bench board

Rock 5A `TACTIQ-BENCH-001`, slot A, dev image rc14, the AK of
`tactiq-os/measurements/stop-receipt-dev-20261028/ak.pub` (name
`000b35c0941662473b6dc78ce636d83dfcaf1bbdfa68bb69121dd9b3c0b414df0a0a`),
build reference `pcr-ref-cnt-20261102.json` slot A. Four status receipts,
each to its own nonce:

1. `r1` at counter 8145;
2. `r2` about ten minutes later, nothing done in between;
3. `recover` (8145 to 8146) and `trip` (8146 to 8147), then `r3`;
4. cold start (poweroff, power pulled), then `r4`.

`r1` alone gives `VERDICT STOPPED`.

| Pair | Result |
|---|---|
| `r1`, `r2` | held: counter 8145, resetCount 380 and restartCount 0 at both ends, 782460 ms of TPM clock |
| `r2`, `r3` | refused: counter moved from 8145 to 8147 |
| `r3`, `r4` | refused: resetCount 380 then 381 |

During the run the board's wall clock was wrong (files on its FAT carry
dates of October, `r4` earlier than `r1`). The check does not read it.
The TPM clock gave about thirteen minutes for a gap of about ten by the
operator's watch; it is not wall time and the result is not read as a
duration.

The receipts, the challenges, the raw output of each check and a script that
runs them again are the measurement record
`measurements/stop-interval-board-20261104.md` in tactiq-os (#299).
