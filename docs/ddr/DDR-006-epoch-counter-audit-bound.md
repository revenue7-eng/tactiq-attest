# DDR-006: Epoch counter and a bounded audit directory

Status: accepted, implemented. Takes up the item DDR-004 left out of scope as
"prover persistent mode (audit retention, NV counter wear)". Does not change
any decision of DDR-004 or DDR-005: the envelope layout is the same, and the
NV index stays at `0x01500016` (DDR-005 decision 4). What changes is what the
value at that index means.

## Context

Observed on the bench (Rock 5A, Infineon SLB9670, agent at the default 30 s
interval):

- Every cycle ran `TPM2_NV_Increment` on the counter index, so the agent made
  2880 NV writes a day. The guaranteed endurance figure we hold for this chip
  is 500 000 cycles, from an Infineon forum answer; it is not in the
  datasheet. On that figure the chip is used up in about 174 days of
  continuous operation.
- Adding `orderly` to the index is not a fix. With `TPM2_PT_ORDERLY_COUNT =
  0xFF`, a freshly defined orderly index advanced to 8039 and, after a power
  cut without shutdown, came back at 256. Counter values already issued were
  issued again, and five envelopes in the audit directory were overwritten.
- The audit directory had no bound. About 8000 cycles took 128.1 MB, so
  roughly 16 KiB a cycle and 46 MB a day, on a data partition of 3.8 GB. The
  rc13 coverage file of tactiq-os lists both points as open.

The per-cycle increment bought less than it appears to. The quote signs a
hash of the 93-byte message; the counter inside it is the number the agent
wrote there, read from NV but not certified by the TPM (`TPM2_NV_Certify` is
not used). Someone with root on the device can put any number there under
either scheme. What the NV counter does provide is that a value is never
handed out twice across agent restarts and reboots.

## Decisions

1. **One NV increment per agent start.** The value read after that increment
   is the epoch. The envelope counter is `(epoch << 24) | seq`, where `seq`
   counts envelopes in memory from 0. All values of epoch `e` are above all
   values of epoch `e - 1`, so the verifier's strictly greater rule holds
   across restarts. When `seq` reaches 2^24 (about 16 years at 30 s) the
   agent takes the next epoch. The epoch is taken before the first envelope
   of it is measured; if the process dies in between, the epoch is never
   used, which the verifier sees as a gap.

2. **The agent refuses an unsuitable index.** Before taking an epoch it reads
   the index attributes and stops unless `TPM_NT` is counter and `orderly`
   is clear. An orderly index can roll back after a power cut, and a rolled
   back epoch repeats every counter of that epoch.

3. **The audit directory is bounded.** After each cycle the agent removes the
   oldest envelopes beyond `TACTIQ_AUDIT_KEEP` (default 2880, one day at the
   default interval). Only files named `<digits>.msg|.attest|.sig|.tag` are
   counted and removed; other files in the directory are left alone. Order is
   numeric. If removal fails, the cycle fails and the watchdog is not fed: an
   agent that cannot bound its directory will fill the partition, and that
   should show as a failed unit.

## Rejected

- **`orderly` on the counter index.** Rolled back on the bench, see above.
- **A longer interval.** Wear only slows down, and the interval is tied to
  `WatchdogSec=120` in the unit.
- **`TPM2_NV_Certify` on every cycle.** It would make the counter something the
  TPM vouches for, but it keeps one NV write per cycle.
- **Appraising `clockInfo` from `TPMS_ATTEST`.** `resetCount`, `restartCount`
  and `clock` are signed by the AK and are the right long term freshness
  anchor. Using them needs a change on the verifier side (DDR-004 boundary D
  parses them and leaves them unappraised), so it is left for a later record.
  This record does not block it.

## Consequences

- NV writes go from 2880 a day to one per agent start. Restarts are bounded by
  `StartLimitBurst=3` in 60 s in the unit, and a start that fails before the
  epoch is taken (identity, AK check, index check) writes nothing.
- Counters jump: the first epoch gives values from 2^24 upward. Every value the
  per-cycle scheme issued on the bench is below that, so no old envelope is
  overwritten and no verifier high-water mark is violated.
- An index created with `orderly` must be removed and defined again before the
  agent runs, with the attributes `nv_define()` uses: `tpm2_nvundefine
  0x1500016 -C o`, `tpm2_nvdefine 0x1500016 -C o -a
  "nt=counter|ownerread|ownerwrite"`, `tpm2_nvincrement 0x1500016 -C o`.
  `provision` cannot do it on a provisioned device, because it refuses to run
  there. New devices get the right index from `provision` as before.
- Envelope file names stay 12 digits up to epoch 59 604. Past that they grow
  to 13 digits; pruning orders numerically, so it keeps working, but tools
  that sort names as text would not.
- On the first cycle after the upgrade, a device with more than
  `TACTIQ_AUDIT_KEEP` envelopes removes the excess at once.

## Verification

Unit tests in `crates/prover`: counter composition and ordering across
epochs and against the old maximum, refusal of out of range parts, attribute
check on the bench values (`0x20020012` accepted, `0x24020012` refused),
parsing of `tpm2_nvreadpublic` output, and pruning on a real directory
(oldest stems go with all four files, other files stay).

On hardware, Rock 5A with SLB9670, `tactiq-image-dev` build 20261003073848
(tactiq-os 677f12b, this change at b853253), written to slot A:

| Check | Observed |
|---|---|
| Start on the orderly index left by the earlier experiment (`0x24020012`) | agent refused three times with the recreate instructions, systemd stopped it; counter (260) and envelopes (8035) untouched |
| Index recreated without `orderly` | `ownerwrite\|nt=0x1\|ownerread\|written`; a fresh counter starts at the highest value any counter on the chip has held, so the first epoch was 8039 and the first envelope `134872039424` (8039 << 24) |
| Cycles within an epoch | counter +1 every 30 s, the NV value stayed at 8039 |
| Agent restart | next epoch, 8040, one NV write |
| Power cut without shutdown | next epoch, 8041, first envelope `134905593856`; no roll back |
| Audit bound | 8035 envelopes reduced to 2880 on the first cycle |

The power cut row is the one the earlier orderly index failed: it came back
at 256 after reaching 8039.
