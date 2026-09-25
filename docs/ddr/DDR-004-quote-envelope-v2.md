# DDR-004: Envelope v2, the signed object is a TPM2_Quote

Status: accepted, implemented (tactiq-attest #7, #8; tactiq-os #206)
Base: tactiq-attest `main` @ `dc8eb1f`
Amended by: DDR-005 decisions 3 and 4 (AK parent and handle)
Scope: `attest-envelope`, `prover`, `attest-appraise` (gate 1)

## Context

Envelope v1 is the 93-byte canonical message (`device_id 16 || counter 8 ||
pcr_selection 5 || sha256(pcr_state) 32 || evidence_hash 32`) signed by
`tpm2_sign` with a key at `0x81010002`. The key is created by `tpm2_create`
without `-a`, so it does not carry the TPM `restricted` attribute. The prover
reads PCRs itself and signs whatever it assembled. A compromised userspace can
therefore sign any PCR claim, and the verifier has no way to tell. v1 proves
that the message came from something holding the key; it does not prove that
the TPM measured the PCR values in it.

The verifier trusts the key as a PEM placed in its trust store
(`read_public_pem`: "it replaces a CA"). Nothing ties that key to a TPM.

This DDR fixes the first gap (what is signed). Binding the key to the
manufacturer EK is a separate decision (see "Not in scope").

## Decisions

1. **The signed object is `TPMS_ATTEST` from `TPM2_Quote`.** The prover quotes
   the selected PCRs with an attestation key (AK) and passes
   `qualifyingData = SHA-256(canonical message)`. The canonical message layout
   and `build_canonical` are unchanged.

2. **Wire format v2 is three files per cycle:** `<stem>.msg` (93 bytes, as v1),
   `<stem>.attest` (marshalled `TPMS_ATTEST`), `<stem>.sig` (ECDSA P-256 over
   `.attest`, not over `.msg`). The evidence bundle is unchanged and stays bound
   through `evidence_hash` inside `.msg`. `<stem>.tag` is unchanged.

3. **Gate 1 order for v2**, each step load-bearing:
   1. parse `.msg` (fixed layout, as v1);
   2. look up the trust entry for `device_id`;
   3. the envelope form must match the entry: an AK entry with a quote, a
      legacy entry without one (decision 5);
   4. parse `.attest`: magic `TPM_GENERATED_VALUE` (`0xff544347`), type
      `TPM_ST_ATTEST_QUOTE` (`0x8018`);
   5. verify `.sig` over `.attest` with the AK;
   6. `extraData` equals `SHA-256(.msg)`;
   7. the quote's PCR selection is a single bank equal to `pcr_selection` in
      `.msg`, and `pcrDigest` equals `pcr_hash` in `.msg`;
   8. only then the evidence bundle against `evidence_hash`.

   A failure at step 3 is `QuoteBindingFail`, at step 4 `Malformed`, at step 5
   `SignatureFail`, at steps 6 and 7 `QuoteBindingFail` (decision 9), at step 8
   `EvidenceBindingFail`.

   `qualifiedSigner` is not compared. It carries the AK's qualified name, a
   hash over the whole parent chain, which the AK public area alone cannot
   reproduce (observed on swtpm: it differs from the name `tpm2_readpublic`
   reports and equals the qualified name). The signature verified under the AK
   in step 5 already proves the signer. An earlier draft compared it with the
   AK name; the end-to-end run refused every genuine quote.

4. **The v2 trust entry is the AK public area (`TPM2B_PUBLIC`), not a PEM.**
   The verifier requires `restricted`, `sign`,
   `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, ECC NIST P-256,
   ECDSA-SHA256, and no `decrypt`, symmetric or KDF scheme. Whether a key is an
   AK is derived from its public area; it is never a flag someone sets on the
   entry. The verifier also computes the AK name, for registration (DDR-005),
   not for gate 1.

5. **No downgrade.** A restricted key can still sign arbitrary data through a
   TPM hash ticket, as long as the data does not start with
   `TPM_GENERATED_VALUE`. A v1 message signed by the AK would therefore verify.
   Observed on swtpm with tpm2-tools 5.6: a restricted AK signs a random
   93-byte message, and refuses data starting with `0xff544347 0x8018` with
   `TPM_RC_TICKET`.
   A trust entry that qualifies as an AK under decision 4 is never accepted on
   the v1 path. The v1 path stays only for legacy PEM entries.

6. **`Authenticated` records how the PCR claim was bound:** `SelfSigned` (v1)
   or `TpmQuote` (v2). Any L3 claim, including the verification page, requires
   `TpmQuote`. A v1 envelope can never yield L3.

7. **AK at `0x81010003`**, created with explicit attributes
   `fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign`
   and algorithm `ecc256:ecdsa-sha256:null`, under the existing parent
   `0x81010001`. The trailing `:null` is required: without it tpm2-tools 5.6
   assigns a symmetric scheme to a restricted key and the TPM refuses the
   create with `TPM_RC_SYMMETRIC` (observed on swtpm). No PCR policy on the key: the
   reasoning in `create_signing_key` (keep `UnrecognizedState` distinct from
   `SignatureFail`) holds unchanged for a quote. The legacy key at
   `0x81010002` is left in place; retiring it is a separate step.

8. **`TPMS_ATTEST` parsing lives in `attest-envelope`, in plain Rust**, with no
   TSS dependency, so `attest-appraise` keeps building for the browser
   (DDR-003 boundary F). Bodies are subslices of the input, as in the bundle
   parser.

9. **New failure reason `QuoteBindingFail`.** It covers steps 3, 6 and 7 of
   decision 3. It amends the verdict
   vocabulary locked in DDR-001 decision 3. Reusing `EvidenceBindingFail` was
   rejected: "the bundle does not match the signed digest" and "the quote does
   not match the message" are different events, and an investigator must be
   able to tell them apart without reading the detail string.

## Boundaries

A. Steps 6 and 7 of decision 3 compare attacker-chosen bytes until step 5
   holds. Running any of them before the signature check proves nothing
   (same reasoning as DDR-002 decision 5 boundary D).

B. The prover reads PCRs before quoting, because `pcr_hash` must be inside the
   message that `qualifyingData` commits to. If a PCR is extended between the
   two calls, step 7 fails and the envelope is refused. This is a safe failure;
   it cannot be turned into acceptance of a false claim.

C. A quote over more than one bank, or over a bank other than the one in
   `pcr_selection`, is refused. v1 already refuses multi-bank specs because the
   message cannot encode them.

D. `clockInfo` and `firmwareVersion` are parsed and carried in
   `Authenticated` verbatim, but not appraised in v2. With the AK under the
   owner hierarchy, the TPM obfuscates `resetCount`, `restartCount` and
   `firmwareVersion` (observed on swtpm: values look random, `clock` is
   plain). They cannot, for example, reveal a warm reboot that left two boot
   chains in the PCRs. Whether the AK moves under the endorsement hierarchy,
   where these fields are in the clear, is a question for DDR-005.

## Not in scope

- AK registration against the EK (`TPM2_MakeCredential` /
  `TPM2_ActivateCredential`, EK certificate at `0x1C0000A` or `0x1C00002`,
  chain to the manufacturer). Planned as DDR-005. Until it lands, a v2 trust
  entry is still trusted on first presentation, and v2 alone does not give L3.
- Prover persistent mode (audit retention, NV counter wear).
- Envelope transport.

## Verification

On a software TPM (swtpm 0.7.3, tpm2-tools 5.6), through the unmodified
`tactiq-agent provision` and `attest`, PCR spec `sha256:0,...,9`. The bytes are
committed as fixtures (`crates/attest-appraise/tests/fixtures/swtpm/`); every
signature in them is the TPM's own. Test `quote_v2_swtpm`:

1. v2 envelope from a restricted AK is accepted, binding `TpmQuote`. Done.
2. v1 envelope signed by the same AK is refused (`QuoteBindingFail`). Done.
   The same bytes pass the v1 path when the AK is held as a bare key, which is
   the case decision 5 closes.
3. `.msg` with one bit of `pcr_hash` flipped, quoted with its own qualifying
   data, is refused at step 7 (`pcrDigest`). Done.
4. A genuine quote with other qualifying data is refused at step 6. Done.
5. A public area without `restricted` is not accepted as an AK. Done.

Also: a quote over a different PCR selection (step 7), a quote under a legacy
entry (step 3), every single-bit change of `.attest` (steps 4 and 5), and a
wrong bundle after a valid quote (step 8). `attest-appraise` still builds for
`wasm32-unknown-unknown`.

The image ships tpm2-tools 5.7 (meta-security `c0d1d620` per
`integration/LAYERS.lock`, recipe `tpm2-tools_5.7.bb`). Rebuilt from the
recipe tarball (sha256 checked against the recipe) and rerun: `provision` and
two `attest` cycles, both envelopes accepted with binding `TpmQuote`.

On Rock 5A with the Infineon SLB9670 (dev image rc11, tpm2-tools 5.7, tpm2-tss
4.1.3), with transient objects only (no persistent handle, NV counter not
touched), running by hand the same tpm2-tools calls the agent makes:

- the AK was created with `ecc256:ecdsa-sha256:null` and the decision 7
  attributes; its public area (`objectAttributes` `0x50072`) passes the
  decision 4 rule, and the name computed from it equals the name the TPM
  reported;
- a quote over `sha256:0,...,9` (145 bytes, one bank, select `ff0300`)
  verified under the AK; `extraData` echoed the qualifying data passed in;
- `pcrDigest` equals SHA-256 of the `tpm2_pcrread -o` output, which is how
  the agent computes `pcr_hash`;
- `resetCount`, `restartCount` and `firmwareVersion` in the quote are
  obfuscated (boundary D): the chip firmware is `0x70055`, the quote says
  otherwise;
- the AK refused to sign data starting with `0xff544347 0x8018`
  (`TPM_RC_TICKET`), the property decision 5 and the whole v2 rest on.

Still to do: the agent binary itself on the board (provision, one attest
cycle, envelope appraised off the board), which comes with the next image
built from `tactiq-os` `191f06d` or later, after a cold start.
