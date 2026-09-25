# DDR-005: Registering the attestation key against the endorsement key

Status: accepted, not implemented
Base: tactiq-attest `main` @ `60de57e` (envelope v2, DDR-004)
Scope: `prover` (key placement, registration commands), registration record
format, a registration tool outside `attest-appraise`. Device-side transport
on the release image is out of scope (see "Not in scope").

## Context

After DDR-004 the TPM quotes the PCRs under a restricted AK and the verifier
accepts an AK by its public area. Nothing yet shows that this AK lives in a
genuine TPM. Whoever provisions a device can hand the verifier any public area
with the right attributes, including one for a key held in software. Until the
AK is tied to the TPM's endorsement key, a v2 envelope is a TPM-quoted
statement under a key whose TPM residence is asserted, not proven. L3 needs it
proven.

Facts this design rests on:

- The EK is a storage (decrypt) key, not a signing key, so the EK cannot
  certify the AK by signing it. The TCG route for a key with only an EK is
  credential activation (`TPM2_MakeCredential` / `TPM2_ActivateCredential`).
- The Rock 5A TPM (Infineon SLB9670) carries EK certificates at NV
  `0x01C00002` (RSA-2048) and `0x01C0000A` (ECC P-256). The RSA certificate
  chain was verified to the Infineon root on 24 Aug 2026 with
  `scripts/verify-ek-chain.sh` (tactiq-os PR #130). The ECC chain has not
  been verified. The chip's NV index list shows the two EK certificates and
  no IAK or IDevID (to be re-read with `tpm2_getcap handles-nv-index` when
  the agent side is implemented). The RSA certificate was re-read on 25 Sep
  and its hash matched the August value.
- The reference implementation fills `TPMS_ATTEST` so that `resetCount`,
  `restartCount` and `firmwareVersion` are obfuscated unless the signing key
  is in the platform or endorsement hierarchy (`FillInAttestInfo`). Observed
  on SLB9670 with an owner-hierarchy AK (DDR-004 boundary D).
- The TCG handle registry, as used by common tooling, reserves `0x81010001`
  (RSA EK) and `0x81010002` (ECC EK) and `0x81000001` / `0x81000002` (SRK).
  The v1 and v2 agent persist their own objects at `0x81010001` (owner
  primary), `0x81010002` (v1 key) and `0x81010003` (v2 AK). The TPM does not
  enforce the convention, but any tool that follows it and looks for the EK at
  `0x81010001` would get a different key on our devices.

## Decisions

1. **Credential activation is the mechanism.** Rejected: EK signing the AK
   (the EK cannot sign); a manufacturer IAK/IDevID (not provisioned on this
   chip); trusting the AK on first presentation (today's state, the thing this
   DDR removes).

2. **The EK is the RSA-2048 EK whose certificate is at `0x01C00002`,**
   recreated from the default TCG template whenever it is needed and never
   persisted. Chosen because its certificate chain is the one already
   verified. Registration refuses the device if the public key of the
   recreated EK differs from the public key in the certificate: that mismatch
   means the certificate does not describe this EK, and nothing after it
   would mean anything.

3. **The AK is created under the EK, in the endorsement hierarchy,** with
   the attributes and algorithm of DDR-004 decision 7. This supersedes the
   parent in DDR-004 decision 7 (owner primary at `0x81010001`). Two reasons:
   the quote then carries `resetCount`, `restartCount` and `firmwareVersion`
   in the clear, which lets a verifier see a TPM reset or a firmware change
   between envelopes; and the AK sits in the same hierarchy as the key that
   vouches for it. The gate 1 rule of DDR-004 decision 4 is unchanged: it
   judges the AK public area, which does not record its parent.

4. **Handles follow the TCG registry, and a handle is never trusted by
   occupancy.** The agent no longer persists anything at `0x81010001`,
   `0x81010002` or `0x81010003`. The AK is persisted at `0x81010100`: the
   first 256 handles of the endorsement range are reserved for primary keys
   such as the EK, the rest is for non-primary keys, and the AK is now a
   non-primary key in the endorsement hierarchy. Before using the object at
   that handle, the agent compares its name with the name of the AK public
   area it recorded at provisioning (`keys/ak.pub`) and refuses on mismatch.
   Today `provision` treats an occupied handle as its own key; with objects
   placed by convention in shared ranges that is how an agent ends up quoting
   with a key that is not its own. The NV counter
   stays at `0x01500016`. A device already provisioned under v1 or v2 keeps its
   old objects until they are evicted deliberately; evicting them is a
   separate, announced step, not something the agent does on its own.

5. **Protocol: three transfers across the air gap.**
   1. Device to registrar: `device_id`, the EK certificate (DER, read from
      `0x01C00002`), the AK `TPM2B_PUBLIC`.
   2. Registrar: verify the EK certificate chain to the pinned Infineon root;
      accept the AK public area under DDR-004 decision 4; compute the AK
      name; draw a fresh 32-byte secret; run `TPM2_MakeCredential` in
      software with the EK public key from the certificate, the secret and
      the AK name. Registrar to device: the credential blob.
   3. Device: `TPM2_ActivateCredential` with the AK and the EK (endorsement
      policy session). The TPM releases the secret only if an object with
      that exact name is loaded in the TPM that holds that EK's private key.
      Device to registrar: the secret.
   The registrar compares. A match is the registration.

6. **The registration record is publishable evidence:** `device_id`, the EK
   certificate, the fingerprint of the root it was verified against, the AK
   `TPM2B_PUBLIC` and name, the credential blob, `SHA-256(secret)`, who
   registered, and when. The secret itself is not published; its hash is. Anyone
   holding the device can run `TPM2_ActivateCredential` on the published blob
   and compare the hash, so the proof can be repeated without trusting the
   registrar.

   The record is signed by a dedicated `Registration Signer` leaf under the
   release root r2. Without a signature the record proves nothing to a reader
   without the device: anyone can make a blob with a secret of their own and
   publish its hash, and the one claim the reader cannot check, "the
   registrar received the right secret", would rest only on where the file is
   published. Rejected: the RIM Signer key (one key for two meanings, and
   revoking one would revoke the other); Sigstore through the release workflow
   (a second trust root for the reader, next to r2). The cost is one key
   ceremony. Until the leaf exists, bench records stay internal and are not
   presented as L3.

7. **Registration is checked outside gate 1.** `attest-appraise` stays as it
   is: stateless, small, wasm-buildable, no X.509 and no RSA. A separate tool
   verifies a registration record (EK chain, EK public key against the
   certificate, AK name in the blob context, AK rule) and emits the AK
   `TPM2B_PUBLIC` for the trust store only if everything holds. A trust entry
   without a record behind it is still accepted by gate 1 but must never be
   presented as L3.

## Boundaries

A. A registration proves that the AK was in the TPM holding this EK, to the
   registrar, at registration time. A reader without the device relies on the
   registrar; a reader with the device can repeat it (decision 6).

B. It says nothing about the SPI bus between SoC and TPM. On the bench the
   module is on flying wires with no HMAC session; an interposer is out of
   scope here and the external wording on bus confidentiality stays as it is.

C. The Infineon root was obtained through a browser and is not yet pinned by
   an independent path in the tree. Until it is, the record names the root
   fingerprint it was checked against, and no external claim about the EK
   chain is made on the strength of the record alone.

D. EK certificate revocation is not checked: the registrar is offline. The
   record states that.

## Not in scope

- Carrying the three transfers to and from a release device, which has no
  login and no automount (automount was rejected as a new interface into a
  hardened device). This is the agent-side DDR that follows (registration
  subcommands and their transport).
- The verification page reading the record (edge-reference-check).
- Pinning the Infineon root independently.

## Verification

**swtpm** (0.7.3, EK certificate from `swtpm_setup` local CA, tpm2-tools 5.7):
the full protocol with tpm2-tools only. `tpm2_createak` under the recreated
EK yields exactly the DDR-004 decision 7 attributes; the registrar makes the
blob with `tpm2_makecredential -T none -G rsa` from the public key in the
certificate (not from the device's EK public area); activation under an
endorsement policy session returns the secret. A blob made for another AK
name is refused (`TPM_RC_INTEGRITY`). A quote by the endorsement-hierarchy AK
carries `firmwareVersion` equal to `TPM_PT_FIRMWARE_VERSION_1/_2`.

**Rock 5A, Infineon SLB9670** (dev image rc11, tpm2-tools 5.7), transient
objects only, NV counter and persistent handles untouched:

- the EK certificate read from `0x01C00002` has sha256
  `10661f65f256e8a30b2ba737061f56a0815a3ea06ac006e4fa5aa2291736a103`,
  the same bytes whose chain was verified to the Infineon root on 24 Aug
  (issuer Infineon OPTIGA RSA Manufacturing CA 034, valid to 2036-04-29);
- the RSA EK recreated from the default template has the certificate's
  modulus, all 2048 bits, and the standard EK policy
  `837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa`
  (decision 2);
- the AK created under it passes the DDR-004 decision 4 rule, and the name
  computed from its public area equals the name the TPM reported;
- the blob was made off the board from the certificate's key, the AK name and
  a fresh 32-byte secret, carried to the board as bytes, and activated there:
  the secret the TPM released equals the registrar's (decision 5);
- a quote by that AK verifies under it and carries `firmwareVersion`
  `0x000700550011cb00` (the chip's `0x70055` / `0x11CB00`), `resetCount` 186
  and `restartCount` 0 in the clear (decision 3).

Observed along the way: `tpm2_activatecredential` prints the released secret
(`certinfodata:`). A registration run must not let the secret reach a log or
a console before the registrar has compared it; the bench run above did, which
is acceptable for a test and not for a record.

Still to do: the registration tool (decision 7), the agent side for the bench
and then for the release image, and the negative cases on hardware.
