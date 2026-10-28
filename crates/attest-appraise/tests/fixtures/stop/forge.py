#!/usr/bin/env python3
"""Forge stop receipts the way a process with access to the AK could.

Writes, into the output directory, receipts whose quote is genuine (signed by
the AK at 0x81010100) but whose stop record or certify lies. Plus an honest
control built the same way, so a refusal of a forgery is due to the check,
not to this script.

usage: forge.py OUTDIR NONCE_HEX OTHER_KEY OTHER_INDEX [odd]
"""
import hashlib, os, struct, subprocess, sys, tempfile

AK = "0x81010100"
STOP = "0x1500017"
SPEC = "sha256:0,1,8"
DEVICE = b"TACTIQ-SWTPM-01"


def sh(*a):
    return subprocess.run(a, check=True, capture_output=True).stdout


def counter(index=STOP):
    return int.from_bytes(sh("tpm2_nvread", index, "-C", index, "--size", "8"), "big")


def record(epoch, stopped=True, policy=b"\x11" * 32, refusal=False):
    kind = 1 if refusal else 2
    tail = b"\x22" * 32 if refusal else b""
    return bytes([1, kind, 2 if stopped else 1, 0]) + struct.pack(">Q", epoch) + policy + tail


def certify(qd, index=STOP, key=AK, tmp=None):
    a, s = os.path.join(tmp, "c.attest"), os.path.join(tmp, "c.sig")
    sh("tpm2_nvcertify", "-C", key, "-c", index, "-g", "sha256", "-s", "ecdsa", "-f", "plain",
       "-q", qd.hex(), "--size", "8", "--offset", "0", "--attestation", a, "-o", s, index)
    return open(a, "rb").read(), open(s, "rb").read()


def section(tag, body):
    return struct.pack(">HI", tag, len(body)) + body


def receipt(body, cert, nonce, epoch, tmp, msg_epoch=None):
    ca, cs = cert
    cert_body = struct.pack(">H", len(ca)) + ca + struct.pack(">H", len(cs)) + cs
    bundle = section(4, body) + section(6, cert_body) + section(5, nonce)
    p = os.path.join(tmp, "p.bin")
    sh("tpm2_pcrread", SPEC, "-o", p)
    pcrs = open(p, "rb").read()
    msg = (DEVICE.ljust(16, b"\0") + struct.pack(">Q", epoch if msg_epoch is None else msg_epoch) + bytes([0, 0x0B, 0x03, 0x01, 0x00])
           + hashlib.sha256(pcrs).digest() + hashlib.sha256(bundle).digest())
    assert len(msg) == 93
    qd = hashlib.sha256(b"tactiq-stop/quote/v1\0" + msg).digest()
    qa, qs = os.path.join(tmp, "q.attest"), os.path.join(tmp, "q.sig")
    sh("tpm2_quote", "-c", AK, "-l", SPEC, "-q", qd.hex(), "-m", qa, "-s", qs, "-g", "sha256", "-f", "plain")
    parts = [msg, open(qa, "rb").read(), open(qs, "rb").read(), bundle]
    return b"TQSR\x01" + b"".join(struct.pack(">I", len(x)) + x for x in parts)


def cq(body, nonce):
    return hashlib.sha256(b"tactiq-stop/certify/v1\0" + body + nonce).digest()


def main():
    out, nonce = sys.argv[1], bytes.fromhex(sys.argv[2])
    other_key, other_index = sys.argv[3], sys.argv[4]
    if len(sys.argv) > 5 and sys.argv[5] == "odd":
        with tempfile.TemporaryDirectory() as tmp:
            c = counter()
            assert c % 2 == 1, f"stop counter {c} must be odd for this forgery"
            w = lambda n, b: open(os.path.join(out, n), "wb").write(b)
            # F6: the TPM's odd counter, reported as running.
            r = record(c, stopped=False)
            w("forge-oddrunning.tqsr", receipt(r, certify(cq(r, nonce), tmp=tmp), nonce, c, tmp))
            print(f"stop counter {c}")
        return
    with tempfile.TemporaryDirectory() as tmp:
        c = counter()
        assert c % 2 == 0, f"stop counter {c} must be even (running) for these forgeries"
        # Honest control, built by this script: must pass.
        honest = record(c, stopped=False)
        w = lambda n, b: open(os.path.join(out, n), "wb").write(b)
        w("forge-control.tqsr", receipt(honest, certify(cq(honest, nonce), tmp=tmp), nonce, c, tmp))
        # F1: claims the odd epoch c+1 (stopped); the TPM certifies c.
        lie = record(c + 1)
        w("forge-epoch.tqsr", receipt(lie, certify(cq(lie, nonce), tmp=tmp), nonce, c + 1, tmp))
        # F2: certify of the true value, signed by another key of the TPM.
        honest_stop = record(c)
        w("forge-key.tqsr", receipt(honest_stop, certify(cq(honest_stop, nonce), key=other_key, tmp=tmp),
                                    nonce, c, tmp))
        # F3: certify of another counter, defined like the stop counter, at an odd value.
        o = counter(other_index)
        odd = record(o)
        w("forge-index.tqsr", receipt(odd, certify(cq(odd, nonce), index=other_index, tmp=tmp), nonce, o, tmp))
        # F4: the message counter differs from the certified record.
        w("forge-msgcounter.tqsr", receipt(honest, certify(cq(honest, nonce), tmp=tmp), nonce, c, tmp,
                                           msg_epoch=c + 1))
        # F5: a refusal bound to the nonce, passed off as a fresh answer.
        ref = record(c, refusal=True)
        w("forge-refusal-nonce.tqsr", receipt(ref, certify(cq(ref, nonce), tmp=tmp), nonce, c, tmp))
        print(f"stop counter {c}, other index {other_index} at {o}")


main()
