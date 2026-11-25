#!/usr/bin/env bash
# close-owner on a software TPM: what it closes and what keeps working.
#
#   bash tests/close-owner/run.sh            # expects every refusal (exit 0 when all hold)
#   bash tests/close-owner/run.sh --no-close # same checks without close-owner: must FAIL
#
# Needs swtpm, tpm2-tools and the built binaries (cargo build -p prover).
# Everything runs in temporary directories against a fresh swtpm; nothing on
# the host TPM is touched.
set -u
here=$(cd "$(dirname "$0")/../.." && pwd)
agent="$here/target/debug/tactiq-agent"
[ -x "$agent" ] || { echo "build first: cargo build -p prover"; exit 2; }
close=1; [ "${1:-}" = "--no-close" ] && close=0

tmp=$(mktemp -d); state="$tmp/swtpm"; mkdir -p "$state"
port=$((21000 + RANDOM % 20000))
trap 'kill "$(cat "$state/pid" 2>/dev/null)" 2>/dev/null; rm -rf "$tmp"' EXIT
swtpm socket --tpm2 --tpmstate dir="$state" --server type=tcp,port="$port" \
  --ctrl type=tcp,port=$((port + 1)) --flags not-need-init,startup-clear \
  --daemon --pid file="$state/pid" || exit 2
sleep 1
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$port"
export TACTIQ_KEYS_DIR="$tmp/keys" TACTIQ_WORK_DIR="$tmp/work" TACTIQ_OUT_DIR="$tmp/out"
mkdir -p "$tmp/work" "$tmp/out" "$tmp/s"
cd "$tmp/s"

fail=0
ok()   { echo "ok    $1"; }
bad()  { echo "FAIL  $1"; fail=1; }
must_refuse() { local l=$1; shift; if "$@" > /dev/null 2>&1; then bad "$l: succeeded"; else ok "$l: refused"; fi; }
must_work()   { local l=$1; shift; if "$@" > /dev/null 2>&1; then ok "$l"; else bad "$l: failed"; fi; }

tpm2_getrandom -o "$tmp/owner.auth" 32 > /dev/null
tpm2_getrandom -o "$tmp/lockout.auth" 32 > /dev/null
head -c 8 "$tmp/owner.auth" > "$tmp/short.auth"
co() { env TACTIQ_NEW_OWNER_AUTH_FILE="$1" TACTIQ_NEW_LOCKOUT_AUTH_FILE="$2" "$agent" close-owner; }

echo "== close-owner refuses to run"
must_refuse "before provisioning"         co "$tmp/owner.auth" "$tmp/lockout.auth"
"$agent" provision TEST-CLOSE-OWNER > /dev/null || { echo "provision failed"; exit 2; }
must_refuse "before the stop counter"     co "$tmp/owner.auth" "$tmp/lockout.auth"
tpm2_nvdefine 0x1500017 -C o -a "nt=counter|authread|authwrite" > /dev/null || exit 2
tpm2_nvincrement 0x1500017 -C 0x1500017 || exit 2
must_refuse "with an 8-byte value"        co "$tmp/short.auth" "$tmp/lockout.auth"
must_refuse "with the same value twice"   co "$tmp/owner.auth" "$tmp/owner.auth"
must_work "and changed nothing"           tpm2_createprimary -C o -c z.ctx
tpm2_flushcontext -t > /dev/null 2>&1

if [ $close -eq 1 ]; then
  echo "== close-owner"
  co "$tmp/owner.auth" "$tmp/lockout.auth" || { echo "close-owner failed"; exit 1; }
else
  echo "== close-owner NOT run (--no-close): the refusals below must fail"
fi

echo "== a process with TPM access and no secret"
must_refuse "evict the AK"                tpm2_evictcontrol -C o -c 0x81010100
[ $close -eq 1 ] && must_refuse "evict the SRK" tpm2_evictcontrol -C o -c 0x81000001
must_refuse "delete the epoch counter"    tpm2_nvundefine 0x1500016 -C o
must_refuse "delete the stop counter"     tpm2_nvundefine 0x1500017 -C o
must_refuse "define a new index"          tpm2_nvdefine 0x1500099 -C o -s 8
must_refuse "create an owner primary"     tpm2_createprimary -C o -c x.ctx
# a value ahead of the TPM clock, so that a refusal is the authorization, not the range
ahead=$(( $(tpm2_readclock | sed -n 's/.*clock: \([0-9]*\).*/\1/p') + 600000 ))
must_refuse "move the TPM clock forward"  tpm2_setclock -c o "$ahead"
# last: in --no-close it succeeds and changes the owner value for the checks after it
must_refuse "set a new owner auth"        tpm2_changeauth -c owner "file:$tmp/lockout.auth"

echo "== what keeps working without the secret"
must_work "AK still in place"             tpm2_readpublic -c 0x81010100
must_work "agent attest"                  "$agent" attest
must_work "trip: increment the stop counter" tpm2_nvincrement 0x1500017 -C 0x1500017
must_work "read the stop counter"         tpm2_nvread 0x1500017 -C 0x1500017
if [ $close -eq 1 ]; then
  must_work "SRK persisted"               tpm2_readpublic -c 0x81000001
  must_work "create a key under the SRK"  tpm2_create -C 0x81000001 -G ecc256:ecdsa-sha256 \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" -u k.pub -r k.priv
  must_work "load it"                     tpm2_load -C 0x81000001 -u k.pub -r k.priv -c k.ctx
  must_work "AK certifies it"             tpm2_certify -c k.ctx -C 0x81010100 -g sha256 -o k.att -s k.sig

  echo "== with the secret: rotation"
  tpm2_getrandom -o "$tmp/owner2.auth" 32 > /dev/null
  tpm2_getrandom -o "$tmp/lockout2.auth" 32 > /dev/null
  must_work "close-owner again with the values in force" env \
    TACTIQ_OWNER_AUTH_FILE="$tmp/owner.auth" TACTIQ_LOCKOUT_AUTH_FILE="$tmp/lockout.auth" \
    TACTIQ_NEW_OWNER_AUTH_FILE="$tmp/owner2.auth" TACTIQ_NEW_LOCKOUT_AUTH_FILE="$tmp/lockout2.auth" \
    "$agent" close-owner
  must_refuse "the old owner value"       tpm2_createprimary -C o -P "file:$tmp/owner.auth" -c y.ctx
  must_work "the new owner value"         tpm2_createprimary -C o -P "file:$tmp/owner2.auth" -c y.ctx
  tpm2_flushcontext -t > /dev/null 2>&1
  must_refuse "close-owner again without the value in force" env \
    TACTIQ_NEW_OWNER_AUTH_FILE="$tmp/owner.auth" TACTIQ_NEW_LOCKOUT_AUTH_FILE="$tmp/lockout.auth" \
    "$agent" close-owner
fi

echo "RESULT: $([ $fail -eq 0 ] && echo 'all checks held' || echo 'FAILED')"
exit $fail
