#!/bin/sh
# How the receipts in this directory were made: tactiq-stop of this tree
# against swtpm 0.7.3 and tpm2-tools 5.6, AK by tpm2_createak at 0x81010100,
# device TACTIQ-SWTPM-01, PCR 0, 1, 8 at reset value. Each receipt answers its
# own nonce (`<name>.nonce`, from `tactiq-stop-verify nonce`).
#
#   s1, s2   stopped at counter 1, one TPM boot, s2 two seconds after s1
#   rs       after Shutdown(STATE) and Startup(STATE): restartCount + 1
#   rb       after Shutdown(CLEAR) and Startup(CLEAR): resetCount + 1, a reboot
#   m0, m2   counter 1, then the counter incremented twice (3): a lift and a
#            new trip move it the same way
#   ev       one more increment: counter 4, even, no release
#   mix-no   after `tactiq-stop trip` (counter 5), built by ../forge.py's
#            functions: certify and quote in one boot
#            (a control that must pass `verify_stop_receipt`)
#   mix-yes  the same, with Shutdown(STATE) and Startup(STATE) between the
#            certify and the quote
#
# The tests in stop_interval_swtpm.rs check these bytes; this script only
# records the steps. It needs root (the service's paths are fixed), swtpm on
# 2321/2322, a swtpm_restart function of the bench and TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321.
set -e
# A power cycle as the TPM sees it: Shutdown, the swtpm process stopped and
# started again on the same state directory (--flags not-need-init), Startup.
cycle() { tpm2_shutdown ${1:+-c}; swtpm_restart; tpm2_startup ${1:+-c}; }
take() { n=$(tactiq-stop-verify nonce); echo "$n" > "$1.nonce"; tactiq-stop status "$n" > "$1.tqsr"; }
tactiq-stop define --initial stopped
take s1; sleep 2; take s2
cycle; take rs
cycle clear; take rb
take m0; tpm2_nvincrement 0x1500017 -C 0x1500017; tpm2_nvincrement 0x1500017 -C 0x1500017; take m2
tpm2_nvincrement 0x1500017 -C 0x1500017; take ev
