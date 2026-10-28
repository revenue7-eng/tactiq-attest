//! The service's view of the TPM, as a trait, so every decision the service
//! makes can be tested without a chip. `Real` forwards to `attest-tpm`, where
//! every TPM call of every device binary lives.

use std::path::Path;

pub type R<T> = Result<T, String>;

/// What the stop service needs from the TPM, and nothing more.
pub trait StopTpm {
    /// Current value of the stop counter.
    fn read_counter(&self) -> R<u64>;
    /// Advance the stop counter by one.
    fn increment(&self) -> R<()>;
    /// TPM-signed statement of the stop counter's value, bound to
    /// `qualifying`. Returns (TPMS_ATTEST, signature).
    fn certify(&self, qualifying: &[u8; 32]) -> R<(Vec<u8>, Vec<u8>)>;
    /// Raw contents of the PCRs in `spec`.
    fn pcr_read(&self, spec: &str) -> R<Vec<u8>>;
    /// Quote over `spec` with the given qualifying data.
    /// Returns (TPMS_ATTEST, signature).
    fn quote(&self, qualifying: &[u8; 32], spec: &str) -> R<(Vec<u8>, Vec<u8>)>;
}

/// Where the operator's release is read from. `None` when there is none:
/// that is a stop, not an error. Any other failure to read is an error, and
/// the caller denies.
pub trait ReleaseStore {
    /// (record, signature), each read whole and at most `limit` bytes.
    fn read(&self) -> R<Option<(Vec<u8>, Vec<u8>)>>;
}

/// The release files on the device, read on every check: a release that is
/// removed or replaced takes effect on the next call, and nothing is cached.
pub struct ReleaseFiles {
    pub record: &'static str,
    pub sig: &'static str,
}

impl ReleaseStore for ReleaseFiles {
    fn read(&self) -> R<Option<(Vec<u8>, Vec<u8>)>> {
        let rec = match read_bounded(Path::new(self.record), crate::release::MAX_RECORD)? {
            Some(b) => b,
            None => return Ok(None),
        };
        match read_bounded(Path::new(self.sig), crate::release::MAX_SIG)? {
            Some(sig) => Ok(Some((rec, sig))),
            // A record without its signature is no release.
            None => Ok(None),
        }
    }
}

/// The whole file if it exists and is at most `limit` bytes; `None` if it
/// does not exist. A longer file is an error rather than a truncated read.
fn read_bounded(p: &Path, limit: usize) -> R<Option<Vec<u8>>> {
    use std::io::Read;
    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", p.display())),
    };
    let mut buf = Vec::new();
    f.take(limit as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {}: {e}", p.display()))?;
    if buf.len() > limit {
        return Err(format!("{}: more than {limit} bytes", p.display()));
    }
    Ok(Some(buf))
}

/// The chip, through `attest-tpm` and tpm2-tools. `scratch` must be a
/// directory private to this process: the tools write their outputs there.
pub struct Real<'a> {
    pub scratch: &'a Path,
}

impl StopTpm for Real<'_> {
    fn read_counter(&self) -> R<u64> {
        attest_tpm::stop_nv_read()
    }

    fn increment(&self) -> R<()> {
        attest_tpm::stop_nv_increment()
    }

    fn certify(&self, qualifying: &[u8; 32]) -> R<(Vec<u8>, Vec<u8>)> {
        let (a, s) = (self.scratch.join("certify.attest"), self.scratch.join("certify.sig"));
        attest_tpm::stop_nv_certify(qualifying, &a, &s)?;
        read_pair(&a, &s)
    }

    fn pcr_read(&self, spec: &str) -> R<Vec<u8>> {
        attest_tpm::pcr_read(spec, self.scratch)
    }

    fn quote(&self, qualifying: &[u8; 32], spec: &str) -> R<(Vec<u8>, Vec<u8>)> {
        let (a, s) = (self.scratch.join("quote.attest"), self.scratch.join("quote.sig"));
        attest_tpm::quote_qualified(qualifying, spec, &a, &s)?;
        read_pair(&a, &s)
    }
}

fn read_pair(a: &Path, s: &Path) -> R<(Vec<u8>, Vec<u8>)> {
    let attest = std::fs::read(a).map_err(|e| format!("read {}: {e}", a.display()))?;
    let sig = std::fs::read(s).map_err(|e| format!("read {}: {e}", s.display()))?;
    Ok((attest, sig))
}

#[cfg(test)]
pub mod fake {
    //! A TPM stand-in for tests. The counter lives in a cell. `certify`
    //! returns a real `TPM_ST_ATTEST_NV` layout (built by attest-stop's test
    //! helper), so the service's own check of it runs as it would on a chip.
    //! Failure switches cover the paths the first version left untested.

    use super::{ReleaseStore, StopTpm, R};
    use attest_stop::{build_nv_certify_info_for_tests, NvCertifyInfo};
    use std::cell::{Cell, RefCell};

    pub const INDEX_NAME: [u8; 4] = [0x00, 0x0b, 0x15, 0x17];

    /// A release held in memory; `fail` makes every read an error.
    #[derive(Default)]
    pub struct FakeRelease {
        pub files: RefCell<Option<(Vec<u8>, Vec<u8>)>>,
        pub fail: Cell<bool>,
    }

    impl FakeRelease {
        pub fn none() -> Self {
            Self::default()
        }
        pub fn signed(device: &str, epoch: u64) -> Self {
            let r = crate::release::testkey::record(device, epoch);
            let s = crate::release::testkey::sign(&r);
            let f = Self::default();
            *f.files.borrow_mut() = Some((r, s));
            f
        }
    }

    impl ReleaseStore for FakeRelease {
        fn read(&self) -> R<Option<(Vec<u8>, Vec<u8>)>> {
            if self.fail.get() {
                return Err("fake: release unreadable".into());
            }
            Ok(self.files.borrow().clone())
        }
    }

    pub struct Fake {
        pub counter: Cell<u64>,
        pub reads: Cell<u32>,
        /// Fail every read whose ordinal (1-based) is >= this, if set.
        pub fail_reads_from: Cell<Option<u32>>,
        pub fail_increment: Cell<bool>,
        pub fail_certify: Cell<bool>,
        pub fail_quote: Cell<bool>,
        /// Another writer advances the counter just before the TPM reads it.
        pub move_before_certify: Cell<bool>,
        /// Another writer advances the counter on every increment we make.
        pub double_increment: Cell<bool>,
        /// The certify names this index instead of the stop counter.
        pub certify_other_index: Cell<bool>,
        pub certified: RefCell<Vec<[u8; 32]>>,
        pub quoted: RefCell<Vec<[u8; 32]>>,
    }

    impl Fake {
        pub fn at(counter: u64) -> Self {
            Fake {
                counter: Cell::new(counter),
                reads: Cell::new(0),
                fail_reads_from: Cell::new(None),
                fail_increment: Cell::new(false),
                fail_certify: Cell::new(false),
                fail_quote: Cell::new(false),
                move_before_certify: Cell::new(false),
                double_increment: Cell::new(false),
                certify_other_index: Cell::new(false),
                certified: RefCell::new(Vec::new()),
                quoted: RefCell::new(Vec::new()),
            }
        }
    }

    impl StopTpm for Fake {
        fn read_counter(&self) -> R<u64> {
            let n = self.reads.get() + 1;
            self.reads.set(n);
            if self.fail_reads_from.get().is_some_and(|k| n >= k) {
                return Err("fake: TPM busy".into());
            }
            Ok(self.counter.get())
        }

        fn increment(&self) -> R<()> {
            if self.fail_increment.get() {
                return Err("fake: increment failed".into());
            }
            let step = if self.double_increment.get() { 2 } else { 1 };
            self.counter.set(self.counter.get() + step);
            Ok(())
        }

        fn certify(&self, qualifying: &[u8; 32]) -> R<(Vec<u8>, Vec<u8>)> {
            if self.fail_certify.get() {
                return Err("fake: certify failed".into());
            }
            if self.move_before_certify.get() {
                self.counter.set(self.counter.get() + 1);
            }
            self.certified.borrow_mut().push(*qualifying);
            let index_name =
                if self.certify_other_index.get() { vec![0x00, 0x0b, 0xEE] } else { INDEX_NAME.to_vec() };
            let a = build_nv_certify_info_for_tests(&NvCertifyInfo {
                qualified_signer: vec![0x00, 0x0b, 0xAA],
                extra_data: qualifying.to_vec(),
                index_name,
                offset: 0,
                contents: self.counter.get().to_be_bytes().to_vec(),
            });
            Ok((a, vec![0xC5; 64]))
        }

        fn pcr_read(&self, _spec: &str) -> R<Vec<u8>> {
            Ok(vec![0xAB; 96])
        }

        fn quote(&self, qualifying: &[u8; 32], _spec: &str) -> R<(Vec<u8>, Vec<u8>)> {
            if self.fail_quote.get() {
                return Err("fake: quote failed".into());
            }
            self.quoted.borrow_mut().push(*qualifying);
            Ok((b"quote".to_vec(), vec![0x51; 64]))
        }
    }
}
