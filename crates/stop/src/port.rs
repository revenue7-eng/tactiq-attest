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
    /// Quote over `spec` with qualifying data SHA-256(`msg`).
    /// Returns (TPMS_ATTEST, signature).
    fn quote(&self, msg: &[u8], spec: &str) -> R<(Vec<u8>, Vec<u8>)>;
}

/// The chip, through `attest-tpm` and tpm2-tools. Scratch files go to `work`.
pub struct Real<'a> {
    pub work: &'a Path,
}

impl StopTpm for Real<'_> {
    fn read_counter(&self) -> R<u64> {
        attest_tpm::stop_nv_read(self.work)
    }

    fn increment(&self) -> R<()> {
        attest_tpm::stop_nv_increment()
    }

    fn certify(&self, qualifying: &[u8; 32]) -> R<(Vec<u8>, Vec<u8>)> {
        let (a, s) = (self.work.join("stop-certify.attest"), self.work.join("stop-certify.sig"));
        attest_tpm::stop_nv_certify(qualifying, &a, &s)?;
        read_pair(&a, &s)
    }

    fn pcr_read(&self, spec: &str) -> R<Vec<u8>> {
        attest_tpm::pcr_read(spec, self.work)
    }

    fn quote(&self, msg: &[u8], spec: &str) -> R<(Vec<u8>, Vec<u8>)> {
        let (a, s) = (self.work.join("stop-quote.attest"), self.work.join("stop-quote.sig"));
        attest_tpm::quote(msg, spec, &a, &s)?;
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
    //! A TPM stand-in for tests: a counter in a cell, and "signatures" that
    //! are deterministic functions of their inputs so tests can check what
    //! was asked to be signed.

    use super::{StopTpm, R};
    use std::cell::{Cell, RefCell};

    pub struct Fake {
        pub counter: Cell<u64>,
        pub fail_read: Cell<bool>,
        pub fail_quote: Cell<bool>,
        pub certified: RefCell<Vec<[u8; 32]>>,
        pub quoted: RefCell<Vec<Vec<u8>>>,
    }

    impl Fake {
        pub fn at(counter: u64) -> Self {
            Fake {
                counter: Cell::new(counter),
                fail_read: Cell::new(false),
                fail_quote: Cell::new(false),
                certified: RefCell::new(Vec::new()),
                quoted: RefCell::new(Vec::new()),
            }
        }
    }

    impl StopTpm for Fake {
        fn read_counter(&self) -> R<u64> {
            if self.fail_read.get() {
                return Err("fake: TPM busy".into());
            }
            Ok(self.counter.get())
        }

        fn increment(&self) -> R<()> {
            self.counter.set(self.counter.get() + 1);
            Ok(())
        }

        fn certify(&self, qualifying: &[u8; 32]) -> R<(Vec<u8>, Vec<u8>)> {
            self.certified.borrow_mut().push(*qualifying);
            let mut a = b"nvcert".to_vec();
            a.extend_from_slice(&self.counter.get().to_be_bytes());
            a.extend_from_slice(qualifying);
            Ok((a, vec![0xC5; 64]))
        }

        fn pcr_read(&self, _spec: &str) -> R<Vec<u8>> {
            Ok(vec![0xAB; 96])
        }

        fn quote(&self, msg: &[u8], _spec: &str) -> R<(Vec<u8>, Vec<u8>)> {
            if self.fail_quote.get() {
                return Err("fake: quote failed".into());
            }
            self.quoted.borrow_mut().push(msg.to_vec());
            let mut a = b"quote".to_vec();
            a.extend_from_slice(msg);
            Ok((a, vec![0x51; 64]))
        }
    }
}
