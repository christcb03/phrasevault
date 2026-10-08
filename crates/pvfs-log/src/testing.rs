//! For tests whose daemon logs from another thread (pvfsd's serve threads),
//! where [`crate::capture`] — thread-local — sees nothing. While at least
//! one [`GlobalCapture`] lives, every record any thread emits is also kept
//! here (and still written as usual). Tests in one binary run in parallel
//! and share it, so a test picks its own records by a value only it uses.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::Record;

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static KEPT: Mutex<Vec<Record>> = Mutex::new(Vec::new());

pub(crate) fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed) > 0
}

pub(crate) fn offer(rec: &Record) {
    if active() {
        KEPT.lock().unwrap_or_else(|p| p.into_inner()).push(rec.clone());
    }
}

pub struct GlobalCapture {
    _private: (),
}

impl GlobalCapture {
    pub fn start() -> GlobalCapture {
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        GlobalCapture { _private: () }
    }

    /// Every record kept so far (from every test that is capturing).
    pub fn records(&self) -> Vec<Record> {
        KEPT.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The kept records with this event name.
    pub fn events(&self, event: &str) -> Vec<Record> {
        self.records().into_iter().filter(|r| r.event == event).collect()
    }
}

impl Drop for GlobalCapture {
    fn drop(&mut self) {
        if ACTIVE.fetch_sub(1, Ordering::SeqCst) == 1 {
            KEPT.lock().unwrap_or_else(|p| p.into_inner()).clear();
        }
    }
}
