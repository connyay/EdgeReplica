//! Wall-clock helpers. Trait-based so tests can inject a fixed clock and so
//! the wasm32 worker can plug in a `worker::Date`-backed impl without
//! pulling worker-rs into this crate.

use std::sync::Arc;

pub trait Clock: Send + Sync + 'static {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;

    fn now_unix_seconds(&self) -> i64 {
        self.now_ms() / 1000
    }
}

pub type SharedClock = Arc<dyn Clock>;

/// Host-only clock backed by `std::time::SystemTime`. The worker crate
/// supplies its own wasm32 clock via `worker::Date`.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
pub struct SystemClock;

#[cfg(not(target_arch = "wasm32"))]
impl SystemClock {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_millis() as i64
    }
}

/// Mockable clock for tests. Available outside `cfg(test)` so dependent
/// crates can use it in their own test modules.
pub struct FixedClock {
    pub at_ms: std::sync::atomic::AtomicI64,
}

impl FixedClock {
    pub fn new(now_ms: i64) -> Arc<Self> {
        Arc::new(Self {
            at_ms: std::sync::atomic::AtomicI64::new(now_ms),
        })
    }

    pub fn advance(&self, by_ms: i64) {
        self.at_ms
            .fetch_add(by_ms, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.at_ms.load(std::sync::atomic::Ordering::Relaxed)
    }
}
