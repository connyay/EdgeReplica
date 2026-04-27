//! `worker::Date`-backed `Clock` impl for the wasm32 worker isolate.
//! `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`, so
//! the host-only `SystemClock` from `edgereplica-shared` isn't usable inside
//! the worker; this provides the wasm equivalent.

#![cfg(target_arch = "wasm32")]

use edgereplica_shared::Clock;

#[derive(Default)]
pub struct WorkerDateClock;

impl WorkerDateClock {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for WorkerDateClock {
    fn now_ms(&self) -> i64 {
        worker::Date::now().as_millis() as i64
    }
}
