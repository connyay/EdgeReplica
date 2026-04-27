//! `x-request-id` tower middleware. Stamps each incoming `http::Request`
//! with a [`RequestId`] in extensions before `ConnectRpcService` dispatches.
//! Honors an inbound `x-request-id` header; otherwise draws from a
//! per-isolate monotonic counter so dev gets useful trace ids without
//! external coordination.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use http::HeaderValue;
use tower::{Layer, Service};

pub const HEADER_NAME: &str = "x-request-id";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(pub HeaderValue);

#[derive(Clone, Default)]
pub struct RequestIdLayer {
    counter: Arc<AtomicU64>,
}

impl RequestIdLayer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService {
            inner,
            counter: Arc::clone(&self.counter),
        }
    }
}

#[derive(Clone)]
pub struct RequestIdService<S> {
    inner: S,
    counter: Arc<AtomicU64>,
}

impl<S, B> Service<http::Request<B>> for RequestIdService<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let value = req.headers().get(HEADER_NAME).cloned().unwrap_or_else(|| {
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            HeaderValue::try_from(format!("req-{n}")).expect("counter id is ascii")
        });
        req.extensions_mut().insert(RequestId(value));
        self.inner.call(req)
    }
}
