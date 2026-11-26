//! What the core reaches outside itself for: the CAs it trusts, the network (NCA's timestamp,
//! OCSP and CRL servers) and the clock. [`Engine`](crate::Engine) holds one [`Env`]; tests
//! give it an in-memory [`Transport`] and a fixed [`Clock`] instead of the real ones. An `Env`
//! also keeps the revocation lists it has fetched (see [`crate::crl`]).

use std::sync::Arc;

use crate::trust::TrustStore;
use crate::{Result, Server};

/// Talks to the servers. [`Http`] is the real one.
pub trait Transport: Send + Sync {
    /// POSTs `body` to `server` at `url`; the answer's body.
    fn post(&self, server: Server, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>>;
    /// GETs `url` (a revocation list), refusing answers over `limit` bytes.
    fn get(&self, server: Server, url: &str, limit: u64) -> Result<Vec<u8>>;
}

/// The network, over HTTP ([`crate::http`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct Http;

impl Transport for Http {
    fn post(&self, server: Server, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>> {
        crate::http::post(url, content_type, body, server)
    }
    fn get(&self, server: Server, url: &str, limit: u64) -> Result<Vec<u8>> {
        crate::http::get(url, limit, server)
    }
}

/// The time now, in milliseconds since 1970 (UTC).
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

/// The system's clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        crate::time::now_ms()
    }
}

/// A clock stopped at one time, for tests.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub i64);

impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.0
    }
}

/// The trusted CAs, the network and the clock, passed together.
pub struct Env {
    pub trust: TrustStore,
    pub net: Arc<dyn Transport>,
    pub clock: Arc<dyn Clock>,
    /// Revocation lists fetched so far.
    pub(crate) crls: crate::crl::Cache,
}

impl Env {
    /// The real network and clock.
    pub fn new(trust: TrustStore) -> Env {
        Env {
            trust,
            net: Arc::new(Http),
            clock: Arc::new(SystemClock),
            crls: Default::default(),
        }
    }

    pub fn with_net(mut self, net: Arc<dyn Transport>) -> Env {
        self.net = net;
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Env {
        self.clock = clock;
        self
    }

    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }
}

impl std::fmt::Debug for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Env").finish_non_exhaustive()
    }
}
