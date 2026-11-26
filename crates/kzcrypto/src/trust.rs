//! Trusted CA certificates (the caller's) and certificate path checks against them, under a
//! [`Policy`].

use crate::cert::{self, Cert};
use crate::prelude::*;

/// Tolerances for checks, set by whoever runs them (the NCA ones are in `kzcrypto-nca`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Policy {
    /// How far ahead of the clock a server's or CA's time may be, in milliseconds.
    pub clock_skew_ms: i64,
    /// How old a fresh OCSP answer without nextUpdate (and without the nonce echoed) may be, in
    /// milliseconds.
    pub ocsp_max_age_ms: i64,
    /// The most issuers in a certificate path.
    pub max_path_len: usize,
}

impl Policy {
    /// 5 minutes of clock skew, OCSP answers up to an hour old, at most 10 issuers.
    pub const DEFAULT: Policy = Policy {
        clock_skew_ms: 5 * 60 * 1000,
        ocsp_max_age_ms: 60 * 60 * 1000,
        max_path_len: 10,
    };

    pub const fn new(clock_skew_ms: i64, ocsp_max_age_ms: i64, max_path_len: usize) -> Policy {
        Policy {
            clock_skew_ms,
            ocsp_max_age_ms,
            max_path_len,
        }
    }
}

impl Default for Policy {
    fn default() -> Policy {
        Policy::DEFAULT
    }
}

/// What a path check found. Names are certificates' common names.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathStatus {
    /// The path ends at the trusted CA `ca`.
    Trusted { ca: String },
    /// No trusted certificate issued `issuer`'s certificate (the path is not wrong, just not
    /// known to be good).
    IssuerNotFound { issuer: String },
    /// `cert` was not valid at `at` (milliseconds since 1970, UTC).
    NotValidAt { cert: String, at: i64 },
    /// A trusted root's own signature does not verify.
    BadRootSignature,
    /// A self-signed certificate that is not trusted.
    UntrustedSelfSigned { cert: String },
    /// An issuer in the path is not a CA.
    IssuerNotCa { issuer: String },
    /// An issuer in the path may not sign certificates (key usage).
    IssuerMayNotSignCerts { issuer: String },
    /// More issuers than [`Policy::max_path_len`].
    TooLong,
}

/// Outcome of a path check. `issuer` is the certificate's direct issuer, if found.
pub struct Chain {
    /// The path ends at a trusted CA ([`PathStatus::Trusted`]).
    pub ok: bool,
    pub status: PathStatus,
    pub path: Vec<String>,
    pub issuer: Option<Cert>,
    /// The issuers found, from the direct issuer up to the trusted CA.
    pub issuers: Vec<Cert>,
}

/// The CA certificates a caller trusts, and the [`Policy`] checks run under. It trusts nothing
/// on its own: `kzcrypto-nca` gives one with NCA RK's CAs.
pub struct TrustStore {
    trusted: Vec<Cert>,
    pub policy: Policy,
}

impl TrustStore {
    /// A store that trusts `cas` alone, under [`Policy::DEFAULT`].
    pub fn new(cas: Vec<Cert>) -> TrustStore {
        TrustStore {
            trusted: cas,
            policy: Policy::DEFAULT,
        }
    }

    /// The same store under `policy`.
    pub fn with_policy(mut self, policy: Policy) -> TrustStore {
        self.policy = policy;
        self
    }

    /// The trusted certificates.
    pub fn certs(&self) -> &[Cert] {
        &self.trusted
    }

    /// Builds the path from `c` to a trusted CA using only trusted certificates, never ones
    /// carried in a file. Checks every signature, validity at `at`, and that each issuer is a CA
    /// allowed to sign certificates.
    pub fn check(&self, c: &Cert, at: i64) -> Chain {
        let mut path = Vec::new();
        let mut issuers: Vec<Cert> = Vec::new();
        let r = self.walk(c, at, &mut path, &mut issuers);
        let issuer = issuers.first().cloned();
        Chain {
            ok: matches!(r, PathStatus::Trusted { .. }),
            status: r,
            path,
            issuer,
            issuers,
        }
    }

    fn walk(&self, c: &Cert, at: i64, path: &mut Vec<String>, seen: &mut Vec<Cert>) -> PathStatus {
        let mut cur = c.clone();
        let mut is_start = true;
        loop {
            path.push(cur.cn());
            if !cur.valid_on(at) {
                return PathStatus::NotValidAt { cert: cur.cn(), at };
            }
            let self_signed = cur.self_issued();
            if self.trusted.contains(&cur) && (!is_start || self_signed) {
                if self_signed && !cur.signed_by(&cur) {
                    return PathStatus::BadRootSignature;
                }
                return PathStatus::Trusted { ca: cur.cn() };
            }
            let Some(issuer) = self.find_issuer(&cur, seen) else {
                if self_signed {
                    return PathStatus::UntrustedSelfSigned { cert: cur.cn() };
                }
                return PathStatus::IssuerNotFound {
                    issuer: cert::cn(&cur.issuer),
                };
            };
            if !issuer.is_ca() {
                return PathStatus::IssuerNotCa {
                    issuer: issuer.cn(),
                };
            }
            if !issuer.may_sign_certs() {
                return PathStatus::IssuerMayNotSignCerts {
                    issuer: issuer.cn(),
                };
            }
            seen.push(issuer.clone());
            cur = issuer;
            is_start = false;
            if seen.len() > self.policy.max_path_len {
                return PathStatus::TooLong;
            }
        }
    }

    /// Trusts one more CA certificate.
    pub fn add(&mut self, ca: Cert) {
        self.trusted.push(ca);
    }

    fn find_issuer(&self, c: &Cert, seen: &[Cert]) -> Option<Cert> {
        self.trusted
            .iter()
            .filter(|t| cert::names_equal(&t.subject, &c.issuer) && !seen.contains(t))
            // a different key under the same name fails here; keep looking
            .find(|t| c.signed_by(t))
            .cloned()
    }
}
