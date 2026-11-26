//! Trusted CA certificates (bundled NCA RK roots and intermediates, plus --trust) and
//! certificate path checks against them.

use crate::Result;
use crate::cert::{self, Cert};
use crate::prelude::*;

/// NCA RK's root and issuing CA certificates, bundled into the executable.
pub const BUNDLED_CA: [(&str, &[u8]); 10] = [
    (
        "root_gost_2022",
        include_bytes!("../certs/root_gost_2022.cer"),
    ),
    ("root_gost", include_bytes!("../certs/root_gost.cer")),
    (
        "root_rsa_2022",
        include_bytes!("../certs/root_rsa_2022.cer"),
    ),
    ("root_rsa", include_bytes!("../certs/root_rsa.cer")),
    (
        "nca_gost_2022",
        include_bytes!("../certs/nca_gost_2022.cer"),
    ),
    ("nca_gost", include_bytes!("../certs/nca_gost.cer")),
    ("nca_rsa_2022", include_bytes!("../certs/nca_rsa_2022.cer")),
    ("nca_rsa", include_bytes!("../certs/nca_rsa.cer")),
    ("nca_gost_old", include_bytes!("../certs/nca_gost_old.cer")),
    ("nca_rsa_old", include_bytes!("../certs/nca_rsa_old.cer")),
];

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
    /// More than 10 issuers.
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

pub struct TrustStore {
    /// The bundled NCA RK certificates, then the extra ones.
    trusted: Vec<Cert>,
    bundled: usize,
}

impl TrustStore {
    /// `extra`: CA certificates to trust on top of the bundled NCA RK ones.
    pub fn new(extra: Vec<Cert>) -> TrustStore {
        let mut trusted: Vec<Cert> = BUNDLED_CA
            .iter()
            .map(|(n, d)| {
                Cert::parse_any(d).unwrap_or_else(|e| panic!("bundled certificate {n}: {e:?}"))
            })
            .collect();
        let bundled = trusted.len();
        trusted.extend(extra);
        TrustStore { trusted, bundled }
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
            if seen.len() > 10 {
                return PathStatus::TooLong;
            }
        }
    }

    /// A store that trusts nothing, not even NCA RK (for tests, and for callers that bring
    /// their own CAs with [`TrustStore::only`]).
    pub fn empty() -> TrustStore {
        TrustStore::only(vec![])
    }

    /// A store that trusts `cas` alone, without the bundled NCA RK certificates.
    pub fn only(cas: Vec<Cert>) -> TrustStore {
        TrustStore {
            trusted: cas,
            bundled: 0,
        }
    }

    /// Trusts one more CA certificate.
    pub fn add(&mut self, ca: Cert) {
        self.trusted.push(ca);
    }

    /// Whether `c` is one of the bundled NCA RK CA certificates.
    pub fn is_nca(&self, c: &Cert) -> bool {
        self.trusted[..self.bundled].contains(c)
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

/// Checks the bundled certificates against each other: how many have a signature that no
/// bundled issuer verifies.
pub fn check_bundled() -> Result<(usize, usize)> {
    let all: Vec<Cert> = BUNDLED_CA
        .iter()
        .map(|(_, d)| Cert::parse_any(d))
        .collect::<Result<_>>()?;
    let bad = all
        .iter()
        .filter(|c| {
            !all.iter()
                .any(|i| cert::names_equal(&i.subject, &c.issuer) && c.signed_by(i))
        })
        .count();
    Ok((all.len(), bad))
}
