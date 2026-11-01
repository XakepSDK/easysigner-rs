//! Trusted CA certificates (bundled NCA RK roots and intermediates, plus --trust) and
//! certificate path checks against them.

use crate::cert::{self, Cert};
use crate::{Result, time};

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

/// Outcome of a path check. `issuer` is the certificate's direct issuer, if found.
pub struct Chain {
    pub ok: bool,
    pub status: String,
    pub path: Vec<String>,
    pub issuer: Option<Cert>,
}

pub struct TrustStore {
    trusted: Vec<Cert>,
}

impl TrustStore {
    /// `extra`: CA certificates to trust on top of the bundled NCA RK ones.
    pub fn new(extra: Vec<Cert>) -> TrustStore {
        let mut trusted: Vec<Cert> = BUNDLED_CA
            .iter()
            .map(|(n, d)| {
                Cert::parse_any(d).unwrap_or_else(|e| panic!("bundled certificate {n}: {e}"))
            })
            .collect();
        trusted.extend(extra);
        TrustStore { trusted }
    }

    /// Builds the path from `c` to a trusted CA using only trusted certificates, never ones
    /// carried in a file. Checks every signature, validity at `at`, and that each issuer is a CA
    /// allowed to sign certificates.
    pub fn check(&self, c: &Cert, at: i64) -> Chain {
        let mut path = Vec::new();
        let mut first_issuer: Option<Cert> = None;
        let r = self.walk(c, at, &mut path, &mut first_issuer);
        match r {
            Ok((ok, status)) => Chain {
                ok,
                status,
                path,
                issuer: first_issuer,
            },
            Err(e) => Chain {
                ok: false,
                status: format!("Certificate path not valid: {e}"),
                path,
                issuer: first_issuer,
            },
        }
    }

    fn walk(
        &self,
        c: &Cert,
        at: i64,
        path: &mut Vec<String>,
        first_issuer: &mut Option<Cert>,
    ) -> std::result::Result<(bool, String), String> {
        let mut cur = c.clone();
        let mut seen: Vec<Cert> = Vec::new();
        let mut is_start = true;
        loop {
            path.push(cur.cn());
            if !cur.valid_on(at) {
                return Err(format!(
                    "certificate '{}' was not valid on {}",
                    cur.cn(),
                    time::fmt(Some(at))
                ));
            }
            let self_signed = cur.self_issued();
            if self.trusted.contains(&cur) && (!is_start || self_signed) {
                if self_signed && !cur.signed_by(&cur) {
                    return Err("root certificate signature is invalid".into());
                }
                return Ok((true, format!("Issued by a trusted CA: {}", cur.cn())));
            }
            let Some(issuer) = self.find_issuer(&cur, &seen) else {
                if self_signed {
                    return Err(format!(
                        "self-signed certificate '{}' is not a trusted root",
                        cur.cn()
                    ));
                }
                return Ok((
                    false,
                    format!(
                        "Issuer not found among trusted NCA RK certificates: {}",
                        cert::cn(&cur.issuer)
                    ),
                ));
            };
            require_ca(&issuer)?;
            if first_issuer.is_none() {
                *first_issuer = Some(issuer.clone());
            }
            seen.push(issuer.clone());
            cur = issuer;
            is_start = false;
            if seen.len() > 10 {
                return Err("certificate path too long".into());
            }
        }
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

fn require_ca(issuer: &Cert) -> std::result::Result<(), String> {
    if !issuer.is_ca() {
        return Err(format!("issuer '{}' is not a CA", issuer.cn()));
    }
    if !issuer.may_sign_certs() {
        return Err(format!(
            "issuer '{}' may not sign certificates",
            issuer.cn()
        ));
    }
    Ok(())
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
