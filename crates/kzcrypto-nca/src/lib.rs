//! NCA RK's data and rules, for [`kzcrypto`]: what the core leaves to its caller when the
//! caller works with Kazakhstan's National Certification Authority.
//!
//! * [`BUNDLED_CA`] and [`trust_store`]: NCA RK's root and issuing CA certificates;
//! * [`POLICY`]: the tolerances NCA's servers need (clock skew, OCSP freshness, path length);
//! * [`tsp`]: the TSA policy and hash NCALayer asks for, by key type;
//! * [`may_not_sign`]: who may sign documents (Order 500).
//!
//! Like kzcrypto it is `no_std` + `alloc`.

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;

use kzcrypto::cert::{ANY_POLICY, Cert, EKU_OCSP_SIGNING, EKU_TIME_STAMPING};
use kzcrypto::cert::{KU_DIGITAL_SIGNATURE, KU_NON_REPUDIATION};
use kzcrypto::trust::{Policy, TrustStore};
use kzcrypto::{Result, cert};

/// NCA RK's root and issuing CA certificates (DER), by file name.
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

/// The tolerances for NCA's servers: 5 minutes of clock skew, OCSP answers without nextUpdate
/// up to an hour old, at most 10 issuers in a path.
pub const POLICY: Policy = Policy::new(5 * 60 * 1000, 60 * 60 * 1000, 10);

/// The bundled certificates, read. A file that does not read is left out (the tests check
/// that every one reads).
pub fn bundled() -> Vec<Cert> {
    BUNDLED_CA
        .iter()
        .filter_map(|(_, d)| Cert::parse(d).ok())
        .collect()
}

/// A trust store with NCA RK's CA certificates, then `extra`, under [`POLICY`].
pub fn trust_store(extra: Vec<Cert>) -> TrustStore {
    let mut cas = bundled();
    cas.extend(extra);
    TrustStore::new(cas).with_policy(POLICY)
}

/// Whether `c` is one of NCA RK's bundled CA certificates.
pub fn is_nca(c: &Cert) -> bool {
    BUNDLED_CA.iter().any(|(_, d)| *d == c.der.as_slice())
}

/// Checks the bundled certificates against each other: how many there are, and how many have a
/// signature that no bundled issuer verifies.
pub fn check_bundled() -> Result<(usize, usize)> {
    let all: Vec<Cert> = BUNDLED_CA
        .iter()
        .map(|(_, d)| Cert::parse(d))
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

pub mod tsp {
    //! NCA's timestamp service (TSA): which policy and hash NCALayer asks for.

    use kzcrypto::gost;
    use kzcrypto::gost::Scheme;

    /// TSA policy for GOST 34.310-2004 keys (GOST 34.311-95 hashes).
    pub const POLICY_GOST2004: &str = "1.2.398.3.3.2.6.1";
    /// TSA policy for RSA keys (SHA-256 hashes).
    pub const POLICY_RSA: &str = "1.2.398.3.3.2.6.2";
    /// TSA policy for GOST 34.10-2015 keys (GOST 34.11-2015 512-bit hashes).
    pub const POLICY_GOST2015: &str = "1.2.398.3.3.2.6.4";

    /// The hash and NCA TSA policy NCALayer uses for each key type.
    pub fn hash_and_policy(scheme: Option<Scheme>) -> (&'static str, &'static str) {
        hash_and_policy_for(scheme.map_or("", |s| s.key_oid))
    }

    /// The hash and NCA TSA policy for timestamps over the work of a key of type `key_alg` (a
    /// certificate's key algorithm), as [`hash_and_policy`] picks them for a signing key.
    pub fn hash_and_policy_for(key_alg: &str) -> (&'static str, &'static str) {
        if key_alg == gost::KEY_GOST2004 {
            (gost::H_GOST34311, POLICY_GOST2004)
        } else if gost::is_gost(key_alg) {
            (gost::H_GOST2015_512, POLICY_GOST2015)
        } else {
            (gost::H_SHA256, POLICY_RSA)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn policies() {
            assert_eq!(
                hash_and_policy_for(gost::KEY_GOST2004),
                (gost::H_GOST34311, "1.2.398.3.3.2.6.1")
            );
            assert_eq!(
                hash_and_policy_for(gost::KEY_GOST2015_512),
                (gost::H_GOST2015_512, "1.2.398.3.3.2.6.4")
            );
            assert_eq!(
                hash_and_policy_for(gost::RSA_ENCRYPTION),
                (gost::H_SHA256, "1.2.398.3.3.2.6.2")
            );
            assert_eq!(hash_and_policy(None), hash_and_policy_for(""));
        }
    }
}

/// Why `c` may not sign documents under its CA's rules (Order 500/НҚ p.16.4): a CA key, key
/// usage without digitalSignature and nonRepudiation, a timestamp or OCSP service key, or (when
/// its CA `issuer` was found) certificate policies outside the CA's. Only the direct issuer's
/// policies count: NCA's issuing CAs have policies outside their root's. A CA without a
/// policies extension, or with anyPolicy, sets no rule on policies. None when it may.
pub fn may_not_sign(c: &Cert, issuer: Option<&Cert>) -> Option<SigningRefusal> {
    use SigningRefusal as R;
    if c.is_ca() {
        return Some(R::IsCa);
    }
    if c.key_usage()
        .is_some_and(|k| !bit(&k, KU_DIGITAL_SIGNATURE) && !bit(&k, KU_NON_REPUDIATION))
    {
        return Some(R::KeyUsage);
    }
    if c.has_eku(EKU_TIME_STAMPING) || c.has_eku(EKU_OCSP_SIGNING) {
        return Some(R::ServiceCert);
    }
    let allowed = match issuer?.policies()? {
        Ok(a) => a,
        Err(_) => return Some(R::CaPoliciesUnreadable),
    };
    if allowed.iter().any(|p| p == ANY_POLICY) {
        return None;
    }
    let under = |p: &String| {
        p == ANY_POLICY
            || allowed.iter().any(|a| {
                p == a
                    || p.strip_prefix(a.as_str())
                        .is_some_and(|r| r.starts_with('.'))
            })
    };
    match c.policies() {
        Some(Ok(own)) if own.iter().any(under) => None,
        Some(Ok(own)) if !own.is_empty() => Some(R::PolicyOutsideCa { own, allowed }),
        Some(Err(_)) => Some(R::PoliciesUnreadable),
        _ => Some(R::NoPolicy { allowed }),
    }
}

/// Whether key usage bit `n` is set (a bit past the end is not).
fn bit(k: &[bool], n: usize) -> bool {
    k.get(n).copied().unwrap_or(false)
}

/// Why a certificate may not sign documents ([`may_not_sign`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningRefusal {
    /// It is a CA's certificate.
    IsCa,
    /// Its key usage allows neither digitalSignature nor nonRepudiation.
    KeyUsage,
    /// It is a timestamp or OCSP service's certificate.
    ServiceCert,
    /// The CA certificate's policies can't be read.
    CaPoliciesUnreadable,
    /// The certificate's policies can't be read.
    PoliciesUnreadable,
    /// Its policies (`own`) are outside the CA's (`allowed`).
    PolicyOutsideCa {
        own: Vec<String>,
        allowed: Vec<String>,
    },
    /// It names no policy, but its CA issues under `allowed`.
    NoPolicy { allowed: Vec<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_certificates() {
        assert_eq!(bundled().len(), BUNDLED_CA.len());
        assert_eq!(check_bundled().unwrap(), (10, 0));
        let store = trust_store(Vec::new());
        assert_eq!(store.certs().len(), 10);
        assert_eq!(store.policy, POLICY);
        assert!(store.certs().iter().all(is_nca));
    }
}
