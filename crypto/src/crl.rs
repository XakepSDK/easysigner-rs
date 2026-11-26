//! Certificate revocation lists (X.509 CRLs, RFC 5280 §5), the fallback when OCSP gives no
//! answer (Order 500/НҚ p.4.3, p.16, p.18). A list counts only when it is DER, issued and signed
//! by the certificate's own CA, current (one past its nextUpdate gives no positive result) and
//! has no critical extension kzsigner doesn't understand. When the certificate or the list
//! names delta lists (freshest CRL), a current delta must be read too, or there is no answer.
//!
//! The caller downloads the lists from the addresses [`urls`] and [`delta_urls`] give.

use crate::cert::{self, Cert};
pub use crate::ocsp::CertStatus;
use crate::prelude::*;
use crate::text::{Text, Time, tr, trf};
use crate::{Error, ErrorKind, Result};

const CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
const FRESHEST_CRL: &str = "2.5.29.46";
const DELTA_CRL_INDICATOR: &str = "2.5.29.27";
/// Critical list extensions that change nothing for this check.
const UNDERSTOOD: [&str; 4] = [
    "2.5.29.20", // cRLNumber
    "2.5.29.35", // authorityKeyIdentifier
    DELTA_CRL_INDICATOR,
    FRESHEST_CRL,
];
const MINUTE: i64 = 60 * 1000;

/// CertificateList (RFC 5280 5.1) from x509-cert's parts. x509-cert's own `TbsCertList` makes
/// the version mandatory, but RFC 5280 has it OPTIONAL (absent in v1 lists).
#[derive(::der::Sequence)]
struct CertificateList {
    tbs_cert_list: TbsCertList,
    signature_algorithm: spki::AlgorithmIdentifierOwned,
    signature: ::der::asn1::BitString,
}

#[derive(::der::Sequence)]
struct TbsCertList {
    #[asn1(optional = "true")]
    _version: Option<x509_cert::certificate::Version>,
    _signature: spki::AlgorithmIdentifierOwned,
    issuer: x509_cert::name::Name,
    this_update: x509_cert::time::Time,
    next_update: Option<x509_cert::time::Time>,
    revoked_certificates: Option<Vec<x509_cert::crl::RevokedCert<x509_cert::certificate::Raw>>>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    crl_extensions: Option<x509_cert::ext::Extensions>,
}

/// A parsed revocation list.
pub struct Crl {
    pub issuer: Vec<u8>,
    pub this_update: i64,
    pub next_update: Option<i64>,
    /// Serial numbers (as in [`Cert::serial`]) with their revocation dates.
    pub revoked: Vec<(Vec<u8>, i64)>,
    /// The same serials, with the moment their key stopped being trustworthy: the revocation
    /// date, an earlier invalidityDate, or never for a compromised key ([`i64::MIN`]).
    pub revoked_from: Vec<(Vec<u8>, i64)>,
    /// A delta list (deltaCRLIndicator).
    pub is_delta: bool,
    /// Delta lists this one names (freshestCRL), http only.
    pub freshest: Vec<String>,
    /// A critical extension kzsigner doesn't understand (e.g. a partial list's
    /// issuingDistributionPoint): the list can't be used.
    pub unknown_critical: Option<String>,
    /// The list as read, to keep in a signature (long-term validation data).
    pub raw: Vec<u8>,
    tbs: Vec<u8>,
    sig_alg: String,
    signature: Vec<u8>,
}

impl Crl {
    /// A list in DER, read by `x509-cert` (its `Raw` profile: serial numbers as CAs issue them).
    pub fn parse(data: &[u8]) -> Result<Crl> {
        use ::der::{Decode, Encode};
        let bad = || Error::of(ErrorKind::Malformed, tr("Unreadable revocation list (CRL)"));
        let l = CertificateList::from_der(data).map_err(|_| bad())?;
        let t = &l.tbs_cert_list;
        let ms = |t: &x509_cert::time::Time| {
            i64::try_from(t.to_unix_duration().as_millis()).map_err(|_| bad())
        };
        let mut revoked = Vec::new();
        let mut revoked_from = Vec::new();
        for e in t.revoked_certificates.iter().flatten() {
            let serial = strip_zeros(e.serial_number.as_bytes()).to_vec();
            let when = ms(&e.revocation_date)?;
            let from = match &e.crl_entry_extensions {
                Some(x) => untrusted_from(x, when).map_err(|_| bad())?,
                None => when,
            };
            revoked_from.push((serial.clone(), from));
            revoked.push((serial, when));
        }
        let (mut is_delta, mut freshest, mut unknown_critical) = (false, vec![], None);
        for x in t.crl_extensions.iter().flatten() {
            let oid = x.extn_id.to_string();
            match oid.as_str() {
                DELTA_CRL_INDICATOR => is_delta = true,
                FRESHEST_CRL => freshest = uris_in(x.extn_value.as_bytes()),
                o if x.critical && !UNDERSTOOD.contains(&o) => unknown_critical = Some(oid),
                _ => {}
            }
        }
        Ok(Crl {
            issuer: t.issuer.to_der().map_err(|_| bad())?,
            this_update: ms(&t.this_update)?,
            next_update: t.next_update.as_ref().map(ms).transpose()?,
            revoked,
            revoked_from,
            is_delta,
            freshest,
            unknown_critical,
            raw: data.to_vec(),
            tbs: t.to_der().map_err(|_| bad())?,
            sig_alg: l.signature_algorithm.oid.to_string(),
            signature: l.signature.as_bytes().ok_or_else(bad)?.to_vec(),
        })
    }

    /// Whether `issuer`'s key signed this list.
    pub fn signed_by(&self, issuer: &Cert) -> bool {
        issuer
            .public_key()
            .and_then(|k| k.verify(&self.sig_alg, None, &self.tbs, &self.signature))
            .unwrap_or(false)
    }

    /// Why this list can't be used for `c` (issued by `issuer`) at `now`; None when it can.
    pub fn unusable(&self, c: &Cert, issuer: &Cert, now: i64) -> Option<Text> {
        let why = if !cert::names_equal(&self.issuer, &c.issuer)
            || !cert::names_equal(&self.issuer, &issuer.subject)
        {
            "ERROR: the revocation list is not from the certificate's CA"
        } else if !self.signed_by(issuer) {
            "ERROR: the revocation list's signature is not valid"
        } else if self.this_update > now + 5 * MINUTE || self.next_update.is_none_or(|n| n < now) {
            "ERROR: the revocation list is out of date"
        } else if self.unknown_critical.is_some() {
            "ERROR: the revocation list has a critical extension kzsigner does not support"
        } else {
            return None;
        };
        Some(tr(why))
    }

    /// From when `c`'s key is not to be trusted, if `c` is listed (see [`Crl::revoked_from`]).
    pub fn untrusted_from(&self, c: &Cert) -> Option<i64> {
        self.revoked_from
            .iter()
            .find(|(s, _)| *s == c.serial)
            .map(|(_, when)| *when)
    }

    pub fn revocation_of(&self, c: &Cert) -> Option<i64> {
        self.revoked
            .iter()
            .find(|(s, _)| *s == c.serial)
            .map(|(_, when)| *when)
    }
}

/// A list entry's extensions: an invalidityDate before `when` moves the moment back, and a
/// compromise reason means the key was never to be trusted ([`i64::MIN`]).
fn untrusted_from(exts: &[x509_cert::ext::Extension], when: i64) -> ::der::Result<i64> {
    use ::der::Decode;
    use x509_cert::ext::pkix::CrlReason as R;
    let mut from = when;
    for x in exts {
        let value = x.extn_value.as_bytes();
        match x.extn_id.to_string().as_str() {
            REASON_CODE
                if matches!(
                    R::from_der(value),
                    Ok(R::KeyCompromise | R::CaCompromise | R::AaCompromise)
                ) =>
            {
                return Ok(i64::MIN);
            }
            INVALIDITY_DATE => {
                let d = ::der::asn1::GeneralizedTime::from_der(value)?;
                let d = i64::try_from(d.to_unix_duration().as_millis())
                    .map_err(|_| ::der::Error::from(::der::ErrorKind::Overflow))?;
                from = from.min(d);
            }
            _ => {}
        }
    }
    Ok(from)
}

/// An INTEGER's content without leading zero bytes (one zero for zero), as [`Cert::serial`].
fn strip_zeros(mut b: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = b
        && !rest.is_empty()
    {
        b = rest;
    }
    b
}

const REASON_CODE: &str = "2.5.29.21";
const INVALIDITY_DATE: &str = "2.5.29.24";

/// The http addresses in a certificate's CRL distribution points extension.
pub fn urls(c: &Cert) -> Vec<String> {
    ext_uris(c, CRL_DISTRIBUTION_POINTS)
}

/// The http addresses of the delta lists (freshest CRL) that `c` and its full list `base` name.
pub fn delta_urls(c: &Cert, base: &Crl) -> Vec<String> {
    let mut u = ext_uris(c, FRESHEST_CRL);
    u.extend(base.freshest.iter().cloned());
    u
}

fn ext_uris(c: &Cert, oid: &str) -> Vec<String> {
    c.extensions
        .iter()
        .find(|(o, _)| o == oid)
        .map(|(_, v)| uris_in(v))
        .unwrap_or_default()
}

/// The http addresses in a CRL distribution points (or freshest CRL) extension value (DER):
/// the uniformResourceIdentifier full names of its distribution points.
pub fn uris_in(ext: &[u8]) -> Vec<String> {
    use ::der::Decode;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
    let Ok(dps) = x509_cert::ext::pkix::CrlDistributionPoints::from_der(ext) else {
        return vec![];
    };
    dps.0
        .iter()
        .filter_map(|dp| match &dp.distribution_point {
            Some(DistributionPointName::FullName(names)) => Some(names),
            _ => None,
        })
        .flatten()
        .filter_map(|n| match n {
            GeneralName::UniformResourceIdentifier(u) => Some(u.as_str()),
            _ => None,
        })
        .filter(|u| u.starts_with("http://"))
        .map(String::from)
        .collect()
}

/// What a full list and, when one is due, a delta list say about `c`: (good, status for
/// people, the answer, or None when they can't be used). `issuer` is `c`'s CA
/// certificate; `now` the moment of checking. A delta is required when `delta_due`.
pub fn evaluate(
    base: &Crl,
    delta: Option<&Crl>,
    delta_due: bool,
    c: &Cert,
    issuer: &Cert,
    now: i64,
) -> (bool, Text, Option<CertStatus>) {
    let no = |s: Text| (false, s, None);
    if base.is_delta {
        return no(tr("ERROR: the revocation list is not a full list"));
    }
    if let Some(why) = base.unusable(c, issuer, now) {
        return no(why);
    }
    if let Some(when) = base.revocation_of(c) {
        return revoked(when);
    }
    match delta {
        Some(d) => {
            if !d.is_delta {
                return no(tr("ERROR: the delta revocation list is not a delta list"));
            }
            if let Some(why) = d.unusable(c, issuer, now) {
                return no(why);
            }
            if let Some(when) = d.revocation_of(c) {
                return revoked(when);
            }
        }
        None if delta_due => {
            return no(tr("ERROR: the delta revocation list could not be read"));
        }
        None => {}
    }
    let at = delta.map_or(base.this_update, |d| d.this_update);
    (
        true,
        trf(
            "GOOD (not in the revocation list of {})",
            &[&Time(Some(at))],
        ),
        Some(CertStatus::Good),
    )
}

fn revoked(when: i64) -> (bool, Text, Option<CertStatus>) {
    (
        false,
        trf("REVOKED on {} (revocation list)", &[&Time(Some(when))]),
        Some(CertStatus::Revoked),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time;

    fn ext(oid: &str, value: &[u8]) -> x509_cert::ext::Extension {
        x509_cert::ext::Extension {
            extn_id: crate::asn1::oid(oid).unwrap(),
            critical: false,
            extn_value: ::der::asn1::OctetString::new(value).unwrap(),
        }
    }

    /// A list entry's reason and invalidity date decide from when its key is not trusted.
    #[test]
    fn untrusted_from_entry_extensions() {
        let when = 1_800_000_000_000;
        let from = |exts: &[&x509_cert::ext::Extension]| {
            let exts: Vec<_> = exts.iter().map(|&e| e.clone()).collect();
            untrusted_from(&exts, when).unwrap()
        };
        // ENUMERATED r
        let reason = |r: u8| ext(REASON_CODE, &[0x0a, 1, r]);
        let invalid = |t: i64| ext(INVALIDITY_DATE, &time::encode_generalized(t).unwrap());
        assert_eq!(from(&[]), when);
        assert_eq!(from(&[&reason(4)]), when, "superseded");
        for r in [1, 2, 10] {
            assert_eq!(from(&[&reason(r)]), i64::MIN, "reason {r}");
        }
        assert_eq!(from(&[&invalid(when - 5000)]), when - 5000);
        assert_eq!(from(&[&invalid(when + 5000)]), when, "never later");
        assert_eq!(from(&[&invalid(when - 5000), &reason(1)]), i64::MIN);
    }
}
