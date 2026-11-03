//! Certificate revocation lists (X.509 CRLs, RFC 5280 §5), the fallback when OCSP gives no
//! answer (Order 500/НҚ p.4.3, p.16, p.18). A list counts only when it is DER, issued and signed
//! by the certificate's own CA, current (one past its nextUpdate gives no positive result) and
//! has no critical extension kzsigner doesn't understand. When the certificate or the list
//! names delta lists (freshest CRL), a current delta must be read too, or there is no answer.
//!
//! Lists come from the certificate's CRL distribution points (http). Parsed lists are kept in
//! memory for at most an hour (and never past their nextUpdate); an address that failed is not
//! tried again for five minutes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::cert::{self, Cert};
use crate::der::{self, Tlv};
use crate::i18n::{tr, trf};
use crate::{Error, Result, http, time};

/// NCA's full lists are large (tens of MB); refuse anything beyond this.
const MAX_CRL: u64 = 256 << 20;
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
    pub fn parse(data: &[u8]) -> Result<Crl> {
        let bad = || Error::new(tr("Unreadable revocation list (CRL)"));
        let top = der::parse(data)?.items(der::SEQUENCE)?;
        if top.len() < 3 {
            return Err(bad());
        }
        let tbs = top[0].items(der::SEQUENCE)?;
        // version (optional), signature, issuer, thisUpdate, nextUpdate?, revoked?, [0] ext?
        let i = usize::from(tbs.first().is_some_and(|t| t.tag == der::INTEGER)) + 1;
        let issuer = tbs.get(i).ok_or_else(bad)?.raw.to_vec();
        let this_update = tbs.get(i + 1).ok_or_else(bad)?.time()?;
        let mut j = i + 2;
        let next_update = match tbs.get(j) {
            Some(t) if t.tag == der::UTC_TIME || t.tag == der::GENERALIZED_TIME => {
                j += 1;
                Some(t.time()?)
            }
            _ => None,
        };
        let mut revoked = Vec::new();
        let mut revoked_from = Vec::new();
        if let Some(list) = tbs.get(j).filter(|t| t.tag == der::SEQUENCE) {
            j += 1;
            for e in list.children()?.iter() {
                let k = e.items(der::SEQUENCE)?;
                if k.len() < 2 {
                    return Err(bad());
                }
                let (serial, when) = (k[0].uint()?.to_vec(), k[1].time()?);
                let from = match k.get(2) {
                    Some(x) => untrusted_from(x, when)?,
                    None => when,
                };
                revoked_from.push((serial.clone(), from));
                revoked.push((serial, when));
            }
        }
        let (mut is_delta, mut freshest, mut unknown_critical) = (false, vec![], None);
        if let Some(x) = tbs.get(j).filter(|t| t.tag == der::ctx(0)) {
            for e in x.inner()?.items(der::SEQUENCE)?.iter() {
                let k = e.items(der::SEQUENCE)?;
                let oid = k.first().ok_or_else(bad)?.oid()?;
                let critical = k.len() > 2 && k[1].boolean()?;
                let value = k.last().ok_or_else(bad)?.expect(der::OCTET_STRING)?.content;
                match oid.as_str() {
                    DELTA_CRL_INDICATOR => is_delta = true,
                    FRESHEST_CRL => freshest = uris_in(value),
                    o if critical && !UNDERSTOOD.contains(&o) => unknown_critical = Some(oid),
                    _ => {}
                }
            }
        }
        Ok(Crl {
            issuer,
            this_update,
            next_update,
            revoked,
            revoked_from,
            is_delta,
            freshest,
            unknown_critical,
            raw: data.to_vec(),
            tbs: top[0].raw.to_vec(),
            sig_alg: crate::keys::alg_id(&top[1])?.0,
            signature: top[2].bits()?.to_vec(),
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
    pub fn unusable(&self, c: &Cert, issuer: &Cert, now: i64) -> Option<String> {
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
        Some(tr(why).into())
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
fn untrusted_from(exts: &der::Tlv, when: i64) -> Result<i64> {
    let mut from = when;
    for e in exts.items(der::SEQUENCE)?.iter() {
        let k = e.items(der::SEQUENCE)?;
        let (Some(oid), Some(value)) = (k.first(), k.last()) else {
            continue;
        };
        let value = der::parse(value.expect(der::OCTET_STRING)?.content)?;
        match oid.oid()?.as_str() {
            REASON_CODE if is_compromise(&value) => return Ok(i64::MIN),
            INVALIDITY_DATE => from = from.min(value.time()?),
            _ => {}
        }
    }
    Ok(from)
}

/// CRLReason keyCompromise (1), cACompromise (2) or aACompromise (10).
pub fn is_compromise(reason: &der::Tlv) -> bool {
    reason.tag == der::ENUMERATED && matches!(reason.content, [1] | [2] | [10])
}

const REASON_CODE: &str = "2.5.29.21";
const INVALIDITY_DATE: &str = "2.5.29.24";

/// The http addresses in a certificate's CRL distribution points extension.
pub fn urls(c: &Cert) -> Vec<String> {
    ext_uris(c, CRL_DISTRIBUTION_POINTS)
}

fn ext_uris(c: &Cert, oid: &str) -> Vec<String> {
    c.extensions
        .iter()
        .find(|(o, _)| o == oid)
        .map(|(_, v)| uris_in(v))
        .unwrap_or_default()
}

/// The http addresses in a CRL distribution points (or freshest CRL) extension value (DER).
pub fn uris_in(ext: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(t) = der::parse(ext) {
        collect_uris(&t, &mut out, 0);
    }
    out.retain(|u| u.starts_with("http://"));
    out
}

/// uniformResourceIdentifier ([6] IA5String) anywhere inside `t`.
fn collect_uris(t: &Tlv, out: &mut Vec<String>, depth: usize) {
    if depth > 8 {
        return;
    }
    if t.tag == der::ctx_prim(6) {
        if let Ok(s) = std::str::from_utf8(t.content) {
            out.push(s.to_string());
        }
    } else if t.constructed()
        && let Ok(k) = t.children()
    {
        for c in k.iter() {
            collect_uris(c, out, depth + 1);
        }
    }
}

/// What a full list and, when one is due, a delta list say about `c`: (good, status for
/// people, answer "good"/"revoked", or "" when they can't be used). `issuer` is `c`'s CA
/// certificate; `now` the moment of checking. A delta is required when `delta_due`.
pub fn evaluate(
    base: &Crl,
    delta: Option<&Crl>,
    delta_due: bool,
    c: &Cert,
    issuer: &Cert,
    now: i64,
) -> (bool, String, &'static str) {
    let no = |s: String| (false, s, "");
    if base.is_delta {
        return no(tr("ERROR: the revocation list is not a full list").into());
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
                return no(tr("ERROR: the delta revocation list is not a delta list").into());
            }
            if let Some(why) = d.unusable(c, issuer, now) {
                return no(why);
            }
            if let Some(when) = d.revocation_of(c) {
                return revoked(when);
            }
        }
        None if delta_due => {
            return no(tr("ERROR: the delta revocation list could not be read").into());
        }
        None => {}
    }
    let at = delta.map_or(base.this_update, |d| d.this_update);
    (
        true,
        trf(
            "GOOD (not in the revocation list of {})",
            &[&time::fmt(Some(at))],
        ),
        "good",
    )
}

fn revoked(when: i64) -> (bool, String, &'static str) {
    (
        false,
        trf("REVOKED on {} (revocation list)", &[&time::fmt(Some(when))]),
        "revoked",
    )
}

/// A parsed list kept until a time, or a failure not retried until a time.
type Cached = (std::result::Result<Arc<Crl>, Error>, i64);

/// Lists fetched in this run, by address.
static CACHE: Mutex<Option<HashMap<String, Cached>>> = Mutex::new(None);

fn fetch(url: &str, now: i64) -> Result<Arc<Crl>> {
    if let Ok(c) = CACHE.lock()
        && let Some((r, until)) = c.as_ref().and_then(|c| c.get(url))
        && *until >= now
    {
        return r.clone();
    }
    let r = http::get(url, MAX_CRL, "revocation list server")
        .and_then(|d| Crl::parse(&d))
        .map(Arc::new);
    let until = match &r {
        Ok(crl) => crl.next_update.unwrap_or(now).min(now + 60 * MINUTE),
        Err(_) => now + 5 * MINUTE,
    };
    if let Ok(mut c) = CACHE.lock() {
        c.get_or_insert_with(HashMap::new)
            .insert(url.to_string(), (r.clone(), until));
    }
    r
}

/// The first list that could be read from `urls`, or the last error.
fn first(urls: &[String], now: i64) -> Result<Arc<Crl>> {
    let mut last = Error::new(tr("the certificate names no revocation list"));
    for u in urls {
        match fetch(u, now) {
            Ok(c) => return Ok(c),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The current lists for `c`: the full list its distribution points name, a delta list when one
/// could be read, and whether a delta list is due (named by the certificate or the full list).
pub fn lists(c: &Cert, now: i64) -> Result<(Arc<Crl>, Option<Arc<Crl>>, bool)> {
    let base = first(&urls(c), now)?;
    let mut delta_urls = ext_uris(c, FRESHEST_CRL);
    delta_urls.extend(base.freshest.iter().cloned());
    let delta_due = !delta_urls.is_empty();
    let delta = first(&delta_urls, now).ok();
    Ok((base, delta, delta_due))
}

/// Checks `c` against the CRLs its distribution points name (and their delta lists).
pub fn check(c: &Cert, issuer: Option<&Cert>) -> (bool, String, &'static str) {
    let Some(issuer) = issuer else {
        return (
            false,
            tr("UNKNOWN (issuer certificate not available)").into(),
            "",
        );
    };
    let now = time::now_ms();
    match lists(c, now) {
        Ok((base, delta, due)) => evaluate(&base, delta.as_deref(), due, c, issuer, now),
        Err(e) => (
            false,
            trf("ERROR: could not check the revocation list ({})", &[&e]),
            "",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(oid: &str, value: &[u8]) -> Vec<u8> {
        der::seq(&[&der::oid(oid), &der::tlv(der::OCTET_STRING, value)])
    }

    /// A list entry's reason and invalidity date decide from when its key is not trusted.
    #[test]
    fn untrusted_from_entry_extensions() {
        let when = 1_800_000_000_000;
        let from = |exts: &[&[u8]]| {
            let e = der::seq(exts);
            untrusted_from(&der::parse(&e).unwrap(), when).unwrap()
        };
        let reason = |r: u8| ext(REASON_CODE, &der::tlv(der::ENUMERATED, &[r]));
        let invalid = |t: i64| ext(INVALIDITY_DATE, &time::encode_generalized(t));
        assert_eq!(from(&[]), when);
        assert_eq!(from(&[&reason(4)]), when, "superseded");
        for r in [1, 2, 10] {
            assert_eq!(from(&[&reason(r)]), i64::MIN, "reason {r}");
        }
        assert_eq!(from(&[&invalid(when - 5000)]), when - 5000);
        assert_eq!(from(&[&invalid(when + 5000)]), when, "never later");
        assert_eq!(from(&[&invalid(when - 5000), &reason(1)]), i64::MIN);
        assert!(!is_compromise(&der::parse(&der::small_int(1)).unwrap()));
    }
}
