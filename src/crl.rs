//! Certificate revocation lists (X.509 CRLs, RFC 5280 §5), the fallback when OCSP gives no
//! answer (Order 500/НҚ p.4.3, p.16, p.18). A CRL counts only when it is DER, issued and signed
//! by the certificate's own CA, and current: one past its nextUpdate gives no positive result.
//! The lists are fetched from the certificate's CRL distribution points (http) and kept in
//! memory until their nextUpdate.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::cert::{self, Cert};
use crate::der::{self, Tlv};
use crate::i18n::{tr, trf};
use crate::{Error, Result, http, time};

/// NCA's full lists are large (tens of MB); refuse anything beyond this.
const MAX_CRL: u64 = 256 << 20;

/// A parsed revocation list.
pub struct Crl {
    pub issuer: Vec<u8>,
    pub this_update: i64,
    pub next_update: Option<i64>,
    /// Serial numbers (as in [`Cert::serial`]) with their revocation dates.
    pub revoked: Vec<(Vec<u8>, i64)>,
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
        let mut i = usize::from(tbs.first().is_some_and(|t| t.tag == der::INTEGER));
        i += 1; // signature algorithm
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
        if let Some(list) = tbs.get(j).filter(|t| t.tag == der::SEQUENCE) {
            for e in list.children()?.iter() {
                let k = e.items(der::SEQUENCE)?;
                if k.len() < 2 {
                    return Err(bad());
                }
                revoked.push((k[0].uint()?.to_vec(), k[1].time()?));
            }
        }
        Ok(Crl {
            issuer,
            this_update,
            next_update,
            revoked,
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
}

/// The http addresses in a certificate's CRL distribution points extension.
pub fn urls(c: &Cert) -> Vec<String> {
    c.extensions
        .iter()
        .find(|(o, _)| o == "2.5.29.31")
        .map(|(_, v)| uris_in(v))
        .unwrap_or_default()
}

/// The http addresses in a CRL distribution points extension value (DER).
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

/// What a CRL says about `c`: (good, status for people, answer "good"/"revoked", or "" when
/// the list can't be used). `issuer` is `c`'s CA certificate; `now` the moment of checking.
pub fn evaluate(crl: &Crl, c: &Cert, issuer: &Cert, now: i64) -> (bool, String, &'static str) {
    if !cert::names_equal(&crl.issuer, &c.issuer)
        || !cert::names_equal(&crl.issuer, &issuer.subject)
    {
        return (
            false,
            tr("ERROR: the revocation list is not from the certificate's CA").into(),
            "",
        );
    }
    if !crl.signed_by(issuer) {
        return (
            false,
            tr("ERROR: the revocation list's signature is not valid").into(),
            "",
        );
    }
    let skew = 5 * 60 * 1000;
    if crl.this_update > now + skew || crl.next_update.is_none_or(|n| n < now) {
        return (
            false,
            tr("ERROR: the revocation list is out of date").into(),
            "",
        );
    }
    let serial = trim(&c.serial);
    match crl.revoked.iter().find(|(s, _)| trim(s) == serial) {
        Some((_, when)) => (
            false,
            trf(
                "REVOKED on {} (revocation list)",
                &[&time::fmt(Some(*when))],
            ),
            "revoked",
        ),
        None => (
            true,
            trf(
                "GOOD (not in the revocation list of {})",
                &[&time::fmt(Some(crl.this_update))],
            ),
            "good",
        ),
    }
}

/// A serial number without leading zero bytes.
fn trim(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|b| **b == 0).count();
    &s[n.min(s.len().saturating_sub(1))..]
}

/// Lists fetched in this run, by address, until their nextUpdate.
static CACHE: Mutex<Option<HashMap<String, (Vec<u8>, i64)>>> = Mutex::new(None);

fn fetch(url: &str, now: i64) -> Result<Vec<u8>> {
    if let Some((data, until)) = CACHE
        .lock()
        .ok()
        .and_then(|c| c.as_ref()?.get(url).cloned())
        && until >= now
    {
        return Ok(data);
    }
    let data = http::get(url, MAX_CRL, "revocation list server")?;
    if let Ok(crl) = Crl::parse(&data)
        && let Some(until) = crl.next_update
        && let Ok(mut c) = CACHE.lock()
    {
        c.get_or_insert_with(HashMap::new)
            .insert(url.to_string(), (data.clone(), until));
    }
    Ok(data)
}

/// Checks `c` against the CRLs its distribution points name; the first usable answer counts.
pub fn check(c: &Cert, issuer: Option<&Cert>) -> (bool, String, &'static str) {
    let Some(issuer) = issuer else {
        return (
            false,
            tr("UNKNOWN (issuer certificate not available)").into(),
            "",
        );
    };
    let urls = urls(c);
    if urls.is_empty() {
        return (
            false,
            tr("ERROR: the certificate names no revocation list").into(),
            "",
        );
    }
    let now = time::now_ms();
    let mut last = String::new();
    for u in &urls {
        let r = fetch(u, now).and_then(|d| Crl::parse(&d));
        match r {
            Ok(crl) => {
                let a = evaluate(&crl, c, issuer, now);
                if !a.2.is_empty() {
                    return a;
                }
                last = a.1;
            }
            Err(e) => last = trf("ERROR: could not check the revocation list ({})", &[&e]),
        }
    }
    (false, last, "")
}
