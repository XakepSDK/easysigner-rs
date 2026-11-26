//! Revocation lists: [`kzcrypto::crl`] reads and judges them; this module downloads them from
//! the certificate's CRL distribution points (http). Parsed lists are kept in memory for at
//! most an hour (and never past their nextUpdate); an address that failed is not tried again
//! for five minutes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::env::Env;

pub use kzcrypto::crl::*;

use crate::cert::Cert;
use crate::i18n::{self, tr};
use crate::{Error, Result};

/// NCA's full lists are large (tens of MB); refuse anything beyond this.
const MAX_CRL: u64 = 256 << 20;
const MINUTE: i64 = 60 * 1000;

/// [`kzcrypto::crl::evaluate`], with the status in the reader's language.
pub fn evaluate(
    base: &Crl,
    delta: Option<&Crl>,
    delta_due: bool,
    c: &Cert,
    issuer: &Cert,
    now: i64,
    policy: &crate::trust::Policy,
) -> (bool, String, Option<CertStatus>) {
    let (good, status, answer) =
        kzcrypto::crl::evaluate(base, delta, delta_due, c, issuer, now, policy);
    (good, i18n::text(&status), answer)
}

/// A parsed list kept until a time, or a failure not retried until a time.
type Cached = (std::result::Result<Arc<Crl>, Error>, i64);

/// Lists fetched through one [`Env`], by address.
#[derive(Default)]
pub struct Cache(Mutex<HashMap<String, Cached>>);

fn fetch(url: &str, now: i64, env: &Env) -> Result<Arc<Crl>> {
    if let Ok(c) = env.crls.0.lock()
        && let Some((r, until)) = c.get(url)
        && *until >= now
    {
        return r.clone();
    }
    let r = env
        .net
        .get(crate::Server::RevocationList, url, MAX_CRL)
        .and_then(|d| Ok(Crl::parse(&d)?))
        .map(Arc::new);
    let until = match &r {
        Ok(crl) => crl.next_update.unwrap_or(now).min(now + 60 * MINUTE),
        Err(_) => now + 5 * MINUTE,
    };
    if let Ok(mut c) = env.crls.0.lock() {
        c.insert(url.to_string(), (r.clone(), until));
    }
    r
}

/// The first list that could be read from `urls`, or the last error.
fn first(urls: &[String], now: i64, env: &Env) -> Result<Arc<Crl>> {
    let mut last = Error::new(tr("the certificate names no revocation list"));
    for u in urls {
        match fetch(u, now, env) {
            Ok(c) => return Ok(c),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The current lists for `c`: the full list its distribution points name, a delta list when one
/// could be read, and whether a delta list is due (named by the certificate or the full list).
pub fn lists(c: &Cert, now: i64, env: &Env) -> Result<(Arc<Crl>, Option<Arc<Crl>>, bool)> {
    let base = first(&urls(c), now, env)?;
    let delta_urls = delta_urls(c, &base);
    let delta_due = !delta_urls.is_empty();
    let delta = first(&delta_urls, now, env).ok();
    Ok((base, delta, delta_due))
}
