//! kzsigner's network calls: an HTTP POST to the NCA timestamp or OCSP server, and a GET of a
//! revocation list (CRL) when OCSP gives no answer, with the ureq client. NCA's servers take requests over plain http only (https answers POST with
//! 405; what they return is signed and checked), so ureq is built without TLS. A proxy set in the environment (http_proxy, ALL_PROXY) is used.

use std::time::Duration;

use crate::i18n::{tr, trf};
use crate::{Error, Result};

/// The User-Agent of NCALayer 1.4 (bundled JRE 1.8.0_492).
const NCALAYER_USER_AGENT: &str = "Java/1.8.0_492";

/// Answers larger than this are refused (timestamp and OCSP answers are a few KB).
const MAX_ANSWER: u64 = 4 << 20;

/// POSTs `body`; `what` names the server in error messages.
pub fn post(url: &str, content_type: &str, body: &[u8], what: &str) -> Result<Vec<u8>> {
    let fail = |e: &dyn std::fmt::Display| {
        Error::new(trf(
            "Could not reach the {} at {}: {}",
            &[&tr_what(what), &url, e],
        ))
    };
    if url.starts_with("https://") {
        return Err(fail(
            &"https is not supported (NCA's timestamp and OCSP servers use http)",
        ));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_global(Some(Duration::from_secs(120)))
        .http_status_as_error(false)
        // what NCALayer sends: its Kalkan modules set no User-Agent, so Java's default for the
        // JRE bundled with it goes out
        .user_agent(NCALAYER_USER_AGENT)
        .build()
        .into();
    let mut resp = agent
        .post(url)
        .header("Content-Type", content_type)
        // Java's HttpURLConnection default, as NCALayer sends it
        .header(
            "Accept",
            "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
        )
        .send(body)
        .map_err(|e| fail(&e))?;
    let code = resp.status().as_u16();
    if code != 200 {
        return Err(Error::new(trf(
            "The {} answered HTTP {} ({})",
            &[&tr_what(what), &code, &url],
        )));
    }
    resp.body_mut()
        .with_config()
        .limit(MAX_ANSWER)
        .read_to_vec()
        .map_err(|e| fail(&e))
}

/// GETs `url` (a certificate revocation list); answers up to `limit` bytes.
pub fn get(url: &str, limit: u64, what: &str) -> Result<Vec<u8>> {
    let fail = |e: &dyn std::fmt::Display| {
        Error::new(trf(
            "Could not reach the {} at {}: {}",
            &[&tr_what(what), &url, e],
        ))
    };
    if !url.starts_with("http://") {
        return Err(fail(&"only http:// addresses are supported"));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_global(Some(Duration::from_secs(300)))
        .http_status_as_error(false)
        .user_agent(NCALAYER_USER_AGENT)
        .build()
        .into();
    let mut resp = agent.get(url).call().map_err(|e| fail(&e))?;
    let code = resp.status().as_u16();
    if code != 200 {
        return Err(Error::new(trf(
            "The {} answered HTTP {} ({})",
            &[&tr_what(what), &code, &url],
        )));
    }
    resp.body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| fail(&e))
}

fn tr_what(what: &str) -> &str {
    match what {
        "timestamp server" => tr("timestamp server"),
        "OCSP server" => tr("OCSP server"),
        "revocation list server" => tr("revocation list server"),
        other => other,
    }
}
