//! The one network call kzsigner makes: an HTTP POST to the NCA timestamp or OCSP server, with
//! the ureq client. NCA's servers speak plain http (what they return is signed and checked), so
//! ureq is built without TLS. A proxy set in the environment (http_proxy, ALL_PROXY) is used.

use std::time::Duration;

use crate::i18n::{tr, trf};
use crate::{Error, Result};

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
        .user_agent("kzsigner")
        .build()
        .into();
    let mut resp = agent
        .post(url)
        .header("Content-Type", content_type)
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

fn tr_what(what: &str) -> &str {
    match what {
        "timestamp server" => tr("timestamp server"),
        "OCSP server" => tr("OCSP server"),
        other => other,
    }
}
