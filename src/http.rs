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
    request(url, what, Some((content_type, body)), MAX_ANSWER, 120)
}

/// GETs `url` (a certificate revocation list); answers up to `limit` bytes.
pub fn get(url: &str, limit: u64, what: &str) -> Result<Vec<u8>> {
    request(url, what, None, limit, 300)
}

fn request(
    url: &str,
    what: &str,
    post: Option<(&str, &[u8])>,
    limit: u64,
    seconds: u64,
) -> Result<Vec<u8>> {
    let fail = |e: &dyn std::fmt::Display| {
        Error::new(trf(
            "Could not reach the {} at {}: {}",
            &[&tr_what(what), &url, e],
        ))
    };
    if !url.starts_with("http://") {
        return Err(fail(
            &"only http:// is supported (NCA's timestamp, OCSP and CRL servers use http)",
        ));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_global(Some(Duration::from_secs(seconds)))
        .http_status_as_error(false)
        // what NCALayer sends: its Kalkan modules set no User-Agent, so Java's default for the
        // JRE bundled with it goes out
        .user_agent(NCALAYER_USER_AGENT)
        .build()
        .into();
    let resp = match post {
        Some((content_type, body)) => agent
            .post(url)
            .header("Content-Type", content_type)
            // Java's HttpURLConnection default, as NCALayer sends it
            .header(
                "Accept",
                "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
            )
            .send(body),
        None => agent.get(url).call(),
    };
    let mut resp = resp.map_err(|e| fail(&e))?;
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    /// Answers one request with `status` and `body` on a local port.
    fn serve(status: &'static str, body: &'static [u8]) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/x", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(body);
        });
        url
    }

    #[test]
    fn answers_and_failures() {
        assert_eq!(
            super::get(&serve("200 OK", b"list"), 100, "x").unwrap(),
            b"list"
        );
        let e = super::get(&serve("200 OK", b"too long"), 4, "x").unwrap_err();
        assert!(e.0.contains("Could not reach the x"), "{}", e.0);
        let e = super::get(&serve("404 Not Found", b""), 100, "OCSP server").unwrap_err();
        assert!(
            e.0.starts_with("The OCSP server answered HTTP 404"),
            "{}",
            e.0
        );
        let e = super::get("https://example.invalid/", 100, "timestamp server").unwrap_err();
        assert!(e.0.contains("timestamp server") && e.0.contains("only http://"));
        assert_eq!(
            super::tr_what("revocation list server"),
            "revocation list server"
        );
    }
}
