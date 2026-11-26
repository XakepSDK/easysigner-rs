//! kzsigner's network calls: an HTTP POST to the NCA timestamp or OCSP server, and a GET of a
//! revocation list (CRL) when OCSP gives no answer, with the ureq client. NCA's servers take requests over plain http only (https answers POST with
//! 405; what they return is signed and checked), so ureq is built without TLS. A proxy set in the environment (http_proxy, ALL_PROXY) is used.

use std::time::Duration;

use crate::{Error, NetProblem, Result, Server};

/// The User-Agent of NCALayer 1.4 (bundled JRE 1.8.0_492).
const NCALAYER_USER_AGENT: &str = "Java/1.8.0_492";

/// Answers larger than this are refused (timestamp and OCSP answers are a few KB).
const MAX_ANSWER: u64 = 4 << 20;

/// POSTs `body` to `server`.
pub fn post(url: &str, content_type: &str, body: &[u8], server: Server) -> Result<Vec<u8>> {
    request(url, server, Some((content_type, body)), MAX_ANSWER, 120)
}

/// GETs `url` (a certificate revocation list); answers up to `limit` bytes.
pub fn get(url: &str, limit: u64, server: Server) -> Result<Vec<u8>> {
    request(url, server, None, limit, 300)
}

fn request(
    url: &str,
    server: Server,
    post: Option<(&str, &[u8])>,
    limit: u64,
    seconds: u64,
) -> Result<Vec<u8>> {
    let fail = |problem| Error::Network {
        server,
        url: url.to_string(),
        problem,
    };
    if !url.starts_with("http://") {
        return Err(fail(NetProblem::NotHttp));
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
    let mut resp = resp.map_err(|e| fail(NetProblem::Unreachable(e.to_string())))?;
    let code = resp.status().as_u16();
    if code != 200 {
        return Err(fail(NetProblem::Status(code)));
    }
    resp.body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| match e {
            // the server answered, with more than any real answer holds
            ureq::Error::BodyExceedsLimit(n) => fail(NetProblem::TooLarge(n)),
            e => fail(NetProblem::Unreachable(e.to_string())),
        })
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
        use crate::{Error, NetProblem, Server};
        assert_eq!(
            super::get(&serve("200 OK", b"list"), 100, Server::RevocationList).unwrap(),
            b"list"
        );
        let big = serve("200 OK", b"too long");
        let e = super::get(&big, 4, Server::RevocationList).unwrap_err();
        assert_eq!(
            e,
            Error::Network {
                server: Server::RevocationList,
                url: big.clone(),
                problem: NetProblem::TooLarge(4)
            }
        );
        assert_eq!(
            e.to_string(),
            format!("The revocation list server at {big} sent an answer larger than 4 bytes")
        );
        let e = super::get(&serve("404 Not Found", b""), 100, Server::Ocsp).unwrap_err();
        assert!(matches!(
            e,
            Error::Network {
                server: Server::Ocsp,
                problem: NetProblem::Status(404),
                ..
            }
        ));
        assert!(
            e.to_string()
                .starts_with("The OCSP server answered HTTP 404"),
            "{e}"
        );
        let e = super::get("https://example.invalid/", 100, Server::Timestamp).unwrap_err();
        assert_eq!(e.server(), Some(Server::Timestamp));
        let m = e.to_string();
        assert!(
            m.contains("timestamp server") && m.contains("only http://"),
            "{m}"
        );
        let e = super::post("http://127.0.0.1:9/", "x", b"", Server::Ocsp).unwrap_err();
        assert!(matches!(
            e,
            Error::Network {
                problem: NetProblem::Unreachable(_),
                ..
            }
        ));
    }
}
