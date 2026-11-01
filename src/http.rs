//! The one network call kzsigner makes: an HTTP POST to the NCA timestamp or OCSP server.
//! NCA's servers speak plain http (the data is signed), so this is a small HTTP/1.1 client.

use crate::i18n::{tr, trf};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::{Error, Result};

struct Url {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> std::result::Result<Url, String> {
    let rest = if let Some(r) = url.strip_prefix("http://") {
        r
    } else if url.starts_with("https://") {
        return Err("https is not supported (NCA's timestamp and OCSP servers use http)".into());
    } else {
        return Err("not an http:// URL".into());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let port = |p: &str| p.parse::<u16>().map_err(|_| "bad port".to_string());
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let (h, rest) = r.split_once(']').ok_or("bad host")?;
        (
            h.to_string(),
            rest.strip_prefix(':').map(port).transpose()?.unwrap_or(80),
        )
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), port(p)?),
            None => (authority.to_string(), 80),
        }
    };
    if host.is_empty() {
        return Err("no host".into());
    }
    Ok(Url { host, port, path })
}

/// POSTs `body`; `what` names the server in error messages.
pub fn post(url: &str, content_type: &str, body: &[u8], what: &str) -> Result<Vec<u8>> {
    let mut url = url.to_string();
    for _ in 0..5 {
        match post_once(&url, content_type, body) {
            Ok(Response::Body(b)) => return Ok(b),
            Ok(Response::Status(code)) => {
                return Err(Error::new(trf(
                    "The {} answered HTTP {} ({})",
                    &[&tr_what(what), &code, &url],
                )));
            }
            Ok(Response::Redirect(loc)) => {
                url = if loc.starts_with("http://") || loc.starts_with("https://") {
                    loc
                } else {
                    let u = parse_url(&url).map_err(Error::new)?;
                    format!("http://{}:{}{}", u.host, u.port, loc)
                };
            }
            Err(e) => {
                return Err(Error::new(trf(
                    "Could not reach the {} at {}: {}",
                    &[&tr_what(what), &url, &e],
                )));
            }
        }
    }
    Err(Error::new(trf(
        "Could not reach the {} at {}: too many redirects",
        &[&tr_what(what), &url],
    )))
}

fn tr_what(what: &str) -> &str {
    match what {
        "timestamp server" => tr("timestamp server"),
        "OCSP server" => tr("OCSP server"),
        other => other,
    }
}

enum Response {
    Body(Vec<u8>),
    Status(u16),
    Redirect(String),
}

fn post_once(url: &str, content_type: &str, body: &[u8]) -> std::result::Result<Response, String> {
    let u = parse_url(url)?;
    let addrs: Vec<_> = (u.host.as_str(), u.port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .collect();
    let mut last = "no address".to_string();
    let mut stream = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(20)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = e.to_string(),
        }
    }
    let mut s = stream.ok_or(last)?;
    s.set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    let host = if u.port == 80 {
        u.host.clone()
    } else {
        format!("{}:{}", u.host, u.port)
    };
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: kzsigner\r\n\r\n",
        u.path,
        body.len()
    );
    s.write_all(head.as_bytes())
        .and_then(|_| s.write_all(body))
        .map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).map_err(|e| e.to_string())?;
    let end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("incomplete HTTP response")?;
    let head = String::from_utf8_lossy(&resp[..end]).to_string();
    let mut data = resp[end + 4..].to_vec();
    let mut lines = head.lines();
    let status = lines.next().ok_or("empty HTTP response")?;
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or("bad HTTP status line")?;
    let mut chunked = false;
    let mut length = None;
    let mut location = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                "content-length" => length = v.parse::<usize>().ok(),
                "location" => location = Some(v.to_string()),
                _ => {}
            }
        }
    }
    if matches!(code, 301 | 302 | 303 | 307 | 308)
        && let Some(l) = location
    {
        return Ok(Response::Redirect(l));
    }
    if code != 200 {
        return Ok(Response::Status(code));
    }
    if chunked {
        data = dechunk(&data)?;
    } else if let Some(n) = length {
        if data.len() < n {
            return Err("connection closed before the whole answer arrived".into());
        }
        data.truncate(n);
    }
    Ok(Response::Body(data))
}

fn dechunk(mut d: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let i = d
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("bad chunked encoding")?;
        let size_s = String::from_utf8_lossy(&d[..i]);
        let size = usize::from_str_radix(size_s.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "bad chunk size")?;
        d = &d[i + 2..];
        if size == 0 {
            return Ok(out);
        }
        if d.len() < size + 2 {
            return Err("truncated chunk".into());
        }
        out.extend(&d[..size]);
        d = &d[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("http://tsp.pki.gov.kz:80").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("tsp.pki.gov.kz", 80, "/")
        );
        let u = parse_url("http://127.0.0.1:18080/x").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("127.0.0.1", 18080, "/x")
        );
        let u = parse_url("http://ocsp.pki.gov.kz").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("ocsp.pki.gov.kz", 80));
        assert!(parse_url("https://x").is_err());
        assert_eq!(
            dechunk(b"3\r\nabc\r\n1\r\nd\r\n0\r\n\r\n").unwrap(),
            b"abcd"
        );
    }
}
