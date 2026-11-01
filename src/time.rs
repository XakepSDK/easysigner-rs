//! Times as milliseconds since 1970 (UTC): ASN.1 parsing and encoding, and display.

use crate::{Error, Result};

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day, hour, minute, second, millisecond) in UTC.
pub fn parts(ms: i64) -> (i64, i64, i64, i64, i64, i64, i64) {
    let secs = ms.div_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86400));
    let s = secs.rem_euclid(86400);
    (y, mo, d, s / 3600, s / 60 % 60, s % 60, ms.rem_euclid(1000))
}

fn bad_time() -> Error {
    Error::new("malformed ASN.1: bad time")
}

/// UTCTime (YYMMDDHHMM[SS]Z) or GeneralizedTime (YYYYMMDDHHMMSS[.fff]Z, or with an offset).
pub fn parse_asn1(tag: u8, content: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(content).map_err(|_| bad_time())?;
    let num = |a: usize, b: usize| -> Result<i64> {
        s.get(a..b).and_then(|x| x.parse::<i64>().ok()).ok_or_else(bad_time)
    };
    let (y, rest) = match tag {
        crate::der::UTC_TIME => {
            let yy = num(0, 2)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
        }
        crate::der::GENERALIZED_TIME => (num(0, 4)?, 4),
        _ => return Err(bad_time()),
    };
    let mo = num(rest, rest + 2)?;
    let d = num(rest + 2, rest + 4)?;
    let h = num(rest + 4, rest + 6)?;
    let mi = num(rest + 6, rest + 8)?;
    let mut i = rest + 8;
    let mut sec = 0;
    if s.len() >= i + 2 && s.as_bytes()[i].is_ascii_digit() {
        sec = num(i, i + 2)?;
        i += 2;
    }
    let mut ms = 0;
    if s.as_bytes().get(i) == Some(&b'.') || s.as_bytes().get(i) == Some(&b',') {
        let start = i + 1;
        let mut end = start;
        while end < s.len() && s.as_bytes()[end].is_ascii_digit() {
            end += 1;
        }
        let frac = &s[start..end];
        let f3: String = frac.chars().chain("000".chars()).take(3).collect();
        ms = f3.parse::<i64>().map_err(|_| bad_time())?;
        i = end;
    }
    let mut offset_min = 0;
    match s.as_bytes().get(i) {
        Some(b'Z') | None => {}
        Some(b'+') | Some(b'-') => {
            let sign = if s.as_bytes()[i] == b'+' { 1 } else { -1 };
            offset_min = sign * (num(i + 1, i + 3)? * 60 + num(i + 3, i + 5).unwrap_or(0));
        }
        _ => return Err(bad_time()),
    }
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return Err(bad_time());
    }
    let secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec - offset_min * 60;
    Ok(secs * 1000 + ms)
}

/// The DER time NCALayer and Bouncy Castle write: UTCTime for 1950..2049, else GeneralizedTime.
pub fn encode(ms: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s, _) = parts(ms);
    if (1950..2050).contains(&y) {
        let t = format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100);
        crate::der::tlv(crate::der::UTC_TIME, t.as_bytes())
    } else {
        encode_generalized(ms)
    }
}

pub fn encode_generalized(ms: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s, _) = parts(ms);
    let t = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z");
    crate::der::tlv(crate::der::GENERALIZED_TIME, t.as_bytes())
}

/// ISO-8601 UTC, like Java's Instant.toString: 2026-11-01T10:00:00Z (with .SSS when not 0).
pub fn iso(ms: i64) -> String {
    let (y, mo, d, h, mi, s, f) = parts(ms);
    let frac = if f == 0 { String::new() } else { format!(".{f:03}") };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{frac}Z")
}

/// Local time for people: 2026-11-01 15:00:00 +05:00.
pub fn fmt(ms: Option<i64>) -> String {
    let Some(ms) = ms else { return "-".into() };
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(ms).single() {
        Some(t) => {
            let off = t.offset().local_minus_utc();
            let zone = if off == 0 { "UTC".to_string() } else { t.format("%:z").to_string() };
            format!("{} {zone}", t.format("%Y-%m-%d %H:%M:%S"))
        }
        None => iso(ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let t = parse_asn1(crate::der::UTC_TIME, b"261031000029Z").unwrap();
        assert_eq!(iso(t), "2026-10-31T00:00:29Z");
        let enc = encode(t);
        assert_eq!(&enc[2..], b"261031000029Z");
        let g = parse_asn1(crate::der::GENERALIZED_TIME, b"20261031000029.5Z").unwrap();
        assert_eq!(iso(g), "2026-10-31T00:00:29.500Z");
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
    }
}
