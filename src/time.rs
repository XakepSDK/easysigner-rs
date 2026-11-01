//! Times as milliseconds since 1970 (UTC): ASN.1 parsing and encoding, and display. The
//! calendar is chrono's; this file only reads and writes the ASN.1 time formats, including the
//! looser BER forms (no seconds, fractions, offsets) that DER-only parsers refuse.

use crate::{Error, Result};

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn utc(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

fn bad_time() -> Error {
    Error::new("malformed ASN.1: bad time")
}

/// UTCTime (YYMMDDHHMM[SS]Z) or GeneralizedTime (YYYYMMDDHHMMSS[.fff]Z, or with an offset).
pub fn parse_asn1(tag: u8, content: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(content).map_err(|_| bad_time())?;
    let num = |a: usize, b: usize| -> Result<i64> {
        s.get(a..b)
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or_else(bad_time)
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
    // chrono checks the date (no 31 February) and time; a leap second 60 counts as 59
    let t = chrono::NaiveDate::from_ymd_opt(y as i32, mo as u32, d as u32)
        .and_then(|day| day.and_hms_opt(h as u32, mi as u32, sec.min(59) as u32))
        .ok_or_else(bad_time)?;
    Ok(t.and_utc().timestamp_millis() + ms - offset_min * 60 * 1000)
}

/// The DER time NCALayer and Bouncy Castle write: UTCTime for 1950..2049, else GeneralizedTime.
pub fn encode(ms: i64) -> Vec<u8> {
    let t = utc(ms);
    if (1950..2050).contains(&chrono::Datelike::year(&t)) {
        let t = t.format("%y%m%d%H%M%SZ").to_string();
        crate::der::tlv(crate::der::UTC_TIME, t.as_bytes())
    } else {
        encode_generalized(ms)
    }
}

pub fn encode_generalized(ms: i64) -> Vec<u8> {
    let t = utc(ms).format("%Y%m%d%H%M%SZ").to_string();
    crate::der::tlv(crate::der::GENERALIZED_TIME, t.as_bytes())
}

/// ISO-8601 UTC, like Java's Instant.toString: 2026-11-01T10:00:00Z (with .SSS when not 0).
pub fn iso(ms: i64) -> String {
    let t = utc(ms);
    if ms.rem_euclid(1000) == 0 {
        t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
    }
}

/// Local time for people: 2026-11-01 15:00:00 +05:00.
pub fn fmt(ms: Option<i64>) -> String {
    let Some(ms) = ms else { return "-".into() };
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(ms).single() {
        Some(t) => {
            let off = t.offset().local_minus_utc();
            let zone = if off == 0 {
                "UTC".to_string()
            } else {
                t.format("%:z").to_string()
            };
            format!("{} {zone}", t.format("%Y-%m-%d %H:%M:%S"))
        }
        None => iso(ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso_ms(year: i32) -> i64 {
        chrono::NaiveDate::from_ymd_opt(year, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis()
    }

    #[test]
    fn round_trip() {
        let t = parse_asn1(crate::der::UTC_TIME, b"261031000029Z").unwrap();
        assert_eq!(iso(t), "2026-10-31T00:00:29Z");
        let enc = encode(t);
        assert_eq!(&enc[2..], b"261031000029Z");
        let g = parse_asn1(crate::der::GENERALIZED_TIME, b"20261031000029.5Z").unwrap();
        assert_eq!(iso(g), "2026-10-31T00:00:29.500Z");
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            iso(parse_asn1(crate::der::UTC_TIME, b"2602031200+0500").unwrap()),
            "2026-02-03T07:00:00Z"
        );
        assert!(parse_asn1(crate::der::UTC_TIME, b"260231000000Z").is_err());
        assert_eq!(&encode_generalized(g)[2..], b"20261031000029Z");
        assert_eq!(&encode(iso_ms(2051))[..1], &[crate::der::GENERALIZED_TIME]);
    }
}
