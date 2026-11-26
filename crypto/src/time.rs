//! Times as milliseconds since 1970 (UTC): reading and writing the ASN.1 time formats,
//! including the looser BER forms (no seconds, fractions, offsets) that DER-only parsers
//! refuse, and ISO-8601 for messages. The calendar is the proleptic Gregorian one.

use ::der::Tag;

use crate::prelude::*;
use crate::{Error, Result};

const DAY_MS: i64 = 86_400_000;

fn bad_time() -> Error {
    Error::BadTime
}

/// Days since 1970-01-01 of a valid date (H. Hinnant's days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// (year, month, day) of a day number since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// The calendar fields of a time: (year, month, day, hour, minute, second, millisecond).
pub fn fields(ms: i64) -> (i64, i64, i64, i64, i64, i64, i64) {
    let (y, m, d) = civil_from_days(ms.div_euclid(DAY_MS));
    let t = ms.rem_euclid(DAY_MS);
    (
        y,
        m,
        d,
        t / 3_600_000,
        t / 60_000 % 60,
        t / 1000 % 60,
        t % 1000,
    )
}

/// UTCTime (`YYMMDDHHMM[SS]Z`) or GeneralizedTime (`YYYYMMDDHHMMSS[.fff]Z`, or with an offset).
pub fn parse_asn1(tag: Tag, content: &[u8]) -> Result<i64> {
    let s = core::str::from_utf8(content).map_err(|_| bad_time())?;
    let num = |a: usize, b: usize| -> Result<i64> {
        s.get(a..b)
            .filter(|x| x.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or_else(bad_time)
    };
    let (y, rest) = match tag {
        Tag::UtcTime => {
            let yy = num(0, 2)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
        }
        Tag::GeneralizedTime => (num(0, 4)?, 4),
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
    // a real date (no 31 February) and time; seconds 60 and over count as 59
    if !(1..=12).contains(&mo)
        || d < 1
        || d > days_in_month(y, mo)
        || !(0..24).contains(&h)
        || !(0..60).contains(&mi)
        || sec < 0
    {
        return Err(bad_time());
    }
    let day = days_from_civil(y, mo, d);
    let t = ((day * 24 + h) * 60 + mi) * 60 + sec.min(59);
    Ok(t * 1000 + ms - offset_min * 60 * 1000)
}

/// The DER time NCALayer and Bouncy Castle write: UTCTime for 1950..2049, else GeneralizedTime.
pub fn encode(ms: i64) -> Result<Vec<u8>> {
    let (y, m, d, h, mi, s, _) = fields(ms);
    if (1950..2050).contains(&y) {
        let t = format!("{:02}{m:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100);
        tlv(Tag::UtcTime, &t)
    } else {
        encode_generalized(ms)
    }
}

/// GeneralizedTime in whole seconds (`YYYYMMDDHHMMSSZ`).
pub fn encode_generalized(ms: i64) -> Result<Vec<u8>> {
    let (y, m, d, h, mi, s, _) = fields(ms);
    if !(0..10_000).contains(&y) {
        return Err(bad_time());
    }
    tlv(
        Tag::GeneralizedTime,
        &format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z"),
    )
}

fn tlv(tag: Tag, text: &str) -> Result<Vec<u8>> {
    use ::der::Encode;
    ::der::asn1::AnyRef::new(tag, text.as_bytes())
        .and_then(|a| a.to_der())
        .map_err(crate::asn1::err)
}

/// ISO-8601 UTC, like Java's Instant.toString: 2026-11-01T10:00:00Z (with .SSS when not 0).
pub fn iso(ms: i64) -> String {
    let (y, m, d, h, mi, s, f) = fields(ms);
    if f == 0 {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{f:03}Z")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn year_ms(year: i64) -> i64 {
        days_from_civil(year, 1, 1) * DAY_MS
    }

    #[test]
    fn round_trip() {
        let t = parse_asn1(Tag::UtcTime, b"261031000029Z").unwrap();
        assert_eq!(iso(t), "2026-10-31T00:00:29Z");
        let enc = encode(t).unwrap();
        assert_eq!(&enc[2..], b"261031000029Z");
        let g = parse_asn1(Tag::GeneralizedTime, b"20261031000029.5Z").unwrap();
        assert_eq!(iso(g), "2026-10-31T00:00:29.500Z");
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            iso(parse_asn1(Tag::UtcTime, b"2602031200+0500").unwrap()),
            "2026-02-03T07:00:00Z"
        );
        assert!(parse_asn1(Tag::UtcTime, b"260231000000Z").is_err());
        assert_eq!(&encode_generalized(g).unwrap()[2..], b"20261031000029Z");
        assert_eq!(&encode(year_ms(2051)).unwrap()[..1], &[0x18]);
        assert_eq!(&encode(year_ms(1949)).unwrap()[..1], &[0x18]);
        assert_eq!(&encode(year_ms(1950)).unwrap()[..1], &[0x17]);
        assert_eq!(&encode(year_ms(2049)).unwrap()[2..], b"490101000000Z");
    }

    #[test]
    fn time_forms() {
        let utc = |t: &[u8]| iso(parse_asn1(Tag::UtcTime, t).unwrap());
        let generalized = |t: &[u8]| iso(parse_asn1(Tag::GeneralizedTime, t).unwrap());
        // two-digit years: 50 and later are the 1900s
        assert_eq!(utc(b"491231235959Z"), "2049-12-31T23:59:59Z");
        assert_eq!(utc(b"500101000000Z"), "1950-01-01T00:00:00Z");
        // without seconds, without Z, with a fraction at the very end
        assert_eq!(utc(b"2602031200"), "2026-02-03T12:00:00Z");
        assert_eq!(
            generalized(b"20261031000029.25"),
            "2026-10-31T00:00:29.250Z"
        );
        // offsets east and west, with and without minutes
        assert_eq!(utc(b"2602031200+0530"), "2026-02-03T06:30:00Z");
        assert_eq!(utc(b"2602031200-0130"), "2026-02-03T13:30:00Z");
        assert_eq!(utc(b"2602031200+05"), "2026-02-03T07:00:00Z");
        // a leap second counts as 59
        assert_eq!(utc(b"161231235960Z"), "2016-12-31T23:59:59Z");
        assert!(parse_asn1(Tag::UtcTime, b"2602031200X").is_err());
        assert!(parse_asn1(Tag::OctetString, b"2602031200Z").is_err());
    }

    #[test]
    fn invalid_dates_and_times() {
        let bad = |t: &[u8]| parse_asn1(Tag::GeneralizedTime, t).is_err();
        assert!(bad(b"20260001000000Z"));
        assert!(bad(b"20261301000000Z"));
        assert!(bad(b"20260100000000Z"));
        assert!(bad(b"20260431000000Z"));
        assert!(bad(b"20260229000000Z"));
        assert!(bad(b"19000229000000Z"));
        assert!(bad(b"20260101240000Z"));
        assert!(bad(b"20260101006000Z"));
        assert!(!bad(b"20240229000000Z"));
        assert!(!bad(b"20000229000000Z"));
        assert!(!bad(b"20261231235959Z"));
        // digits only: no signs or spaces inside the fields
        assert!(bad(b"2026+101000000Z"));
        assert!(bad(b"202601-1000000Z"));
        assert!(bad(b"20260101 1 0000Z"));
        assert!(bad(b"20260101000000+-100"));
        assert!(parse_asn1(Tag::UtcTime, b"+60101000000Z").is_err());
    }

    #[test]
    fn calendar_matches_day_counts() {
        // every day from 1900 to 2100 round-trips, and the days are consecutive
        let mut day = days_from_civil(1900, 1, 1);
        for y in 1900..2100 {
            for m in 1..=12 {
                for d in 1..=days_in_month(y, m) {
                    assert_eq!(days_from_civil(y, m, d), day);
                    assert_eq!(civil_from_days(day), (y, m, d));
                    day += 1;
                }
            }
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(iso(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(fields(1_700_000_000_123), (2023, 11, 14, 22, 13, 20, 123));
    }
}
