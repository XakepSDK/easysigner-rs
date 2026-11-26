//! Times as milliseconds since 1970 (UTC). Reading and writing the ASN.1 time formats is
//! [`kzcrypto::time`]'s; this module adds the clock and times for people.

pub use kzcrypto::time::*;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `ms` in this computer's time zone (None outside years -9999 to 9999).
pub fn local(ms: i64) -> Option<jiff::Zoned> {
    Some(
        jiff::Timestamp::from_millisecond(ms)
            .ok()?
            .to_zoned(jiff::tz::TimeZone::system()),
    )
}

/// `ms` in Astana's time (UTC+5 all year), as Kazakhstan's documents give it.
pub fn astana(ms: i64) -> Option<jiff::civil::DateTime> {
    let t = jiff::Timestamp::from_millisecond(ms).ok()?;
    Some(jiff::tz::offset(5).to_datetime(t))
}

/// `ms` as UTC, formatted with `strftime` codes ("" outside years -9999 to 9999).
pub fn utc_format(ms: i64, format: &str) -> String {
    jiff::Timestamp::from_millisecond(ms)
        .map(|t| t.strftime(format).to_string())
        .unwrap_or_default()
}

/// An RFC 3339 / ISO 8601 time with its offset ("2026-11-01T10:00:00+05:00"), as ms.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    s.trim()
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_millisecond())
}

/// Local time for people: 2026-11-01 15:00:00 +05:00.
pub fn fmt(ms: Option<i64>) -> String {
    let Some(ms) = ms else { return "-".into() };
    match local(ms) {
        Some(t) => {
            let zone = if t.offset().seconds() == 0 {
                "UTC".to_string()
            } else {
                t.strftime("%:z").to_string()
            };
            format!("{} {zone}", t.strftime("%Y-%m-%d %H:%M:%S"))
        }
        None => iso(ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_for_people() {
        assert_eq!(fmt(None), "-");
        let s = fmt(Some(0));
        if local(0).unwrap().offset().seconds() == 0 {
            assert_eq!(s, "1970-01-01 00:00:00 UTC");
        } else {
            assert!(!s.ends_with("UTC") && s.contains(':'), "{s}");
        }
    }

    #[test]
    fn fixed_zones_and_formats() {
        assert_eq!(astana(0).unwrap().to_string(), "1970-01-01T05:00:00");
        assert_eq!(utc_format(0, "%Y-%m-%dT%H:%M:%SZ"), "1970-01-01T00:00:00Z");
        assert_eq!(parse_rfc3339("1970-01-01T05:00:00+05:00"), Some(0));
        assert_eq!(
            parse_rfc3339(" 2026-11-01T10:00:00Z "),
            Some(1_793_527_200_000)
        );
        assert_eq!(parse_rfc3339("yesterday"), None);
    }
}
