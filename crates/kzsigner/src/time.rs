//! Times as milliseconds since 1970 (UTC). Reading and writing the ASN.1 time formats is
//! [`kzcrypto::time`]'s; this module adds the clock and times for people.

pub use kzcrypto::time::*;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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

    #[test]
    fn times_for_people() {
        use chrono::{Local, Offset, TimeZone};
        assert_eq!(fmt(None), "-");
        let s = fmt(Some(0));
        let local_offset = Local
            .timestamp_millis_opt(0)
            .single()
            .unwrap()
            .offset()
            .fix();
        if local_offset.local_minus_utc() == 0 {
            assert_eq!(s, "1970-01-01 00:00:00 UTC");
        } else {
            assert!(!s.ends_with("UTC") && s.contains(':'), "{s}");
        }
    }
}
