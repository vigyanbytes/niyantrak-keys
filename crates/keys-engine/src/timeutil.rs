//! UTC time without a date library: epoch seconds <-> ISO 8601 / YYYYMMDD / file stamps.

use std::time::{SystemTime, UNIX_EPOCH};

pub const DAY: i64 = 86_400;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// (year, month, day) for days since 1970-01-01 (Howard Hinnant's civil_from_days).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn split(ts: i64) -> (i64, u32, u32, i64, i64, i64) {
    let days = ts.div_euclid(DAY);
    let secs = ts.rem_euclid(DAY);
    let (y, m, d) = civil(days);
    (y, m, d, secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// `2026-10-23T03:30:00Z`
pub fn iso(ts: i64) -> String {
    let (y, m, d, hh, mm, ss) = split(ts);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// `20261023` (the date in a key comment)
pub fn ymd(ts: i64) -> String {
    let (y, m, d, ..) = split(ts);
    format!("{y:04}{m:02}{d:02}")
}

/// `20261023T033000Z` (the suffix of a retired key file)
pub fn stamp(ts: i64) -> String {
    let (y, m, d, hh, mm, ss) = split(ts);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.frac]Z` (UTC only) or plain epoch seconds.
pub fn parse_iso(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || !s.ends_with('Z') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo as u32, d as u32) * DAY + h * 3600 + mi * 60 + se)
}

/// Parse a retired-file stamp `YYYYMMDDTHHMMSSZ`.
pub fn parse_stamp(s: &str) -> Option<i64> {
    if s.len() != 16 || s.as_bytes()[8] != b'T' || !s.ends_with('Z') {
        return None;
    }
    let iso = format!("{}-{}-{}T{}:{}:{}Z", &s[0..4], &s[4..6], &s[6..8], &s[9..11], &s[11..13], &s[13..15]);
    parse_iso(&iso)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trips() {
        let t = 1_792_726_200; // 2026-10-23T03:30:00Z
        assert_eq!(iso(t), "2026-10-23T03:30:00Z");
        assert_eq!(parse_iso(&iso(t)), Some(t));
        assert_eq!(ymd(t), "20261023");
        assert_eq!(stamp(t), "20261023T033000Z");
        assert_eq!(parse_stamp("20261023T033000Z"), Some(t));
    }

    #[test]
    fn epoch_and_leap_days() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        let leap = parse_iso("2028-02-29T12:00:00Z").unwrap();
        assert_eq!(iso(leap), "2028-02-29T12:00:00Z");
        assert_eq!(parse_iso("1700000000"), Some(1_700_000_000));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_iso("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_iso("yesterday"), None);
        assert_eq!(parse_iso("2026-10-23T03:30:00+05:30"), None);
        assert_eq!(parse_stamp("2026-10-23"), None);
    }
}
