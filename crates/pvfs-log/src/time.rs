//! UTC timestamps, RFC 3339 with milliseconds (D222 decision 2). No date
//! crate in this tree; the civil-date arithmetic is Howard Hinnant's.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// `2026-10-07T18:04:05.123Z`.
pub fn format_ts(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let s = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        (s % 3600) / 60,
        s % 60,
        ms % 1000
    )
}

/// The inverse of [`format_ts`]; also takes no fraction, a longer one, or
/// a `+hh:mm`/`-hh:mm` offset (a record from somewhere else).
pub fn parse_ts(t: &str) -> Option<u64> {
    let b = t.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { t.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut i = 19;
    let mut frac_ms = 0i64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &t[start..i];
        if digits.is_empty() {
            return None;
        }
        let ms3: String = digits.chars().chain("000".chars()).take(3).collect();
        frac_ms = ms3.parse().ok()?;
    }
    let offset_s: i64 = match b.get(i) {
        Some(b'Z') | Some(b'z') if i + 1 == b.len() => 0,
        Some(&c @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
            let oh: i64 = t.get(i + 1..i + 3)?.parse().ok()?;
            let om: i64 = t.get(i + 4..i + 6)?.parse().ok()?;
            let o = oh * 3600 + om * 60;
            if c == b'+' {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86_400 + h * 3600 + mi * 60 + s - offset_s;
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1000 + frac_ms as u64)
}

/// (year, month, day, hour, minute, second) in UTC — RFC 3164's stamp.
pub(crate) fn utc_parts(ms: u64) -> (i64, u32, u32, u64, u64, u64) {
    let secs = ms / 1000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let s = secs % 86_400;
    (y, m, d, s / 3600, (s % 3600) / 60, s % 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
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
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
