//! The iCloud Keychain client core.
//!
//! The protocol this speaks was reverse-engineered from the wire; the findings and
//! the byte-level pins live in the Python implementation's RESEARCH.md. Every module
//! here has a Python counterpart that was verified against live Apple servers, and
//! the two are checked against each other.

pub mod anisette;
pub mod apple_tls;
pub mod ckks;
pub mod cloudkit;
pub mod crypto;
pub mod cuttlefish;
pub mod device;
pub mod engine;
pub mod error;
pub mod escrow;
pub mod gsa;
pub mod icloud;
pub mod join;
pub mod joinflow;
pub mod keychain;
pub mod login;
pub mod nska;
pub mod octagon;
pub mod proto;
pub mod session;
pub mod srp;
pub mod totp;
pub mod vault;
pub mod write;

pub use error::{Error, Result};

/// A random UUID in Apple's upper-case form.
pub fn uuid_upper() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
    .to_uppercase()
}

/// Turn a header map into the HTTP one, skipping what cannot be a header value.
pub fn header_map(
    headers: std::collections::BTreeMap<String, String>,
) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (key, value) in headers {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
            reqwest::header::HeaderValue::from_str(&value),
        ) {
            out.insert(name, value);
        }
    }
    out
}

/// The current time, as RFC 3339 in UTC - the format Apple's headers use.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let time = secs % 86400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// The calendar date from the days since the Unix epoch.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The zone web passwords live in.
pub const PASSWORDS_ZONE: &str = "Passwords";
/// The view inside that zone they live under.
pub const CLASS_A_VIEW: &str = "classA";
