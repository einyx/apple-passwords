//! One-time passwords (the "Codes" category).
//!
//! The verification code lives in a login's metadata sidecar, as an `otpauth`
//! description: the secret, the issuer, the account name and the parameters. This
//! turns that into the `otpauth://totp/...` URI a generator can use, and then into
//! the code itself.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::keychain::Credential;

/// The algorithm names Apple's sidecar uses.
fn algorithm(name: &str) -> &'static str {
    match name.to_ascii_uppercase().as_str() {
        "SHA256" => "SHA256",
        "SHA512" => "SHA512",
        _ => "SHA1",
    }
}

fn number(value: Option<&plist::Value>, default: u32) -> u32 {
    value
        .and_then(|v| v.as_signed_integer())
        .map(|v| v as u32)
        .unwrap_or(default)
}

/// The `otpauth://totp/...` URI for a sidecar's `totp` block, or "" when it holds
/// no usable secret.
///
/// The sidecar also keeps the scanned `originalURL` verbatim, but an enrolment typed
/// in as a setup key has none, so the URI is rebuilt from the structured fields.
pub fn uri_from_sidecar(block: Option<&plist::Value>) -> String {
    let Some(block) = block else {
        return String::new();
    };
    let Some(d) = block.as_dictionary() else {
        return String::new();
    };
    let secret = d.get("secret").and_then(|v| v.as_data()).unwrap_or_default();
    if secret.is_empty() {
        return String::new();
    }
    let issuer = d
        .get("issuer")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    let account = d
        .get("accountName")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    let label = if issuer.is_empty() && account.is_empty() {
        "icloud".to_string()
    } else {
        [issuer.as_str(), account.as_str()]
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(":")
    };
    let b32 = base64::engine::general_purpose::STANDARD.encode(secret);
    let mut params = vec![
        ("secret".to_string(), b32.trim_end_matches('=').to_string()),
        (
            "algorithm".to_string(),
            algorithm(d.get("algorithm").and_then(|v| v.as_string()).unwrap_or("SHA1")).to_string(),
        ),
        (
            "digits".to_string(),
            number(d.get("digits"), 6).to_string(),
        ),
        ("period".to_string(), number(d.get("period"), 30).to_string()),
    ];
    if !issuer.is_empty() {
        params.push(("issuer".to_string(), issuer));
    }
    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("otpauth://totp/{}?{}", percent_encode(&label), query)
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The one-time code for a URI, and when it expires.
pub struct Code {
    pub code: String,
    pub expires: f64,
    pub period: u64,
}

/// Generate the code for an `otpauth://totp/...` URI.
pub fn generate(uri: &str, at: Option<f64>) -> Option<Code> {
    let (label, query) = uri.split_once("?")?;
    let mut secret = String::new();
    let mut algorithm_name = "SHA1".to_string();
    let mut digits = 6u32;
    let mut period = 30u64;
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let v = percent_decode(v);
        match k {
            "secret" => secret = v,
            "algorithm" => algorithm_name = v.to_ascii_uppercase(),
            "digits" => digits = v.parse().unwrap_or(6),
            "period" => period = v.parse().unwrap_or(30),
            _ => {}
        }
    }
    if secret.is_empty() {
        return None;
    }
    let key = base32_decode(&secret)?;
    let now = at.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    });
    let counter = (now as u64) / period.max(1);
    let code = hotp(&key, counter, digits, &algorithm_name)?;
    Some(Code {
        code,
        expires: ((counter + 1) * period.max(1)) as f64,
        period: period.max(1),
    })
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// The base32 alphabet (RFC 4648), without padding.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = Vec::new();
    for c in text.trim_end_matches('=').bytes() {
        let index = ALPHABET.iter().position(|a| *a == c.to_ascii_uppercase())? as u32;
        value = (value << 5) | index;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((value >> bits) as u8);
            value &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// The HOTP value (RFC 4226), truncated to `digits`.
fn hotp(key: &[u8], counter: u64, digits: u32, algorithm_name: &str) -> Option<String> {
    let mut mac = match algorithm_name {
        "SHA256" => {
            let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).ok()?;
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut m = Hmac::<sha2::Sha512>::new_from_slice(key).ok()?;
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut m = Hmac::<Sha1>::new_from_slice(key).ok()?;
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
    };
    mac.truncate(20);
    let offset = (mac[19] & 0x0f) as usize;
    let value = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    let modulus = 10u32.pow(digits);
    Some(format!(
        "{:0width$}",
        value % modulus,
        width = digits as usize
    ))
}

/// The code for a credential, if it has one.
pub fn code_for(credential: &Credential, at: Option<f64>) -> Option<Code> {
    if credential.totp.is_empty() {
        return None;
    }
    generate(&credential.totp, at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4226_test_vector() {
        // RFC 4226's test secret "12345678901234567890" (base32: GEZDGNBVGY3TQOJQ).
        let key = b"12345678901234567890";
        assert_eq!(hotp(key, 0, 6, "SHA1").unwrap(), "755224");
        assert_eq!(hotp(key, 1, 6, "SHA1").unwrap(), "287082");
        assert_eq!(hotp(key, 2, 6, "SHA1").unwrap(), "359152");
    }

    #[test]
    fn base32_roundtrip() {
        // "12345678901234567890" in base32.
        let b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(base32_decode(b32).unwrap(), b"12345678901234567890".to_vec());
    }

    #[test]
    fn a_uri_without_a_secret_gives_nothing() {
        assert_eq!(uri_from_sidecar(None), "");
        let mut d = plist::Dictionary::new();
        d.insert("title".into(), plist::Value::String("x".into()));
        assert_eq!(uri_from_sidecar(Some(&plist::Value::Dictionary(d))), "");
    }
}
