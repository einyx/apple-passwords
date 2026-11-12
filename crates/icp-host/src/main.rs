//! The native-messaging host for the browser extension.
//!
//! It speaks Chrome's native-messaging protocol on stdin/stdout (a 4-byte
//! little-endian length prefix, then UTF-8 JSON), and answers the extension's
//! requests from the local encrypted vault.
//!
//! Protocol (JSON):
//!   -> {"cmd":"ping"}                                 <- {"ok":true,"count":N}
//!   -> {"cmd":"match","domain":"login.example.com"}  <- {"ok":true,"credentials":[{...}]}
//!   -> {"cmd":"totp","domain":...,"username":...}      <- {"ok":true,"totp":{"code":...}}
//!   -> {"cmd":"save","domain":...,"username":...,"password":...}
//!                                                     <- {"ok":true,"record_name":"..."}
//!   -> {"cmd":"update","record":...,"password":...}   <- {"ok":true,"record_name":"..."}
//!   -> {"cmd":"delete","record":...}                   <- {"ok":true}
//!   -> {"cmd":"generate","count":3}                    <- {"ok":true,"passwords":[...]}
//!
//! A credential's one-time-code secret never crosses this protocol: `match`
//! carries the code generated at request time, and `totp` re-generates it when
//! the browser's copy has rolled over.

use std::io::{Read, Write};

use icp_core::engine::Engine;
use icp_core::keychain::Credential;
use icp_core::vault;
use serde_json::{json, Value};

/// A native-messaging request is a small JSON object. The length prefix is 32
/// bit, so cap it: the peer is the browser, but a bad length should not ask for
/// a huge read.
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

fn main() {
    let mut credentials = vault::load().unwrap_or_default();
    let aliases = load_aliases();

    loop {
        let Some(request) = read_message() else {
            return;
        };
        let response = handle(&request, &credentials, &aliases);
        if write_message(&response).is_err() {
            return;
        }
    }
}

/// Read one message from stdin.
fn read_message() -> Option<Value> {
    let mut len_bytes = [0u8; 4];
    if std::io::stdin().read_exact(&mut len_bytes).is_err() {
        return None;
    }
    let length = u32::from_le_bytes(len_bytes) as usize;
    if length > MAX_MESSAGE_BYTES {
        return None;
    }
    let mut data = vec![0u8; length];
    if std::io::stdin().read_exact(&mut data).is_err() {
        return None;
    }
    serde_json::from_slice(&data).ok()
}

/// Write one message to stdout.
fn write_message(message: &Value) -> std::io::Result<()> {
    let encoded = serde_json::to_vec(message).unwrap_or_default();
    std::io::stdout().write_all(&(encoded.len() as u32).to_le_bytes())?;
    std::io::stdout().write_all(&encoded)?;
    std::io::stdout().flush()
}

/// Answer a request.
fn handle(request: &Value, credentials: &[Credential], aliases: &[Value]) -> Value {
    let cmd = request.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    match cmd {
        "ping" => json!({"ok": true, "count": credentials.len()}),
        "match" => {
            let domain = request.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            if domain.is_empty() {
                return json!({"ok": false, "error": "missing domain"});
            }
            let matched: Vec<Value> = credentials
                .iter()
                .filter(|c| domains_match(domain, &c.domain))
                .map(|c| credential_json(c))
                .collect();
            json!({"ok": true, "credentials": matched, "aliases": aliases})
        }
        "totp" => {
            let domain = request.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            let username = request.get("username").and_then(|v| v.as_str()).unwrap_or("");
            for c in credentials {
                if c.username == username && domains_match(domain, &c.domain) {
                    if let Some(code) = icp_core::totp::code_for(c, None) {
                        return json!({"ok": true, "totp": {
                            "code": code.code,
                            "expires": code.expires,
                            "period": code.period,
                        }});
                    }
                }
            }
            json!({"ok": false, "error": "no code for that login"})
        }
        "generate" => {
            let count = request
                .get("count")
                .and_then(|v| v.as_u64())
                .unwrap_or(3)
                .clamp(1, 10) as usize;
            json!({"ok": true, "passwords": icp_core::write::suggest_passwords(count)})
        }
        "save" => save(request),
        "update" => update(request),
        "delete" => delete(request),
        other => json!({"ok": false, "error": format!("unknown cmd {other}")}),
    }
}

/// Write a new login into the keychain.
fn save(request: &Value) -> Value {
    let domain = request.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let username = request.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = request.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if !valid_domain(domain) {
        return json!({"ok": false, "error": "that does not look like a site name"});
    }
    if username.is_empty() || password.is_empty() {
        return json!({"ok": false, "error": "the page did not give a username and a password"});
    }
    let notes = request.get("notes").and_then(|v| v.as_str());
    match Engine::open(None) {
        Ok(mut engine) => match engine.add_password(
            domain,
            username,
            password,
            None,
            notes,
            "Passwords",
        ) {
            Ok(outcome) => json!({"ok": true, "record_name": outcome.record_name}),
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        },
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

/// Change a password that is already in the keychain.
fn update(request: &Value) -> Value {
    let record = request.get("record").and_then(|v| v.as_str()).unwrap_or("");
    let password = request.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if record.is_empty() || password.is_empty() {
        return json!({"ok": false, "error": "missing record or password"});
    }
    match Engine::open(None) {
        Ok(mut engine) => {
            match engine.update_password(record, password, None, None, "Passwords") {
                Ok(outcome) => json!({"ok": true, "record_name": outcome.record_name}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

/// Remove a login from the keychain.
fn delete(request: &Value) -> Value {
    let record = request.get("record").and_then(|v| v.as_str()).unwrap_or("");
    if record.is_empty() {
        return json!({"ok": false, "error": "missing record"});
    }
    match Engine::open(None) {
        Ok(mut engine) => match engine.delete_password(record, "Passwords") {
            Ok(()) => json!({"ok": true}),
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        },
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

/// A credential, as the extension sees it.
fn credential_json(c: &Credential) -> Value {
    let code = icp_core::totp::code_for(c, None);
    json!({
        "domain": c.domain,
        "username": c.username,
        "password": c.password,
        "title": c.title,
        "mdat": c.mdat,
        "notes": c.notes,
        "last_used": c.last_used,
        "record": c.record_name,
        "totp": match code {
            Some(code) => json!({"code": code.code, "expires": code.expires}),
            None => Value::Null,
        },
    })
}

/// Does the page's domain match the stored one?
///
/// Matches the exact host, and either being a sub-domain of the other (so
/// `example.com` fills on `login.example.com` and vice-versa). Conservative: it
/// requires a dotted-boundary suffix, so `notexample.com` never matches
/// `example.com`, and the shorter side has to contain a dot - a stored domain of
/// `com` would otherwise match every .com page.
fn domains_match(page: &str, stored: &str) -> bool {
    let p = normalise(page);
    let s = normalise(stored);
    if p.is_empty() || s.is_empty() {
        return false;
    }
    if p == s {
        return true;
    }
    if !p.contains('.') || !s.contains('.') {
        return false;
    }
    p.ends_with(&format!(".{s}")) || s.ends_with(&format!(".{p}"))
}

/// A stored login with no host of its own can still match, by its title - but
/// only on the label left of the top-level domain, so a site like
/// `cloudflare.attacker.net` cannot claim a "Cloudflare" entry.
///
/// This is the fallback for the *dotless* entries only: a login stored against
/// `example.com` never matches `login.example.com` by its name.
fn title_matches(page: &str, credential: &Credential) -> bool {
    if normalise(&credential.domain).contains('.') {
        return false;
    }
    let host = normalise(page);
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return false;
    }
    let candidate = labels[labels.len() - 2];
    let name = if credential.title.is_empty() {
        &credential.domain
    } else {
        &credential.title
    };
    let lowered = name.to_lowercase();
    let tokens: Vec<&str> = lowered
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 4 && !GENERIC.contains(t))
        .collect();
    tokens.contains(&candidate)
}

const GENERIC: [&str; 11] = [
    "account", "accounts", "admin", "app", "dashboard", "login", "password", "passwords", "signin",
    "sign", "www",
];

/// Reduce a URL or host to a bare lowercase hostname (strip scheme/port/path/leading www).
fn normalise(value: &str) -> String {
    let mut v = value.trim().to_lowercase();
    if let Some((_, rest)) = v.split_once("://") {
        v = rest.to_string();
    }
    v = v.split('/').next().unwrap_or("").to_string();
    v = v.split('?').next().unwrap_or("").to_string();
    v = v.rsplit('@').next().unwrap_or("").to_string();
    v = v.split(':').next().unwrap_or("").to_string();
    if let Some(rest) = v.strip_prefix("www.") {
        v = rest.to_string();
    }
    v
}

/// A site name and nothing else - no scheme, no path, no whitespace.
fn valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.contains("://") || domain.contains('/') || domain.contains(' ') {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// The Hide My Email aliases, from the cache the Python client writes.
fn load_aliases() -> Vec<Value> {
    let path = icp_core::device::config_dir().join("aliases.enc");
    if !path.exists() {
        return Vec::new();
    }
    let Ok(blob) = std::fs::read(&path) else {
        return Vec::new();
    };
    let Ok(plaintext) = icp_core::session::open(&icp_core::session::master_key(), &blob) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_slice::<Value>(&plaintext) else {
        return Vec::new();
    };
    parsed
        .get("aliases")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}
