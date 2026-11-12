//! The keychain's unwrap chain: TLKShare -> TLK -> class key -> item key -> item.
//!
//! * A **TLKShare** is the sponsor's gift of a view's top-level key, wrapped for this
//!   peer with ECIES. Unwrapping it yields a `CuttlefishSerializedKey` protobuf whose
//!   field 1 is the key's id and field 4 the key material.
//! * A **class key** (a `synckey` record) is a view key wrapped with the top-level key.
//! * An **item key** (an item record's `wrappedkey`) is wrapped with the class key.
//! * The **item** itself is the record's `data`, encrypted under the item key with the
//!   record's authenticated data as the associated data.

use base64::Engine;
use p384::SecretKey;

use crate::crypto;
use crate::error::{Error, Result};
use crate::proto::{Fields, Value};
use crate::ckks::{CloudKitRecord, FieldValue};

/// The item-record fields that are *not* part of the authenticated data.
const AAD_EXCLUDED: &[&str] = &[
    "gen",
    "pcspublickey",
    "UUID",
    "data",
    "pcsservice",
    "pcspublicidentity",
    "parentkeyref",
    "uploadver",
    "wrappedkey",
    "encver",
];

fn le8(n: i64) -> [u8; 8] {
    (n as u64).to_le_bytes()
}

/// Build the associated data of an `item` record (encver 2).
///
/// The values are sorted by key and used in that order, after the leading IV: the
/// record's own name, the encryption version, the generation and the class key the
/// item hangs under. A reader recomputes this from the record it fetched, so it is
/// what stops an item from being moved to another record.
pub fn authenticated_data_v2(
    uuid: &str,
    fields: &[(String, FieldValue)],
    encver: i64,
    gen: i64,
    parent_key_id: &str,
) -> Vec<Vec<u8>> {
    let mut aad: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut push = |key: &'static str, value: Vec<u8>| aad.push((key, value));

    // The keys are static strings so the map can be sorted by key.
    let mut map: Vec<(&'static str, Vec<u8>)> = Vec::new();
    map.push(("UUID", uuid.as_bytes().to_vec()));
    map.push(("encver", le8(encver).to_vec()));
    map.push(("gen", le8(gen).to_vec()));
    map.push(("wrappedkey", parent_key_id.as_bytes().to_vec()));

    // The PCS fields are authenticated when present, with their own encodings.
    if let Some(v) = field_value(fields, "pcsservice") {
        if let FieldValue::Int(i) = v {
            map.push(("pcsservice", le8(*i).to_vec()));
        }
    }
    for name in ["pcspublicidentity", "pcspublickey"] {
        if let Some(FieldValue::Bytes(b)) = field_value(fields, name) {
            let key: &'static str = if name == "pcspublicidentity" {
                "pcspublicidentity"
            } else {
                "pcspublickey"
            };
            map.push((key, b.clone()));
        }
    }
    for (name, value) in fields {
        if AAD_EXCLUDED.contains(&name.as_str()) || name.starts_with("server_") {
            continue;
        }
        match value {
            FieldValue::Str(s) => {
                if let Some(slot) = intern(name) {
                    map.push((slot, s.as_bytes().to_vec()));
                }
            }
            FieldValue::Bytes(b) => {
                if let Some(slot) = intern(name) {
                    map.push((slot, b.clone()));
                }
            }
            FieldValue::Int(i) => {
                if let Some(slot) = intern(name) {
                    map.push((slot, le8(*i).to_vec()));
                }
            }
            FieldValue::Reference { .. } => {}
        }
    }
    let _ = &mut push;
    map.sort_by(|a, b| a.0.cmp(b.0));
    map.into_iter().map(|(_, v)| v).collect()
}

/// Field names are compared as strings, but the map needs a `&'static str`; the
/// names that can appear in the authenticated data are known, so they are interned.
fn intern(name: &str) -> Option<&'static str> {
    const NAMES: &[&str] = &[
        "UUID",
        "encver",
        "gen",
        "wrappedkey",
        "pcsservice",
        "pcspublicidentity",
        "pcspublickey",
    ];
    NAMES.iter().copied().find(|n| *n == name)
}

fn field_value<'a>(fields: &'a [(String, FieldValue)], name: &str) -> Option<&'a FieldValue> {
    fields.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}

/// Unwrap the TLKShares addressed to this peer, yielding {key id: TLK}.
///
/// A TLKShare's `wrappedkey` ECIES-decrypts to a `CuttlefishSerializedKey` protobuf
/// {uuid(1), zoneName(2), keyclass(3), key(4)} - the id is field 1 and the key
/// material field 4.
pub fn unwrap_tlkshares(
    tlkshares: &[CloudKitRecord],
    our_peer_id: &str,
    our_encryption_key: &SecretKey,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for share in tlkshares {
        if share.get_str("receiver") != Some(our_peer_id) {
            continue;
        }
        let wrapped = match share.get_str("wrappedkey") {
            Some(w) => w,
            None => continue,
        };
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(wrapped) else {
            continue;
        };
        let Ok(expanded) = crate::nska::expand_ies(&blob) else {
            continue;
        };
        let Ok(serialized) = crypto::ecies_decrypt(
            our_encryption_key,
            &expanded.ephemeral_sender_public_key,
            &expanded.ciphertext,
            &expanded.auth_code,
        ) else {
            continue; // a poisoned or foreign share - skip it, keep the rest
        };
        let f = Fields::decode(&serialized)?;
        let key_id = f.string(1);
        let key = f.bytes(4).map(|b| b.to_vec());
        if let (Some(id), Some(k)) = (key_id, key) {
            out.push((id, k));
        }
    }
    Ok(out)
}

/// Unwrap each `synckey` with its parent TLK: {class key id: class key}.
pub fn unwrap_class_keys(
    synckeys: &[CloudKitRecord],
    tlks: &[(String, Vec<u8>)],
) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for sk in synckeys {
        let parent = match sk.get_str("parentkeyref") {
            Some(p) => p,
            None => continue,
        };
        let tlk = match tlks.iter().find(|(id, _)| id == parent) {
            Some((_, k)) => k,
            None => continue,
        };
        let wrapped = match sk.get_str("wrappedkey") {
            Some(w) => w,
            None => continue,
        };
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(wrapped) else {
            continue;
        };
        if let Ok(key) = crypto::siv_decrypt(tlk, &blob, &[]) {
            out.push((sk.record_name.clone(), key));
        }
    }
    out
}

/// Decrypt the items whose class key we hold.
///
/// Returns the item plists as a list of `(record name, plist)`.
pub fn decrypt_items(
    items: &[CloudKitRecord],
    class_keys: &[(String, Vec<u8>)],
) -> Vec<(String, plist::Value)> {
    let mut out = Vec::new();
    for item in items {
        let parent = match item.get_str("parentkeyref") {
            Some(p) => p,
            None => continue,
        };
        let ck = match class_keys.iter().find(|(id, _)| id == parent) {
            Some((_, k)) => k,
            None => continue,
        };
        let data = match item.get_bytes("data") {
            Some(d) => d,
            None => continue,
        };
        let wrapped = match item.get_str("wrappedkey") {
            Some(w) => w,
            None => continue,
        };
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(wrapped) else {
            continue;
        };
        let Ok(item_key) = crypto::siv_decrypt(ck, &blob, &[]) else {
            continue;
        };
        let encver = item.get_int("encver").unwrap_or(2);
        let gen = item.get_int("gen").unwrap_or(0);
        let aad = authenticated_data_v2(&item.record_name, &item.fields, encver, gen, parent);
        let headers: Vec<&[u8]> = aad.iter().map(|v| v.as_slice()).collect();
        let Ok(plaintext) = crypto::decrypt_item(&item_key, data, &headers) else {
            continue;
        };
        let Ok(value) = plist::Value::from_reader(std::io::Cursor::new(plaintext)) else {
            continue;
        };
        out.push((item.record_name.clone(), value));
    }
    out
}

/// A credential, as the app shows it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Credential {
    pub domain: String,
    pub username: String,
    pub password: String,
    pub title: String,
    pub notes: String,
    pub mdat: f64,
    pub last_used: f64,
    pub totp: String,
}

/// Apple's epoch: 2001-01-01, in unix seconds.
const APPLE_EPOCH: f64 = 978307200.0;

/// Best-effort conversion of a keychain date to unix seconds.
pub fn to_unix(value: &plist::Value) -> f64 {
    match value {
        plist::Value::Date(d) => {
            let t: std::time::SystemTime = (*d).into();
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        }
        plist::Value::Integer(i) => {
            let v = i.as_unsigned().unwrap_or(0) as f64;
            if v > 0.0 {
                if v < 1e9 {
                    v + APPLE_EPOCH
                } else {
                    v
                }
            } else {
                0.0
            }
        }
        _ => 0.0,
    }
}

/// The access groups the keychain uses.
const AGRP_LOGIN: &[&str] = &["com.apple.cfnetwork", "apple"];
const AGRP_SIDECAR_PREFIX: &str = "com.apple.password-manager";
const AGRP_CARD: &str = "com.apple.safari.credit-cards";
const AGRP_PASSKEY: &str = "com.apple.webkit.webauthn";
const SIDECAR_LABEL_PREFIX: &str = "password manager metadata:";
/// The sidecar keys that are kept (an allowlist: unknown keys are dropped).
const SIDECAR_KEEP: &[&str] = &["notes", "title", "ctxt", "totp"];
const PLUMBING_KEYSETS: &[&[&str]] = &[&["tlkUUID", "srcIdentity"], &["viewName", "encryptedData"]];
const CARD_KEYS: &[&str] = &["CardNumber", "FPANHash", "PrimaryAccountIdentifier", "CardSecurityCode"];

/// What an item's payload is.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    /// The secret, as text.
    Password(String),
    /// A metadata record (its plist).
    Sidecar(plist::Value),
    /// A payment card (its plist).
    Card(plist::Value),
    /// Keychain-sync internals.
    Plumbing,
    /// Key material.
    Binary,
    /// A passkey.
    Passkey,
    /// Something the keychain syncs that is not a login.
    Subsystem,
}

/// Classify a payload.
///
/// A password is text, so a payload that is not valid UTF-8 is classified rather
/// than decoded.
pub fn classify_payload(value: Option<&plist::Value>) -> Payload {
    let Some(value) = value else {
        return Payload::Password(String::new());
    };
    if let Some(text) = value.as_string() {
        return Payload::Password(text.to_string());
    }
    let Some(blob) = value.as_data() else {
        return Payload::Password(String::new());
    };
    if blob.is_empty() {
        return Payload::Password(String::new());
    }
    if blob.starts_with(b"bplist00") {
        if let Ok(parsed) = plist::Value::from_reader(std::io::Cursor::new(blob)) {
            let keys: Vec<String> = parsed
                .as_dictionary()
                .map(|d| d.keys().cloned().collect())
                .unwrap_or_default();
            for keyset in PLUMBING_KEYSETS {
                if keyset.iter().all(|k| keys.iter().any(|x| x == k)) {
                    return Payload::Plumbing;
                }
            }
            if CARD_KEYS.iter().any(|k| keys.iter().any(|x| x == k)) {
                return Payload::Card(parsed);
            }
            return Payload::Sidecar(parsed);
        }
    }
    if blob.starts_with(b"<?xml") {
        return Payload::Plumbing;
    }
    let Ok(text) = std::str::from_utf8(blob) else {
        return Payload::Binary;
    };
    // Some records decode as valid UTF-8 but are not text; a password has no C0
    // control bytes.
    if text
        .chars()
        .any(|c| (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' || c as u32 == 0x7f)
    {
        return Payload::Binary;
    }
    Payload::Password(text.to_string())
}

/// Classify an item, keying on its `agrp` access group.
///
/// An item whose group is unrecognised falls back to inspecting the payload.
pub fn classify_item(item: &plist::Value) -> Payload {
    let dict = match item.as_dictionary() {
        Some(d) => d,
        None => return Payload::Binary,
    };
    let agrp = dict
        .get("agrp")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    let raw = dict.get("v_Data").or_else(|| dict.get("password"));

    if agrp.starts_with(AGRP_SIDECAR_PREFIX) {
        return match classify_payload(raw) {
            Payload::Sidecar(p) => Payload::Sidecar(p),
            _ => Payload::Sidecar(plist::Value::Dictionary(plist::Dictionary::new())),
        };
    }
    if agrp == AGRP_CARD {
        return match classify_payload(raw) {
            Payload::Card(p) => Payload::Card(p),
            _ => Payload::Card(plist::Value::Dictionary(plist::Dictionary::new())),
        };
    }
    if agrp == AGRP_PASSKEY {
        return Payload::Passkey;
    }
    if AGRP_LOGIN.contains(&agrp.as_str()) {
        // A login group still holds the odd non-text blob.
        return match classify_payload(raw) {
            Payload::Password(p) => Payload::Password(p),
            Payload::Sidecar(p) => Payload::Sidecar(p),
            _ => Payload::Binary,
        };
    }
    if agrp.starts_with("com.apple.") {
        return Payload::Subsystem;
    }
    classify_payload(raw)
}

/// False for the non-login records the keychain also syncs: Protected Cloud Storage
/// service blobs (label "PCS com.apple.*", whose `acct` is a base64 key) and per-site
/// "Website Metadata" records.
pub fn is_credential(domain: &str, title: &str) -> bool {
    for tag in [domain, title] {
        let t = tag.trim().to_lowercase();
        if t.starts_with("pcs ") || t.starts_with("pcs-") || t.starts_with("website metadata")
            || t.contains("com.apple.")
        {
            return false;
        }
    }
    true
}

/// Turn decrypted item plists into credentials.
///
/// A login and its metadata sidecar are separate items joined on (server, account),
/// so this runs in two passes: collect both, then fold each sidecar onto its login.
pub fn credentials_from_items(items: &[(String, plist::Value)]) -> Vec<Credential> {
    let mut logins: Vec<Login> = Vec::new();
    let mut sidecars: Vec<(String, Sidecar)> = Vec::new();

    for (_, item) in items {
        let dict = match item.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        let get_str = |key: &str| -> String {
            dict.get(key)
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string()
        };
        let domain = {
            let d = ["srvr", "server", "domain", "url", "svce"]
                .iter()
                .find_map(|k| dict.get(*k).and_then(|v| v.as_string()))
                .unwrap_or("")
                .to_string();
            d
        };
        let username = ["acct", "username", "user"]
            .iter()
            .find_map(|k| dict.get(*k).and_then(|v| v.as_string()))
            .unwrap_or("")
            .to_string();
        let label = get_str("labl");
        let mdat = dict
            .get("mdat")
            .or_else(|| dict.get("cdat"))
            .map(to_unix)
            .unwrap_or(0.0);
        let key = format!("{}|{}", domain.to_lowercase(), username.to_lowercase());

        match classify_item(item) {
            Payload::Sidecar(payload) => {
                // The label names the login the sidecar describes, so trust it over an
                // empty payload.
                let d = payload.as_dictionary();
                let mut title = String::new();
                let mut notes = String::new();
                let mut totp = String::new();
                let mut last_used = 0.0;
                if let Some(d) = d {
                    for key in SIDECAR_KEEP {
                        if let Some(value) = d.get(*key) {
                            match *key {
                                "title" => {
                                    title = value.as_string().unwrap_or("").to_string()
                                }
                                "notes" => {
                                    notes = value.as_string().unwrap_or("").to_string()
                                }
                                "totp" => totp = value.as_string().unwrap_or("").to_string(),
                                "ctxt" => last_used = sidecar_last_used(value),
                                _ => {}
                            }
                        }
                    }
                }
                sidecars.push((
                    key,
                    Sidecar {
                        title,
                        notes,
                        totp,
                        last_used,
                    },
                ));
                continue;
            }
            Payload::Password(password) => {
                if domain.is_empty() && username.is_empty() {
                    continue;
                }
                if username.is_empty() && password.is_empty() {
                    continue;
                }
                logins.push(Login {
                    key,
                    domain,
                    username,
                    password,
                    label,
                    mdat,
                });
            }
            _ => continue,
        }
    }

    logins
        .into_iter()
        .map(|login| {
            let side = sidecars.iter().find(|(k, _)| *k == login.key);
            let mut cred = Credential {
                domain: login.domain,
                username: login.username,
                password: login.password,
                title: login.label,
                notes: String::new(),
                mdat: login.mdat,
                last_used: 0.0,
                totp: String::new(),
            };
            if let Some((_, side)) = side {
                if !side.title.is_empty() {
                    cred.title = side.title.clone();
                }
                cred.notes = side.notes.clone();
                cred.totp = side.totp.clone();
                cred.last_used = side.last_used;
            }
            cred
        })
        .filter(|c| is_credential(&c.domain, &c.title))
        .collect()
}

/// The sidecar's last-used time.
fn sidecar_last_used(ctxt: &plist::Value) -> f64 {
    ctxt.as_dictionary()
        .and_then(|d| d.get("lUsed"))
        .map(to_unix)
        .unwrap_or(0.0)
}

struct Login {
    key: String,
    domain: String,
    username: String,
    password: String,
    label: String,
    mdat: f64,
}

struct Sidecar {
    title: String,
    notes: String,
    totp: String,
    last_used: f64,
}

/// Look up a field in a decoded message, for the callers that need the raw shape.
pub fn field<'a>(fields: &'a Fields, n: u32) -> Option<&'a Value> {
    fields.get(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::FieldValue;

    #[test]
    fn aad_order_is_sorted_and_stable() {
        let fields = vec![
            ("encver".to_string(), FieldValue::Int(2)),
            ("gen".to_string(), FieldValue::Int(0)),
            ("uploadver".to_string(), FieldValue::Str("x".into())),
            ("parentkeyref".to_string(), FieldValue::Str("P".into())),
        ];
        let aad = authenticated_data_v2("UUID-1", &fields, 2, 0, "P");
        assert_eq!(aad.len(), 4);
        assert_eq!(aad[0], b"UUID-1".to_vec());
        assert_eq!(aad[1], le8(2).to_vec());
        assert_eq!(aad[2], le8(0).to_vec());
        assert_eq!(aad[3], b"P".to_vec());
    }

    #[test]
    fn aad_ignores_server_fields() {
        let fields = vec![
            ("server_wascurrent".to_string(), FieldValue::Int(0)),
            ("server_suggestDeletion".to_string(), FieldValue::Int(0)),
        ];
        let aad = authenticated_data_v2("U", &fields, 2, 0, "P");
        assert_eq!(aad.len(), 4);
    }
}
