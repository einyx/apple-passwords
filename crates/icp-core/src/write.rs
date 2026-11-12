//! Writing new items into the iCloud Keychain.
//!
//! The read side is: TLKShare -> TLK -> class key -> item key -> item plist. This is
//! the other direction: build an item plist, wrap its item key with the view's class
//! key, encrypt the plist, and save the record that carries it.
//!
//! The item written here is the classic "Web form password" one: the secret lives in
//! `v_Data` of an `inet` item whose access group is `com.apple.cfnetwork`. Apple's
//! current clients still store the password that way - the newer "Password Manager
//! Metadata" and "Website Metadata" items hold *metadata about* a credential, not the
//! credential - so a classic item is what a reader on any Apple device understands.

use std::time::{SystemTime, UNIX_EPOCH};

use rand::seq::SliceRandom;
use rand::Rng;

use base64::Engine;

use crate::ckks::{self, CloudKitRecord, FieldValue};
use crate::crypto;
use crate::error::{Error, Result};
use crate::keychain::authenticated_data_v2;
use crate::proto::Writer;

/// The zone web passwords live in.
pub const PASSWORDS_ZONE: &str = "Passwords";
/// The view inside it they live under.
pub const CLASS_A_VIEW: &str = "classA";

/// The attribute set of an internet-password item, as Apple's clients write it.
pub const INET_CLASS: &str = "inet";
pub const ACCESS_GROUP_NETWORK: &str = "com.apple.cfnetwork";
pub const AUTH_TYPE_FORM: &str = "form";
pub const DESCRIPTION_FORM: &str = "Web form password";
pub const DEFAULT_COMMENT: &str = "default";
/// Every item in the Passwords zone carries this value.
pub const PRIMARY_DOMAIN: &str = "ak";
pub const PROTOCOL_HTTPS: &str = "htps";
pub const PROTOCOL_HTTP: &str = "http";

/// The `uploadver` string says which client wrote the record.
pub fn default_uploadver() -> String {
    format!("apple-passwords {} (linux)", env!("CARGO_PKG_VERSION"))
}

/// The plist an `inet` keychain item carries.
///
/// `sha1` is 20 opaque bytes: it is *not* a hash of the password (items with
/// identical passwords have different values, so it cannot be one) and nothing can
/// verify it, so random bytes reproduce what Apple's clients write.
#[allow(clippy::too_many_arguments)]
pub fn build_internet_password_item(
    domain: &str,
    username: &str,
    password: &str,
    title: Option<&str>,
    notes: Option<&str>,
    protocol: Option<&str>,
    path: &str,
    port: i64,
    now: f64,
) -> plist::Value {
    let mut d = plist::Dictionary::new();
    d.insert("acct".into(), plist::Value::String(username.into()));
    d.insert("agrp".into(), plist::Value::String(ACCESS_GROUP_NETWORK.into()));
    d.insert("atyp".into(), plist::Value::String(AUTH_TYPE_FORM.into()));
    d.insert("cdat".into(), plist::Value::Date(date_from_unix(now)));
    d.insert("class".into(), plist::Value::String(INET_CLASS.into()));
    d.insert("desc".into(), plist::Value::String(DESCRIPTION_FORM.into()));
    d.insert(
        "icmt".into(),
        plist::Value::String(match notes {
            Some(n) if !n.is_empty() => n.into(),
            _ => DEFAULT_COMMENT.into(),
        }),
    );
    d.insert(
        "labl".into(),
        plist::Value::String(match title {
            Some(t) if !t.is_empty() => t.into(),
            _ => format!("{domain} ({username})"),
        }),
    );
    d.insert("mdat".into(), plist::Value::Date(date_from_unix(now)));
    d.insert("musr".into(), plist::Value::Data(Vec::new()));
    d.insert("path".into(), plist::Value::String(path.into()));
    d.insert("pdmn".into(), plist::Value::String(PRIMARY_DOMAIN.into()));
    d.insert("port".into(), plist::Value::Integer(port.into()));
    d.insert(
        "ptcl".into(),
        plist::Value::String(protocol.unwrap_or(PROTOCOL_HTTPS).into()),
    );
    d.insert("sdmn".into(), plist::Value::String(String::new()));
    d.insert("sha1".into(), plist::Value::Data(random_bytes(20)));
    d.insert("srvr".into(), plist::Value::String(domain.into()));
    d.insert("tomb".into(), plist::Value::Integer(0.into()));
    d.insert(
        "v_Data".into(),
        plist::Value::Data(password.as_bytes().to_vec()),
    );
    plist::Value::Dictionary(d)
}

fn date_from_unix(unix: f64) -> plist::Date {
    let secs = unix as u64;
    let nanos = ((unix - secs as f64) * 1e9) as u32;
    let time = UNIX_EPOCH + std::time::Duration::new(secs, nanos);
    plist::Date::from(time)
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// The result of building a record: its name and the fields it carries.
pub struct BuiltRecord {
    pub record_name: String,
    pub fields: Vec<(String, FieldValue)>,
}

/// Build the record that carries one item.
///
/// The field set is exactly the one a real item record carries - `data`, `encver`,
/// `gen`, `parentkeyref`, `server_suggestDeletion`, `server_wascurrent`,
/// `uploadver`, `wrappedkey` - because the record's own fields are what the item's
/// authenticated data is computed over: a reader recomputes it from the record it
/// fetched, so a field it does not know about would break the check.
pub fn build_item_record(
    item: &plist::Value,
    class_key: &[u8],
    parent_key_id: &str,
    zone: &str,
    user_id: &str,
    record_name: Option<&str>,
    encver: i64,
    gen: i64,
    uploadver: &str,
) -> Result<BuiltRecord> {
    let record_name = record_name
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid_upper());
    let item_key = random_bytes(64);

    let mut plaintext = Vec::new();
    plist::to_writer_binary(&mut plaintext, item)
        .map_err(|e| Error::Apple(format!("could not encode the item: {e}")))?;

    let wrapped_key = base64::engine::general_purpose::STANDARD
        .encode(crypto::siv_encrypt(class_key, &item_key, &[])?);

    let mut fields: Vec<(String, FieldValue)> = vec![
        ("encver".into(), FieldValue::Int(encver)),
        ("gen".into(), FieldValue::Int(gen)),
        (
            "parentkeyref".into(),
            FieldValue::Reference {
                record: parent_key_id.to_string(),
                zone: zone.to_string(),
                user: user_id.to_string(),
            },
        ),
        ("server_suggestDeletion".into(), FieldValue::Int(0)),
        ("server_wascurrent".into(), FieldValue::Int(0)),
        ("uploadver".into(), FieldValue::Str(uploadver.to_string())),
        ("wrappedkey".into(), FieldValue::Str(wrapped_key)),
    ];

    let aad = authenticated_data_v2(&record_name, &fields, encver, gen, parent_key_id);
    let headers: Vec<&[u8]> = aad.iter().map(|v| v.as_slice()).collect();
    let data = crypto::encrypt_item(&item_key, &plaintext, &headers)?;
    fields.insert(0, ("data".into(), FieldValue::Bytes(data)));

    Ok(BuiltRecord { record_name, fields })
}

/// Build the `CKDPRecord` for an item.
pub fn build_item_record_message(
    record_name: &str,
    fields: &[(String, FieldValue)],
    zone: &str,
    user_id: &str,
) -> Vec<u8> {
    ckks::build_record(record_name, "item", zone, user_id, fields)
}

/// The view's class key: (key id, key bytes).
pub fn view_key_from_records(
    records: &[CloudKitRecord],
    tlks: &[(String, Vec<u8>)],
    view: &str,
) -> Result<(String, Vec<u8>)> {
    let current = records
        .iter()
        .find(|r| r.record_type == "currentkey" && r.record_name == view)
        .ok_or(Error::NoViewKey)?;
    let key_id = current.get_str("parentkeyref").ok_or(Error::NoViewKey)?;
    let synckey = records
        .iter()
        .find(|r| r.record_type == "synckey" && r.record_name == key_id)
        .ok_or(Error::NoViewKey)?;
    let wrapped = synckey.get_str("wrappedkey").ok_or(Error::NoViewKey)?;
    let parent = synckey.get_str("parentkeyref").ok_or(Error::NoViewKey)?;
    let tlk = tlks
        .iter()
        .find(|(id, _)| id == parent)
        .map(|(_, k)| k)
        .ok_or(Error::NoViewKey)?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(wrapped)
        .map_err(|_| Error::NoViewKey)?;
    let key = crypto::siv_decrypt(tlk, &blob, &[])?;
    Ok((key_id.to_string(), key))
}

/// The outcome of a write.
pub struct SaveOutcome {
    pub record_name: String,
    pub etag: Option<String>,
}

/// Decrypt a record that was just written and check it holds what we wrote.
///
/// A save response is not proof - the escrow service reports success for writes that
/// addressed nothing. What counts is that the record is there, decrypts, and holds
/// what was written.
pub fn verify_saved_record(
    record: &CloudKitRecord,
    class_key: &[u8],
    expected_password: &str,
    expected_username: Option<&str>,
) -> bool {
    let parent = match record.get_str("parentkeyref") {
        Some(p) => p,
        None => return false,
    };
    let data = match record.get_bytes("data") {
        Some(d) => d,
        None => return false,
    };
    let wrapped = match record.get_str("wrappedkey") {
        Some(w) => w,
        None => return false,
    };
    let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(wrapped) else {
        return false;
    };
    let Ok(item_key) = crypto::siv_decrypt(class_key, &blob, &[]) else {
        return false;
    };
    let encver = record.get_int("encver").unwrap_or(2);
    let gen = record.get_int("gen").unwrap_or(0);
    let aad = authenticated_data_v2(&record.record_name, &record.fields, encver, gen, parent);
    let headers: Vec<&[u8]> = aad.iter().map(|v| v.as_slice()).collect();
    let Ok(plaintext) = crypto::decrypt_item(&item_key, data, &headers) else {
        return false;
    };
    let Ok(value) = plist::Value::from_reader(std::io::Cursor::new(plaintext)) else {
        return false;
    };
    let Some(d) = value.as_dictionary() else {
        return false;
    };
    let secret = d.get("v_Data").and_then(|v| v.as_data()).unwrap_or_default();
    if secret != expected_password.as_bytes() {
        return false;
    }
    if let Some(user) = expected_username {
        let acct = d.get("acct").and_then(|v| v.as_string()).unwrap_or("");
        if acct != user {
            return false;
        }
    }
    true
}

/// A random record name, in Apple's upper-case UUID form.
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

/// The characters a generated password is made of.
///
/// The ambiguous ones (`l`, `I`, `O`, `0`, `1`) are left out: a password that has to
/// be read off a screen and typed by hand should not contain letters and digits that
/// look alike.
const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*-_=+";

/// Generate a strong password.
///
/// At least one character of each class, the rest drawn at random from all of them.
pub fn generate_password(length: usize) -> String {
    let length = length.max(12);
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(length);
    // One of each class to start with.
    for set in [LOWER, UPPER, DIGITS, SYMBOLS] {
        let pick = set
            .as_bytes()
            .choose(&mut rng)
            .copied()
            .unwrap_or(b'x') as char;
        out.push(pick);
    }
    let all: Vec<char> = format!("{LOWER}{UPPER}{DIGITS}{SYMBOLS}").chars().collect();
    while out.chars().count() < length {
        let pick = all.choose(&mut rng).copied().unwrap_or('x');
        out.push(pick);
    }
    // Shuffle, so the guaranteed characters are not always at the front.
    let mut chars: Vec<char> = out.chars().collect();
    for i in (1..chars.len()).rev() {
        let j = rng.gen_range(0..=i);
        chars.swap(i, j);
    }
    chars.into_iter().collect()
}

/// A few suggestions, the way a password manager offers them.
pub fn suggest_passwords(count: usize) -> Vec<String> {
    (0..count.max(1))
        .map(|i| generate_password(if i == 0 { 20 } else { 16 }))
        .collect()
}

/// A reference-only helper: the record's fields, in the order Apple's writer uses.
pub fn field_order(fields: &[(String, FieldValue)]) -> Vec<String> {
    let mut names: Vec<String> = fields.iter().map(|(n, _)| n.clone()).collect();
    names.sort();
    names
}

/// The `uploadver` string of a record, for diagnostics.
pub fn uploadver_of(record: &CloudKitRecord) -> Option<&str> {
    record.get_str("uploadver")
}

/// Silence an unused-import warning when the Writer is not otherwise needed.
#[allow(dead_code)]
fn _writer_marker() -> Vec<u8> {
    Writer::new().finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_plist_shape() {
        let item = build_internet_password_item(
            "example.com",
            "alice",
            "hunter2",
            None,
            None,
            None,
            "",
            0,
            1_700_000_000.0,
        );
        let d = item.as_dictionary().unwrap();
        assert_eq!(d.get("class").unwrap().as_string(), Some("inet"));
        assert_eq!(d.get("atyp").unwrap().as_string(), Some("form"));
        assert_eq!(
            d.get("agrp").unwrap().as_string(),
            Some("com.apple.cfnetwork")
        );
        assert_eq!(d.get("pdmn").unwrap().as_string(), Some("ak"));
        assert_eq!(d.get("ptcl").unwrap().as_string(), Some("htps"));
        assert_eq!(d.get("labl").unwrap().as_string(), Some("example.com (alice)"));
        assert_eq!(d.get("v_Data").unwrap().as_data().unwrap(), b"hunter2");
        assert_eq!(d.get("sha1").unwrap().as_data().unwrap().len(), 20);
        assert_eq!(d.get("musr").unwrap().as_data().unwrap().len(), 0);
    }

    #[test]
    fn record_roundtrips_and_decrypts() {
        let class_key = [7u8; 64];
        let item = build_internet_password_item(
            "example.com",
            "alice",
            "hunter2",
            None,
            None,
            None,
            "",
            0,
            1_700_000_000.0,
        );
        let built = build_item_record(
            &item,
            &class_key,
            "CLASS-ID",
            PASSWORDS_ZONE,
            "user-1",
            Some("RECORD-NAME"),
            2,
            0,
            "test 1.0 (x)",
        )
        .unwrap();
        assert_eq!(built.record_name, "RECORD-NAME");
        let names: Vec<&str> = built.fields.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"data"));
        assert!(names.contains(&"wrappedkey"));
        assert!(names.contains(&"parentkeyref"));

        let raw = build_item_record_message(
            &built.record_name,
            &built.fields,
            PASSWORDS_ZONE,
            "user-1",
        );
        let record = ckks::parse_record(&raw).unwrap();
        assert_eq!(record.record_type, "item");
        assert!(verify_saved_record(&record, &class_key, "hunter2", Some("alice")));
        assert!(!verify_saved_record(&record, &class_key, "wrong", Some("alice")));
        assert!(!verify_saved_record(&record, &[9u8; 64], "hunter2", Some("alice")));
    }

    #[test]
    fn the_payload_is_authenticated_over_the_record() {
        let class_key = [7u8; 64];
        let item = build_internet_password_item(
            "example.com",
            "alice",
            "hunter2",
            None,
            None,
            None,
            "",
            0,
            1_700_000_000.0,
        );
        let built = build_item_record(
            &item,
            &class_key,
            "CLASS-ID",
            PASSWORDS_ZONE,
            "user-1",
            Some("RECORD-NAME"),
            2,
            0,
            "test 1.0 (x)",
        )
        .unwrap();
        let raw = build_item_record_message(
            &built.record_name,
            &built.fields,
            PASSWORDS_ZONE,
            "user-1",
        );
        let mut record = ckks::parse_record(&raw).unwrap();
        // A record under a different name must not decrypt.
        record.record_name = "OTHER".into();
        assert!(!verify_saved_record(&record, &class_key, "hunter2", Some("alice")));
    }
}
