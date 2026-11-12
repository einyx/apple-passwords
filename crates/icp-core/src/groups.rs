//! The shared password groups.
//!
//! A group is a CloudKit zone in the sharing container whose records are encrypted
//! under keys the members hold. Reading one is a read-only operation: list the
//! zones, open the zone's protection with the service keys from the keychain, and
//! decrypt the records.

use crate::ckks::{self, CloudKitRecord};
use crate::cloudkit::CloudKitTransport;
use crate::error::{Error, Result};
use crate::pcs::{self, PcsKey, ShareProtection};
use crate::proto::{Fields, Value};

/// The sharing container.
pub const KCSHARING_CONTAINER: &str = "com.apple.security.shared.keychain";
/// The bundle the sharing container is addressed with.
pub const KCSHARING_BUNDLE: &str = "com.apple.security.kcsharing";

/// The zone retrieve operation.
const OP_TYPE_ZONE_RETRIEVE: u64 = 201;
/// Where the zone retrieve is posted.
const ZONE_RETRIEVE_URL: &str = "https://gateway.icloud.com/ckdatabase/api/client/zone/retrieve";

/// A trace line, when `ICP_DEBUG_GROUPS` is set.
fn trace(message: &str) {
    if std::env::var("ICP_DEBUG_GROUPS").is_ok() {
        eprintln!("[groups] {message}");
    }
}

/// A shared group.
#[derive(Debug, Clone, Default)]
pub struct Group {
    /// The group's id (the zone name without the prefix).
    pub id: String,
    /// The group's name.
    pub name: String,
    /// The items, as the keychain's own items: the sharing record's name and the
    /// decrypted item.
    pub items: Vec<(String, plist::Value)>,
}

impl Group {
    /// The group's label: its name, or its id when it has none.
    pub fn label(&self) -> String {
        if self.name.is_empty() {
            self.id.clone()
        } else {
            self.name.clone()
        }
    }

    /// The group's logins, as credentials.
    ///
    /// A shared item has no keychain record of its own, so it carries no record
    /// name: it cannot be edited or deleted from here.
    pub fn credentials(&self) -> Vec<crate::keychain::Credential> {
        let items: Vec<(String, plist::Value)> = self
            .items
            .iter()
            .map(|(_, item)| (String::new(), item.clone()))
            .collect();
        crate::keychain::credentials_from_items(&items)
    }
}

/// A field's value: its type and its bytes.
type FieldValue = (u64, Option<Vec<u8>>);

/// A record in a group zone, with the protection the keychain parser leaves out.
#[derive(Debug, Clone, Default)]
struct GroupRecord {
    name: String,
    record_type: String,
    /// The field name -> (type, value).
    fields: Vec<(String, FieldValue)>,
    protection: Option<Vec<u8>>,
}

/// Fetch the groups this account owns, skipping any that cannot be opened.
pub fn fetch_groups(
    transport: &CloudKitTransport,
    user_id: &str,
    anisette: &mut crate::anisette::Anisette,
    device: &crate::device::Device,
    keychain_items: &[(String, plist::Value)],
) -> Result<Vec<Group>> {
    // The zones that changed.
    let mut zones: Vec<(String, Vec<u8>, Option<u64>)> = Vec::new();
    let mut continuation: Option<Vec<u8>> = None;
    for _ in 0..25 {
        let page = transport.fetch_zone_changes(
            continuation.as_deref(),
            KCSHARING_BUNDLE,
            anisette,
            device,
        )?;
        let parsed = ckks::parse_zone_changes_response(&page)?;
        for zone in parsed.zones {
            zones.push((zone.name, zone.raw, zone.change_type));
        }
        continuation = parsed.continuation_token.clone();
        if parsed.status == Some(2) || continuation.is_none() {
            break;
        }
    }
    let deleted: Vec<String> = zones
        .iter()
        .filter(|(_, _, change_type)| *change_type == Some(2))
        .map(|(name, _, _)| name.clone())
        .collect();
    let live: Vec<(String, Vec<u8>)> = zones
        .iter()
        .filter(|(name, _, _)| name.starts_with("group-") && !deleted.contains(name))
        .map(|(name, raw, _)| (name.clone(), raw.clone()))
        .collect();
    let _ = user_id;
    trace(&format!(
        "{} zones changed, {} live",
        zones.len(),
        live.len()
    ));
    for (name, _, change_type) in &zones {
        trace(&format!("zone {name} change {change_type:?}"));
    }

    let keychain_keys = pcs::keychain_key_index(keychain_items);
    trace(&format!(
        "{} PCS service keys in the keychain",
        keychain_keys.len()
    ));
    let mut groups = Vec::new();
    for (name, raw) in live {
        let id = name.trim_start_matches("group-").to_string();
        let mut group = Group {
            id,
            name: String::new(),
            items: Vec::new(),
        };
        // The zone's protection, and the records' protection.
        let (protection, record_protection) =
            match fetch_zone_protection(transport, &raw, anisette, device) {
                Ok(v) => v,
                Err(e) => {
                    trace(&format!("{name}: the zone cannot be retrieved ({e})"));
                    continue;
                }
            };
        let Some(protection) = protection else {
            trace(&format!("{name}: the zone has no protection"));
            continue;
        };
        let share = match ShareProtection::parse(&protection) {
            Ok(s) => s,
            Err(e) => {
                trace(&format!("{name}: the protection does not parse ({e})"));
                continue;
            }
        };
        let privs: Vec<p256::SecretKey> = share
            .public_keys()
            .iter()
            .filter_map(|x| {
                keychain_keys
                    .iter()
                    .find(|(kx, _)| kx == x)
                    .and_then(|(_, der)| pcs::private_key_from_der(der).ok())
            })
            .collect();
        if privs.is_empty() {
            trace(&format!(
                "{name}: none of the {} service keys opens it",
                share.public_keys().len()
            ));
            continue;
        }
        // The zone's own symmetric keys are not the record keys: the records are
        // protected by the zone's record protection, which the identity keys open.
        let (_zone_keys, idents) = match share.open(&privs) {
            Ok(v) => v,
            Err(e) => {
                trace(&format!("{name}: the protection does not open ({e})"));
                continue;
            }
        };
        let mut default_keys: Vec<PcsKey> = Vec::new();
        if let Some(record_protection) = record_protection {
            if let Ok(share) = ShareProtection::parse(&record_protection) {
                if let Ok((keys, _)) = share.open(&idents) {
                    default_keys = keys;
                }
            }
        }
        let records = match fetch_records(transport, &raw, anisette, device) {
            Ok(r) => r,
            Err(e) => {
                trace(&format!("{name}: the records cannot be fetched ({e})"));
                continue;
            }
        };
        trace(&format!("{name}: {} records", records.len()));
        for record in records {
            let keys = if record.protection.is_some() {
                match record
                    .protection
                    .as_ref()
                    .and_then(|p| ShareProtection::parse(p).ok())
                {
                    Some(share) => match share.open(&idents) {
                        Ok((keys, _)) => keys,
                        Err(_) => continue,
                    },
                    None => continue,
                }
            } else {
                default_keys.clone()
            };
            if record.record_type == "cloudkit.share" {
                if let Some(raw) = decrypt_field(&record, &name, "displayName", &keys) {
                    group.name = field_string(&raw, 6);
                }
            } else if record.record_type == "item" {
                if let Some(raw) = decrypt_field(&record, &name, "payload", &keys) {
                    if let Some(item) = sharing_item_to_keychain(&raw) {
                        group.items.push((record.name.clone(), item));
                    }
                }
            }
        }
        groups.push(group);
    }
    Ok(groups)
}

/// The zone's protection structures: the zone's own, and the records'.
type ZoneProtections = (Option<Vec<u8>>, Option<Vec<u8>>);
fn fetch_zone_protection(
    transport: &CloudKitTransport,
    zone_raw: &[u8],
    anisette: &mut crate::anisette::Anisette,
    device: &crate::device::Device,
) -> Result<ZoneProtections> {
    let mut request = crate::proto::Writer::new();
    request.bytes(1, Some(zone_raw));
    let result = transport.perform(
        ZONE_RETRIEVE_URL,
        OP_TYPE_ZONE_RETRIEVE,
        OP_TYPE_ZONE_RETRIEVE,
        &request.finish(),
        KCSHARING_BUNDLE,
        None,
        "Private",
        crate::cloudkit::DB_PRIVATE,
        None,
        anisette,
        device,
    )?;
    let raw = result.field(OP_TYPE_ZONE_RETRIEVE).unwrap_or_default();
    let response = Fields::decode(&raw)?;
    let summary = response
        .bytes(1)
        .ok_or_else(|| Error::Apple("the zone answer had no summary".into()))?;
    let summary = Fields::decode(summary)?;
    let zone = summary
        .bytes(1)
        .ok_or_else(|| Error::Apple("the zone answer had no zone".into()))?;
    let zone = Fields::decode(zone)?;
    let blob = |n: u32| -> Option<Vec<u8>> {
        zone.bytes(n)
            .and_then(|info| Fields::decode(info).ok())
            .and_then(|f| f.bytes(1).map(|b| b.to_vec()))
    };
    Ok((blob(3), blob(6)))
}

/// The records of a group zone.
fn fetch_records(
    transport: &CloudKitTransport,
    zone_raw: &[u8],
    anisette: &mut crate::anisette::Anisette,
    device: &crate::device::Device,
) -> Result<Vec<GroupRecord>> {
    let mut out = Vec::new();
    let mut continuation: Option<Vec<u8>> = None;
    for _ in 0..50 {
        let raw = transport.fetch_records_with(
            &ckks::build_retrieve_changes_request(zone_raw, continuation.as_deref(), 500),
            KCSHARING_BUNDLE,
            anisette,
            device,
        )?;
        let response = Fields::decode(&raw)?;
        for change in response.get_all(1) {
            let Value::Bytes(bytes) = change else {
                continue;
            };
            let change = Fields::decode(bytes)?;
            if let Some(rec) = change.bytes(5) {
                out.push(parse_record(rec)?);
            }
        }
        continuation = response.bytes(2).map(|b| b.to_vec());
        if response.uint(4) != Some(1) || continuation.is_none() {
            break;
        }
    }
    Ok(out)
}

/// Parse a group record.
fn parse_record(raw: &[u8]) -> Result<GroupRecord> {
    let f = Fields::decode(raw)?;
    let mut name = String::new();
    if let Some(rid) = f.bytes(2) {
        let rid = Fields::decode(rid)?;
        if let Some(idval) = rid.bytes(1) {
            let idval = Fields::decode(idval)?;
            name = idval.string(1).unwrap_or_default();
        }
    }
    let record_type = f
        .bytes(3)
        .and_then(|t| Fields::decode(t).ok())
        .and_then(|t| t.string(1))
        .unwrap_or_default();
    let mut fields = Vec::new();
    for fld in f.get_all(7) {
        let Value::Bytes(bytes) = fld else { continue };
        let ff = Fields::decode(bytes)?;
        let (Some(ident), Some(val)) = (ff.bytes(1), ff.bytes(2)) else {
            continue;
        };
        let ident = Fields::decode(ident)?;
        let name = ident.string(1).unwrap_or_default();
        let vf = Fields::decode(val)?;
        let value = match vf.get(2) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        };
        fields.push((name, (vf.uint(1).unwrap_or(0), value)));
    }
    let protection = f
        .bytes(13)
        .and_then(|p| Fields::decode(p).ok())
        .and_then(|p| p.bytes(1).map(|b| b.to_vec()));
    Ok(GroupRecord {
        name,
        record_type,
        fields,
        protection,
    })
}

/// Decrypt one field of a group record.
fn decrypt_field(
    record: &GroupRecord,
    zone_name: &str,
    field: &str,
    keys: &[PcsKey],
) -> Option<Vec<u8>> {
    let (_, (_, data)) = record.fields.iter().find(|(name, _)| name == field)?;
    let data = data.as_ref()?;
    let aad = format!("{zone_name}-{}-{field}", record.name).into_bytes();
    pcs::decrypt_with_any(keys, data, &aad).ok()
}

/// A string out of a decrypted field.
fn field_string(raw: &[u8], field: u32) -> String {
    Fields::decode(raw)
        .ok()
        .and_then(|f| f.string(field))
        .unwrap_or_default()
}

/// Convert a shared item into the keychain's own item shape.
pub fn sharing_item_to_keychain(payload: &[u8]) -> Option<plist::Value> {
    let f = Fields::decode(payload).ok()?;
    let ip = f.bytes(3)?;
    let f = Fields::decode(ip).ok()?;
    let mut item = plist::Dictionary::new();
    item.insert(
        "agrp".into(),
        plist::Value::String(f.string(1).unwrap_or_default()),
    );
    item.insert("mdat".into(), plist::Value::Real(fixed64(f.uint(2))));
    item.insert("cdat".into(), plist::Value::Real(fixed64(f.uint(3))));
    item.insert(
        "acct".into(),
        plist::Value::String(f.string(4).unwrap_or_default()),
    );
    item.insert(
        "srvr".into(),
        plist::Value::String(f.string(6).unwrap_or_default()),
    );
    if let Some(Value::Bytes(data)) = f.get(9) {
        item.insert("v_Data".into(), plist::Value::Data(data.clone()));
    }
    item.insert(
        "labl".into(),
        plist::Value::String(f.string(12).unwrap_or_default()),
    );
    item.insert(
        "desc".into(),
        plist::Value::String(f.string(24).unwrap_or_default()),
    );
    if f.get(10).is_some() {
        item.insert(
            "path".into(),
            plist::Value::String(f.string(10).unwrap_or_default()),
        );
    }
    Some(plist::Value::Dictionary(item))
}

/// A 64-bit value as a double.
fn fixed64(value: Option<u64>) -> f64 {
    match value {
        Some(v) => f64::from_bits(v),
        None => 0.0,
    }
}

/// The records of a group zone, for the diagnostics.
pub fn zone_names(records: &[CloudKitRecord]) -> Vec<String> {
    records.iter().map(|r| r.record_name.clone()).collect()
}
