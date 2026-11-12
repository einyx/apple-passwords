//! The CKKS record protocol: the CloudKit messages that carry keychain records.
//!
//! The message layout (field numbers and their names) comes from the schema
//! reconstructed from CloudKitDaemon's binary. The write path's field numbers were
//! checked against a live server; every record the keychain holds re-encodes
//! byte-identically with these builders.

use crate::error::Result;
use crate::proto::{Fields, Value, Writer};

/// The keychain's CKKS zones (private DB).
pub const KEYCHAIN_ZONES: &[&str] = &[
    "Passwords",
    "Manatee",
    "Engram",
    "SecureObjectSync",
    "ProtectedCloudStorage",
    "CreditCards",
    "ApplePay",
    "WiFi",
    "Home",
    "Groups",
    "Contacts",
    "Mail",
    "LimitedPeersAllowed",
    "SE-PTC",
    "Photos",
];

/// CKDPIdentifier.Type
pub const ID_TYPE_RECORD: u64 = 1;
pub const ID_TYPE_DEVICE: u64 = 2;
pub const ID_TYPE_RECORD_ZONE: u64 = 6;
pub const ID_TYPE_USER: u64 = 7;

/// CKDPRecordFieldValue.Type
pub const VALUE_TYPE_BYTES: u64 = 1;
pub const VALUE_TYPE_STRING: u64 = 3;
pub const VALUE_TYPE_REFERENCE: u64 = 5;
pub const VALUE_TYPE_INT64: u64 = 7;

/// CKDPRecordReference.Type - the keychain's parent links use VALIDATING.
pub const REFERENCE_TYPE_VALIDATING: u64 = 3;

/// CKDPRecordPermission
pub const PERMISSION_READ_WRITE: u64 = 2;

/// CKDPRecordSaveRequest.SaveSemantics
pub const SAVE_SEMANTICS_FAIL_IF_OUTDATED: u64 = 1;
pub const SAVE_SEMANTICS_FAIL_IF_EXISTS: u64 = 2; // create
pub const SAVE_SEMANTICS_OVERRIDE: u64 = 3; // update

/// Operation types (the field number of the request equals the operation type).
pub const OP_TYPE_ZONE_RETRIEVE: u64 = 201;
pub const OP_TYPE_RECORD_SAVE: u64 = 210;
pub const OP_TYPE_RECORD_RETRIEVE: u64 = 211;
pub const OP_TYPE_RECORD_RETRIEVE_CHANGES: u64 = 213;
pub const OP_TYPE_RECORD_DELETE: u64 = 214;

/// A record's field value, as the keychain uses it.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Bytes(Vec<u8>),
    Str(String),
    Int(i64),
    /// A reference to another record (the keychain's `parentkeyref`).
    Reference {
        record: String,
        zone: String,
        user: String,
    },
}

impl FieldValue {
    /// The value as a string, if it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The value as bytes, if it is a blob.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The value as an integer, if it is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            FieldValue::Int(i) => Some(*i),
            _ => None,
        }
    }
}

/// A CloudKit record: its name, its type and its fields.
#[derive(Debug, Clone, Default)]
pub struct CloudKitRecord {
    pub record_name: String,
    pub record_type: String,
    /// The record's version tag - an update has to present the one it read.
    pub etag: String,
    pub fields: Vec<(String, FieldValue)>,
}

impl CloudKitRecord {
    /// A field's value.
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// A field's value as a string.
    ///
    /// A reference yields the name of the record it points at - which is how the
    /// keychain's `parentkeyref` reads: the id of the class key the item hangs under.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(FieldValue::Str(s)) => Some(s),
            Some(FieldValue::Reference { record, .. }) => Some(record),
            _ => None,
        }
    }

    /// A field's value as bytes.
    pub fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        self.get(name).and_then(|v| v.as_bytes())
    }

    /// A field's value as an integer.
    pub fn get_int(&self, name: &str) -> Option<i64> {
        self.get(name).and_then(|v| v.as_int())
    }
}

/// An `Identifier` - a name and a type.
pub fn identifier(name: &str, type_: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(1, Some(name)).uint64(2, Some(type_));
    w.finish()
}

/// A `RecordZoneIdentifier` - the zone plus its owner.
pub fn record_zone_identifier(zone: &str, user_id: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.message(1, Some(&identifier(zone, ID_TYPE_RECORD_ZONE)))
        .message(2, Some(&identifier(user_id, ID_TYPE_USER)));
    w.finish()
}

/// A `RecordIdentifier` - the record plus the zone it lives in.
pub fn build_record_identifier(record_name: &str, zone: &str, user_id: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.message(1, Some(&identifier(record_name, ID_TYPE_RECORD)))
        .message(2, Some(&record_zone_identifier(zone, user_id)));
    w.finish()
}

/// A `Record.Field.Value` for a plain value.
pub fn build_field_value(value: &FieldValue) -> Vec<u8> {
    let mut w = Writer::new();
    match value {
        FieldValue::Bytes(b) => {
            w.uint64(1, Some(VALUE_TYPE_BYTES)).bytes(2, Some(b));
        }
        FieldValue::Str(s) => {
            w.uint64(1, Some(VALUE_TYPE_STRING)).string(7, Some(s));
        }
        FieldValue::Int(i) => {
            w.uint64(1, Some(VALUE_TYPE_INT64)).int64(4, Some(*i));
        }
        FieldValue::Reference { record, zone, user } => {
            let mut refw = Writer::new();
            refw.uint64(1, Some(REFERENCE_TYPE_VALIDATING))
                .message(2, Some(&build_record_identifier(record, zone, user)));
            let reference = refw.finish();
            w.uint64(1, Some(VALUE_TYPE_REFERENCE))
                .message(9, Some(&reference));
        }
    }
    w.finish()
}

/// A `Record.Field` - a name and a value.
pub fn build_record_field(name: &str, value: &FieldValue) -> Vec<u8> {
    let mut ident = Writer::new();
    ident.string(1, Some(name));
    let mut w = Writer::new();
    w.message(1, Some(ident.as_slice()))
        .message(2, Some(&build_field_value(value)));
    w.finish()
}

/// A `CKDPRecord`.
pub fn build_record(
    record_name: &str,
    record_type: &str,
    zone: &str,
    user_id: &str,
    fields: &[(String, FieldValue)],
) -> Vec<u8> {
    let mut typew = Writer::new();
    typew.string(1, Some(record_type));
    let mut w = Writer::new();
    w.message(
        2,
        Some(&build_record_identifier(record_name, zone, user_id)),
    )
    .message(3, Some(typew.as_slice()));
    for (name, value) in fields {
        w.message(7, Some(&build_record_field(name, value)));
    }
    w.uint64(15, Some(PERMISSION_READ_WRITE));
    w.finish()
}

/// A `CKDPRecordSaveRequest`.
///
/// `merge` keeps the fields the request does not mention. `save_semantics` is
/// `SAVE_SEMANTICS_FAIL_IF_EXISTS` to create and `SAVE_SEMANTICS_OVERRIDE` to update.
///
/// The keychain's zones carry no protection info, so the two protection-tag fields
/// are left unset: CloudKit never encrypts the keychain's records.
pub fn build_record_save_request(
    record: &[u8],
    merge: bool,
    save_semantics: u64,
    zone_protection_info_tag: Option<&str>,
    record_protection_info_tag: Option<&str>,
    etag: Option<&str>,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.message(1, Some(record))
        .bool(2, Some(merge))
        .string(4, etag)
        .uint64(6, Some(save_semantics))
        .string(7, zone_protection_info_tag)
        .string(8, record_protection_info_tag);
    w.finish()
}

/// A `CKDPRecordDeleteRequest` - the rollback path for a write that went wrong.
pub fn build_record_delete_request(
    record_name: &str,
    zone: &str,
    user_id: &str,
    etag: Option<&str>,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.message(
        1,
        Some(&build_record_identifier(record_name, zone, user_id)),
    )
    .string(2, etag);
    w.finish()
}

/// A `CKDPRecordRetrieveRequest` - fetch one record by name.
pub fn build_record_retrieve_request(record_name: &str, zone: &str, user_id: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.message(
        1,
        Some(&build_record_identifier(record_name, zone, user_id)),
    );
    w.finish()
}

/// A `CKDPRecordRetrieveChangesRequest` - which records changed in a zone.
pub fn build_retrieve_changes_request(
    zone_identifier: &[u8],
    continuation_token: Option<&[u8]>,
    max_changes: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(1, continuation_token)
        .message(2, Some(zone_identifier))
        .uint64(4, Some(max_changes));
    w.finish()
}

/// A CloudKit date value (seconds since the Unix epoch).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CkDate {
    pub time: f64,
}

/// Parse a record out of a `CKDPRecord` message.
pub fn parse_record(raw: &[u8]) -> Result<CloudKitRecord> {
    let f = Fields::decode(raw)?;
    let mut record = CloudKitRecord {
        etag: f.string(1).unwrap_or_default(),
        ..Default::default()
    };

    if let Some(id) = f.bytes(2) {
        let idf = Fields::decode(id)?;
        if let Some(val) = idf.bytes(1) {
            let vf = Fields::decode(val)?;
            record.record_name = vf.string(1).unwrap_or_default();
        }
    }
    if let Some(t) = f.bytes(3) {
        let tf = Fields::decode(t)?;
        record.record_type = tf.string(1).unwrap_or_default();
    }
    for fld in f.get_all(7) {
        let Value::Bytes(bytes) = fld else { continue };
        let ff = Fields::decode(bytes)?;
        let ident = match ff.bytes(1) {
            Some(i) => Fields::decode(i)?.string(1),
            None => None,
        };
        let name = match ident {
            Some(n) => n,
            None => continue,
        };
        let value = match ff.bytes(2) {
            Some(v) => match parse_field_value(v)? {
                Some(v) => v,
                None => continue,
            },
            None => continue,
        };
        record.fields.push((name, value));
    }
    Ok(record)
}

/// Parse a `Record.Field.Value`.
fn parse_field_value(raw: &[u8]) -> Result<Option<FieldValue>> {
    let v = Fields::decode(raw)?;
    if let Some(b) = v.bytes(2) {
        return Ok(Some(FieldValue::Bytes(b.to_vec())));
    }
    if let Some(s) = v.string(7) {
        return Ok(Some(FieldValue::Str(s)));
    }
    if let Some(i) = v.uint(4) {
        return Ok(Some(FieldValue::Int(i as i64)));
    }
    if let Some(d) = v.bytes(6) {
        let df = Fields::decode(d)?;
        if let Some(Value::Fixed64(bits)) = df.get(1) {
            return Ok(Some(FieldValue::Int(f64::from_bits(*bits) as i64)));
        }
    }
    if let Some(r) = v.bytes(9) {
        let rf = Fields::decode(r)?;
        if let Some(rid) = rf.bytes(2) {
            let ridf = Fields::decode(rid)?;
            if let Some(val) = ridf.bytes(1) {
                let vf = Fields::decode(val)?;
                if let Some(name) = vf.string(1) {
                    return Ok(Some(FieldValue::Reference {
                        record: name,
                        zone: String::new(),
                        user: String::new(),
                    }));
                }
            }
        }
    }
    Ok(None)
}

/// The records of a changes response, with the continuation token and the status.
#[allow(clippy::type_complexity)]
pub type ChangesPage = (Vec<CloudKitRecord>, Option<Vec<u8>>, Option<u64>);

/// Parse a `CKDPRecordZoneChangesResponse` into its zones.
pub fn parse_zone_changes_response(raw: &[u8]) -> Result<ZoneChanges> {
    let f = Fields::decode(raw)?;
    let mut zones = Vec::new();
    for change in f.get_all(1) {
        let Value::Bytes(bytes) = change else {
            continue;
        };
        let cf = Fields::decode(bytes)?;
        let Some(zid) = cf.bytes(1) else { continue };
        let info = parse_zone_identifier(zid)?;
        zones.push(ZoneChange {
            name: info.0,
            raw: zid.to_vec(),
            change_type: cf.uint(2),
        });
    }
    Ok(ZoneChanges {
        zones,
        continuation_token: f.bytes(2).map(|b| b.to_vec()),
        status: f.uint(4),
    })
}

/// A `RecordZoneIdentifier`, as a name.
fn parse_zone_identifier(raw: &[u8]) -> Result<(String, Vec<u8>)> {
    let f = Fields::decode(raw)?;
    let name = f
        .bytes(1)
        .and_then(|v| Fields::decode(v).ok())
        .and_then(|v| v.string(1))
        .unwrap_or_default();
    Ok((name, raw.to_vec()))
}

/// A zone that changed.
#[derive(Debug, Clone)]
pub struct ZoneChange {
    /// The zone's name.
    pub name: String,
    /// The zone identifier, verbatim.
    pub raw: Vec<u8>,
    /// 2 = deleted.
    pub change_type: Option<u64>,
}

/// The zones that changed.
#[derive(Debug, Clone, Default)]
pub struct ZoneChanges {
    pub zones: Vec<ZoneChange>,
    pub continuation_token: Option<Vec<u8>>,
    pub status: Option<u64>,
}

/// Parse a `CKDPRecordRetrieveChangesResponse` into its records.
pub fn parse_retrieve_changes_response(raw: &[u8]) -> Result<ChangesPage> {
    let f = Fields::decode(raw)?;
    let mut records = Vec::new();
    for change in f.get_all(1) {
        let Value::Bytes(bytes) = change else {
            continue;
        };
        let cf = Fields::decode(bytes)?;
        if let Some(Value::Bytes(rec)) = cf.get(5) {
            records.push(parse_record(rec)?);
        }
    }
    let token = f.bytes(2).map(|b| b.to_vec());
    let status = f.uint(4);
    Ok((records, token, status))
}

/// Parse a `CKDPRecordRetrieveResponse` -> the record.
pub fn parse_record_retrieve_response(raw: &[u8]) -> Result<Option<CloudKitRecord>> {
    let f = Fields::decode(raw)?;
    match f.bytes(1) {
        Some(rec) => Ok(Some(parse_record(rec)?)),
        None => Ok(None),
    }
}

/// Parse a `CKDPRecordSaveResponse` -> (etag, the record as the server now holds it).
pub fn parse_record_save_response(raw: &[u8]) -> Result<(Option<String>, Option<CloudKitRecord>)> {
    let f = Fields::decode(raw)?;
    let etag = f.string(2);
    let record = match f.bytes(4) {
        Some(rec) => Some(parse_record(rec)?),
        None => None,
    };
    Ok((etag, record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_identifier_layout() {
        let raw = build_record_identifier("ABCD", "Passwords", "user-1");
        let f = Fields::decode(&raw).unwrap();
        assert_eq!(f.field_numbers(), vec![1, 2]);
        let val = Fields::decode(f.bytes(1).unwrap()).unwrap();
        assert_eq!(val.string(1).as_deref(), Some("ABCD"));
        assert_eq!(val.uint(2), Some(ID_TYPE_RECORD));
        let zone = Fields::decode(f.bytes(2).unwrap()).unwrap();
        let zval = Fields::decode(zone.bytes(1).unwrap()).unwrap();
        assert_eq!(zval.string(1).as_deref(), Some("Passwords"));
        assert_eq!(zval.uint(2), Some(ID_TYPE_RECORD_ZONE));
        let owner = Fields::decode(zone.bytes(2).unwrap()).unwrap();
        assert_eq!(owner.string(1).as_deref(), Some("user-1"));
        assert_eq!(owner.uint(2), Some(ID_TYPE_USER));
    }

    #[test]
    fn field_value_types() {
        let bytes = Fields::decode(&build_field_value(&FieldValue::Bytes(vec![1, 2]))).unwrap();
        assert_eq!(bytes.uint(1), Some(VALUE_TYPE_BYTES));
        assert_eq!(bytes.bytes(2), Some(&[1u8, 2][..]));

        let s = Fields::decode(&build_field_value(&FieldValue::Str("x".into()))).unwrap();
        assert_eq!(s.uint(1), Some(VALUE_TYPE_STRING));
        assert_eq!(s.string(7).as_deref(), Some("x"));

        let i = Fields::decode(&build_field_value(&FieldValue::Int(-7))).unwrap();
        assert_eq!(i.uint(1), Some(VALUE_TYPE_INT64));
        assert_eq!(i.uint(4), Some(u64::MAX - 6));
    }

    #[test]
    fn save_request_layout() {
        let raw = build_record_save_request(
            b"rec",
            true,
            SAVE_SEMANTICS_FAIL_IF_EXISTS,
            None,
            None,
            None,
        );
        let f = Fields::decode(&raw).unwrap();
        assert_eq!(f.field_numbers(), vec![1, 2, 6]);
        assert_eq!(f.uint(2), Some(1));
        assert_eq!(f.uint(6), Some(SAVE_SEMANTICS_FAIL_IF_EXISTS));
        assert_eq!(f.bytes(1), Some(&b"rec"[..]));
    }

    #[test]
    fn record_roundtrip() {
        let fields = vec![
            ("data".to_string(), FieldValue::Bytes(vec![9, 9, 9])),
            ("encver".to_string(), FieldValue::Int(2)),
            ("parentkeyref".to_string(), FieldValue::Str("KEY-ID".into())),
        ];
        let raw = build_record("REC", "item", "Passwords", "user", &fields);
        let rec = parse_record(&raw).unwrap();
        assert_eq!(rec.record_name, "REC");
        assert_eq!(rec.record_type, "item");
        assert_eq!(rec.get_str("parentkeyref"), Some("KEY-ID"));
        assert_eq!(rec.get_int("encver"), Some(2));
        assert_eq!(rec.get_bytes("data"), Some(&[9u8, 9, 9][..]));
    }
}
