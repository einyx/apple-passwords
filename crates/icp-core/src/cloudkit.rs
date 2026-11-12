//! The CloudKit transport.
//!
//! Every operation is a gzipped, length-delimited `RequestOperation` posted to the
//! CloudKit gateway, authenticated by the `cloudKitToken` in an HTTP header (never in
//! the body), with the anisette machine identity on top.

use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use sha1::Digest;

use crate::anisette::Anisette;
use crate::ckks;
use crate::device::Device;
use crate::error::{Error, Result};
use crate::proto::{delimit, Fields, Value, Writer};

pub const CKCODE_INVOKE_URL: &str =
    "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke";
pub const CKDATABASE_SYNC_URL: &str =
    "https://gateway.icloud.com/ckdatabase/api/client/record/sync";
pub const CKDATABASE_SAVE_URL: &str =
    "https://gateway.icloud.com/ckdatabase/api/client/record/save";
pub const CKDATABASE_DELETE_URL: &str =
    "https://gateway.icloud.com/ckdatabase/api/client/record/delete";
pub const CKDATABASE_RETRIEVE_URL: &str =
    "https://gateway.icloud.com/ckdatabase/api/client/record/retrieve";

pub const CUTTLEFISH_CONTAINER: &str = "com.apple.security.keychain";
pub const CUTTLEFISH_BUNDLE: &str = "com.apple.security.cuttlefish";
pub const SECURITYD_BUNDLE: &str = "com.apple.securityd";
pub const CUTTLEFISH_SERVICE: &str = "Cuttlefish";
pub const CK_SERVICE_IDENTITY: &str =
    "com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)";

pub const ENV_PRODUCTION: u64 = 1;
pub const DB_PRIVATE: u64 = 1;
pub const ISOLATION_ZONE: u64 = 1;
pub const OP_TYPE_FUNCTION_INVOKE: u64 = 1101;

/// The device fields CloudKit's header wants.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub device_uuid: String,
    pub serial: String,
    pub name: String,
    pub software_version: String,
    pub hardware_version: String,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            device_uuid: String::new(),
            serial: "0000000000".into(),
            name: "Mac".into(),
            software_version: "Mac OS X;13.4.1;22F8".into(),
            hardware_version: "MacBookPro18,3".into(),
        }
    }
}

/// Build the `RequestOperation.Header`.
///
/// `locale` is (language, region) at field 17. Reads do not need it; writes do.
pub fn build_header(
    config: &DeviceConfig,
    container: &str,
    bundle: &str,
    database: u64,
    locale: Option<(&str, &str)>,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(2, Some(container))
        .string(3, Some(bundle))
        .message(
            7,
            Some(&ckks::identifier(&config.device_uuid, ckks::ID_TYPE_DEVICE)),
        )
        .string(8, Some(&config.software_version))
        .string(9, Some(&config.hardware_version))
        .string(10, Some("com.apple.cloudkit.CloudKitDaemon"))
        .string(11, Some("1970"));
    if let Some((lang, region)) = locale {
        let mut l = Writer::new();
        l.string(1, Some(lang)).string(2, Some(region));
        w.message(17, Some(l.as_slice()));
    }
    w.string(18, Some("5.0"))
        .uint64(19, Some(ENV_PRODUCTION))
        .string(21, Some(&config.name))
        .string(22, Some(&config.device_uuid))
        .uint64(23, Some(database))
        .uint64(25, Some(ISOLATION_ZONE))
        .uint64(29, Some(0))
        .string(
            32,
            Some(&hex::encode(sha1::Sha1::digest(
                config.device_uuid.as_bytes(),
            ))),
        )
        .string(33, Some(&config.serial))
        .uint64(34, Some(0))
        .uint64(35, Some(1));
    w.finish()
}

/// Wrap a request in the `RequestOperation` envelope.
///
/// The request rides in its own high field number, which equals the operation type.
pub fn build_request_operation(
    header: &[u8],
    op_type: u64,
    request_field: u64,
    request_bytes: &[u8],
    operation_uuid: &str,
) -> Vec<u8> {
    let mut operation = Writer::new();
    operation
        .string(1, Some(operation_uuid))
        .uint64(2, Some(op_type))
        .bool(4, Some(true));
    let mut w = Writer::new();
    w.message(1, Some(header))
        .message(2, Some(operation.as_slice()))
        .message(request_field as u32, Some(request_bytes));
    w.finish()
}

/// A CloudKit response.
pub struct CloudKitResult {
    pub code: i64,
    pub error_description: Option<String>,
    pub fields: Fields,
}

impl CloudKitResult {
    /// An operation-specific response field.
    pub fn field(&self, num: u64) -> Option<Vec<u8>> {
        match self.fields.get(num as u32) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        }
    }
}

/// Parse a `ResponseOperation`.
pub fn parse_response_operation(raw: &[u8]) -> Result<CloudKitResult> {
    let f = Fields::decode(raw)?;
    let mut code = 1i64;
    let mut description = None;
    if let Some(result) = f.bytes(3) {
        let rf = Fields::decode(result)?;
        if let Some(c) = rf.uint(1) {
            code = c as i64;
        }
        if let Some(err) = rf.bytes(2) {
            let ef = Fields::decode(err)?;
            description = ef.string(4);
        }
    }
    Ok(CloudKitResult {
        code,
        error_description: description,
        fields: f,
    })
}

/// Performs CloudKit operations for the keychain container.
pub struct CloudKitTransport {
    ck_token: String,
    pub user_id: String,
    pub device: DeviceConfig,
    pub container: String,
    client: reqwest::blocking::Client,
}

impl CloudKitTransport {
    /// Build a transport.
    pub fn new(ck_token: &str, user_id: &str, device: DeviceConfig) -> Result<CloudKitTransport> {
        let client = crate::apple_tls::client(Duration::from_secs(30))?;
        Ok(CloudKitTransport {
            ck_token: ck_token.to_string(),
            user_id: user_id.to_string(),
            device,
            container: CUTTLEFISH_CONTAINER.to_string(),
            client,
        })
    }

    /// The container headers plus the two CKCode-invoke headers.
    fn headers(
        &self,
        bundle: &str,
        routing_hint: Option<&str>,
        database_scope: &str,
        anisette: &mut Anisette,
        device: &Device,
    ) -> Result<HashMap<String, String>> {
        let mut h: HashMap<String, String> = HashMap::new();
        h.insert("accept".into(), "application/x-protobuf".into());
        h.insert("accept-encoding".into(), "gzip".into());
        h.insert("accept-language".into(), "en-US,en;q=0.9".into());
        h.insert("cache-control".into(), "no-transform".into());
        h.insert("content-encoding".into(), "gzip".into());
        h.insert(
            "content-type".into(),
            "application/x-protobuf; desc=\"https://gateway.icloud.com:443/static/protobuf/\
CloudDB/CloudDBClient.desc\"; messageType=RequestOperation; delimited=true"
                .into(),
        );
        h.insert("user-agent".into(), "CloudKit/1970 (19H384)".into());
        h.insert("x-apple-c2-metric-triggers".into(), "0".into());
        h.insert(
            "x-apple-operation-group-id".into(),
            hex::encode(random_bytes(8)).to_uppercase(),
        );
        h.insert(
            "x-apple-operation-id".into(),
            hex::encode(random_bytes(8)).to_uppercase(),
        );
        h.insert("x-apple-request-uuid".into(), uuid_upper());
        h.insert("x-cloudkit-bundleid".into(), bundle.to_string());
        h.insert("x-cloudkit-containerid".into(), self.container.clone());
        h.insert(
            "x-cloudkit-databasescope".into(),
            database_scope.to_string(),
        );
        h.insert("x-cloudkit-duetpreclearedmode".into(), "None".into());
        h.insert("x-cloudkit-environment".into(), "Production".into());
        h.insert("x-cloudkit-userid".into(), self.user_id.clone());
        h.insert("x-cloudkit-authtoken".into(), self.ck_token.clone());
        if let Some(hint) = routing_hint {
            h.insert("x-cloudkit-functionroutinghint".into(), hint.to_string());
        }
        h.insert(
            "x-mme-client-info".into(),
            crate::anisette::service_client_info(anisette, CK_SERVICE_IDENTITY)?,
        );
        for (k, v) in anisette.headers()? {
            h.insert(k, v);
        }
        // The device identity is the fallback for whatever the server did not supply.
        h.entry("X-Mme-Device-Id".to_string())
            .or_insert_with(|| device.device_id.to_uppercase());
        h.entry("X-Apple-I-SRL-NO".to_string())
            .or_insert_with(|| device.serial.clone());
        Ok(h)
    }

    /// Build, gzip and POST a `RequestOperation`, then check the result.
    #[allow(clippy::too_many_arguments)]
    pub fn perform(
        &self,
        url: &str,
        op_type: u64,
        request_field: u64,
        request_bytes: &[u8],
        bundle: &str,
        routing_hint: Option<&str>,
        database_scope: &str,
        database: u64,
        locale: Option<(&str, &str)>,
        anisette: &mut Anisette,
        device: &Device,
    ) -> Result<CloudKitResult> {
        let header = build_header(&self.device, &self.container, bundle, database, locale);
        let request = build_request_operation(
            &header,
            op_type,
            request_field,
            request_bytes,
            &uuid_upper(),
        );
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&delimit(&request))?;
        let body = encoder.finish()?;

        let headers = self.headers(bundle, routing_hint, database_scope, anisette, device)?;
        let mut header_map = reqwest::header::HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(&v),
            ) {
                header_map.insert(name, value);
            }
        }
        let resp = self
            .client
            .post(url)
            .headers(header_map)
            .body(body)
            .send()
            .map_err(|e| Error::Network {
                url: url.to_string(),
                source: e,
            })?;

        let status = resp.status();
        let content = resp.bytes().map_err(|e| Error::Network {
            url: url.to_string(),
            source: e,
        })?;
        let plain = maybe_gunzip(&content);
        let messages = crate::proto::undelimit(&plain);
        let result =
            parse_response_operation(messages.first().map(|m| m.as_slice()).unwrap_or(&[]))
                .map_err(|_| Error::BadResponse {
                    url: url.to_string(),
                })?;
        if result.code != 1 {
            return Err(Error::Apple(format!(
                "CloudKit operation failed: {}",
                result
                    .error_description
                    .clone()
                    .unwrap_or_else(|| format!("error {}", result.code))
            )));
        }
        let _ = status;
        Ok(result)
    }

    /// Fetch one record by name.
    pub fn fetch_record(
        &self,
        record_name: &str,
        zone: &str,
        user_id: &str,
        anisette: &mut Anisette,
        device: &Device,
    ) -> Result<Option<ckks::CloudKitRecord>> {
        let request = ckks::build_record_retrieve_request(record_name, zone, user_id);
        let result = self.perform(
            CKDATABASE_RETRIEVE_URL,
            ckks::OP_TYPE_RECORD_RETRIEVE,
            ckks::OP_TYPE_RECORD_RETRIEVE,
            &request,
            SECURITYD_BUNDLE,
            None,
            "Private",
            DB_PRIVATE,
            None,
            anisette,
            device,
        )?;
        match result.field(ckks::OP_TYPE_RECORD_RETRIEVE) {
            Some(raw) => ckks::parse_record_retrieve_response(&raw),
            None => Ok(None),
        }
    }

    /// Fetch the records that changed in a zone.
    pub fn fetch_zone_records(
        &self,
        zone: &str,
        user_id: &str,
        anisette: &mut Anisette,
        device: &Device,
    ) -> Result<Vec<ckks::CloudKitRecord>> {
        let zid = ckks::record_zone_identifier(zone, user_id);
        let mut out = Vec::new();
        let mut continuation: Option<Vec<u8>> = None;
        for _ in 0..50 {
            let request = ckks::build_retrieve_changes_request(&zid, continuation.as_deref(), 500);
            let result = self.perform(
                CKDATABASE_SYNC_URL,
                ckks::OP_TYPE_RECORD_RETRIEVE_CHANGES,
                ckks::OP_TYPE_RECORD_RETRIEVE_CHANGES,
                &request,
                SECURITYD_BUNDLE,
                None,
                "Private",
                DB_PRIVATE,
                None,
                anisette,
                device,
            )?;
            let raw = result
                .field(ckks::OP_TYPE_RECORD_RETRIEVE_CHANGES)
                .unwrap_or_default();
            let (records, token, status) = ckks::parse_retrieve_changes_response(&raw)?;
            out.extend(records);
            match (status, token) {
                (Some(1), Some(t)) => continuation = Some(t),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Save one record.
    pub fn save_record(
        &self,
        record: &[u8],
        merge: bool,
        save_semantics: u64,
        anisette: &mut Anisette,
        device: &Device,
    ) -> Result<(Option<String>, Option<ckks::CloudKitRecord>)> {
        self.save_record_with_etag(record, merge, save_semantics, None, anisette, device)
    }

    /// Save one record, presenting the version tag of the record it replaces.
    pub fn save_record_with_etag(
        &self,
        record: &[u8],
        merge: bool,
        save_semantics: u64,
        etag: Option<&str>,
        anisette: &mut Anisette,
        device: &Device,
    ) -> Result<(Option<String>, Option<ckks::CloudKitRecord>)> {
        let request =
            ckks::build_record_save_request(record, merge, save_semantics, None, None, etag);
        let result = self.perform(
            CKDATABASE_SAVE_URL,
            ckks::OP_TYPE_RECORD_SAVE,
            ckks::OP_TYPE_RECORD_SAVE,
            &request,
            SECURITYD_BUNDLE,
            None,
            "Private",
            DB_PRIVATE,
            Some(("en-US", "US")),
            anisette,
            device,
        )?;
        let raw = result.field(ckks::OP_TYPE_RECORD_SAVE).unwrap_or_default();
        ckks::parse_record_save_response(&raw)
    }

    /// Delete one record - the rollback path for a write that went wrong.
    pub fn delete_record(
        &self,
        record_name: &str,
        zone: &str,
        user_id: &str,
        etag: Option<&str>,
        anisette: &mut Anisette,
        device: &Device,
    ) -> Result<()> {
        let request = ckks::build_record_delete_request(record_name, zone, user_id, etag);
        self.perform(
            CKDATABASE_DELETE_URL,
            ckks::OP_TYPE_RECORD_DELETE,
            ckks::OP_TYPE_RECORD_DELETE,
            &request,
            SECURITYD_BUNDLE,
            None,
            "Private",
            DB_PRIVATE,
            Some(("en-US", "US")),
            anisette,
            device,
        )?;
        Ok(())
    }

    /// A CKCode function invoke (the Cuttlefish RPCs).
    pub fn invoke(
        &self,
        op_name: &str,
        parameters: &[u8],
        anisette: &mut Anisette,
        device: &Device,
    ) -> Result<Vec<u8>> {
        let fir = crate::cuttlefish::encode_function_invoke_request(
            CUTTLEFISH_SERVICE,
            op_name,
            parameters,
        );
        let result = self.perform(
            CKCODE_INVOKE_URL,
            OP_TYPE_FUNCTION_INVOKE,
            OP_TYPE_FUNCTION_INVOKE,
            &fir,
            CUTTLEFISH_BUNDLE,
            Some(&format!("{CUTTLEFISH_SERVICE}/{op_name}")),
            "Private",
            DB_PRIVATE,
            None,
            anisette,
            device,
        )?;
        // functionInvokeResponse(1101).serializedResult(1)
        match result.field(OP_TYPE_FUNCTION_INVOKE) {
            Some(raw) => {
                let rf = Fields::decode(&raw)?;
                Ok(rf.bytes(1).map(|b| b.to_vec()).unwrap_or_default())
            }
            None => Ok(Vec::new()),
        }
    }
}

/// Decompress a gzipped body, if it is one.
pub fn maybe_gunzip(data: &[u8]) -> Vec<u8> {
    if data.starts_with(&[0x1f, 0x8b]) {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut out = Vec::new();
        if GzDecoder::new(data).read_to_end(&mut out).is_ok() {
            return out;
        }
    }
    data.to_vec()
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf
}

fn uuid_upper() -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        let cfg = DeviceConfig {
            device_uuid: "DEV".into(),
            serial: "SER".into(),
            ..Default::default()
        };
        let raw = build_header(&cfg, "c", "b", DB_PRIVATE, Some(("en-US", "US")));
        let f = Fields::decode(&raw).unwrap();
        // 17 is the locale, and it sits between 11 and 18.
        let nums = f.field_numbers();
        assert!(nums.contains(&17));
        assert_eq!(f.string(2).as_deref(), Some("c"));
        assert_eq!(f.string(22).as_deref(), Some("DEV"));
        assert_eq!(f.uint(23), Some(DB_PRIVATE));
    }

    #[test]
    fn gunzip_roundtrip() {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(b"hello").unwrap();
        let gz = e.finish().unwrap();
        assert_eq!(maybe_gunzip(&gz), b"hello");
        assert_eq!(maybe_gunzip(b"plain"), b"plain");
    }
}
