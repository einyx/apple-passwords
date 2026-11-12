//! The iCloud services: minting the long-lived token, and the service-URL map.
//!
//! The sign-in gives a PET (a password-equivalent token); `loginDelegates` trades
//! it for the persistent `mmeAuthToken`, which is what every later call uses - no
//! password, no 2FA.

use std::collections::BTreeMap;

use base64::Engine;

use crate::anisette::Anisette;
use crate::device::Device;
use crate::error::{Error, Result};

/// Where the PET is traded for the long-lived token.
pub const LOGIN_DELEGATES_URL: &str = "https://setup.icloud.com/setup/iosbuddy/loginDelegates";
/// Where the service URLs come from.
pub const ACCOUNT_SETTINGS_URL: &str = "https://setup.icloud.com/setup/get_account_settings";
/// The container-open call, which hands out the per-container user id.
pub const CK_APP_INIT_URL: &str = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit";

/// The client identity the iCloud services expect.
pub const ICLOUD_USER_AGENT: &str = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0";
/// The service identity the iCloud services expect.
pub const ICLOUD_SERVICE_IDENTITY: &str = "com.apple.AOSKit/282 (com.apple.accountsd/113)";
/// The keychain container.
pub const KEYCHAIN_CONTAINER: &str = "com.apple.security.keychain";

/// What `loginDelegates` hands back.
pub struct LoginDelegates {
    pub dsid: String,
    pub mme_auth_token: String,
    /// The rest of the service data (the tokens map, the account info).
    pub service_data: plist::Value,
}

/// The headers every iCloud call carries.
fn identity_headers(device: &Device, anisette: &mut Anisette) -> Result<BTreeMap<String, String>> {
    let mut headers = BTreeMap::new();
    headers.insert("User-Agent".to_string(), ICLOUD_USER_AGENT.to_string());
    headers.insert("X-Apple-I-Client-Time".to_string(), crate::now_rfc3339());
    headers.insert("X-Apple-I-TimeZone".to_string(), "UTC".to_string());
    headers.insert(
        "X-Mme-Device-Id".to_string(),
        device.device_id.to_uppercase(),
    );
    headers.insert("X-Apple-I-SRL-NO".to_string(), device.serial.clone());
    headers.insert(
        "X-Apple-I-MD-LU".to_string(),
        base64::engine::general_purpose::STANDARD.encode(device.local_user_uuid.to_uppercase()),
    );
    headers.insert("X-Apple-I-MD-RINFO".to_string(), "17106176".to_string());
    for (key, value) in anisette.headers()? {
        headers.insert(key, value);
    }
    Ok(headers)
}

/// Trade a fresh PET for the persistent `mmeAuthToken`.
pub fn login_delegates(
    username: &str,
    pet: &str,
    adsid: &str,
    client_id: &str,
    device: &Device,
    anisette: &mut Anisette,
) -> Result<LoginDelegates> {
    let mut body = plist::Dictionary::new();
    body.insert("apple-id".into(), plist::Value::String(username.into()));
    let delegate = plist::Dictionary::new();
    body.insert(
        "delegates".into(),
        plist::Value::Dictionary({
            let mut d = plist::Dictionary::new();
            d.insert(
                "com.apple.mobileme".into(),
                plist::Value::Dictionary(delegate),
            );
            d
        }),
    );
    body.insert("password".into(), plist::Value::String(pet.into()));
    body.insert("client-id".into(), plist::Value::String(client_id.into()));

    let mut encoded = Vec::new();
    plist::to_writer_xml(&mut encoded, &plist::Value::Dictionary(body))
        .map_err(|e| Error::Apple(format!("could not encode the sign-in request: {e}")))?;

    let mut headers = identity_headers(device, anisette)?;
    headers.insert("X-Apple-ADSID".to_string(), adsid.to_string());
    headers.insert(
        "X-Mme-Client-Info".to_string(),
        crate::anisette::service_client_info(anisette, ICLOUD_SERVICE_IDENTITY)?,
    );
    // apple-id:PET - not dsid:PET.
    headers.insert(
        "Authorization".to_string(),
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{pet}"))
        ),
    );

    let http = crate::apple_tls::client(std::time::Duration::from_secs(30))?;
    let response = http
        .post(LOGIN_DELEGATES_URL)
        .headers(crate::header_map(headers))
        .body(encoded)
        .send()
        .map_err(|e| Error::Apple(format!("the sign-in request failed: {e}")))?;
    let status = response.status();
    let content = response
        .bytes()
        .map_err(|e| Error::Apple(format!("the sign-in answer was unreadable: {e}")))?;
    let parsed = plist::Value::from_reader(std::io::Cursor::new(content.as_ref()))
        .map_err(|e| Error::Apple(format!("the sign-in answer was not a plist: {e}")))?;
    let dict = parsed
        .as_dictionary()
        .ok_or_else(|| Error::Apple("the sign-in answer was not a dictionary".into()))?;

    let mm = dict
        .get("delegates")
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("com.apple.mobileme"))
        .and_then(|v| v.as_dictionary())
        .cloned()
        .unwrap_or_default();
    let status_code = mm
        .get("status")
        .and_then(|v| v.as_signed_integer())
        .or_else(|| dict.get("status").and_then(|v| v.as_signed_integer()))
        .unwrap_or(0);
    if status_code != 0 {
        let message = mm
            .get("status-message")
            .or_else(|| dict.get("status-message"))
            .and_then(|v| v.as_string())
            .unwrap_or("unknown error");
        return Err(Error::Apple(format!(
            "the sign-in was refused (status {status_code}, HTTP {}): {message}",
            status.as_u16()
        )));
    }

    let service_data = mm
        .get("service-data")
        .and_then(|v| v.as_dictionary())
        .cloned()
        .unwrap_or_default();
    let dsid = dict
        .get("dsid")
        .and_then(|v| v.as_string())
        .or_else(|| {
            service_data
                .get("appleAccountInfo")
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("dsid"))
                .and_then(|v| v.as_string())
        })
        .unwrap_or("")
        .to_string();
    let token = service_data
        .get("tokens")
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("mmeAuthToken"))
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    if dsid.is_empty() || token.is_empty() {
        return Err(Error::Apple(
            "the sign-in answer carried no long-lived token".into(),
        ));
    }
    Ok(LoginDelegates {
        dsid,
        mme_auth_token: token,
        service_data: plist::Value::Dictionary(service_data),
    })
}

/// The account settings, with the service URLs and the CloudKit token.
pub fn fetch_account_settings(
    dsid: &str,
    mme_auth_token: &str,
    device: &Device,
    anisette: &mut Anisette,
) -> Result<plist::Value> {
    let mut headers = identity_headers(device, anisette)?;
    headers.insert(
        "Authorization".to_string(),
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{dsid}:{mme_auth_token}"))
        ),
    );
    headers.insert(
        "X-Mme-Client-Info".to_string(),
        crate::anisette::service_client_info(anisette, ICLOUD_SERVICE_IDENTITY)?,
    );

    let http = crate::apple_tls::client(std::time::Duration::from_secs(30))?;
    let response = http
        .post(ACCOUNT_SETTINGS_URL)
        .headers(crate::header_map(headers))
        .body("")
        .send()
        .map_err(|e| Error::Apple(format!("the account settings request failed: {e}")))?;
    let status = response.status();
    let content = response
        .bytes()
        .map_err(|e| Error::Apple(format!("the account settings were unreadable: {e}")))?;
    if status.as_u16() == 401 {
        return Err(Error::Apple(
            "the long-lived token is no longer accepted - sign in again".into(),
        ));
    }
    if status.as_u16() == 429 || status.as_u16() >= 500 {
        return Err(Error::Apple(format!(
            "the account settings are unavailable (HTTP {})",
            status.as_u16()
        )));
    }
    plist::Value::from_reader(std::io::Cursor::new(content.as_ref()))
        .map_err(|e| Error::Apple(format!("the account settings were not a plist: {e}")))
}

/// The service URLs, flattened.
pub fn extract_webservices(settings: &plist::Value) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let Some(dict) = settings.as_dictionary() else {
        return out;
    };
    if let Some(ws) = dict.get("webservices").and_then(|v| v.as_dictionary()) {
        for (name, value) in ws {
            if let Some(url) = value
                .as_dictionary()
                .and_then(|d| d.get("url"))
                .and_then(|v| v.as_string())
            {
                out.insert(name.clone(), url.to_string());
            }
        }
    }
    // Some services carry their endpoint under another key.
    const ALT_KEYS: [&str; 4] = ["url", "escrowProxyUrl", "configURL", "wsUrl"];
    if let Some(mm) = dict
        .get("com.apple.mobileme")
        .and_then(|v| v.as_dictionary())
    {
        for (name, value) in mm {
            let Some(entry) = value.as_dictionary() else {
                continue;
            };
            let Some(url) = ALT_KEYS
                .iter()
                .find_map(|k| entry.get(k).and_then(|v| v.as_string()))
            else {
                continue;
            };
            out.entry(name.clone()).or_insert_with(|| url.to_string());
            if let Some(short) = name.rsplit('.').next() {
                out.entry(short.to_lowercase())
                    .or_insert_with(|| url.to_string());
            }
        }
    }
    out
}

/// The per-container CloudKit user id.
pub fn ck_app_init(
    dsid: &str,
    mme_auth_token: &str,
    container: &str,
    device: &Device,
    anisette: &mut Anisette,
) -> Result<String> {
    let mut headers = identity_headers(device, anisette)?;
    headers.insert(
        "Authorization".to_string(),
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{dsid}:{mme_auth_token}"))
        ),
    );
    headers.insert(
        "X-Mme-Client-Info".to_string(),
        crate::anisette::service_client_info(anisette, ICLOUD_SERVICE_IDENTITY)?,
    );

    let http = crate::apple_tls::client(std::time::Duration::from_secs(30))?;
    let response = http
        .post(format!("{CK_APP_INIT_URL}?container={container}"))
        .headers(crate::header_map(headers))
        .body("")
        .send()
        .map_err(|e| Error::Apple(format!("the container request failed: {e}")))?;
    let status = response.status();
    let content = response
        .bytes()
        .map_err(|e| Error::Apple(format!("the container answer was unreadable: {e}")))?;
    if !status.is_success() {
        return Err(Error::Apple(format!(
            "the container request failed (HTTP {})",
            status.as_u16()
        )));
    }
    let parsed: serde_json::Value = serde_json::from_slice(content.as_ref())
        .map_err(|e| Error::Apple(format!("the container answer was not JSON: {e}")))?;
    parsed
        .get("cloudKitUserId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Apple("the container answer carried no user id".into()))
}
