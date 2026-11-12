//! The idmsa web session - the second Apple auth surface.
//!
//! This is the icloud.com browser flow: an SRP-6a sign-in against
//! `idmsa.apple.com` that cannot join the Octagon circle, but that reaches the
//! web-scoped webservices the device path never sees - `premiummailsettings`,
//! which is Hide My Email.
//!
//! The session state (the frame tag, the response headers and the cookies) is
//! what is persisted: a saved trust token then skips the 2FA prompt.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::srp::{stretch_password, SrpClient};

/// The sign-in endpoint.
pub const AUTH_ENDPOINT: &str = "https://idmsa.apple.com/appleauth/auth";
/// The account endpoint.
pub const SETUP_ENDPOINT: &str = "https://setup.icloud.com/setup/ws/1";
/// The icloud.com origin.
pub const ICLOUD_ORIGIN: &str = "https://www.icloud.com";
/// icloud.com's public OAuth widget key (not account-specific).
pub const WIDGET_KEY: &str = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d";

const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
                          (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15";

/// The response headers Apple uses to thread session state across calls.
const HEADER_DATA: &[(&str, &str)] = &[
    ("X-Apple-ID-Account-Country", "account_country"),
    ("X-Apple-ID-Session-Id", "session_id"),
    ("X-Apple-Session-Token", "session_token"),
    ("X-Apple-TwoSV-Trust-Token", "trust_token"),
    ("X-Apple-Auth-Attributes", "auth_attributes"),
    ("scnt", "scnt"),
];

/// The persisted state of a web session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebAuthState {
    /// The random per-session `auth-<uuid>` threaded through the OAuth headers.
    pub frame_tag: String,
    /// The headers Apple sent back.
    #[serde(default)]
    pub session_data: HashMap<String, String>,
    /// The cookies the session holds.
    #[serde(default)]
    pub cookies: HashMap<String, String>,
}

/// One idmsa web-session login.
pub struct WebAuthSession {
    /// The persistable state.
    pub state: WebAuthState,
    /// True when the sign-in stopped at the 2FA challenge.
    pub needs_2fa: bool,
    client: reqwest::blocking::Client,
}

impl WebAuthSession {
    /// Start a session, resuming a saved one if there is one.
    pub fn new(state: Option<&WebAuthState>) -> Result<WebAuthSession> {
        let state = state.cloned().unwrap_or_default();
        let mut state = state;
        if state.frame_tag.is_empty() {
            state.frame_tag = format!("auth-{}", crate::uuid_upper());
        }
        let client = crate::apple_tls::client(Duration::from_secs(30))?;
        Ok(WebAuthSession {
            state,
            needs_2fa: false,
            client,
        })
    }

    /// The headers for the idmsa calls.
    fn auth_headers(&self) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert("Accept".into(), "application/json".into());
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("Origin".into(), "https://idmsa.apple.com".into());
        headers.insert("Referer".into(), "https://idmsa.apple.com/".into());
        headers.insert("X-Apple-Widget-Key".into(), WIDGET_KEY.into());
        headers.insert("X-Apple-OAuth-Client-Id".into(), WIDGET_KEY.into());
        headers.insert("X-Apple-OAuth-Client-Type".into(), "firstPartyAuth".into());
        headers.insert("X-Apple-OAuth-Redirect-URI".into(), ICLOUD_ORIGIN.into());
        headers.insert("X-Apple-OAuth-Require-Grant-Code".into(), "true".into());
        headers.insert("X-Apple-OAuth-Response-Mode".into(), "web_message".into());
        headers.insert("X-Apple-OAuth-Response-Type".into(), "code".into());
        headers.insert("X-Apple-OAuth-State".into(), self.state.frame_tag.clone());
        headers.insert("X-Apple-Frame-Id".into(), self.state.frame_tag.clone());
        headers.insert("X-Requested-With".into(), "XMLHttpRequest".into());
        headers.insert("X-Apple-Mandate-Security-Upgrade".into(), "0".into());
        headers.insert("X-Apple-I-Require-UE".into(), "true".into());
        for (header, key) in HEADER_DATA {
            if let Some(value) = self.state.session_data.get(*key) {
                if *header == "scnt" {
                    headers.insert("scnt".into(), value.clone());
                } else {
                    headers.insert((*header).to_string(), value.clone());
                }
            }
        }
        headers
    }

    /// The headers for the setup.icloud.com calls: another origin, another referer.
    fn setup_headers(&self) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("Origin".into(), ICLOUD_ORIGIN.into());
        headers.insert("Referer".into(), format!("{ICLOUD_ORIGIN}/"));
        headers
    }

    /// The cookies, as a `Cookie` header.
    fn cookie_header(&self) -> Option<String> {
        if self.state.cookies.is_empty() {
            return None;
        }
        let mut pairs: Vec<String> = self
            .state
            .cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        pairs.sort();
        Some(pairs.join("; "))
    }

    /// Take the session state out of a response.
    fn capture(&mut self, headers: &reqwest::header::HeaderMap) {
        for (header, key) in HEADER_DATA {
            if let Some(value) = headers.get(*header).and_then(|v| v.to_str().ok()) {
                self.state
                    .session_data
                    .insert((*key).to_string(), value.to_string());
            }
        }
        for value in headers.get_all(reqwest::header::SET_COOKIE) {
            let Some(text) = value.to_str().ok() else {
                continue;
            };
            let pair = text.split(';').next().unwrap_or("").trim();
            if let Some((name, value)) = pair.split_once('=') {
                self.state
                    .cookies
                    .insert(name.trim().to_string(), value.trim().to_string());
            }
        }
    }

    /// A GET.
    fn get(
        &mut self,
        url: &str,
        headers: &BTreeMap<String, String>,
        query: &[(&str, &str)],
    ) -> Result<reqwest::blocking::Response> {
        let mut request = self
            .client
            .get(url)
            .headers(crate::header_map(headers.clone()))
            .header(reqwest::header::USER_AGENT, USER_AGENT);
        if !query.is_empty() {
            request = request.query(query);
        }
        if let Some(cookies) = self.cookie_header() {
            request = request.header(reqwest::header::COOKIE, cookies);
        }
        let response = request
            .send()
            .map_err(|e| Error::Apple(format!("the web session request failed: {e}")))?;
        self.capture(response.headers());
        Ok(response)
    }

    /// A POST with a JSON body.
    fn post(
        &mut self,
        url: &str,
        headers: &BTreeMap<String, String>,
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<reqwest::blocking::Response> {
        let mut request = self
            .client
            .post(url)
            .headers(crate::header_map(headers.clone()))
            .header(reqwest::header::USER_AGENT, USER_AGENT);
        if !query.is_empty() {
            request = request.query(query);
        }
        if let Some(cookies) = self.cookie_header() {
            request = request.header(reqwest::header::COOKIE, cookies);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .map_err(|e| Error::Apple(format!("the web session request failed: {e}")))?;
        self.capture(response.headers());
        Ok(response)
    }

    /// A PUT with no body.
    fn put(
        &mut self,
        url: &str,
        headers: &BTreeMap<String, String>,
    ) -> Result<reqwest::blocking::Response> {
        let mut request = self
            .client
            .put(url)
            .headers(crate::header_map(headers.clone()))
            .header(reqwest::header::USER_AGENT, USER_AGENT);
        if let Some(cookies) = self.cookie_header() {
            request = request.header(reqwest::header::COOKIE, cookies);
        }
        let response = request
            .send()
            .map_err(|e| Error::Apple(format!("the web session request failed: {e}")))?;
        self.capture(response.headers());
        Ok(response)
    }

    /// Load the widget: it sets the session cookies the rest of the flow needs.
    fn auth_start(&mut self) -> Result<()> {
        let mut headers = BTreeMap::new();
        headers.insert("Accept".into(), "*/*".into());
        let frame_tag = self.state.frame_tag.clone();
        let query = [
            ("frame_id", frame_tag.as_str()),
            ("language", "en_US"),
            ("skVersion", "7"),
            ("iframeId", frame_tag.as_str()),
            ("client_id", WIDGET_KEY),
            ("redirect_uri", ICLOUD_ORIGIN),
            ("response_type", "code"),
            ("response_mode", "web_message"),
            ("state", frame_tag.as_str()),
            ("authVersion", "latest"),
        ];
        let response = self.get(
            &format!("{AUTH_ENDPOINT}/authorize/signin"),
            &headers,
            &query,
        )?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Apple(format!(
                "could not start the web session (HTTP {})",
                status.as_u16()
            )));
        }
        Ok(())
    }

    /// Name the account before the SRP exchange.
    fn federate(&mut self, username: &str) -> Result<()> {
        let headers = self.auth_headers();
        let body = serde_json::json!({"accountName": username, "rememberMe": true});
        let response = self.post(
            &format!("{AUTH_ENDPOINT}/federate"),
            &headers,
            &[("isRememberMeEnabled", "true")],
            Some(&body),
        )?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Apple(format!(
                "the federate call failed (HTTP {})",
                status.as_u16()
            )));
        }
        Ok(())
    }

    /// The server's challenge.
    fn srp_init(&mut self, username: &str, a_bytes: &[u8]) -> Result<Value> {
        let headers = self.auth_headers();
        let body = serde_json::json!({
            "a": base64::engine::general_purpose::STANDARD.encode(a_bytes),
            "accountName": username,
            "protocols": ["s2k", "s2k_fo"],
        });
        let response = self.post(
            &format!("{AUTH_ENDPOINT}/signin/init"),
            &headers,
            &[],
            Some(&body),
        )?;
        let status = response.status();
        let text = response.text().unwrap_or_default();
        let data: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let reason = error_reason(&data);
        if data.is_null() || reason.is_some() || !status.is_success() {
            return Err(Error::Apple(format!(
                "the SRP init failed (HTTP {}): {}",
                status.as_u16(),
                reason.unwrap_or_else(|| "no reason given".to_string())
            )));
        }
        Ok(data)
    }

    /// Sign in: the full SRP-6a exchange.
    ///
    /// A 409 (the 2FA challenge) sets [`Self::needs_2fa`] instead of failing.
    pub fn signin(
        &mut self,
        username: &str,
        password: &str,
        trust_token: Option<&str>,
    ) -> Result<()> {
        // Apple lowercases the account name for the SRP proof.
        let username = username.to_lowercase();
        self.auth_start()?;
        self.federate(&username)?;

        let mut client = SrpClient::new(&username);
        let a_bytes = client.a_public_padded();
        let init = self.srp_init(&username, &a_bytes)?;

        let salt = decode_field(&init, "salt")?;
        let b_bytes = decode_field(&init, "b")?;
        let iterations = init
            .get("iteration")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Apple("the SRP challenge had no iteration count".into()))?
            as u32;
        let protocol = init
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("s2k")
            .to_string();

        let password_key = stretch_password(password, &salt, iterations, &protocol);
        client.process_challenge(&salt, &b_bytes, &password_key)?;

        let headers = self.auth_headers();
        let body = serde_json::json!({
            "accountName": username,
            "m1": base64::engine::general_purpose::STANDARD.encode(&client.m),
            "m2": base64::engine::general_purpose::STANDARD.encode(&client.h_amk),
            "c": init.get("c").cloned().unwrap_or(Value::Null),
            "rememberMe": true,
            "trustTokens": match trust_token {
                Some(token) if !token.is_empty() => serde_json::json!([token]),
                _ => serde_json::json!([]),
            },
        });
        let response = self.post(
            &format!("{AUTH_ENDPOINT}/signin/complete"),
            &headers,
            &[("isRememberMeEnabled", "true")],
            Some(&body),
        )?;
        let status = response.status();
        if status.as_u16() == 409 {
            self.needs_2fa = true;
            return Ok(());
        }
        self.needs_2fa = false;
        if status.is_success() {
            return Ok(());
        }
        let text = response.text().unwrap_or_default();
        let data: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let reason = error_reason(&data);
        Err(Error::Apple(format!(
            "the web sign-in failed (HTTP {}): {}",
            status.as_u16(),
            reason.unwrap_or_else(|| "no reason given".to_string())
        )))
    }

    /// Ask Apple to push the 2FA code to the trusted devices.
    pub fn request_push_notification(&mut self) -> Result<()> {
        let headers = self.auth_headers();
        let response = self.put(
            &format!("{AUTH_ENDPOINT}/verify/trusteddevice/securitycode"),
            &headers,
        )?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Apple(format!(
                "could not ask for the 2FA push (HTTP {})",
                status.as_u16()
            )));
        }
        Ok(())
    }

    /// Submit the 6-digit code, then trust the browser.
    pub fn submit_2fa(&mut self, code: &str) -> Result<()> {
        let headers = self.auth_headers();
        let body = serde_json::json!({"securityCode": {"code": code}});
        let response = self.post(
            &format!("{AUTH_ENDPOINT}/verify/trusteddevice/securitycode"),
            &headers,
            &[],
            Some(&body),
        )?;
        let status = response.status();
        let text = response.text().unwrap_or_default();
        let data: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if !status.is_success() {
            let reason = error_reason(&data);
            return Err(Error::Apple(format!(
                "the 2FA code was rejected (HTTP {}): {}",
                status.as_u16(),
                reason.unwrap_or_else(|| "no reason given".to_string())
            )));
        }
        let headers = self.auth_headers();
        let trust = self.get(&format!("{AUTH_ENDPOINT}/2sv/trust"), &headers, &[])?;
        let status = trust.status();
        if !status.is_success() {
            return Err(Error::Apple(format!(
                "could not trust the session (HTTP {})",
                status.as_u16()
            )));
        }
        self.needs_2fa = false;
        Ok(())
    }

    /// The account payload: the dsInfo, the webservices, the 2FA state.
    pub fn account_login(&mut self) -> Result<Value> {
        let headers = self.setup_headers();
        let body = serde_json::json!({
            "accountCountryCode": self.state.session_data.get("account_country"),
            "dsWebAuthToken": self.state.session_data.get("session_token"),
            "extended_login": true,
            "trustToken": self.state.session_data.get("trust_token").cloned().unwrap_or_default(),
        });
        let response = self.post(
            &format!("{SETUP_ENDPOINT}/accountLogin"),
            &headers,
            &[],
            Some(&body),
        )?;
        let status = response.status();
        let text = response.text().unwrap_or_default();
        let data: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if data.is_null() {
            return Err(Error::Apple(format!(
                "accountLogin returned no JSON (HTTP {})",
                status.as_u16()
            )));
        }
        let reason = error_reason(&data);
        if reason.is_some() || !status.is_success() {
            return Err(Error::Apple(format!(
                "accountLogin failed (HTTP {}): {}",
                status.as_u16(),
                reason.unwrap_or_else(|| "no reason given".to_string())
            )));
        }
        Ok(data)
    }

    /// A GET against a webservice, with the session's cookies.
    ///
    /// The Hide My Email client uses this; it needs the raw `Set-Cookie`
    /// handling the session already does.
    pub fn get_json(&mut self, url: &str, headers: &BTreeMap<String, String>) -> Result<Value> {
        let response = self.get(url, headers, &[])?;
        let status = response.status();
        let text = response.text().unwrap_or_default();
        let data: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if data.is_null() {
            return Err(Error::Apple(format!(
                "the request returned no JSON (HTTP {})",
                status.as_u16()
            )));
        }
        Ok(data)
    }
}

/// Reach a valid idmsa web session.
///
/// Reuses a saved session when there is one; otherwise signs in with the saved
/// password and asks for the 2FA code once. The session record is updated with
/// the new state, so the next call can reuse the trust token.
pub fn ensure_session(
    record: &mut Value,
    mut code: impl FnMut() -> Result<String>,
) -> Result<(WebAuthSession, Value)> {
    let saved: Option<WebAuthState> = record
        .get("webauth")
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let mut session = WebAuthSession::new(saved.as_ref())?;

    // A saved session may still be trusted: then no password is needed.
    let mut account: Option<Value> = None;
    if session.state.session_data.contains_key("session_token") {
        if let Ok(data) = session.account_login() {
            if !hsa_challenge_required(&data) {
                account = Some(data);
            }
        }
    }

    if account.is_none() {
        let username = record
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let password = record
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if username.is_empty() || password.is_empty() {
            return Err(Error::Apple(
                "no saved Apple ID password for the web session - run `icp login` \
                 without --no-save-password"
                    .into(),
            ));
        }
        let trust = session.state.session_data.get("trust_token").cloned();
        session.signin(&username, &password, trust.as_deref())?;
        if session.needs_2fa {
            // The 409 no longer pushes the code on its own.
            session.request_push_notification()?;
            let code = code()?;
            session.submit_2fa(&code)?;
        }
        let data = session.account_login()?;
        if hsa_challenge_required(&data) {
            return Err(Error::Apple(
                "the 2FA did not clear the web-session challenge".into(),
            ));
        }
        account = Some(data);
    }

    if let Some(object) = record.as_object_mut() {
        object.insert(
            "webauth".into(),
            serde_json::to_value(&session.state).unwrap_or(Value::Null),
        );
    }
    Ok((session, account.unwrap_or(Value::Null)))
}

/// Apple's error text, out of a JSON body.
fn error_reason(data: &Value) -> Option<String> {
    let object = data.as_object()?;
    for key in ["errorMessage", "reason", "errorReason"] {
        if let Some(value) = object.get(key).and_then(|v| v.as_str()) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    if let Some(value) = object.get("error").and_then(|v| v.as_str()) {
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// A base64 field out of a JSON body.
fn decode_field(data: &Value, key: &str) -> Result<Vec<u8>> {
    let text = data
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Apple(format!("the SRP challenge had no {key}")))?;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| Error::Apple(format!("the SRP challenge had a bad {key}: {e}")))
}

/// True when the account payload still needs a 2FA code.
pub fn hsa_challenge_required(account: &Value) -> bool {
    let version = account
        .get("dsInfo")
        .and_then(|d| d.get("hsaVersion"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    version == 2
        && (account
            .get("hsaChallengeRequired")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || !account
                .get("hsaTrustedBrowser")
                .and_then(|v| v.as_bool())
                .unwrap_or(false))
}

/// The webservices the account payload names: `{name: url}`.
pub fn extract_webservices(account: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(services) = account.get("webservices").and_then(|v| v.as_object()) {
        for (name, value) in services {
            let Some(entry) = value.as_object() else {
                continue;
            };
            let Some(url) = entry.get("url").and_then(|v| v.as_str()) else {
                continue;
            };
            if url.is_empty() {
                continue;
            }
            if entry.get("status").and_then(|v| v.as_str()) == Some("off") {
                continue;
            }
            out.insert(name.clone(), url.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_webservices_are_flattened() {
        let account = serde_json::json!({
            "webservices": {
                "premiummailsettings": {"url": "https://pms.example.com", "status": "active"},
                "offline": {"url": "https://off.example.com", "status": "off"},
                "broken": {"status": "active"}
            }
        });
        let services = extract_webservices(&account);
        assert_eq!(
            services.get("premiummailsettings").map(|s| s.as_str()),
            Some("https://pms.example.com")
        );
        assert!(!services.contains_key("offline"));
        assert!(!services.contains_key("broken"));
    }

    #[test]
    fn the_challenge_is_read_out_of_the_account_payload() {
        let account = serde_json::json!({
            "dsInfo": {"hsaVersion": 2},
            "hsaChallengeRequired": true,
            "hsaTrustedBrowser": false
        });
        assert!(hsa_challenge_required(&account));
        let trusted = serde_json::json!({
            "dsInfo": {"hsaVersion": 2},
            "hsaChallengeRequired": false,
            "hsaTrustedBrowser": true
        });
        assert!(!hsa_challenge_required(&trusted));
    }
}
