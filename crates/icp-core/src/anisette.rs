//! The anisette server client.
//!
//! Apple's servers want a set of `X-Apple-I-MD*` headers that only a real Apple
//! machine can produce. The anisette server produces them for us: it runs Apple's
//! ADI library and hands out a fresh set of headers per request.
//!
//! Two endpoints matter: the server root returns the machine data headers, and
//! `/v3/client_info` returns the client identity and user agent.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, Result};

/// The header names the server returns.
const MACHINE_HEADERS: &[&str] = &[
    "X-Apple-I-MD",
    "X-Apple-I-MD-M",
    "X-Apple-I-MD-RINFO",
    "X-Apple-I-MD-LU",
    "X-Apple-I-SRL-NO",
    "X-Mme-Device-Id",
    "X-Apple-I-Client-Time",
    "X-Apple-I-TimeZone",
    "X-Apple-Locale",
];

/// What `/v3/client_info` returns.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientInfo {
    pub client_info: String,
    pub user_agent: String,
}

/// Talks to the anisette server.
#[derive(Clone)]
pub struct Anisette {
    base: String,
    query: Option<String>,
    client: reqwest::blocking::Client,
    info: Option<ClientInfo>,
}

impl Anisette {
    /// Build a client for the server at `url`.
    ///
    /// The URL may carry a query string - the server is told its backend through one
    /// (`?backend=macos`), so it has to survive into every request.
    pub fn new(url: &str) -> Result<Anisette> {
        let configured = url.trim().trim_end_matches('/');
        if configured.is_empty() {
            return Err(Error::Apple(
                "no anisette server URL configured; set ICP_ANISETTE_URL".into(),
            ));
        }
        let (base, query) = match configured.split_once('?') {
            Some((b, q)) => (b.to_string(), Some(q.to_string())),
            None => (configured.to_string(), None),
        };
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| Error::Network {
                url: base.clone(),
                source: e,
            })?;
        Ok(Anisette {
            base,
            query,
            client,
            info: None,
        })
    }

    /// Build a URL for one of the server's endpoints.
    fn url(&self, path: &str) -> String {
        let base = if path.is_empty() {
            self.base.clone()
        } else {
            format!("{}{}", self.base.trim_end_matches('/'), path)
        };
        match &self.query {
            Some(q) => format!("{base}?{q}"),
            None => base,
        }
    }

    /// The client identity and user agent, fetched once and reused.
    pub fn client_info(&mut self) -> Result<&ClientInfo> {
        if self.info.is_none() {
            let url = self.url("/v3/client_info");
            let resp = self.client.get(&url).send().map_err(|e| Error::Network {
                url: url.clone(),
                source: e,
            })?;
            if !resp.status().is_success() {
                return Err(Error::BadResponse { url });
            }
            let info: ClientInfo = resp.json().map_err(|_| Error::BadResponse { url })?;
            self.info = Some(info);
        }
        Ok(self.info.as_ref().unwrap())
    }

    /// The client identity string, as the server sends it.
    pub fn client_info_string(&mut self) -> Result<String> {
        Ok(self.client_info()?.client_info.clone())
    }

    /// The user agent the server's identity comes with.
    pub fn user_agent(&mut self) -> Result<String> {
        Ok(self.client_info()?.user_agent.clone())
    }

    /// The client identity string Apple's servers want
    /// (`<platform> <com.apple.service/version>`).
    pub fn platform(&mut self) -> Result<String> {
        let info = self.client_info()?;
        let platform = info
            .client_info
            .split(" <com.apple.")
            .next()
            .unwrap_or("")
            .to_string();
        if platform.is_empty() {
            return Err(Error::Apple(
                "the anisette server's client info has no service identity".into(),
            ));
        }
        Ok(platform)
    }

    /// The machine identity headers.
    pub fn headers(&self) -> Result<HashMap<String, String>> {
        let url = self.url("");
        let resp = self.client.get(&url).send().map_err(|e| Error::Network {
            url: url.clone(),
            source: e,
        })?;
        if !resp.status().is_success() {
            return Err(Error::BadResponse { url });
        }
        let data: serde_json::Value = resp.json().map_err(|_| Error::BadResponse { url })?;
        let mut out = HashMap::new();
        for key in MACHINE_HEADERS {
            if let Some(v) = data.get(*key).and_then(|v| v.as_str()) {
                if v.is_empty() {
                    return Err(Error::Apple(format!(
                        "the anisette server returned an empty {key}"
                    )));
                }
                out.insert((*key).to_string(), v.to_string());
            }
        }
        if !out.contains_key("X-Apple-I-MD") || !out.contains_key("X-Apple-I-MD-M") {
            return Err(Error::Apple(
                "the anisette server did not return X-Apple-I-MD / X-Apple-I-MD-M".into(),
            ));
        }
        Ok(out)
    }
}

/// The client identity string CloudKit wants (`<platform> <com.apple.service/version>`).
pub fn service_client_info(anisette: &mut Anisette, service_identity: &str) -> Result<String> {
    Ok(format!("{} <{}>", anisette.platform()?, service_identity))
}
