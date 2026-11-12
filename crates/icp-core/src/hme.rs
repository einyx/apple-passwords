//! Hide My Email - the iCloud+ aliases.
//!
//! A thin read-only JSON layer over the `premiummailsettings` webservice, authed
//! purely by the web session's cookies. The aliases are cached, encrypted, next
//! to the vault: the browser extension reads the cache, never the live service.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::webauth::WebAuthSession;

/// One alias.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HmeAlias {
    pub anonymous_id: String,
    pub address: String,
    pub label: String,
    pub note: String,
    pub forward_to: String,
    pub is_active: bool,
    pub domain: String,
    /// Unix epoch seconds.
    pub created_at: f64,
}

impl HmeAlias {
    /// The public shape the extension gets.
    pub fn public_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "label": self.label,
            "domain": self.domain,
        })
    }
}

/// The alias list.
pub fn list(session: &mut WebAuthSession, base_url: &str) -> Result<Vec<HmeAlias>> {
    let url = format!("{}/v2/hme/list", base_url.trim_end_matches('/'));
    let mut headers = BTreeMap::new();
    headers.insert("Accept".into(), "application/json".into());
    headers.insert("Origin".into(), "https://www.icloud.com".into());
    headers.insert("Referer".into(), "https://www.icloud.com/".into());
    let data = session.get_json(&url, &headers)?;
    let success = data
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !success {
        return Err(Error::Apple(format!(
            "the alias list failed: {}",
            error_detail(&data)
        )));
    }
    let entries = data
        .get("result")
        .and_then(|r| r.get("hmeEmails"))
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(entries.iter().map(parse_alias).collect())
}

/// Apple's `error` field varies in shape; fall back to the raw body.
fn error_detail(data: &serde_json::Value) -> String {
    match data.get("error") {
        Some(serde_json::Value::Object(map)) => map
            .get("errorMessage")
            .or_else(|| map.get("message"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{map:?}")),
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => data
            .get("errorMessage")
            .or_else(|| data.get("message"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| data.to_string()),
    }
}

/// Parse one alias out of the list.
fn parse_alias(entry: &serde_json::Value) -> HmeAlias {
    let text = |key: &str| {
        entry
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    HmeAlias {
        anonymous_id: text("anonymousId"),
        address: text("hme"),
        label: text("label"),
        note: text("note"),
        forward_to: text("forwardToEmail"),
        is_active: entry
            .get("isActive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        domain: text("domain"),
        created_at: entry
            .get("createTimestamp")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
            / 1000.0,
    }
}

/// The cache file's shape.
#[derive(Debug, Serialize, Deserialize)]
struct AliasFile {
    aliases: Vec<HmeAlias>,
}

/// The aliases, as they are cached on disk.
pub fn load() -> Vec<HmeAlias> {
    let path = crate::device::config_dir().join("aliases.enc");
    if !path.exists() {
        return Vec::new();
    }
    let blob = match std::fs::read(&path) {
        Ok(blob) => blob,
        Err(_) => return Vec::new(),
    };
    let plaintext = match crate::session::open(&crate::session::master_key(), &blob) {
        Ok(plaintext) => plaintext,
        Err(e) => {
            // A master key that does not match usually means the keyring was
            // unreachable, not that the data is worthless: leave the file alone.
            eprintln!(
                "cannot decrypt {} ({e}) - the keyring was probably unreachable. \
                 The aliases are left alone; a sign-in refetches them.",
                path.display()
            );
            return Vec::new();
        }
    };
    serde_json::from_slice::<AliasFile>(&plaintext)
        .map(|f| f.aliases)
        .unwrap_or_default()
}

/// Cache the aliases.
pub fn save(aliases: &[HmeAlias]) -> Result<()> {
    let file = AliasFile {
        aliases: aliases.to_vec(),
    };
    let plaintext = serde_json::to_vec(&file)?;
    let blob = crate::session::seal(&crate::session::master_key(), &plaintext)?;
    crate::device::write_private(&crate::device::config_dir().join("aliases.enc"), &blob)
        .map_err(|e| Error::Apple(format!("the alias cache could not be written: {e}")))
}

/// Does the page's domain match the alias's?
///
/// The alias's domain is what the site sees, so a page on `example.com` matches
/// an alias recorded for `example.com`.
pub fn matches_domain(page_domain: &str, alias: &HmeAlias) -> bool {
    if alias.domain.is_empty() {
        return false;
    }
    crate::hostmatch::domains_match(page_domain, &alias.domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_alias_is_parsed() {
        let entry = serde_json::json!({
            "anonymousId": "abc",
            "hme": "abcd@icloud.com",
            "label": "Shopping",
            "note": "the shop",
            "forwardToEmail": "me@example.com",
            "isActive": true,
            "domain": "example.com",
            "createTimestamp": 1_700_000_000_000i64
        });
        let alias = parse_alias(&entry);
        assert_eq!(alias.address, "abcd@icloud.com");
        assert_eq!(alias.label, "Shopping");
        assert!(alias.is_active);
        assert_eq!(alias.domain, "example.com");
        assert_eq!(alias.created_at, 1_700_000_000.0);
    }

    #[test]
    fn the_domain_matching_is_a_dotted_boundary() {
        let alias = HmeAlias {
            domain: "example.com".into(),
            ..Default::default()
        };
        assert!(matches_domain("example.com", &alias));
        assert!(matches_domain("login.example.com", &alias));
        assert!(!matches_domain("notexample.com", &alias));
    }
}
