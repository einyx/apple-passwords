//! The encrypted local vault of decrypted credentials.
//!
//! The same file and format the Python implementation uses, so the browser
//! extension's native host and this app read the same vault.

use std::fs;

use serde::{Deserialize, Serialize};

use crate::device::{vault_file, write_private};
use crate::error::Result;
use crate::keychain::Credential;
use crate::session;

/// The stored form of a credential.
///
/// Every field has a default: the Python implementation writes a smaller set, and
/// a vault that is one field short is still a good vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct StoredCredential {
    domain: String,
    username: String,
    password: String,
    title: String,
    mdat: f64,
    notes: String,
    last_used: f64,
    totp: String,
    group: String,
    /// The keychain record a login lives in.
    ///
    /// The Python implementation does not write this, so it may be missing.
    #[serde(default)]
    record_name: String,
}

impl From<&Credential> for StoredCredential {
    fn from(c: &Credential) -> Self {
        StoredCredential {
            domain: c.domain.clone(),
            username: c.username.clone(),
            password: c.password.clone(),
            title: c.title.clone(),
            mdat: c.mdat,
            notes: c.notes.clone(),
            last_used: c.last_used,
            totp: c.totp.clone(),
            group: c.group.clone(),
            record_name: c.record_name.clone(),
        }
    }
}

impl From<StoredCredential> for Credential {
    fn from(c: StoredCredential) -> Self {
        Credential {
            domain: c.domain,
            username: c.username,
            password: c.password,
            title: c.title,
            notes: c.notes,
            mdat: c.mdat,
            last_used: c.last_used,
            totp: c.totp,
            record_name: c.record_name,
            group: c.group,
        }
    }
}

/// The vault file's inner shape.
#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    credentials: Vec<StoredCredential>,
}

/// Read the vault.
///
/// A master key that does not match the vault is *not* a reason to delete it: that
/// almost always means the keyring was unreachable (the native host is spawned by
/// the browser, without the session bus), and deleting it would throw away the
/// credentials. The vault is left alone and the caller gets an empty one.
pub fn load() -> Result<Vec<Credential>> {
    let path = vault_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let blob = fs::read(&path)?;
    let plaintext = match session::open(&session::master_key(), &blob) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "cannot decrypt {} ({e}) - the keyring was probably unreachable. \
                 The vault is left alone; a sync rebuilds it.",
                path.display()
            );
            return Ok(Vec::new());
        }
    };
    let parsed: VaultFile = serde_json::from_slice(&plaintext)?;
    Ok(parsed
        .credentials
        .into_iter()
        .map(Credential::from)
        .collect())
}

/// Write the vault.
pub fn save(credentials: &[Credential]) -> Result<()> {
    let file = VaultFile {
        credentials: credentials.iter().map(StoredCredential::from).collect(),
    };
    let plaintext = serde_json::to_vec(&file)?;
    let blob = session::seal(&session::master_key(), &plaintext)?;
    write_private(&vault_file(), &blob)?;
    Ok(())
}

/// Add (or replace) one credential.
pub fn upsert(credential: &Credential) -> Result<()> {
    let mut creds = load()?;
    let key = (
        credential.domain.to_lowercase(),
        credential.username.to_lowercase(),
    );
    let mut replaced = false;
    for c in creds.iter_mut() {
        if (c.domain.to_lowercase(), c.username.to_lowercase()) == key {
            *c = credential.clone();
            replaced = true;
            break;
        }
    }
    if !replaced {
        creds.push(credential.clone());
    }
    save(&creds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_conversion_keeps_the_fields() {
        let c = Credential {
            domain: "example.com".into(),
            username: "alice".into(),
            password: "hunter2".into(),
            title: "example.com (alice)".into(),
            ..Default::default()
        };
        let stored = StoredCredential::from(&c);
        assert_eq!(stored.password, "hunter2");
        let back: Credential = stored.into();
        assert_eq!(back.domain, "example.com");
        assert_eq!(back.username, "alice");
    }
}
