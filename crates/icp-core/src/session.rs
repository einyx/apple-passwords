//! The encrypted session store.
//!
//! The session holds the auth artifacts (the iCloud tokens, the Octagon peer
//! identity, the sponsor's key). It is encrypted with a libsodium secret box, the
//! master key living in the GNOME login keyring (Secret Service) - or in a 0600 file
//! if there is no keyring.
//!
//! The same file and the same keyring item the Python implementation uses, so the two
//! clients can share one sign-in.

use std::fs;

use base64::Engine;
use serde_json::Value;

use crate::device::{fallback_key_file, session_file, write_private};
use crate::error::{Error, Result};

const KEY_SIZE: usize = 32;
const ATTR_APPLICATION: &str = "icp";
const ATTR_TYPE: &str = "master-key";
const KEY_LABEL: &str = "ApplePasswords-Linux master key";

/// Decode a stored key: raw bytes, or base64 of them.
fn decode_key(stored: &[u8]) -> Option<Vec<u8>> {
    if stored.len() == KEY_SIZE {
        return Some(stored.to_vec());
    }
    let text = std::str::from_utf8(stored).ok()?.trim();
    let key = base64::engine::general_purpose::STANDARD.decode(text).ok()?;
    if key.len() == KEY_SIZE {
        Some(key)
    } else {
        None
    }
}

/// The master key from the Secret Service, if there is one.
fn key_from_secret_service() -> Option<Vec<u8>> {
    let service = secret_service::blocking::SecretService::connect(
        secret_service::EncryptionType::Plain,
    )
    .ok()?;
    let collection = service.get_default_collection().ok()?;
    if collection.is_locked().unwrap_or(false) {
        // The keyring is locked and we cannot ask the user for it here.
        return None;
    }
    let mut wanted = std::collections::HashMap::new();
    wanted.insert("application", ATTR_APPLICATION);
    wanted.insert("type", ATTR_TYPE);
    for item in collection.search_items(wanted).ok()? {
        let secret = item.get_secret().ok()?;
        let key = decode_key(&secret);
        if key.is_some() {
            return key;
        }
    }
    None
}

/// The master key from the key file, creating one if needed.
fn key_from_file() -> Vec<u8> {
    let path = fallback_key_file();
    if path.exists() {
        if let Ok(raw) = fs::read(&path) {
            if let Some(key) = decode_key(&raw) {
                return key;
            }
        }
    }
    let key = random_bytes(KEY_SIZE);
    let _ = write_private(
        &path,
        base64::engine::general_purpose::STANDARD.encode(&key).as_bytes(),
    );
    key
}

/// The master key: the keyring if there is one, the key file otherwise.
pub fn master_key() -> Vec<u8> {
    key_from_secret_service().unwrap_or_else(key_from_file)
}

/// Encrypt with the libsodium secret box.
pub fn seal(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use crypto_secretbox::aead::{Aead, KeyInit};
    let cipher = crypto_secretbox::XSalsa20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Apple("bad master key".into()))?;
    let mut nonce_bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = crypto_secretbox::aead::Nonce::<crypto_secretbox::XSalsa20Poly1305>::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::Apple("could not encrypt".into()))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt with the libsodium secret box.
pub fn open(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use crypto_secretbox::aead::{Aead, KeyInit};
    if data.len() < 24 {
        return Err(Error::Apple("the stored session is truncated".into()));
    }
    let (nonce, ciphertext) = data.split_at(24);
    let cipher = crypto_secretbox::XSalsa20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Apple("bad master key".into()))?;
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| {
            Error::Apple(
                "cannot decrypt the session - the master key no longer matches it. \
                 Sign in again."
                    .into(),
            )
        })
}

/// Save the session.
pub fn save(data: &Value) -> Result<()> {
    let plaintext = serde_json::to_vec(data)?;
    let blob = seal(&master_key(), &plaintext)?;
    write_private(&session_file(), &blob)?;
    Ok(())
}

/// Load the session, if there is one.
pub fn load() -> Result<Option<Value>> {
    let path = session_file();
    if !path.exists() {
        return Ok(None);
    }
    let blob = fs::read(&path)?;
    let plaintext = open(&master_key(), &blob)?;
    Ok(Some(serde_json::from_slice(&plaintext)?))
}

/// Remove the session.
pub fn clear() -> Result<()> {
    let path = session_file();
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = random_bytes(KEY_SIZE);
        let blob = seal(&key, b"hello").unwrap();
        assert_eq!(open(&key, &blob).unwrap(), b"hello");
        assert!(open(&random_bytes(KEY_SIZE), &blob).is_err());
    }

    #[test]
    fn key_decoding_accepts_both_forms() {
        let raw = random_bytes(KEY_SIZE);
        assert_eq!(decode_key(&raw), Some(raw.clone()));
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(decode_key(b64.as_bytes()), Some(raw));
        assert_eq!(decode_key(b"too short"), None);
    }
}
