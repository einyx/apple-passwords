//! The persistent local device identity.
//!
//! Generated once and reused forever: a stable `X-Mme-Device-Id` is what lets Apple
//! remember the 2FA approval instead of asking again.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Where everything this app stores lives.
pub fn config_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
            PathBuf::from(home).join(".config")
        });
    let dir = base.join("icp");
    let _ = fs::create_dir_all(&dir);
    let _ = set_private(&dir);
    dir
}

pub fn device_file() -> PathBuf {
    config_dir().join("device.json")
}

pub fn session_file() -> PathBuf {
    config_dir().join("session.enc")
}

pub fn vault_file() -> PathBuf {
    config_dir().join("vault.enc")
}

pub fn fallback_key_file() -> PathBuf {
    config_dir().join("master.key")
}

#[cfg(unix)]
fn set_private(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Write a file with 0600 permissions from the start - a secret must never exist
/// world-readable, even briefly.
#[cfg(unix)]
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    fs::write(path, data)
}

/// The device identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub serial: String,
    pub local_user_uuid: String,
}

impl Device {
    /// Load the stored identity, or create one.
    pub fn load_or_create() -> Result<Device> {
        let path = device_file();
        if path.exists() {
            if let Ok(text) = fs::read_to_string(&path) {
                if let Ok(dev) = serde_json::from_str::<Device>(&text) {
                    return Ok(dev);
                }
            }
        }
        let dev = Device {
            device_id: uuid_upper(),
            serial: format!("C02{}", &uuid_simple()[..9]),
            local_user_uuid: uuid_upper(),
        };
        let json = serde_json::to_string_pretty(&dev)?;
        write_private(&path, json.as_bytes())?;
        Ok(dev)
    }
}

/// A random UUID in Apple's upper-case form.
fn uuid_upper() -> String {
    uuid_simple().to_uppercase()
}

/// A random UUID without dashes.
fn uuid_simple() -> String {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_shape() {
        let u = uuid_upper();
        assert_eq!(u.len(), 36);
        assert_eq!(u.matches('-').count(), 4);
        assert!(u.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }
}
