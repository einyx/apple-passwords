//! The engine: the live client, from the stored session to decrypted credentials.
//!
//! This is what the app drives. It opens the stored session, refreshes the tokens if
//! they have expired, fetches the views' keys, fetches the keychain zones and
//! decrypts them - and it can write a new login back.

use base64::Engine as _;
use serde_json::Value;

use crate::anisette::Anisette;
use crate::ckks::CloudKitRecord;
use crate::cloudkit::{CloudKitTransport, DeviceConfig};
use crate::cuttlefish;
use crate::device::Device;
use crate::error::{Error, Result};
use crate::keychain::{self, Credential};
use crate::octagon::{self, PeerKeySet};
use crate::session;
use crate::write;

/// The default anisette server - the one the local service runs on.
pub const DEFAULT_ANISETTE_URL: &str = "http://127.0.0.1:6969";

/// The live client.
pub struct Engine {
    pub session: Value,
    pub device: Device,
    pub anisette: Anisette,
    pub transport: CloudKitTransport,
}

impl Engine {
    /// Open the stored session and build a client for it.
    pub fn open(anisette_url: Option<&str>) -> Result<Engine> {
        let session = session::load()?.ok_or(Error::NotSignedIn)?;
        let device = Device::load_or_create()?;
        let url = anisette_url
            .map(|s| s.to_string())
            .or_else(|| std::env::var("ICP_ANISETTE_URL").ok())
            .unwrap_or_else(|| DEFAULT_ANISETTE_URL.to_string());
        let anisette = Anisette::new(&url)?;
        let transport = build_transport(&session, &device)?;
        Ok(Engine {
            session,
            device,
            anisette,
            transport,
        })
    }

    /// The cloudKitUserId - the per-container id CloudKit wants.
    pub fn user_id(&self) -> Result<String> {
        self.session
            .get("mme")
            .and_then(|m| m.get("cloudKitUserId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(Error::NotSignedIn)
    }

    /// The Octagon peer identity.
    pub fn peer_id(&self) -> Result<String> {
        self.session
            .get("octagon")
            .and_then(|o| o.get("peer_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(Error::NotJoined)
    }

    /// This peer's key pair.
    pub fn peer_keys(&self) -> Result<PeerKeySet> {
        let keys = self
            .session
            .get("octagon")
            .and_then(|o| o.get("keys"))
            .ok_or(Error::NotJoined)?;
        PeerKeySet::from_storage(keys)
    }

    /// The sponsor's identity, if the join recovered one.
    pub fn sponsor(&self) -> Option<(String, Vec<u8>)> {
        let sponsor = self.session.get("octagon")?.get("sponsor")?;
        let peer_id = sponsor.get("peer_id")?.as_str()?.to_string();
        let key = sponsor
            .get("encryption_priv_x963")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())?;
        Some((peer_id, key))
    }

    /// Every view's top-level key, and the view's `synckey` records.
    ///
    /// A freshly-joined peer is only entitled to the always-on views (WiFi, Home,
    /// ...); the escrow-recovered *sponsor* is entitled to the user-controllable ones
    /// (Passwords, Manatee). Both are asked, and the results are unioned.
    pub fn fetch_view_keys(
        &mut self,
    ) -> Result<(Vec<(String, Vec<u8>)>, Vec<CloudKitRecord>)> {
        let mut tlks: Vec<(String, Vec<u8>)> = Vec::new();
        let mut synckeys: Vec<CloudKitRecord> = Vec::new();

        let peer_id = self.peer_id()?;
        let keys = self.peer_keys()?;
        let (own_tlks, own_synckeys) =
            self.fetch_recoverable_for(&peer_id, &keys.encryption.private_key.to_bytes())?;
        tlks.extend(own_tlks);
        synckeys.extend(own_synckeys);

        if let Some((sponsor_id, sponsor_key)) = self.sponsor() {
            if let Ok(key) = crate::crypto::load_private_x963(&sponsor_key) {
                let (sp_tlks, sp_synckeys) = self.fetch_recoverable_for(&sponsor_id, &key.to_bytes())?;
                tlks.extend(sp_tlks);
                synckeys.extend(sp_synckeys);
            }
        }
        Ok((tlks, synckeys))
    }

    /// Ask the server for the TLKShares a peer can recover.
    fn fetch_recoverable_for(
        &mut self,
        for_peer_id: &str,
        encryption_key: &[u8],
    ) -> Result<(Vec<(String, Vec<u8>)>, Vec<CloudKitRecord>)> {
        let request = cuttlefish::encode_fetch_recoverable_tlkshares_request(for_peer_id);
        let raw = self.transport.invoke(
            "fetchRecoverableTLKShares",
            &request,
            &mut self.anisette,
            &self.device,
        )?;
        let (share_bytes, synckey_bytes) = cuttlefish::parse_recoverable_tlkshares_response(&raw)?;
        let mut shares = Vec::new();
        for b in &share_bytes {
            shares.push(crate::ckks::parse_record(b)?);
        }
        let mut synckeys = Vec::new();
        for b in &synckey_bytes {
            synckeys.push(crate::ckks::parse_record(b)?);
        }
        let key = p384::SecretKey::from_slice(encryption_key)
            .map_err(|e| Error::Crypto(format!("bad peer key: {e}")))?;
        let tlks = keychain::unwrap_tlkshares(&shares, for_peer_id, &key)?;
        Ok((tlks, synckeys))
    }

    /// Every record in every keychain zone.
    pub fn fetch_zones(&mut self, zones: &[&str]) -> Result<Vec<CloudKitRecord>> {
        let user_id = self.user_id()?;
        let mut out = Vec::new();
        for zone in zones {
            match self
                .transport
                .fetch_zone_records(zone, &user_id, &mut self.anisette, &self.device)
            {
                Ok(records) => out.extend(records),
                Err(e) => {
                    // A missing or empty zone is skipped, not fatal.
                    eprintln!("skipping the {zone} zone: {e}");
                }
            }
        }
        Ok(out)
    }

    /// Fetch the keychain and decrypt it into credentials.
    pub fn sync(&mut self, zones: &[&str]) -> Result<Vec<Credential>> {
        let (tlks, view_synckeys) = self.fetch_view_keys()?;
        let mut records = self.fetch_zones(zones)?;
        records.extend(view_synckeys);
        let class_keys = keychain::unwrap_class_keys(&records, &tlks);
        let items = keychain::decrypt_items(&records, &class_keys);
        Ok(keychain::credentials_from_items(&items))
    }

    /// The class key of a view, fetched record by record (two requests).
    pub fn view_class_key(
        &mut self,
        zone: &str,
        view: &str,
    ) -> Result<(String, Vec<u8>)> {
        let user_id = self.user_id()?;
        let (tlks, _) = self.fetch_view_keys()?;
        let current = self
            .transport
            .fetch_record(view, zone, &user_id, &mut self.anisette, &self.device)?
            .ok_or(Error::NoViewKey)?;
        let key_id = current.get_str("parentkeyref").ok_or(Error::NoViewKey)?;
        let synckey = self
            .transport
            .fetch_record(key_id, zone, &user_id, &mut self.anisette, &self.device)?
            .ok_or(Error::NoViewKey)?;
        let parent = synckey.get_str("parentkeyref").ok_or(Error::NoViewKey)?;
        let wrapped = synckey.get_str("wrappedkey").ok_or(Error::NoViewKey)?;
        let tlk = tlks
            .iter()
            .find(|(id, _)| id == parent)
            .map(|(_, k)| k.clone())
            .ok_or(Error::NoViewKey)?;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(wrapped)
            .map_err(|_| Error::NoViewKey)?;
        let key = crate::crypto::siv_decrypt(&tlk, &blob, &[])?;
        Ok((key_id.to_string(), key))
    }

    /// Add a password to the keychain, and check that it landed.
    pub fn add_password(
        &mut self,
        domain: &str,
        username: &str,
        password: &str,
        title: Option<&str>,
        notes: Option<&str>,
        zone: &str,
    ) -> Result<write::SaveOutcome> {
        let user_id = self.user_id()?;
        let (class_key_id, class_key) = self.view_class_key(zone, write::CLASS_A_VIEW)?;

        let item = write::build_internet_password_item(
            domain,
            username,
            password,
            title,
            notes,
            None,
            "",
            0,
            now_unix(),
        );
        let built = write::build_item_record(
            &item,
            &class_key,
            &class_key_id,
            zone,
            &user_id,
            None,
            2,
            0,
            &write::default_uploadver(),
        )?;
        let record =
            write::build_item_record_message(&built.record_name, &built.fields, zone, &user_id);
        let (etag, _server_record) = self.transport.save_record(
            &record,
            true,
            crate::ckks::SAVE_SEMANTICS_FAIL_IF_EXISTS,
            &mut self.anisette,
            &self.device,
        )?;

        // A save response is not proof: read the record back and decrypt it.
        let fetched = self
            .transport
            .fetch_record(
                &built.record_name,
                zone,
                &user_id,
                &mut self.anisette,
                &self.device,
            )?;
        let fetched = fetched.ok_or_else(|| {
            Error::Apple("the write could not be read back - not confirmed".into())
        })?;
        if !write::verify_saved_record(&fetched, &class_key, password, Some(username)) {
            return Err(Error::Apple(
                "the write could not be read back - not confirmed".into(),
            ));
        }
        Ok(write::SaveOutcome {
            record_name: built.record_name,
            etag,
        })
    }

    /// Remove a record that was written (the rollback path).
    pub fn delete_record(&mut self, record_name: &str, zone: &str) -> Result<()> {
        let user_id = self.user_id()?;
        self.transport.delete_record(
            record_name,
            zone,
            &user_id,
            None,
            &mut self.anisette,
            &self.device,
        )
    }
}

fn build_transport(session: &Value, device: &Device) -> Result<CloudKitTransport> {
    let ck_token = session
        .get("mme")
        .and_then(|m| m.get("tokens"))
        .and_then(|t| t.get("cloudKitToken"))
        .and_then(|v| v.as_str())
        .ok_or(Error::NotSignedIn)?;
    let user_id = session
        .get("mme")
        .and_then(|m| m.get("cloudKitUserId"))
        .and_then(|v| v.as_str())
        .ok_or(Error::NotSignedIn)?;
    let config = DeviceConfig {
        device_uuid: device.device_id.clone(),
        serial: device.serial.clone(),
        name: "Mac".to_string(),
        ..Default::default()
    };
    CloudKitTransport::new(ck_token, user_id, config)
}

fn now_unix() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// The peer's public encryption key, as the trust circle knows it.
pub fn peer_public_encryption_key(keys: &PeerKeySet) -> Vec<u8> {
    octagon::public_encryption_key(keys)
}
