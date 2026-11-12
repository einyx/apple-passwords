//! The Octagon peer identity.
//!
//! Two P-384 key pairs (signing and encryption) and the peerID derived from a signed
//! permanentInfo. Pure offline crypto - the peerID is what the trust circle knows
//! this device by, so it is generated once and never changes.

use base64::Engine;
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::Result;
use crate::proto::{Fields, Value, Writer};

/// The permanentInfo's signature type (domain separation).
pub const PERMANENT_INFO_SIG_TYPE: &str = "TPPB.PeerPermanentInfo";
/// The voucher's signature type.
pub const VOUCHER_SIG_TYPE: &str = "TPPB.Voucher";

/// The prevailing builtin Octagon policy, as declared in the stable info.
pub const FROZEN_POLICY_VERSION: i64 = 5;
pub const FROZEN_POLICY_HASH: &str = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo=";
pub const FLEXIBLE_POLICY_VERSION: i64 = 20;
pub const FLEXIBLE_POLICY_HASH: &str = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY=";
/// The OS version the peer claims.
pub const PEER_OS_VERSION: &str = "macOS 13.4.1 (22F8)";
/// The model the peer claims.
pub const PEER_MODEL_ID: &str = "MacBookPro18,3";

/// One P-384 key pair.
#[derive(Debug, Clone)]
pub struct PeerKey {
    pub private_key: SecretKey,
}

impl PeerKey {
    /// Generate one.
    pub fn generate() -> PeerKey {
        PeerKey {
            private_key: SecretKey::random(&mut rand::thread_rng()),
        }
    }

    /// Rebuild a key from its external representation.
    pub fn from_x963(blob: &[u8]) -> Result<PeerKey> {
        Ok(PeerKey {
            private_key: crypto::load_private_x963(blob)?,
        })
    }

    /// The uncompressed public point (`0x04 || X || Y`).
    pub fn public_x963(&self) -> Vec<u8> {
        crypto::public_x963(&self.private_key)
    }

    /// The SubjectPublicKeyInfo DER.
    pub fn public_spki(&self) -> Vec<u8> {
        crypto::public_spki(&self.private_key)
    }

    /// The external representation of the full key: `0x04 || X || Y || D`.
    pub fn private_x963(&self) -> Vec<u8> {
        crypto::private_x963(&self.private_key)
    }

    /// Sign with ECDSA over SHA-384.
    pub fn sign_sha384(&self, data: &[u8]) -> Result<Vec<u8>> {
        crypto::sign_sha384(&self.private_key, data)
    }
}

/// The two key pairs that make up one self-peer identity.
#[derive(Debug, Clone)]
pub struct PeerKeySet {
    pub signing: PeerKey,
    pub encryption: PeerKey,
}

impl PeerKeySet {
    /// Generate a fresh identity.
    pub fn generate() -> PeerKeySet {
        PeerKeySet {
            signing: PeerKey::generate(),
            encryption: PeerKey::generate(),
        }
    }

    /// The serializable form (the hex of the X9.63 privates).
    pub fn to_storage(&self) -> serde_json::Value {
        serde_json::json!({
            "curve": "P-384",
            "signing_priv_x963": hex::encode(self.signing.private_x963()),
            "encryption_priv_x963": hex::encode(self.encryption.private_x963()),
        })
    }

    /// Rebuild from the stored form.
    pub fn from_storage(value: &serde_json::Value) -> Result<PeerKeySet> {
        let signing = value
            .get("signing_priv_x963")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::error::Error::Apple("no signing key".into()))?;
        let encryption = value
            .get("encryption_priv_x963")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::error::Error::Apple("no encryption key".into()))?;
        Ok(PeerKeySet {
            signing: PeerKey {
                private_key: crypto::load_private_x963(&hex::decode(signing)?)?,
            },
            encryption: PeerKey {
                private_key: crypto::load_private_x963(&hex::decode(encryption)?)?,
            },
        })
    }
}

/// `TPHashBuilder`: `"<ALGO>:" + base64(digest)`.
pub fn tphash(data: &[u8], algo: &str) -> String {
    use sha2::Digest;
    let digest = match algo {
        "SHA384" => sha2::Sha384::digest(data).to_vec(),
        _ => sha2::Sha256::digest(data).to_vec(),
    };
    format!(
        "{}:{}",
        algo,
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// The peerID: the hash of the permanent info *and* its signature.
///
/// The signature is randomized, so the peerID is generated once; a verifier only
/// re-checks that the peerID still equals the hash.
pub fn derive_peer_id(permanent_info_data: &[u8], sig: &[u8], algo: &str) -> String {
    let mut both = permanent_info_data.to_vec();
    both.extend_from_slice(sig);
    tphash(&both, algo)
}

/// The signed self-peer permanentInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermanentInfo {
    pub peer_id: String,
    pub data: String,
    pub sig: String,
    pub machine_id: String,
    pub model_id: String,
    pub epoch: i64,
    pub creation_time: i64,
}

/// The `TPPBPeerPermanentInfo` fields.
const F_EPOCH: u32 = 1;
const F_SIGNING: u32 = 2;
const F_ENCRYPTION: u32 = 3;
const F_MACHINE: u32 = 4;
const F_MODEL: u32 = 5;
const F_CREATION: u32 = 6;

/// Serialize the permanentInfo's data.
pub fn serialize_permanent_info_data(
    signing_spki: &[u8],
    encryption_spki: &[u8],
    machine_id: &str,
    model_id: &str,
    epoch: i64,
    creation_time: i64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.uint64(F_EPOCH, Some(epoch as u64))
        .bytes(F_SIGNING, Some(signing_spki))
        .bytes(F_ENCRYPTION, Some(encryption_spki))
        .bytes(F_MACHINE, Some(machine_id.as_bytes()))
        .bytes(F_MODEL, Some(model_id.as_bytes()))
        .uint64(F_CREATION, Some(creation_time as u64));
    w.finish()
}

/// `prefixedData()` - the signature type name in front of the data, so a signature
/// over one type cannot be replayed as another.
pub fn prefixed_data(data: &[u8], sig_type: &str) -> Vec<u8> {
    let mut out = sig_type.as_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// Build the signed permanentInfo and derive the peerID.
pub fn build_permanent_info(
    keys: &PeerKeySet,
    machine_id: &str,
    model_id: &str,
    epoch: i64,
    creation_time: i64,
) -> Result<PermanentInfo> {
    let data = serialize_permanent_info_data(
        &keys.signing.public_spki(),
        &keys.encryption.public_spki(),
        machine_id,
        model_id,
        epoch,
        creation_time,
    );
    let sig = keys
        .signing
        .sign_sha384(&prefixed_data(&data, PERMANENT_INFO_SIG_TYPE))?;
    let peer_id = derive_peer_id(&data, &sig, "SHA256");
    Ok(PermanentInfo {
        peer_id,
        data: hex::encode(&data),
        sig: hex::encode(&sig),
        machine_id: machine_id.to_string(),
        model_id: model_id.to_string(),
        epoch,
        creation_time,
    })
}

/// The peer's public encryption key, as Octagon stores it (SPKI DER).
pub fn public_encryption_key(keys: &PeerKeySet) -> Vec<u8> {
    keys.encryption.public_spki()
}

/// The stable info: the peer's clock and the prevailing policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StableInfo {
    pub data: String,
    pub sig: String,
    pub clock: i64,
}

/// The dynamic info: the peers this one trusts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicInfo {
    pub data: String,
    pub sig: String,
    pub clock: i64,
    pub included_peer_ids: Vec<String>,
}

/// The stable info's fields (the `TPPBPeerStableInfo` proto).
const S_CLOCK: u32 = 1;
const S_FROZEN_VERSION: u32 = 2;
const S_FROZEN_HASH: u32 = 3;
const S_OSVERSION: u32 = 5;
const S_DEVICENAME: u32 = 6;
const S_SERIAL: u32 = 9;
const S_FLEX_VERSION: u32 = 10;
const S_FLEX_HASH: u32 = 11;
const S_UCV: u32 = 12;

/// The `TPPBPeerStableInfo` proto.
#[allow(clippy::too_many_arguments)]
pub fn serialize_stable_info_data(
    clock: i64,
    frozen_policy_version: i64,
    frozen_policy_hash: &str,
    flexible_policy_version: i64,
    flexible_policy_hash: &str,
    device_name: &str,
    serial_number: &str,
    os_version: &str,
    user_controllable_views: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.uint64(S_CLOCK, Some(clock as u64))
        .uint64(S_FROZEN_VERSION, Some(frozen_policy_version as u64))
        .string(S_FROZEN_HASH, Some(frozen_policy_hash))
        .string(S_OSVERSION, Some(os_version))
        .string(S_DEVICENAME, Some(device_name))
        .string(S_SERIAL, Some(serial_number))
        .uint64(S_FLEX_VERSION, Some(flexible_policy_version as u64))
        .string(S_FLEX_HASH, Some(flexible_policy_hash))
        .uint64(S_UCV, Some(user_controllable_views));
    w.finish()
}

/// The user-controllable-views status.
pub const UCV_FOLLOWING: u64 = 1;

/// Build and sign the stable info.
#[allow(clippy::too_many_arguments)]
pub fn build_stable_info(
    keys: &PeerKeySet,
    clock: i64,
    frozen_policy_version: i64,
    frozen_policy_hash: &str,
    flexible_policy_version: i64,
    flexible_policy_hash: &str,
    device_name: &str,
    serial_number: &str,
    os_version: &str,
    user_controllable_views: u64,
) -> Result<StableInfo> {
    let data = serialize_stable_info_data(
        clock,
        frozen_policy_version,
        frozen_policy_hash,
        flexible_policy_version,
        flexible_policy_hash,
        device_name,
        serial_number,
        os_version,
        user_controllable_views,
    );
    let sig = keys
        .signing
        .sign_sha384(&prefixed_data(&data, "TPPB.PeerStableInfo"))?;
    Ok(StableInfo {
        data: hex::encode(&data),
        sig: hex::encode(&sig),
        clock,
    })
}

/// The dynamic info's fields (the `TPPBPeerDynamicInfo` proto).
const D_CLOCK: u32 = 1;
const D_INCLUDED: u32 = 2;
const D_EXCLUDED: u32 = 3;
const D_PREAPPROVALS: u32 = 5;

/// The `TPPBPeerDynamicInfo` proto.
pub fn serialize_dynamic_info_data(
    clock: i64,
    included_peer_ids: &[String],
    excluded_peer_ids: &[String],
    preapprovals: &[String],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.uint64(D_CLOCK, Some(clock as u64));
    for id in included_peer_ids {
        w.string(D_INCLUDED, Some(id));
    }
    for id in excluded_peer_ids {
        w.string(D_EXCLUDED, Some(id));
    }
    for h in preapprovals {
        w.string(D_PREAPPROVALS, Some(h));
    }
    w.finish()
}

/// Build and sign the dynamic info.
pub fn build_dynamic_info(
    keys: &PeerKeySet,
    clock: i64,
    included_peer_ids: &[String],
) -> Result<DynamicInfo> {
    let data = serialize_dynamic_info_data(clock, included_peer_ids, &[], &[]);
    let sig = keys
        .signing
        .sign_sha384(&prefixed_data(&data, "TPPB.PeerDynamicInfo"))?;
    Ok(DynamicInfo {
        data: hex::encode(&data),
        sig: hex::encode(&sig),
        clock,
        included_peer_ids: included_peer_ids.to_vec(),
    })
}

/// The peerID of a stored permanentInfo.
pub fn stored_peer_id(permanent: &PermanentInfo) -> String {
    permanent.peer_id.clone()
}

/// The verification key of the signing pair.
pub fn signing_verifying_key(keys: &PeerKeySet) -> Result<VerifyingKey> {
    let signing = SigningKey::from_bytes(&keys.signing.private_key.to_bytes())
        .map_err(|e| crate::error::Error::Crypto(format!("bad signing key: {e}")))?;
    Ok(*signing.verifying_key())
}

/// Verify a signature over data with the peer's signing key.
pub fn verify(keys: &PeerKeySet, data: &[u8], sig: &[u8]) -> bool {
    match signing_verifying_key(keys) {
        Ok(vk) => crypto::verify_sha384(&vk, data, sig),
        Err(_) => false,
    }
}

/// The peer's public key in the `Identifier` shape Octagon uses.
pub fn public_key_bytes(key: &PeerKey) -> Vec<u8> {
    key.public_x963()
}

/// Decode a stored hex blob.
pub fn decode_hex(value: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(value)?)
}

/// The public key of a peer, from its X9.63 bytes.
pub fn public_from_x963(blob: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(blob).map_err(|e| crate::error::Error::Key(e.to_string()))
}

/// The signature of a stored blob.
pub fn signature_from_hex(value: &str) -> Result<Signature> {
    Signature::from_slice(&hex::decode(value)?).map_err(|e| crate::error::Error::Key(e.to_string()))
}

/// Read a field out of a decoded message.
pub fn read_field(f: &Fields, n: u32) -> Option<&Value> {
    f.get(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_is_the_hash_of_data_and_signature() {
        let keys = PeerKeySet::generate();
        let info = build_permanent_info(&keys, "machine", "model", 1, 1700000000).unwrap();
        assert!(info.peer_id.starts_with("SHA256:"));
        let data = hex::decode(&info.data).unwrap();
        let sig = hex::decode(&info.sig).unwrap();
        assert_eq!(derive_peer_id(&data, &sig, "SHA256"), info.peer_id);
        // The signature verifies against the signing key.
        assert!(verify(
            &keys,
            &prefixed_data(&data, PERMANENT_INFO_SIG_TYPE),
            &sig
        ));
    }

    #[test]
    fn key_set_storage_roundtrip() {
        let keys = PeerKeySet::generate();
        let stored = keys.to_storage();
        let back = PeerKeySet::from_storage(&stored).unwrap();
        assert_eq!(
            hex::encode(back.signing.private_x963()),
            hex::encode(keys.signing.private_x963())
        );
        assert_eq!(
            hex::encode(back.encryption.private_x963()),
            hex::encode(keys.encryption.private_x963())
        );
    }

    #[test]
    fn tphash_shape() {
        let h = tphash(b"x", "SHA256");
        assert!(h.starts_with("SHA256:"));
        let h384 = tphash(b"x", "SHA384");
        assert!(h384.starts_with("SHA384:"));
        assert_ne!(h, h384);
    }
}
