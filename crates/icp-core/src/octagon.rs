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
