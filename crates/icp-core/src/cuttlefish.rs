//! The Cuttlefish wire messages.
//!
//! Cuttlefish is Apple's server-side RPC service; the keychain uses it for the
//! trust-circle operations (fetching the TLKShares the sponsor shared with this peer,
//! joining the circle with a voucher).

use crate::error::Result;
use crate::proto::{Fields, Value, Writer};

/// A `functionInvokeRequest`.
pub fn encode_function_invoke_request(service: &str, name: &str, parameters: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(1, Some(service))
        .string(2, Some(name))
        .bytes(3, Some(parameters));
    w.finish()
}

/// A signed blob (info + signature).
#[derive(Debug, Clone, Default)]
pub struct SignedBlob {
    pub info: Vec<u8>,
    pub sig: Vec<u8>,
}

impl SignedBlob {
    /// Encode it.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(1, Some(&self.info)).bytes(2, Some(&self.sig));
        w.finish()
    }

    /// Parse one.
    pub fn parse(raw: &[u8]) -> Result<SignedBlob> {
        let f = Fields::decode(raw)?;
        Ok(SignedBlob {
            info: f.bytes(1).unwrap_or_default().to_vec(),
            sig: f.bytes(2).unwrap_or_default().to_vec(),
        })
    }
}

/// A `CuttlefishPeer` - the peer identity with its signed infos.
#[derive(Debug, Clone, Default)]
pub struct CuttlefishPeer {
    pub peer_id: String,
    pub permanent: SignedBlob,
    pub stable: SignedBlob,
    pub dynamic: SignedBlob,
    pub voucher: Option<SignedBlob>,
}

impl CuttlefishPeer {
    /// Encode it.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(1, Some(&self.peer_id))
            .message(2, Some(&self.permanent.encode()))
            .message(3, Some(&self.stable.encode()))
            .message(4, Some(&self.dynamic.encode()));
        if let Some(v) = &self.voucher {
            w.message(5, Some(&v.encode()));
        }
        w.finish()
    }
}

/// A `TlkShare` - the sponsor's gift of a view's top-level key.
#[derive(Debug, Clone, Default)]
pub struct TlkShare {
    pub service: String,
    pub curve: u64,
    pub epoch: u64,
    pub key_id: String,
    pub poisoned: u64,
    pub receiver: String,
    pub receiver_public_encryption_key: String,
    pub sender: String,
    pub signature: String,
    pub version: u64,
    pub wrapped_key: String,
}

impl TlkShare {
    /// Encode it.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(1, Some(&self.service))
            .uint64(2, Some(self.curve))
            .uint64(3, Some(self.epoch))
            .string(4, Some(&self.key_id))
            .uint64(5, Some(self.poisoned))
            .string(6, Some(&self.receiver))
            .string(7, Some(&self.receiver_public_encryption_key))
            .string(8, Some(&self.sender))
            .string(9, Some(&self.signature))
            .uint64(10, Some(self.version))
            .string(11, Some(&self.wrapped_key));
        w.finish()
    }

    /// Parse one.
    pub fn parse(raw: &[u8]) -> Result<TlkShare> {
        let f = Fields::decode(raw)?;
        Ok(TlkShare {
            service: f.string(1).unwrap_or_default(),
            curve: f.uint(2).unwrap_or(0),
            epoch: f.uint(3).unwrap_or(0),
            key_id: f.string(4).unwrap_or_default(),
            poisoned: f.uint(5).unwrap_or(0),
            receiver: f.string(6).unwrap_or_default(),
            receiver_public_encryption_key: f.string(7).unwrap_or_default(),
            sender: f.string(8).unwrap_or_default(),
            signature: f.string(9).unwrap_or_default(),
            version: f.uint(10).unwrap_or(0),
            wrapped_key: f.string(11).unwrap_or_default(),
        })
    }
}

/// A `ViewKey` - one key of a view, as the server hands it over.
#[derive(Debug, Clone, Default)]
pub struct ViewKey {
    pub key_id: String,
    pub top_level_key_id: String,
    pub key_number: u64,
    pub key: String,
    pub hardware: String,
}

impl ViewKey {
    /// Encode it.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(1, Some(&self.key_id))
            .string(2, Some(&self.top_level_key_id))
            .uint64(3, Some(self.key_number))
            .string(4, Some(&self.key))
            .string(5, Some(&self.hardware));
        w.finish()
    }
}

/// A `Voucher{reason, beneficiary, sponsor}` - the credential a new peer presents to
/// join the trust circle.
pub fn encode_voucher(reason: i64, beneficiary: &str, sponsor: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.uint64(1, Some(reason as u64))
        .string(2, Some(beneficiary))
        .string(3, Some(sponsor));
    w.finish()
}

/// One peer in the trust state.
#[derive(Debug, Clone, Default)]
pub struct PeerChange {
    /// The peer's id.
    pub hash: String,
    /// Its permanent info (signed).
    pub permanent_info: Option<SignedBlob>,
    /// Its stable info (signed).
    pub stable_info: Option<SignedBlob>,
    /// Its dynamic info (signed).
    pub dynamic_info: Option<SignedBlob>,
}

/// The trust state: the peers and the sync token.
#[derive(Debug, Clone, Default)]
pub struct FetchChanges {
    pub sync_token: Option<String>,
    pub peers: Vec<PeerChange>,
}

/// Parse the answer to `fetchChanges`.
pub fn parse_fetch_changes_response(raw: &[u8]) -> Result<FetchChanges> {
    let f = crate::proto::Fields::decode(raw)?;
    let Some(changes) = f.bytes(1) else {
        return Ok(FetchChanges::default());
    };
    let cf = crate::proto::Fields::decode(changes)?;
    let mut peers = Vec::new();
    for change in cf.get_all(2) {
        let crate::proto::Value::Bytes(bytes) = change else {
            continue;
        };
        let chf = crate::proto::Fields::decode(bytes)?;
        let Some(peer) = chf.bytes(3) else { continue };
        let pf = crate::proto::Fields::decode(peer)?;
        let mut peer_change = PeerChange {
            hash: pf.string(1).unwrap_or_default(),
            ..Default::default()
        };
        for (num, slot) in [(2u32, 0usize), (3, 1), (4, 2)] {
            if let Some(blob) = pf.bytes(num) {
                let signed = SignedBlob::parse(blob)?;
                match slot {
                    0 => peer_change.permanent_info = Some(signed),
                    1 => peer_change.stable_info = Some(signed),
                    _ => peer_change.dynamic_info = Some(signed),
                }
            }
        }
        peers.push(peer_change);
    }
    Ok(FetchChanges {
        sync_token: cf.string(1),
        peers,
    })
}

/// The `joinWithVoucher` request: the peer and the restore point.
pub fn encode_join_with_voucher_request(peer: &[u8], restore_point: Option<&str>) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(1, restore_point).message(2, Some(peer));
    w.finish()
}

/// The keys of one view.
#[derive(Debug, Clone, Default)]
pub struct ViewKeys {
    pub service: String,
    pub top_level_key: Option<ViewKey>,
    pub class_a: Option<ViewKey>,
    pub class_c: Option<ViewKey>,
    pub old_top_level_key: Option<ViewKey>,
}

impl ViewKeys {
    /// Encode it.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(1, Some(&self.service));
        for (num, vk) in [
            (2, &self.top_level_key),
            (3, &self.class_a),
            (4, &self.class_c),
            (5, &self.old_top_level_key),
        ] {
            if let Some(vk) = vk {
                w.message(num, Some(&vk.encode()));
            }
        }
        w.finish()
    }
}

/// Ask the server for every TLKShare a peer can recover - including the
/// user-controllable views (Passwords) that have no plain record addressed to us.
pub fn encode_fetch_recoverable_tlkshares_request(peer_id: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(1, Some(peer_id));
    w.finish()
}

/// The recoverable TLKShares: (share records, synckey records), as raw record bytes.
#[allow(clippy::type_complexity)]
pub fn parse_recoverable_tlkshares_response(raw: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let f = Fields::decode(raw)?;
    let inner = |blob: Option<&[u8]>| -> Option<Vec<u8>> {
        blob.and_then(|b| Fields::decode(b).ok())
            .and_then(|f| f.bytes(2).map(|r| r.to_vec()))
    };
    let mut share_records = Vec::new();
    let mut synckey_records = Vec::new();
    for grp in f.get_all(1) {
        let Value::Bytes(gb) = grp else { continue };
        let g = Fields::decode(gb)?;
        if let Some(sh) = inner(g.bytes(3)) {
            share_records.push(sh);
        }
        if let Some(vk) = g.bytes(2) {
            let vf = Fields::decode(vk)?;
            for n in [1u32, 2, 3] {
                if let Some(rec) = inner(vf.bytes(n)) {
                    synckey_records.push(rec);
                }
            }
        }
    }
    Ok((share_records, synckey_records))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlkshare_roundtrip() {
        let share = TlkShare {
            service: "svc".into(),
            curve: 4,
            epoch: 1,
            key_id: "KEY".into(),
            receiver: "RK-x".into(),
            wrapped_key: "base64".into(),
            ..Default::default()
        };
        let raw = share.encode();
        let back = TlkShare::parse(&raw).unwrap();
        assert_eq!(back.service, "svc");
        assert_eq!(back.curve, 4);
        assert_eq!(back.key_id, "KEY");
        assert_eq!(back.wrapped_key, "base64");
    }

    #[test]
    fn function_invoke_layout() {
        let raw = encode_function_invoke_request("Cuttlefish", "op", b"params");
        let f = Fields::decode(&raw).unwrap();
        assert_eq!(f.string(1).as_deref(), Some("Cuttlefish"));
        assert_eq!(f.string(2).as_deref(), Some("op"));
        assert_eq!(f.bytes(3), Some(&b"params"[..]));
    }
}
