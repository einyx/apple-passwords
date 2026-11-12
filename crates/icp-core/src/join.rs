//! The join: becoming part of the keychain's trust circle.
//!
//! A new device recovers the *previous* device's identity out of the escrow bottle -
//! which is encrypted with a key derived from that device's passcode - and signs a
//! voucher that lets the new peer in.
//!
//! **IRREVERSIBLE.** The escrow service allows ten attempts and the tenth wrong
//! passcode destroys the record forever, so the recovery is gated on an explicit
//! confirmation.

use p384::SecretKey;
use serde_json::Value;

use crate::anisette::Anisette;
use crate::cuttlefish::{self, SignedBlob};
use crate::device::Device;
use crate::error::Result;
use crate::escrow::{self, bottle::OTBottle, RecoveredIdentity};
use crate::octagon::{self, PeerKey, PeerKeySet};

/// The new peer's identity, as it is stored in the session.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub peer_id: String,
    pub keys: PeerKeySet,
    pub permanent_data: Vec<u8>,
    pub permanent_sig: Vec<u8>,
}

impl PeerIdentity {
    /// Generate a fresh identity and its permanent info.
    pub fn generate(
        machine_id: &str,
        model_id: &str,
        epoch: i64,
        creation_time: i64,
    ) -> Result<PeerIdentity> {
        let keys = PeerKeySet::generate();
        let info =
            octagon::build_permanent_info(&keys, machine_id, model_id, epoch, creation_time)?;
        Ok(PeerIdentity {
            peer_id: info.peer_id.clone(),
            keys,
            permanent_data: hex::decode(&info.data)?,
            permanent_sig: hex::decode(&info.sig)?,
        })
    }
}

/// What a join needs.
pub struct Join {
    /// The recovered identity of the previous device.
    pub sponsor: RecoveredIdentity,
    /// The new peer's identity.
    pub peer: PeerIdentity,
    /// The sponsor's peers this one should trust.
    pub included_peer_ids: Vec<String>,
    /// The clocks to join with.
    pub stable_clock: i64,
    pub dynamic_clock: i64,
}

/// Recover the sponsor's identity from an escrow bottle.
///
/// `passcode` is the passcode of the device the bottle belongs to.
#[allow(clippy::too_many_arguments)]
pub fn recover_sponsor(
    escrow_host: &str,
    email: &str,
    pet: &str,
    bottle: &OTBottle,
    passcode: &[u8],
    adsid: &str,
    device: &Device,
    anisette: &mut Anisette,
    confirm_irreversible: bool,
) -> Result<RecoveredIdentity> {
    let mut recovery = escrow::EscrowRecovery::new(escrow_host, email, pet, device, anisette)?;
    let entropy = recovery.try_recover_escrow(&bottle.bottle_id, passcode, confirm_irreversible)?;
    escrow::recover_identity(bottle, &entropy, adsid)
}

/// The bottles the account can recover, with the metadata that names their device.
pub fn list_bottles(
    escrow_host: &str,
    email: &str,
    pet: &str,
    device: &Device,
    anisette: &mut Anisette,
) -> Result<Vec<(String, plist::Value)>> {
    let mut recovery = escrow::EscrowRecovery::new(escrow_host, email, pet, device, anisette)?;
    let records = recovery.list_records("com.apple.securebackup.record")?;
    Ok(records.into_iter().map(|r| (r.label, r.meta)).collect())
}

/// Parse a bottle out of the escrow listing.
pub fn parse_bottle(raw: &[u8]) -> Result<OTBottle> {
    OTBottle::parse(raw)
}

/// Build the peer that joins, and the request that carries it.
///
/// The permanent info is the fixed identity; the stable and dynamic infos are fresh at
/// join time, as the real client does.
pub fn build_join_request(
    join: &Join,
    serial: &str,
    restore_point: Option<&str>,
) -> Result<Vec<u8>> {
    let stable = octagon::build_stable_info(
        &join.peer.keys,
        join.stable_clock,
        octagon::FROZEN_POLICY_VERSION,
        octagon::FROZEN_POLICY_HASH,
        octagon::FLEXIBLE_POLICY_VERSION,
        octagon::FLEXIBLE_POLICY_HASH,
        "",
        serial,
        octagon::PEER_OS_VERSION,
        octagon::UCV_FOLLOWING,
    )?;
    let mut included = join.included_peer_ids.clone();
    if !included.contains(&join.peer.peer_id) {
        included.push(join.peer.peer_id.clone());
    }
    let dynamic = octagon::build_dynamic_info(&join.peer.keys, join.dynamic_clock, &included)?;

    let peer = cuttlefish::CuttlefishPeer {
        peer_id: join.peer.peer_id.clone(),
        permanent: SignedBlob {
            info: join.peer.permanent_data.clone(),
            sig: join.peer.permanent_sig.clone(),
        },
        stable: SignedBlob {
            info: hex::decode(&stable.data)?,
            sig: hex::decode(&stable.sig)?,
        },
        dynamic: SignedBlob {
            info: hex::decode(&dynamic.data)?,
            sig: hex::decode(&dynamic.sig)?,
        },
        voucher: None,
    };
    Ok(cuttlefish::encode_join_with_voucher_request(
        &peer.encode(),
        restore_point,
    ))
}

/// The voucher the sponsor signs for the new peer.
pub fn make_voucher(sponsor: &RecoveredIdentity, beneficiary_peer_id: &str) -> Result<SignedBlob> {
    sponsor.make_voucher(beneficiary_peer_id, 1)
}

/// The sponsor's trusted peers, and the clocks to join with, from the trust state.
pub fn trust_from_changes(
    changes: &cuttlefish::FetchChanges,
    sponsor_peer_id: &str,
) -> (Vec<String>, i64, i64) {
    let mut stable_clocks = vec![0i64];
    let mut sponsor_included: Vec<String> = Vec::new();
    let mut sponsor_dynamic_clock = 0i64;
    for peer in &changes.peers {
        if let Some(stable) = &peer.stable_info {
            stable_clocks.push(parse_stable_clock(&stable.info));
        }
        if peer.hash == sponsor_peer_id {
            if let Some(dynamic) = &peer.dynamic_info {
                let (clock, included) = parse_dynamic_info(&dynamic.info);
                sponsor_dynamic_clock = clock;
                sponsor_included = included;
            }
        }
    }
    let stable_clock = stable_clocks.iter().copied().max().unwrap_or(0) + 1;
    (sponsor_included, stable_clock, sponsor_dynamic_clock + 1)
}

/// The clock out of a stable info.
fn parse_stable_clock(data: &[u8]) -> i64 {
    let mut out = 0i64;
    let f = match crate::proto::Fields::decode(data) {
        Ok(f) => f,
        Err(_) => return out,
    };
    if let Some(crate::proto::Value::Varint(v)) = f.get(1) {
        out = *v as i64;
    }
    out
}

/// The clock and the trusted peers out of a dynamic info.
fn parse_dynamic_info(data: &[u8]) -> (i64, Vec<String>) {
    let mut clock = 0i64;
    let mut included = Vec::new();
    let f = match crate::proto::Fields::decode(data) {
        Ok(f) => f,
        Err(_) => return (clock, included),
    };
    if let Some(crate::proto::Value::Varint(v)) = f.get(1) {
        clock = *v as i64;
    }
    for value in f.get_all(2) {
        if let crate::proto::Value::Bytes(b) = value {
            included.push(String::from_utf8_lossy(b).to_string());
        }
    }
    (clock, included)
}

/// A peer key from its X9.63 bytes.
pub fn peer_key_from_x963(blob: &[u8]) -> Result<PeerKey> {
    PeerKey::from_x963(blob)
}

/// A private key from its X9.63 bytes.
pub fn secret_key_from_x963(blob: &[u8]) -> Result<SecretKey> {
    crate::crypto::load_private_x963(blob)
}

/// The session's octagon state, as it is stored.
pub type OctagonState = Value;
