//! The join: becoming part of the keychain's trust circle.

use std::io::Write;

use crate::anisette::Anisette;
use crate::device::Device;
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::join::{self, Join, PeerIdentity};

/// The join, end to end.
///
/// `passcode` is the passcode of the device whose escrow bottle is being recovered.
/// **IRREVERSIBLE**: this spends one of the escrow service's ten attempts, and the
/// tenth failure destroys the record forever - so it is only ever run after the user
/// has typed a confirmation.
#[allow(clippy::too_many_arguments)]
pub fn run(
    client: &mut Engine,
    anisette: &mut Anisette,
    device: &Device,
    email: &str,
    pet: &str,
    escrow_host: &str,
    bottle_raw: &[u8],
    passcode: &str,
    confirm_irreversible: bool,
) -> Result<String> {
    let bottle = join::parse_bottle(bottle_raw)?;
    let sponsor = join::recover_sponsor(
        escrow_host,
        email,
        pet,
        &bottle,
        passcode.as_bytes(),
        &client.session_id(),
        device,
        anisette,
        confirm_irreversible,
    )?;

    // The new peer's identity.
    let peer = PeerIdentity::generate(
        &device.device_id,
        crate::octagon::PEER_MODEL_ID,
        1,
        now_unix(),
    )?;

    // The trust state: the sponsor's peers and the clocks to join with.
    let changes = client.fetch_changes(None)?;
    let (included, stable_clock, dynamic_clock) =
        join::trust_from_changes(&changes, &sponsor.peer_id);

    let join = Join {
        sponsor: sponsor.clone(),
        peer: peer.clone(),
        included_peer_ids: included,
        stable_clock,
        dynamic_clock,
    };

    // The voucher: the sponsor signs it with the recovered key.
    let voucher = join::make_voucher(&sponsor, &peer.peer_id)?;
    let request = build_request_with_voucher(&join, &voucher, &device.serial)?;
    client.join_with_voucher(&request)?;

    Ok(peer.peer_id)
}

/// The join request, with the voucher attached.
fn build_request_with_voucher(
    join: &Join,
    voucher: &crate::cuttlefish::SignedBlob,
    serial: &str,
) -> Result<Vec<u8>> {
    let mut peer = crate::cuttlefish::CuttlefishPeer {
        peer_id: join.peer.peer_id.clone(),
        permanent: crate::cuttlefish::SignedBlob {
            info: join.peer.permanent_data.clone(),
            sig: join.peer.permanent_sig.clone(),
        },
        stable: crate::cuttlefish::SignedBlob::default(),
        dynamic: crate::cuttlefish::SignedBlob::default(),
        voucher: Some(voucher.clone()),
    };
    // The stable and dynamic infos are built here so the voucher covers the same peer
    // the server sees.
    let stable = crate::octagon::build_stable_info(
        &join.peer.keys,
        join.stable_clock,
        crate::octagon::FROZEN_POLICY_VERSION,
        crate::octagon::FROZEN_POLICY_HASH,
        crate::octagon::FLEXIBLE_POLICY_VERSION,
        crate::octagon::FLEXIBLE_POLICY_HASH,
        "",
        serial,
        crate::octagon::PEER_OS_VERSION,
        crate::octagon::UCV_FOLLOWING,
    )?;
    peer.stable = crate::cuttlefish::SignedBlob {
        info: hex::decode(&stable.data)?,
        sig: hex::decode(&stable.sig)?,
    };
    let mut included = join.included_peer_ids.clone();
    if !included.contains(&join.peer.peer_id) {
        included.push(join.peer.peer_id.clone());
    }
    let dynamic =
        crate::octagon::build_dynamic_info(&join.peer.keys, join.dynamic_clock, &included)?;
    peer.dynamic = crate::cuttlefish::SignedBlob {
        info: hex::decode(&dynamic.data)?,
        sig: hex::decode(&dynamic.sig)?,
    };
    Ok(crate::cuttlefish::encode_join_with_voucher_request(
        &peer.encode(),
        None,
    ))
}

/// The current time, in unix seconds.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Read a line from the terminal.
pub fn ask(prompt: &str) -> String {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return String::new();
    }
    line.trim().to_string()
}

/// Read a secret from the terminal.
pub fn ask_secret(prompt: &str) -> String {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return String::new();
    }
    let secret = line.trim().to_string();
    println!();
    secret
}

/// The error the CLI shows when the escrow gate refuses.
pub fn gate_refusal() -> Error {
    Error::Apple(
        "the escrow recovery consumes one of 10 irreversible attempts (the 10th wrong passcode \
         destroys the record forever). Confirm it to continue."
            .into(),
    )
}
