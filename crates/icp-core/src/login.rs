//! The sign-in: the Apple ID, the two-factor code, and the long-lived token.
//!
//! The password is read from the terminal and never stored unless it is asked for;
//! the token it mints *is* stored, encrypted in the session file.

use std::io::Write;

use crate::anisette::Anisette;
use crate::device::Device;
use crate::error::{Error, Result};
use crate::gsa::{self, GsaClient};
use crate::icloud;

/// What a sign-in produced.
pub struct Login {
    /// The account's numeric id.
    pub dsid: String,
    /// The long-lived token (what every later call uses).
    pub mme_auth_token: String,
    /// The CloudKit token.
    pub cloudkit_token: String,
    /// The service URLs.
    pub webservices: std::collections::BTreeMap<String, String>,
    /// The per-container CloudKit user id.
    pub cloudkit_user_id: String,
    /// The password, when it was asked to be kept.
    pub password: Option<String>,
}

/// The sign-in, with a callback for the two-factor code.
pub fn sign_in(
    username: &str,
    password: &str,
    anisette: &mut Anisette,
    device: &Device,
    twofa: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<Login> {
    let mut client = GsaClient::new(device)?;

    // The first exchange tells us whether Apple wants a second factor.
    let (response, spd) = client.authenticate(anisette, username, password)?;
    let spd = if gsa::two_factor_needed(&response).is_some() {
        let (dsid, idms) = spd_identity(&spd)?;
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| Error::Apple(format!("could not build the sign-in client: {e}")))?;
        match gsa::two_factor_needed(&response) {
            Some("sms") => {
                gsa::trigger_sms_factor(&http, device, anisette, &dsid, &idms)?;
                let code = twofa("sms")?;
                gsa::submit_sms_factor(&http, device, anisette, &code, &dsid, &idms)?;
            }
            _ => {
                gsa::trigger_trusted_factor(&http, device, anisette, &dsid, &idms)?;
                let code = twofa("trusted")?;
                gsa::submit_trusted_factor(&http, device, anisette, &code, &dsid, &idms)?;
            }
        }
        // Sign in again, now that the device is trusted.
        let (response, spd) = client.authenticate(anisette, username, password)?;
        if gsa::two_factor_needed(&response).is_some() {
            return Err(Error::Apple(
                "Apple still asks for a second factor after the code was accepted".into(),
            ));
        }
        spd
    } else {
        spd
    };

    let (dsid, pet, _expiry) = gsa::extract_pet(&spd)?;
    let client_id = format!("auth-{dsid}");

    // The PET becomes the long-lived token.
    let delegates = icloud::login_delegates(username, &pet, &dsid, &client_id, device, anisette)?;

    // And that token opens the account: the service URLs and the CloudKit token.
    let settings = icloud::fetch_account_settings(
        &delegates.dsid,
        &delegates.mme_auth_token,
        device,
        anisette,
    )?;
    let mut webservices = icloud::extract_webservices(&settings);
    let cloudkit_token = settings
        .as_dictionary()
        .and_then(|d| d.get("tokens"))
        .and_then(|v| v.as_dictionary())
        .and_then(|t| t.get("cloudKitToken"))
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    if cloudkit_token.is_empty() {
        return Err(Error::Apple(
            "the account settings carried no CloudKit token".into(),
        ));
    }

    // The container open hands out the per-container user id.
    let cloudkit_user_id = icloud::ck_app_init(
        &delegates.dsid,
        &delegates.mme_auth_token,
        icloud::KEYCHAIN_CONTAINER,
        device,
        anisette,
    )?;
    webservices.insert("ckdatabasews".to_string(), String::new());

    Ok(Login {
        dsid: delegates.dsid,
        mme_auth_token: delegates.mme_auth_token,
        cloudkit_token,
        webservices,
        cloudkit_user_id,
        password: None,
    })
}

/// The account and identity tokens from the server provisioning data.
fn spd_identity(spd: &plist::Value) -> Result<(String, String)> {
    let dict = spd
        .as_dictionary()
        .ok_or_else(|| Error::Apple("the account data was not a dictionary".into()))?;
    let dsid = dict
        .get("adsid")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    let idms = dict
        .get("GsIdmsToken")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    if dsid.is_empty() || idms.is_empty() {
        return Err(Error::Apple(
            "the account data carried no identity token".into(),
        ));
    }
    Ok((dsid, idms))
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
    // The terminal echoed it; there is no getpass in the standard library.
    println!();
    secret
}
