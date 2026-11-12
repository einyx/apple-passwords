//! The sign-in: Apple's GrandSlam service (SRP-6a) and the 2FA factors.
//!
//! The password never leaves the machine in the clear: it is hashed, stretched
//! with PBKDF2 over a salt the server sends, and only the stretched form goes
//! into the SRP verifier.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::anisette::Anisette;
use crate::device::Device;
use crate::error::{Error, Result};
use crate::srp::{stretch_password, SrpClient};

/// Apple's GrandSlam endpoint.
pub const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";
/// The client identity the sign-in presents.
pub const XCODE_VERSION: &str = "14310";

type HmacSha256 = Hmac<Sha256>;

/// The decrypted server provisioning data.
pub type Spd = plist::Value;

/// The client for Apple's sign-in service.
pub struct GsaClient<'a> {
    device: &'a Device,
    anisette: &'a mut Anisette,
    http: reqwest::blocking::Client,
}

impl<'a> GsaClient<'a> {
    /// Build a client.
    pub fn new(device: &'a Device, anisette: &'a mut Anisette) -> Result<GsaClient<'a>> {
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| Error::Apple(format!("could not build the sign-in client: {e}")))?;
        Ok(GsaClient {
            device,
            anisette,
            http,
        })
    }

    /// The machine data the sign-in carries.
    fn cpd(&self) -> Result<plist::Value> {
        let mut cpd = plist::Dictionary::new();
        cpd.insert("bootstrap".into(), plist::Value::Boolean(true));
        cpd.insert("icscrec".into(), plist::Value::Boolean(true));
        cpd.insert("pbe".into(), plist::Value::Boolean(false));
        cpd.insert("prkgen".into(), plist::Value::Boolean(true));
        cpd.insert("svct".into(), plist::Value::String("iCloud".into()));
        // The device's own identity.
        cpd.insert(
            "X-Apple-I-Client-Time".into(),
            plist::Value::String(crate::now_rfc3339()),
        );
        cpd.insert(
            "X-Apple-I-TimeZone".into(),
            plist::Value::String("UTC".into()),
        );
        cpd.insert(
            "X-Mme-Device-Id".into(),
            plist::Value::String(self.device.device_id.to_uppercase()),
        );
        cpd.insert(
            "X-Apple-I-SRL-NO".into(),
            plist::Value::String(self.device.serial.clone()),
        );
        cpd.insert(
            "X-Apple-I-MD-LU".into(),
            plist::Value::String(
                base64::engine::general_purpose::STANDARD
                    .encode(self.device.local_user_uuid.to_uppercase()),
            ),
        );
        cpd.insert(
            "X-Apple-I-MD-RINFO".into(),
            plist::Value::String("17106176".into()),
        );
        // The anisette machine data.
        for (key, value) in self.anisette.headers()? {
            cpd.insert(key, plist::Value::String(value));
        }
        Ok(plist::Value::Dictionary(cpd))
    }

    /// One request to the sign-in service.
    fn request(&mut self, parameters: Vec<(String, plist::Value)>) -> Result<plist::Value> {
        let mut request = plist::Dictionary::new();
        request.insert("cpd".into(), self.cpd()?);
        for (key, value) in parameters {
            request.insert(key, value);
        }
        let mut body = plist::Dictionary::new();
        let mut header = plist::Dictionary::new();
        header.insert("Version".into(), plist::Value::String("1.0.1".into()));
        body.insert("Header".into(), plist::Value::Dictionary(header));
        body.insert("Request".into(), plist::Value::Dictionary(request));

        let mut encoded = Vec::new();
        plist::to_writer_xml(&mut encoded, &plist::Value::Dictionary(body))
            .map_err(|e| Error::Apple(format!("could not encode the sign-in request: {e}")))?;

        let mut headers: std::collections::BTreeMap<String, String> = Default::default();
        headers.insert("Content-Type".into(), "text/x-xml-plist".into());
        headers.insert("Accept".into(), "*/*".into());
        headers.insert("Connection".into(), "close".into());
        headers.insert("User-Agent".into(), self.anisette.user_agent()?);
        headers.insert(
            "X-Mme-Client-Info".into(),
            self.anisette.client_info_string()?,
        );

        let response = self
            .http
            .post(GSA_ENDPOINT)
            .headers(crate::header_map(headers))
            .body(encoded)
            .send()
            .map_err(|e| Error::Apple(format!("the sign-in request failed: {e}")))?;
        let status = response.status();
        let content = response
            .bytes()
            .map_err(|e| Error::Apple(format!("the sign-in answer was unreadable: {e}")))?;
        let payload = plist::Value::from_reader(std::io::Cursor::new(content.as_ref()))
            .map_err(|e| Error::Apple(format!("the sign-in answer was not a plist: {e}")))?;
        let response_dict = payload
            .as_dictionary()
            .and_then(|d| d.get("Response"))
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| Error::Apple("the sign-in answer had no Response".into()))?;
        if !status.is_success() {
            let ec = response_dict
                .get("Status")
                .and_then(|s| s.as_dictionary())
                .and_then(|s| s.get("ec"))
                .and_then(|v| v.as_signed_integer())
                .unwrap_or(0);
            let em = response_dict
                .get("Status")
                .and_then(|s| s.as_dictionary())
                .and_then(|s| s.get("em"))
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string();
            return Err(Error::Apple(format!(
                "the sign-in failed (HTTP {}, ec={ec}): {em}",
                status.as_u16()
            )));
        }
        Ok(plist::Value::Dictionary(response_dict.clone()))
    }

    /// The sign-in: SRP, and (when Apple asks) the 2FA is left to the caller.
    ///
    /// Returns the raw response (which says whether a 2FA factor is needed) and the
    /// decrypted server provisioning data.
    pub fn authenticate(&mut self, username: &str, password: &str) -> Result<(plist::Value, Spd)> {
        let mut client = SrpClient::new(username);
        let init = self.request(vec![
            ("A2k".into(), plist::Value::Data(client.a_public_bytes())),
            (
                "ps".into(),
                plist::Value::Array(vec![
                    plist::Value::String("s2k".into()),
                    plist::Value::String("s2k_fo".into()),
                ]),
            ),
            ("u".into(), plist::Value::String(username.into())),
            ("o".into(), plist::Value::String("init".into())),
        ])?;

        let dict = init
            .as_dictionary()
            .ok_or_else(|| Error::Apple("the sign-in answer was not a dictionary".into()))?;
        let salt = dict
            .get("s")
            .and_then(|v| v.as_data())
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Apple("the sign-in answer carried no salt".into()))?;
        let iterations = dict
            .get("i")
            .and_then(|v| v.as_signed_integer())
            .unwrap_or(1) as u32;
        let protocol = dict
            .get("sp")
            .and_then(|v| v.as_string())
            .unwrap_or("s2k")
            .to_string();
        let challenge = dict
            .get("B")
            .and_then(|v| v.as_data())
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Apple("the sign-in answer carried no challenge".into()))?;
        let c = dict.get("c").cloned();

        // The password is stretched with the server's salt, and the stretched form
        // is what the verifier is built from.
        let stretched = stretch_password(password, &salt, iterations, &protocol);
        client.process_challenge(&salt, &challenge, &stretched)?;

        let mut parameters = vec![
            ("M1".into(), plist::Value::Data(client.m.clone())),
            ("u".into(), plist::Value::String(username.into())),
            ("o".into(), plist::Value::String("complete".into())),
        ];
        if let Some(c) = c {
            parameters.insert(0, ("c".into(), c));
        }
        let complete = self.request(parameters)?;

        let complete_dict = complete
            .as_dictionary()
            .ok_or_else(|| Error::Apple("the sign-in answer was not a dictionary".into()))?;
        let proof = complete_dict
            .get("M2")
            .and_then(|v| v.as_data())
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Apple("the sign-in answer carried no proof".into()))?;
        if !client.verify_session(&proof) {
            return Err(Error::Apple(
                "the server's session proof did not match - the sign-in was not accepted".into(),
            ));
        }
        let spd = complete_dict
            .get("spd")
            .and_then(|v| v.as_data())
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Apple("the sign-in answer carried no account data".into()))?;
        let spd = decrypt_spd(&client.session_key, &spd)?;
        Ok((complete, spd))
    }
}

/// Decrypt the server provisioning data.
///
/// The session key derives the AES key and the IV by HMAC, and the data is
/// AES-CBC with PKCS#7 padding.
pub fn decrypt_spd(session_key: &[u8], data: &[u8]) -> Result<Spd> {
    let key = hmac_sha256(session_key, b"extra data key:");
    let iv = hmac_sha256(session_key, b"extra data iv:")[..16].to_vec();
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    let cipher = cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv)
        .map_err(|e| Error::Apple(format!("bad session key: {e}")))?;
    let mut buffer = data.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|_| Error::Apple("the account data could not be decrypted".into()))?;
    plist::Value::from_reader(std::io::Cursor::new(plaintext))
        .map_err(|e| Error::Apple(format!("the account data was not a plist: {e}")))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// The PET (a password-equivalent token) from the server provisioning data.
pub fn extract_pet(spd: &Spd) -> Result<(String, String, Option<i64>)> {
    let dict = spd
        .as_dictionary()
        .ok_or_else(|| Error::Apple("the account data was not a dictionary".into()))?;
    let dsid = dict
        .get("adsid")
        .or_else(|| dict.get("DsPrsId"))
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    let pet = dict
        .get("t")
        .and_then(|v| v.as_dictionary())
        .and_then(|t| t.get("com.apple.gs.idms.pet"))
        .and_then(|v| v.as_dictionary())
        .and_then(|p| p.get("token"))
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    let expiry = dict
        .get("t")
        .and_then(|v| v.as_dictionary())
        .and_then(|t| t.get("com.apple.gs.idms.pet"))
        .and_then(|v| v.as_dictionary())
        .and_then(|p| p.get("expiry"))
        .and_then(|v| v.as_signed_integer());
    if dsid.is_empty() || pet.is_empty() {
        return Err(Error::Apple("the account data carried no token".into()));
    }
    Ok((dsid, pet, expiry))
}

/// Whether the sign-in answer says a second factor is needed.
pub fn two_factor_needed(response: &plist::Value) -> Option<&'static str> {
    let status = response
        .as_dictionary()
        .and_then(|d| d.get("Status"))
        .and_then(|s| s.as_dictionary())?;
    let au = status.get("au").and_then(|v| v.as_string());
    let hsc = status.get("hsc").and_then(|v| v.as_signed_integer());
    if au == Some("secondaryAuth") {
        return Some("sms");
    }
    if au == Some("trustedDeviceSecondaryAuth") {
        // A 409 without a mode means Apple already sent a trusted-device code.
        return Some("trusted");
    }
    let _ = hsc;
    None
}
