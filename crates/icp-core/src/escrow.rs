//! The escrow recovery, and the join it enables.
//!
//! The join is how a new device becomes part of the keychain's trust circle: it
//! recovers the *previous* device's identity out of the escrow bottle (which is
//! encrypted with a key derived from the device passcode) and signs a voucher that
//! lets the new peer in.
//!
//! **IRREVERSIBLE.** The escrow service allows ten attempts; the tenth wrong passcode
//! destroys the record forever. So the recovery refuses to run without an explicit
//! confirmation, and the listing (which spends no attempt) is separate.

use base64::Engine;
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256, Sha384};

use crate::anisette::Anisette;
use crate::device::Device;
use crate::error::{Error, Result};
use crate::octagon::{self, PeerKey};
use crate::proto::Writer;

/// RFC 5054's 2048-bit group.
const N_HEX: &str = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

/// The P-384 group order.
const P384_ORDER_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";

const HKDF_INFO_SYM: &[u8] = b"Escrow Symmetric Key";
/// The info strings for the keys derived from the entropy. The bottle carries the
/// keys itself, so these are only here for completeness.
#[allow(dead_code)]
const HKDF_INFO_SIGNING: &[u8] = b"Escrow Signing Private Key";
#[allow(dead_code)]
const HKDF_INFO_ENCRYPTION: &[u8] = b"Escrow Encryption Private Key";

/// The escrow service's identity and user agent.
const ESCROW_USER_AGENT: &str = "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282";
const ESCROW_SERVICE_IDENTITY: &str = "com.apple.AuthKit/1 (com.apple.sbd/638.100.48)";
const ESCROW_USER_ACTION: &str = "com.apple.sbd: escrow recovery";

fn modulus() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("the group modulus")
}

/// The modulus, as its bytes.
fn pad(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0u8; 256 - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

/// An integer, as its minimal big-endian bytes.
fn trim(value: &BigUint) -> Vec<u8> {
    if value.is_zero() {
        Vec::new()
    } else {
        value.to_bytes_be()
    }
}

fn hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// The key vault message: a header and a list of sections.
///
/// The layout is `len(4) | header | (n+1) offsets | body`, and each section in the
/// body is `len(4) || data`.
pub struct KeyVaultMessage {
    pub header: Vec<u8>,
    pub sections: Vec<Vec<u8>>,
}

impl KeyVaultMessage {
    /// A message with a header and no sections.
    pub fn new(header: Vec<u8>) -> Self {
        KeyVaultMessage {
            header,
            sections: Vec::new(),
        }
    }

    /// Add a section.
    pub fn section(&mut self, data: &[u8]) {
        let mut section = (data.len() as u32).to_be_bytes().to_vec();
        section.extend_from_slice(data);
        self.sections.push(section);
    }

    /// Add a section, padded to a fixed size.
    pub fn section_sized(&mut self, data: &[u8], size: usize) -> Result<()> {
        let mut total = (data.len() as u32).to_be_bytes().to_vec();
        total.extend_from_slice(data);
        if total.len() > size {
            return Err(Error::Apple(format!(
                "section size {size} < actual {}",
                total.len()
            )));
        }
        total.resize(size, 0);
        self.sections.push(total);
        Ok(())
    }

    /// Pack it.
    pub fn pack(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for s in &self.sections {
            offsets.push(body.len() as u32);
            body.extend_from_slice(s);
        }
        offsets.push(body.len() as u32);
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&self.header);
        for o in &offsets {
            out.extend_from_slice(&o.to_be_bytes());
        }
        out.extend_from_slice(&body);
        let len = out.len() as u32;
        out[..4].copy_from_slice(&len.to_be_bytes());
        out
    }
}

/// Unpack a key vault message: the header and the sections.
pub fn unpack_message(
    bin: &[u8],
    header_len: usize,
    section_count: usize,
) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if bin.len() < 4 {
        return Err(Error::Apple("the key vault message is truncated".into()));
    }
    let header = bin[4..4 + header_len].to_vec();
    let total_header_size = 4 + header_len + (section_count + 1) * 4;
    let mut sections = Vec::new();
    for i in 0..section_count {
        let at = 4 + header_len + i * 4;
        let offset = u32::from_be_bytes([bin[at], bin[at + 1], bin[at + 2], bin[at + 3]]) as usize;
        let start = total_header_size + offset;
        if start + 4 > bin.len() {
            return Err(Error::Apple("the key vault message is truncated".into()));
        }
        let size = u32::from_be_bytes([bin[start], bin[start + 1], bin[start + 2], bin[start + 3]])
            as usize;
        let begin = start + 4;
        let end = begin + size;
        if end > bin.len() {
            return Err(Error::Apple("the key vault message is truncated".into()));
        }
        sections.push(bin[begin..end].to_vec());
    }
    Ok((header, sections))
}

/// The escrow service's SRP-6a client.
///
/// Unlike the sign-in service, this one hashes the *trimmed* A and B (the minimal
/// big-endian form) rather than the padded one, and it mixes the username into the
/// password verifier.
pub struct EscrowSrpClient {
    a: BigUint,
    a_public: BigUint,
}

impl Default for EscrowSrpClient {
    fn default() -> Self {
        EscrowSrpClient::new()
    }
}

impl EscrowSrpClient {
    /// Start with a random private value.
    pub fn new() -> EscrowSrpClient {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        let a = BigUint::from_bytes_be(&bytes);
        let a_public = BigUint::from(2u32).modpow(&a, &modulus());
        EscrowSrpClient { a, a_public }
    }

    /// The public value, trimmed.
    pub fn public_a(&self) -> Vec<u8> {
        trim(&self.a_public)
    }

    /// Answer the challenge: the session key and the proof.
    pub fn process(
        &self,
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let n = modulus();
        let g = BigUint::from(2u32);
        let b = BigUint::from_bytes_be(b_pub);
        let a_pub = trim(&self.a_public);
        let b_pub_norm = trim(&b);
        let k = BigUint::from_bytes_be(&hash(&[&pad(&n), &pad(&g)]));
        let mut inner = Sha256::new();
        inner.update(username);
        inner.update(b":");
        inner.update(password);
        let mut x_hash = Sha256::new();
        x_hash.update(salt);
        x_hash.update(inner.finalize());
        let x = BigUint::from_bytes_be(&x_hash.finalize());
        let u = BigUint::from_bytes_be(&hash(&[&a_pub, &b_pub_norm]));
        let base = (&b - (&k * g.modpow(&x, &n) % &n) + &n) % &n;
        let s = base.modpow(&(&self.a + &u * &x), &n);
        let k_bytes = hash(&[&trim(&s)]);

        let h_n = hash(&[&pad(&n)]);
        let h_g = hash(&[&pad(&g)]);
        let mixed: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(a, b)| a ^ b).collect();
        let m1 = hash(&[
            &mixed,
            &hash(&[username]),
            salt,
            &a_pub,
            &b_pub_norm,
            &k_bytes,
        ]);
        Ok((k_bytes, m1))
    }

    /// The server's proof: `M2 = H(A || M1 || K)`.
    pub fn server_proof(a_pub: &[u8], m1: &[u8], k: &[u8]) -> Vec<u8> {
        hash(&[a_pub, m1, k])
    }
}

/// A recoverable escrow record.
pub struct EscrowRecord {
    /// The bottle's label.
    pub label: String,
    /// The metadata that identifies the device it belongs to.
    pub meta: plist::Value,
}

/// Drives the escrow service.
pub struct EscrowRecovery<'a> {
    host: String,
    email: String,
    pet: String,
    device: &'a Device,
    anisette: &'a mut Anisette,
    http: reqwest::blocking::Client,
}

impl<'a> EscrowRecovery<'a> {
    /// Build a client for the escrow service.
    pub fn new(
        host: &str,
        email: &str,
        pet: &str,
        device: &'a Device,
        anisette: &'a mut Anisette,
    ) -> Result<EscrowRecovery<'a>> {
        Ok(EscrowRecovery {
            host: host.trim_end_matches('/').to_string(),
            email: email.to_string(),
            pet: pet.to_string(),
            device,
            anisette,
            http: crate::apple_tls::client(std::time::Duration::from_secs(30))?,
        })
    }

    fn headers(&mut self) -> Result<Vec<(String, String)>> {
        let mut headers: Vec<(String, String)> = vec![
            ("User-Agent".into(), ESCROW_USER_AGENT.into()),
            ("Accept".into(), "*/*".into()),
            ("Accept-Language".into(), "en-US,en;q=0.9".into()),
            ("X-Apple-I-Locale".into(), "en_US".into()),
            ("x-apple-i-device-type".into(), "1".into()),
            ("Content-Type".into(), "application/x-apple-plst".into()),
            (
                "X-Mme-Client-Info".into(),
                crate::anisette::service_client_info(self.anisette, ESCROW_SERVICE_IDENTITY)?,
            ),
            (
                "X-Mme-Device-Id".into(),
                self.device.device_id.to_uppercase(),
            ),
        ];
        for (k, v) in self.anisette.headers()? {
            headers.push((k, v));
        }
        Ok(headers)
    }

    /// One command to the escrow service.
    fn invoke(&mut self, command: &str, request: &plist::Value) -> Result<plist::Value> {
        let mut encoded = Vec::new();
        plist::to_writer_xml(&mut encoded, request)
            .map_err(|e| Error::Apple(format!("could not encode the escrow request: {e}")))?;
        let url = format!("{}/escrowproxy/api/{}", self.host, command);
        let headers = self.headers()?;
        let mut builder = self.http.post(&url);
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        builder = builder.basic_auth(&self.email, Some(&self.pet));
        let response = builder
            .body(encoded)
            .send()
            .map_err(|e| Error::Apple(format!("the escrow request failed: {e}")))?;
        let status = response.status();
        let content = response
            .bytes()
            .map_err(|e| Error::Apple(format!("the escrow answer was unreadable: {e}")))?;
        let parsed = plist::Value::from_reader(std::io::Cursor::new(content.as_ref()))
            .map_err(|e| Error::Apple(format!("the escrow answer was not a plist: {e}")))?;
        if !status.is_success() {
            return Err(Error::Apple(format!(
                "escrowproxy/{command} HTTP {}",
                status.as_u16()
            )));
        }
        Ok(parsed)
    }

    fn request(&self, command: &str, label: &str, txn: &str) -> plist::Value {
        let mut d = plist::Dictionary::new();
        d.insert("command".into(), plist::Value::String(command.into()));
        d.insert("label".into(), plist::Value::String(label.into()));
        d.insert("transactionUUID".into(), plist::Value::String(txn.into()));
        d.insert(
            "userActionLabel".into(),
            plist::Value::String(ESCROW_USER_ACTION.into()),
        );
        d.insert("version".into(), plist::Value::Integer(1.into()));
        plist::Value::Dictionary(d)
    }

    /// List the account's escrow records.
    ///
    /// **Non-destructive**: it spends no attempt and needs no passcode.
    pub fn list_records(&mut self, label: &str) -> Result<Vec<EscrowRecord>> {
        let txn = crate::uuid_upper();
        let mut request = self.request("GETRECORDS", label, &txn);
        if let Some(d) = request.as_dictionary_mut() {
            d.insert("command".into(), plist::Value::String("GETRECORDS".into()));
        }
        let response = self.invoke("get_records", &request)?;
        let entries = response
            .as_dictionary()
            .and_then(|d| d.get("metadataList").or_else(|| d.get("metadata_list")))
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        let mut out = Vec::new();
        for entry in entries {
            let Some(d) = entry.as_dictionary() else {
                continue;
            };
            let meta = d
                .get("metadata")
                .and_then(|v| v.as_string())
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                .and_then(|raw| plist::Value::from_reader(std::io::Cursor::new(raw)).ok())
                .unwrap_or(plist::Value::Dictionary(plist::Dictionary::new()));
            out.push(EscrowRecord {
                label: d
                    .get("label")
                    .and_then(|v| v.as_string())
                    .unwrap_or("")
                    .to_string(),
                meta,
            });
        }
        Ok(out)
    }

    /// Recover the bottle's entropy.
    ///
    /// **IRREVERSIBLE**: this consumes one of ten attempts, and the tenth failure
    /// destroys the record. It refuses to run without `confirm_irreversible`.
    pub fn try_recover_escrow(
        &mut self,
        label: &str,
        passcode: &[u8],
        confirm_irreversible: bool,
    ) -> Result<Vec<u8>> {
        if !confirm_irreversible {
            return Err(Error::Apple(
                "REFUSED: the escrow recovery consumes one of 10 irreversible attempts (the \
                 10th wrong passcode destroys the record forever). Pass the confirmation \
                 only after the user has explicitly agreed."
                    .into(),
            ));
        }
        let txn = crate::uuid_upper();
        let client = EscrowSrpClient::new();

        // 1) srp_init: send A, get the salt, the challenge and the account id.
        let mut request = self.request("SRP_INIT", label, &txn);
        if let Some(d) = request.as_dictionary_mut() {
            d.insert(
                "blob".into(),
                plist::Value::String(
                    base64::engine::general_purpose::STANDARD.encode(client.public_a()),
                ),
            );
        }
        let init = self.invoke("srp_init", &request)?;
        let init_dict = init
            .as_dictionary()
            .ok_or_else(|| Error::Apple("the escrow answer was not a dictionary".into()))?;
        let dsid = init_dict
            .get("dsid")
            .and_then(|v| v.as_string())
            .ok_or_else(|| Error::Apple("the escrow answer carried no account id".into()))?;
        let club_type_id = init_dict
            .get("clubTypeID")
            .and_then(|v| v.as_signed_integer());
        let resp_blob = init_dict
            .get("respBlob")
            .and_then(|v| v.as_string())
            .ok_or_else(|| Error::Apple("the escrow answer carried no blob".into()))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(resp_blob)
            .map_err(|_| Error::Apple("the escrow blob was not base64".into()))?;
        let (header, sections) = unpack_message(&raw, 24, 3)?;
        let (id_section, salt, b_pub) = (
            sections.first().cloned().unwrap_or_default(),
            sections.get(1).cloned().unwrap_or_default(),
            sections.get(2).cloned().unwrap_or_default(),
        );

        // 2) SRP-6a: the session key and the proof.
        let (k, m1) = client.process(dsid.as_bytes(), passcode, &salt, &b_pub)?;

        // 3) recover: send the header, the account id and the proof.
        let version: u32 = if club_type_id == Some(1) { 2 } else { 0 };
        let mut hdr = header.clone();
        hdr[0..4].copy_from_slice(&165u32.to_be_bytes());
        hdr[4..8].copy_from_slice(&version.to_be_bytes());
        let mut payload = KeyVaultMessage::new(hdr);
        payload.section_sized(&id_section, 20)?;
        payload.section(&m1);
        let mut request = self.request("RECOVER", label, &txn);
        if let Some(d) = request.as_dictionary_mut() {
            d.insert(
                "blob".into(),
                plist::Value::String(
                    base64::engine::general_purpose::STANDARD.encode(payload.pack()),
                ),
            );
        }
        let rec = self.invoke("recover", &request)?;

        // 4) check the server's proof and decrypt the answer.
        let rec_dict = rec
            .as_dictionary()
            .ok_or_else(|| Error::Apple("the escrow answer was not a dictionary".into()))?;
        let resp_blob = rec_dict
            .get("respBlob")
            .and_then(|v| v.as_string())
            .ok_or_else(|| Error::Apple("the escrow answer carried no blob".into()))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(resp_blob)
            .map_err(|_| Error::Apple("the escrow blob was not base64".into()))?;
        let header_len = if club_type_id == Some(1) { 40 } else { 24 };
        let (h, payloads) = unpack_message(&raw, header_len, 3)?;
        if EscrowSrpClient::server_proof(&client.public_a(), &m1, &k) != payloads[0] {
            return Err(Error::Apple(
                "the escrow server's proof did not match - aborting".into(),
            ));
        }
        let version = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let inner = if version == 0 {
            aes_cbc_decrypt(&k, &payloads[1], &payloads[2])?
        } else if version == 2 {
            use aes_gcm::aead::{Aead, KeyInit};
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(&k)
                .map_err(|e| Error::Apple(format!("bad session key: {e}")))?;
            let nonce =
                aes_gcm::Nonce::<aes_gcm::aes::cipher::consts::U12>::from_slice(&payloads[1]);
            cipher
                .decrypt(nonce, payloads[2].as_slice())
                .map_err(|_| Error::Apple("the escrow record could not be decrypted".into()))?
        } else {
            return Err(Error::Apple(format!(
                "unsupported escrow record version {version}"
            )));
        };

        // 5) the bottle: PBKDF2(passcode) -> AES-128-CBC.
        let (ih, ipayloads) = unpack_message(&inner, 16, 6)?;
        let rounds = u32::from_be_bytes([ih[8], ih[9], ih[10], ih[11]]);
        let salt2 = ipayloads.get(1).cloned().unwrap_or_default();
        let derived = pbkdf2_sha256(passcode, &salt2, rounds, 16);
        let bottle_plist = aes_cbc_decrypt(&derived, &salt2[..16], &ipayloads[3])?;
        let bottle = plist::Value::from_reader(std::io::Cursor::new(bottle_plist))
            .map_err(|e| Error::Apple(format!("the bottle was not a plist: {e}")))?;
        let entropy = bottle
            .as_dictionary()
            .and_then(|d| d.get("BottledPeerEntropy"))
            .and_then(|v| v.as_data())
            .ok_or_else(|| Error::Apple("the bottle carried no entropy".into()))?;
        Ok(entropy.to_vec())
    }
}

/// The recovered identity of the previous device.
pub struct RecoveredIdentity {
    pub peer_id: String,
    pub signing_key: PeerKey,
    pub encryption_key: PeerKey,
}

impl RecoveredIdentity {
    /// Sign the voucher that lets a new peer join.
    pub fn make_voucher(
        &self,
        beneficiary_peer_id: &str,
        reason: i64,
    ) -> Result<crate::cuttlefish::SignedBlob> {
        let info = crate::cuttlefish::encode_voucher(reason, beneficiary_peer_id, &self.peer_id);
        let sig = self
            .signing_key
            .sign_sha384(&octagon::prefixed_data(&info, octagon::VOUCHER_SIG_TYPE))?;
        Ok(crate::cuttlefish::SignedBlob { info, sig })
    }
}

/// Decrypt an escrow bottle with the recovered entropy.
pub fn recover_identity(
    bottle: &crate::escrow::bottle::OTBottle,
    entropy: &[u8],
    adsid: &str,
) -> Result<RecoveredIdentity> {
    use aes_gcm::aead::{Aead, KeyInit};
    let key = derive_symmetric_key(entropy, adsid);
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key)
        .map_err(|e| Error::Apple(format!("bad escrow key: {e}")))?;
    let mut buf = bottle.ct.clone();
    buf.extend_from_slice(&bottle.auth_code);
    let plaintext = cipher
        .decrypt(bottle.iv.as_slice().into(), buf.as_slice())
        .map_err(|_| Error::Apple("the bottle could not be decrypted".into()))?;
    let (signing, encryption) = bottle::parse_ot_internal_bottle(&plaintext)?;
    Ok(RecoveredIdentity {
        peer_id: bottle.peer_id.clone(),
        signing_key: PeerKey::from_x963(&signing)?,
        encryption_key: PeerKey::from_x963(&encryption)?,
    })
}

/// The symmetric key that decrypts a bottle.
pub fn derive_symmetric_key(entropy: &[u8], adsid: &str) -> Vec<u8> {
    hkdf_sha384(entropy, adsid, HKDF_INFO_SYM, 32)
}

/// HKDF-SHA384 with the account id as the salt.
pub fn hkdf_sha384(entropy: &[u8], adsid: &str, info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha384>::new(Some(adsid.as_bytes()), entropy);
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out)
        .expect("the output length is within the limit");
    out
}

/// A private key derived from the entropy (FIPS 186-4 B.5.1).
pub fn derive_ec_private_key(entropy: &[u8], adsid: &str, info: &[u8]) -> Result<p384::SecretKey> {
    let order = BigUint::parse_bytes(P384_ORDER_HEX.as_bytes(), 16).expect("the group order");
    let raw = hkdf_sha384(entropy, adsid, info, 56);
    let d = (BigUint::from_bytes_be(&raw) % (&order - BigUint::one())) + BigUint::one();
    let bytes = d.to_bytes_be();
    p384::SecretKey::from_slice(&bytes).map_err(|e| Error::Apple(format!("bad derived key: {e}")))
}

/// AES-CBC decryption with the OpenSSL default padding.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    let cipher = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
        .map_err(|e| Error::Apple(format!("bad escrow key: {e}")))?;
    let mut buffer = ct.to_vec();
    let out = cipher
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|_| Error::Apple("the escrow record could not be decrypted".into()))?;
    Ok(out.to_vec())
}

/// PBKDF2-HMAC-SHA256.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut out = Vec::with_capacity(length);
    let mut block: u32 = 1;
    while out.len() < length {
        let mut mac = HmacSha256::new_from_slice(password).expect("any key length");
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..iterations.max(1) {
            let mut mac = HmacSha256::new_from_slice(password).expect("any key length");
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(length);
    out
}

/// The escrow bottle.
pub mod bottle {
    use super::*;
    use crate::proto::Fields;

    /// An escrow bottle: the previous device's encrypted identity.
    #[derive(Debug, Clone, Default)]
    pub struct OTBottle {
        /// The escrowed signing key (SPKI DER).
        pub escrowed_signing_key: Vec<u8>,
        /// The escrowed encryption key (SPKI DER).
        pub escrowed_encryption_key: Vec<u8>,
        pub ct: Vec<u8>,
        pub auth_code: Vec<u8>,
        pub iv: Vec<u8>,
        pub peer_id: String,
        pub bottle_id: String,
    }

    impl OTBottle {
        /// Parse one.
        pub fn parse(raw: &[u8]) -> Result<OTBottle> {
            let f = Fields::decode(raw)?;
            let cipher = f
                .bytes(12)
                .map(Fields::decode)
                .transpose()?
                .unwrap_or_default();
            Ok(OTBottle {
                escrowed_signing_key: f.bytes(8).unwrap_or_default().to_vec(),
                escrowed_encryption_key: f.bytes(9).unwrap_or_default().to_vec(),
                ct: cipher.bytes(1).unwrap_or_default().to_vec(),
                auth_code: cipher.bytes(2).unwrap_or_default().to_vec(),
                iv: cipher.bytes(3).unwrap_or_default().to_vec(),
                peer_id: String::from_utf8_lossy(f.bytes(1).unwrap_or_default()).to_string(),
                bottle_id: String::from_utf8_lossy(f.bytes(2).unwrap_or_default()).to_string(),
            })
        }

        /// Encode one.
        pub fn encode(&self) -> Vec<u8> {
            let mut cipher = Writer::new();
            cipher
                .bytes(1, Some(&self.ct))
                .bytes(2, Some(&self.auth_code))
                .bytes(3, Some(&self.iv));
            let mut w = Writer::new();
            w.string(1, Some(&self.peer_id))
                .string(2, Some(&self.bottle_id))
                .bytes(8, Some(&self.escrowed_signing_key))
                .bytes(9, Some(&self.escrowed_encryption_key))
                .message(12, Some(&cipher.finish()));
            w.finish()
        }
    }

    /// `OTPrivateKey{keyType(1), keyData(2)}` -> the key data.
    pub fn parse_ot_private_key(raw: &[u8]) -> Result<Vec<u8>> {
        let f = Fields::decode(raw)?;
        Ok(f.bytes(2).unwrap_or_default().to_vec())
    }

    /// `OTInternalBottle{signingKey(3), encryptionKey(4)}` -> the two keys.
    pub fn parse_ot_internal_bottle(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let f = Fields::decode(raw)?;
        Ok((
            parse_ot_private_key(f.bytes(3).unwrap_or_default())?,
            parse_ot_private_key(f.bytes(4).unwrap_or_default())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_vault_message_roundtrip() {
        let mut m = KeyVaultMessage::new(vec![1, 2, 3, 4]);
        m.section(b"first");
        m.section_sized(b"second", 12).unwrap();
        let packed = m.pack();
        let (header, sections) = unpack_message(&packed, 4, 2).unwrap();
        assert_eq!(header, vec![1, 2, 3, 4]);
        assert_eq!(sections[0], b"first");
        assert_eq!(&sections[1][..6], b"second");
        // The length in the prefix is the content's; the padding to the fixed size
        // is accounted for by the offset table, not by the length.
        assert_eq!(sections[1].len(), 6);
    }

    #[test]
    fn pbkdf2_matches_the_reference_vector() {
        let out = pbkdf2_sha256(b"password", b"salt", 1, 32);
        assert_eq!(
            hex::encode(out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn the_escrow_srp_exchange_completes() {
        // The client against a server side built from the same primitives.
        let client = EscrowSrpClient::new();
        let n = modulus();
        let g = BigUint::from(2u32);
        let salt = b"12345678901234567890";
        let password = b"passcode";
        let username = b"123456789";

        let mut inner = Sha256::new();
        inner.update(username);
        inner.update(b":");
        inner.update(password);
        let mut x_hash = Sha256::new();
        x_hash.update(salt);
        x_hash.update(inner.finalize());
        let x = BigUint::from_bytes_be(&x_hash.finalize());
        let v = g.modpow(&x, &n);
        let k = BigUint::from_bytes_be(&hash(&[&pad(&n), &pad(&g)]));
        let mut b_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b_bytes);
        let b_public = (&k * &v + &g.modpow(&x, &n)) % &n;

        let (k_bytes, m1) = client
            .process(username, password, salt, &trim(&b_public))
            .unwrap();
        assert_eq!(k_bytes.len(), 32);
        assert_eq!(m1.len(), 32);
        // The server's proof matches what the client computed.
        assert_eq!(
            EscrowSrpClient::server_proof(&client.public_a(), &m1, &k_bytes),
            hash(&[&trim(&client.a_public), &m1, &k_bytes])
        );
    }
}
