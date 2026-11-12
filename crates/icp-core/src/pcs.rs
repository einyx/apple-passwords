//! Protected Cloud Storage: the crypto behind the shared password groups.
//!
//! A shared group is a CloudKit zone whose records are encrypted under keys that the
//! members hold. The keys come in two layers: a "share protection" structure that
//! wraps the zone's master key to the members' service keys, and per-record keys
//! derived from it.
//!
//! The formats are DER (`ShareProtection`) and a compact PCS ciphertext (version 3).

use hmac::{Hmac, Mac};
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// The DER tag classes.
const UNIVERSAL: u8 = 0;
const APPLICATION: u8 = 1;
const CONTEXT: u8 = 2;

/// A DER node.
#[derive(Debug, Clone)]
pub struct Node {
    pub class: u8,
    pub constructed: bool,
    pub tag: u8,
    /// The content.
    pub value: Vec<u8>,
    /// The encoded TLV.
    pub raw: Vec<u8>,
}

impl Node {
    /// The nodes inside.
    pub fn children(&self) -> Result<Vec<Node>> {
        parse_all(&self.value)
    }

    /// The content of an EXPLICIT tag: the single TLV inside.
    pub fn unwrap(&self) -> Result<Node> {
        let kids = self.children()?;
        if kids.len() != 1 {
            return Err(Error::Crypto(format!(
                "explicit tag holds {} elements",
                kids.len()
            )));
        }
        Ok(kids.into_iter().next().unwrap())
    }

    /// The node's content as an integer.
    pub fn int(&self) -> i64 {
        let mut v: i64 = 0;
        for b in &self.value {
            v = (v << 8) | (*b as i64);
        }
        // two's complement, for the lengths and versions
        let bits = (self.value.len() * 8) as u32;
        if bits < 64 && (v >> (bits - 1)) & 1 == 1 {
            v - (1i64 << bits)
        } else {
            v
        }
    }
}

/// Parse one TLV.
fn parse_one(buf: &[u8], pos: usize) -> Result<(Node, usize)> {
    let start = pos;
    if pos + 2 > buf.len() {
        return Err(Error::Crypto("truncated DER".into()));
    }
    let b = buf[pos];
    let class = b >> 6;
    let constructed = b & 0x20 != 0;
    let mut tag = b & 0x1f;
    let mut pos = pos + 1;
    if tag == 0x1f {
        tag = 0;
        loop {
            let c = buf[pos];
            pos += 1;
            tag = (tag << 7) | (c & 0x7f);
            if c & 0x80 == 0 {
                break;
            }
        }
    }
    let mut n = buf[pos] as usize;
    pos += 1;
    if n & 0x80 != 0 {
        // The long form: the length follows in `k` bytes, big-endian.
        let k = n & 0x7f;
        if pos + k > buf.len() {
            return Err(Error::Crypto("truncated DER length".into()));
        }
        let mut value: u64 = 0;
        for byte in &buf[pos..pos + k] {
            value = (value << 8) | (*byte as u64);
        }
        n = value as usize;
        pos += k;
    }
    if pos + n > buf.len() {
        return Err(Error::Crypto(
            "DER length past the end of the buffer".into(),
        ));
    }
    Ok((
        Node {
            class,
            constructed,
            tag,
            value: buf[pos..pos + n].to_vec(),
            raw: buf[start..pos + n].to_vec(),
        },
        pos + n,
    ))
}

/// Parse one TLV.
pub fn parse(buf: &[u8]) -> Result<Node> {
    Ok(parse_one(buf, 0)?.0)
}

/// Parse every TLV.
pub fn parse_all(buf: &[u8]) -> Result<Vec<Node>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let (node, next) = parse_one(buf, pos)?;
        out.push(node);
        pos = next;
    }
    Ok(out)
}

/// The context-tagged child with this tag.
fn ctx(nodes: &[Node], tag: u8) -> Option<&Node> {
    nodes.iter().find(|n| n.class == CONTEXT && n.tag == tag)
}

/// Derive bytes with the NIST SP 800-108 counter-mode HMAC-SHA256 KDF.
pub fn kdf_ctr_hmac(key: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut suffix = label.to_vec();
    suffix.push(0);
    suffix.extend_from_slice(context);
    suffix.extend_from_slice(&((length as u32) * 8).to_be_bytes());
    let mut out = Vec::with_capacity(length);
    let mut i: u32 = 1;
    while out.len() < length {
        let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
        mac.update(&i.to_be_bytes());
        mac.update(&suffix);
        out.extend_from_slice(&mac.finalize().into_bytes());
        i += 1;
    }
    out.truncate(length);
    out
}

/// Restore a P-256 point from its X coordinate; either Y works, because ECDH uses
/// the shared point's X.
fn public_from_x(x: &[u8]) -> Result<PublicKey> {
    let mut point = Vec::with_capacity(65);
    point.push(0x03);
    point.extend_from_slice(x);
    PublicKey::from_sec1_bytes(&point).map_err(|e| Error::Crypto(format!("bad PCS point: {e}")))
}

/// A compact private key: X(32) || d(32), or just d(32).
pub fn private_from_compact(raw: &[u8]) -> Result<SecretKey> {
    let d = if raw.len() == 64 { &raw[32..] } else { raw };
    if d.len() != 32 {
        return Err(Error::Crypto(format!(
            "unexpected compact private key size {}",
            raw.len()
        )));
    }
    SecretKey::from_slice(d).map_err(|e| Error::Crypto(format!("bad PCS key: {e}")))
}

/// The public X coordinate of a key.
pub fn compact_x(key: &SecretKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    key.public_key().to_encoded_point(false).as_bytes()[1..33].to_vec()
}

/// The P-256 curve's object identifier.
const P256_OID: [u8; 9] = [0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// Unwrap `[u16 bits][ephemeral X][u8 len][AES-KW blob]` with ECDH and the RFC 6637 KDF.
pub fn rfc6637_unwrap(key: &SecretKey, wrapped: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 3 {
        return Err(Error::Crypto("the wrapped key is too short".into()));
    }
    let bits = u16::from_be_bytes([wrapped[0], wrapped[1]]) as usize;
    let elen = bits / 8;
    let eph = &wrapped[2..2 + elen];
    let wlen = wrapped[2 + elen] as usize;
    let blob = &wrapped[3 + elen..3 + elen + wlen];
    let ephemeral = public_from_x(eph)?;
    let secret = p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), ephemeral.as_affine());
    let mut kek_input = vec![0u8, 0, 0, 1];
    kek_input.extend_from_slice(secret.raw_secret_bytes());
    kek_input.extend_from_slice(&P256_OID);
    kek_input.extend_from_slice(&[18, 0x03, 0x01, 0x08, 0x07]);
    kek_input.extend_from_slice(b"Anonymous Sender    ");
    let mut fp = fingerprint.to_vec();
    fp.resize(20, 0);
    kek_input.extend_from_slice(&fp);
    let kek = &Sha256::digest(&kek_input)[..16];
    let msg = aes_kw_unwrap(kek, blob)?;
    let pad = *msg.last().unwrap_or(&0) as usize;
    if pad == 0 || pad > msg.len() - 3 || !msg[msg.len() - pad..].iter().all(|b| *b as usize == pad)
    {
        return Err(Error::Crypto("bad RFC 6637 padding".into()));
    }
    let key = &msg[1..msg.len() - pad - 2];
    let checksum = u16::from_be_bytes([msg[1 + key.len()], msg[2 + key.len()]]) as u32;
    if key.iter().map(|b| *b as u32).sum::<u32>() & 0xffff != checksum {
        return Err(Error::Crypto("bad RFC 6637 checksum".into()));
    }
    Ok(key.to_vec())
}

/// The AES key unwrap (RFC 3394).
fn aes_kw_unwrap(kek: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(kek)
        .map_err(|e| Error::Crypto(format!("bad unwrap key: {e}")))?;
    if !blob.len().is_multiple_of(8) || blob.len() < 16 {
        return Err(Error::Crypto("the wrapped key has a bad length".into()));
    }
    // RFC 3394: the blob is A followed by R[1..n]; n is the number of wrapped
    // plaintext blocks.
    let n = blob.len() / 8 - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&blob[..8]);
    let mut r: Vec<[u8; 8]> = blob[8..]
        .chunks(8)
        .map(|c| {
            let mut b = [0u8; 8];
            b.copy_from_slice(c);
            b
        })
        .collect();
    for j in (0..6usize).rev() {
        for i in (1..=n).rev() {
            // RFC 3394: B = AES-1(K, (A ^ t) | R[i]), t = n*j + i.
            let t = (n * j + i) as u64;
            let mut block = [0u8; 16];
            for (k, byte) in a.iter().enumerate() {
                block[k] = byte ^ ((t >> (8 * (7 - k))) as u8);
            }
            block[8..].copy_from_slice(&r[i - 1]);
            let mut decrypted = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
            cipher.decrypt_block(&mut decrypted);
            a.copy_from_slice(&decrypted[..8]);
            r[i - 1].copy_from_slice(&decrypted[8..]);
        }
    }
    // The integrity check: A == 0xa6a6a6a6a6a6a6a6.
    if a != [0xa6; 8] {
        return Err(Error::Crypto("the PCS key unwrap failed".into()));
    }
    Ok(r.concat())
}

/// A PCS master key and its label-derived working keys.
#[derive(Clone)]
pub struct PcsKey {
    pub raw: Vec<u8>,
}

impl PcsKey {
    /// A key from its raw bytes.
    pub fn new(raw: Vec<u8>) -> PcsKey {
        PcsKey { raw }
    }

    fn derive(&self, label: &[u8]) -> Vec<u8> {
        kdf_ctr_hmac(&self.raw, label, b"", self.raw.len())
    }

    /// The key's id.
    pub fn key_id(&self) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.derive(b"master key id labell"))
            .expect("any key length");
        mac.update(b"M key input data 2 u");
        mac.finalize().into_bytes().to_vec()
    }

    /// The share variant of the key.
    pub fn share_variant(&self) -> PcsKey {
        PcsKey::new(self.derive(b"MsaeEooevaX fooo 012"))
    }

    /// The key's HMAC over some data.
    pub fn hmac(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.derive(b"hmackey-of-masterkey"))
            .expect("any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Decrypt a PCS ciphertext.
    ///
    /// Version 3: `0x03 || id[0:2] || n || id[2:2+n] || iv(12) || tag(12) || data`. The
    /// header is authenticated together with the caller's AAD.
    pub fn decrypt(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::AeadInPlace;
        use aes_gcm::aes::cipher::consts::U12;
        use aes_gcm::KeyInit;
        let (want, hlen) = ciphertext_key_id(ct)?;
        if self.key_id()[..want.len()] != want[..] {
            return Err(Error::Crypto(
                "the ciphertext is for a different key".into(),
            ));
        }
        let iv = &ct[hlen..hlen + 12];
        let tag = &ct[hlen + 12..hlen + 24];
        let data = &ct[hlen + 24..];
        // The working key is the master key's length, so it picks the AES variant.
        let key = self.derive(b"encryption key key m");
        let mut buffer = data.to_vec();
        let nonce = aes_gcm::Nonce::<U12>::from_slice(iv);
        let header = ct[..hlen].iter().chain(aad).copied().collect::<Vec<u8>>();
        // GCM's tag is 12 bytes here, not the crate's default of 16.
        let tag = aes_gcm::Tag::<U12>::from_slice(tag);
        let failed = || Error::Crypto("the PCS ciphertext authentication failed".into());
        match key.len() {
            16 => Gcm128::new_from_slice(&key)
                .map_err(|e| Error::Crypto(format!("bad PCS key: {e}")))?
                .decrypt_in_place_detached(nonce, &header, &mut buffer, tag)
                .map_err(|_| failed())?,
            32 => Gcm256::new_from_slice(&key)
                .map_err(|e| Error::Crypto(format!("bad PCS key: {e}")))?
                .decrypt_in_place_detached(nonce, &header, &mut buffer, tag)
                .map_err(|_| failed())?,
            _ => return Err(Error::Crypto("the PCS key has a bad length".into())),
        };
        Ok(buffer)
    }
}

/// GCM with a 96-bit nonce and a 96-bit tag.
type Gcm128 = aes_gcm::AesGcm<aes_gcm::aes::Aes128, U12Tag, U12Tag>;
/// GCM with a 96-bit nonce and a 96-bit tag.
type Gcm256 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, U12Tag, U12Tag>;
/// 96 bits.
type U12Tag = aes_gcm::aes::cipher::consts::U12;

/// The key id a PCS ciphertext carries, and the header's length.
pub fn ciphertext_key_id(ct: &[u8]) -> Result<(Vec<u8>, usize)> {
    if ct.is_empty() || ct[0] != 3 {
        return Err(Error::Crypto(format!(
            "unsupported PCS ciphertext version {}",
            ct.first().map(|b| format!("{b:02x}")).unwrap_or_default()
        )));
    }
    let n = ct[3] as usize;
    Ok((
        ct[1..3].iter().chain(&ct[4..4 + n]).copied().collect(),
        4 + n,
    ))
}

/// Decrypt with whichever key fits.
pub fn decrypt_with_any(keys: &[PcsKey], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let (want, _) = ciphertext_key_id(ct)?;
    for key in keys {
        if key.key_id()[..want.len()] == want[..] {
            return key.decrypt(ct, aad);
        }
    }
    Err(Error::Crypto("no key for this ciphertext".into()))
}

/// A PCS private key: either V1 `SEQUENCE{OCTET compact-key, public OPTIONAL}` or
/// V2 `[APPLICATION 5]{OCTET protobuf{1: {1: compact encryption key}, 2: signing key}}`.
pub fn private_key_from_der(der: &[u8]) -> Result<SecretKey> {
    let node = parse(der)?;
    if node.class == APPLICATION && node.tag == 5 {
        let kids = node.children()?;
        let pb = kids
            .first()
            .map(|k| k.value.clone())
            .ok_or_else(|| Error::Crypto("the V2 PCS key has no body".into()))?;
        let fields = crate::proto::Fields::decode(&pb)?;
        let enc = fields
            .bytes(1)
            .ok_or_else(|| Error::Crypto("the V2 PCS key has no encryption key".into()))?;
        let inner = crate::proto::Fields::decode(enc)?;
        let compact = inner
            .bytes(1)
            .ok_or_else(|| Error::Crypto("the V2 PCS key has no key material".into()))?;
        return private_from_compact(compact);
    }
    let kids = node.children()?;
    let compact = kids
        .first()
        .map(|k| k.value.clone())
        .ok_or_else(|| Error::Crypto("the PCS key is empty".into()))?;
    private_from_compact(&compact)
}

/// One key in a share.
#[derive(Debug, Clone)]
pub struct ShareKey {
    pub public_x: Vec<u8>,
    pub wrapped: Vec<u8>,
    pub flags: i64,
}

/// The share protection structure.
#[derive(Debug, Clone)]
pub struct ShareProtection {
    pub keyset_raw: Vec<u8>,
    pub share_keys: Vec<ShareKey>,
    pub meta: Vec<u8>,
    pub sig_version: i64,
    pub sig_data: Vec<u8>,
    pub hmac: Vec<u8>,
    pub truncated_key_id: Vec<u8>,
}

impl ShareProtection {
    /// Parse it.
    pub fn parse(raw: &[u8]) -> Result<ShareProtection> {
        let outer = parse(raw)?;
        let seq = if outer.class == APPLICATION {
            outer.unwrap()?
        } else {
            outer
        };
        let kids = seq.children()?;
        let keyset = kids
            .iter()
            .find(|n| n.class == UNIVERSAL && n.tag == 0x10)
            .ok_or_else(|| Error::Crypto("the share protection has no key set".into()))?;
        let hmac_node = kids
            .iter()
            .find(|n| n.class == UNIVERSAL && n.tag == 0x04)
            .ok_or_else(|| Error::Crypto("the share protection has no HMAC".into()))?;
        let mut share_keys = Vec::new();
        let ks = keyset.children()?;
        for entry in ks
            .iter()
            .find(|n| n.tag == 0x11)
            .map(|n| n.children())
            .transpose()?
            .unwrap_or_default()
        {
            let e = entry.children()?;
            if e.len() < 2 {
                continue;
            }
            let keyref = e[0].children()?;
            if keyref.len() < 2 {
                continue;
            }
            let flags = if e.len() > 2 && e[2].tag == 0x02 {
                e[2].int()
            } else {
                0
            };
            share_keys.push(ShareKey {
                public_x: keyref[1].value.clone(),
                wrapped: e[1].value.clone(),
                flags,
            });
        }
        let sig = ctx(&kids, 1)
            .ok_or_else(|| Error::Crypto("the share protection has no signature".into()))?
            .unwrap()?
            .children()?;
        Ok(ShareProtection {
            keyset_raw: keyset.raw.clone(),
            share_keys,
            meta: ctx(&kids, 0)
                .map(|n| n.unwrap().map(|u| u.value.clone()))
                .transpose()?
                .ok_or_else(|| Error::Crypto("the share protection has no meta".into()))?,
            sig_version: sig.first().map(|n| n.int()).ok_or_else(|| {
                Error::Crypto("the share protection has no signature version".into())
            })?,
            sig_data: sig.get(1).map(|n| n.value.clone()).ok_or_else(|| {
                Error::Crypto("the share protection has no signature data".into())
            })?,
            hmac: hmac_node.value.clone(),
            truncated_key_id: ctx(&kids, 2)
                .map(|n| n.unwrap().map(|u| u.value.clone()))
                .transpose()?
                .unwrap_or_default(),
        })
    }

    /// The public keys it names.
    pub fn public_keys(&self) -> Vec<Vec<u8>> {
        self.share_keys.iter().map(|k| k.public_x.clone()).collect()
    }

    /// Open it with the private keys.
    pub fn open(&self, privs: &[SecretKey]) -> Result<(Vec<PcsKey>, Vec<SecretKey>)> {
        let match_key = self.share_keys.iter().find_map(|k| {
            privs
                .iter()
                .find(|p| compact_x(p) == k.public_x)
                .map(|p| (p, k))
        });
        let Some((priv_key, share)) = match_key else {
            return Err(Error::Crypto(
                "none of our keys opens this share protection".into(),
            ));
        };
        let mut master = PcsKey::new(rfc6637_unwrap(priv_key, &share.wrapped, b"fingerprint")?);
        let readonly = share.flags & 1 != 0;
        if self.sig_version != 5 && !readonly {
            master = master.share_variant();
        }
        if master.key_id()[..self.truncated_key_id.len().min(master.key_id().len())]
            != self.truncated_key_id[..self.truncated_key_id.len().min(master.key_id().len())]
        {
            return Err(Error::Crypto(
                "the unwrapped key does not match the protection's key id".into(),
            ));
        }
        let mut hmac_input = self.keyset_raw.clone();
        hmac_input.extend_from_slice(&self.meta);
        hmac_input.extend_from_slice(&self.sig_data);
        if master.hmac(&hmac_input) != self.hmac {
            return Err(Error::Crypto(
                "the share protection's HMAC does not match".into(),
            ));
        }

        let meta = parse(&master.decrypt(&self.meta, b"")?)?.children()?;
        // The symmetric keys: a context tag holding a set of raw keys.
        let symm: Vec<PcsKey> = ctx(&meta, 0)
            .map(|n| n.unwrap().and_then(|u| u.children()))
            .transpose()?
            .unwrap_or_default()
            .iter()
            .map(|n| PcsKey::new(n.value.clone()))
            .collect();
        let mut idents = Vec::new();
        if let Some(ident_set) = ctx(&meta, 2) {
            for ident in ident_set.unwrap()?.children()? {
                let kids = ident.children()?;
                let raw = kids
                    .get(1)
                    .map(|k| k.value.clone())
                    .ok_or_else(|| Error::Crypto("an identity key has no key set".into()))?;
                let keyset = parse(&raw)?;
                let inner = if keyset.class == APPLICATION {
                    keyset.unwrap()?.children()?
                } else {
                    keyset.children()?
                };
                let set = inner
                    .get(1)
                    .map(|n| n.children())
                    .transpose()?
                    .unwrap_or_default();
                for k in set {
                    idents.push(private_key_from_der(&k.raw)?);
                }
            }
        }
        let mut all = vec![master];
        all.extend(symm);
        Ok((all, idents))
    }
}

/// The PCS service keys of the keychain, indexed by their public X coordinate.
///
/// The service key items carry the public X in `acct` (base64) and the private key
/// in `v_Data`.
pub fn keychain_key_index(items: &[(String, plist::Value)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    use base64::Engine;
    let mut out = Vec::new();
    for (_, item) in items {
        let Some(dict) = item.as_dictionary() else {
            continue;
        };
        let agrp = dict.get("agrp").and_then(|v| v.as_string()).unwrap_or("");
        if !agrp.starts_with("com.apple.ProtectedCloudStorage") {
            continue;
        }
        let acct = dict.get("acct").and_then(|v| v.as_string()).unwrap_or("");
        let Some(data) = dict.get("v_Data").and_then(|v| v.as_data()) else {
            continue;
        };
        let Ok(x) = base64::engine::general_purpose::STANDARD.decode(acct) else {
            continue;
        };
        out.push((x, data.to_vec()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_parsing_roundtrip() {
        // SEQUENCE { OCTET STRING "abc" }
        let der = [0x30, 0x05, 0x04, 0x03, b'a', b'b', b'c'];
        let node = parse(&der).unwrap();
        assert_eq!(node.tag, 0x10);
        // The sequence's content is the inner TLV.
        assert_eq!(node.value, vec![0x04, 0x03, b'a', b'b', b'c']);
        let inner = node.children().unwrap();
        assert_eq!(inner[0].value, b"abc");
    }

    #[test]
    fn kdf_is_deterministic() {
        let a = kdf_ctr_hmac(b"key", b"label", b"", 32);
        let b = kdf_ctr_hmac(b"key", b"label", b"", 32);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn the_key_id_is_derived() {
        let key = PcsKey::new(vec![1u8; 32]);
        assert_eq!(key.key_id().len(), 32);
        // The share variant is a different key.
        assert_ne!(key.key_id(), key.share_variant().key_id());
    }

    #[test]
    fn the_aes_unwrap_follows_rfc3394() {
        // RFC 3394, 4.1: a 128-bit key wrapped with a 128-bit KEK.
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let blob = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();
        let out = aes_kw_unwrap(&kek, &blob).unwrap();
        assert_eq!(hex::encode(out), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn the_aes_unwrap_rejects_a_bad_key() {
        let blob = vec![0u8; 16];
        assert!(aes_kw_unwrap(&[1u8; 16], &blob).is_err());
    }
}
