//! The keychain's cryptography.
//!
//! * `AES-256-SIV` wraps and unwraps the item key under the view's class key.
//! * `AES-256-SIV` also encrypts the item payload, with the record's authenticated
//!   data as the associated data and a random IV in front of it.
//! * `X9.63-KDF` and `ECIES` (P-384) unwrap the TLKShares the sponsor sent.
//!
//! The SIV mode is Apple's *AES-SIV* (RFC 5297), not XSalsa20 - the `aes-siv` crate
//! implements it.

use aes_gcm::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use aes_gcm::aes::cipher::consts::U16;
use aes_siv::siv::Aes256Siv;
use p384::ecdh::diffie_hellman;
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::{PublicKey, SecretKey};
use rand::RngCore;

/// AES-GCM with a 16-byte nonce (Apple's SecurityFoundation uses one).
type Aes256Gcm16 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, U16>;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// The AES-SIV key length (32 bytes for AES-256).
pub const SIV_KEY_LEN: usize = 32;
/// The class key is 64 bytes: two AES-256-SIV keys (the mac key and the cipher key).
pub const CLASS_KEY_LEN: usize = 64;
/// The item key is 64 bytes too.
pub const ITEM_KEY_LEN: usize = 64;

/// X9.63-KDF (SEC1 / ANSI X9.63) with SHA-256.
pub fn x963_kdf(secret: &[u8], shared_info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut h = Sha256::new();
        h.update(secret);
        h.update(counter.to_be_bytes());
        h.update(shared_info);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

/// The ISO-7816-4 padding Apple's keychain uses around the item payload:
/// `0x80` then `0x00`s, to a multiple of 16.
pub fn pad_iso7816(data: &[u8]) -> Vec<u8> {
    let pad = 16 - (data.len() % 16);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.push(0x80);
    out.extend(std::iter::repeat_n(0u8, pad - 1));
    out
}

/// The inverse of [`pad_iso7816`].
pub fn strip_iso7816_padding(data: &[u8]) -> Result<Vec<u8>> {
    let mut ptr = data.len();
    while ptr > 0 {
        ptr -= 1;
        match data[ptr] {
            0x00 => continue,
            0x80 => return Ok(data[..ptr].to_vec()),
            _ => return Err(Error::Crypto("bad ISO-7816-4 padding".into())),
        }
    }
    Err(Error::Crypto("bad ISO-7816-4 padding".into()))
}

/// AES-256-SIV encryption with associated data.
///
/// The keychain's SIV takes a *list* of associated-data elements (the item's IV plus
/// its authenticated metadata), which is what `aes-siv`'s `Siv` API is for - the
/// `Aead` API's single blob would hash differently and would not decrypt.
pub fn siv_encrypt(key: &[u8], plaintext: &[u8], associated: &[&[u8]]) -> Result<Vec<u8>> {
    if key.len() != CLASS_KEY_LEN {
        return Err(Error::Crypto(format!("bad SIV key length {}", key.len())));
    }
    let mut cipher =
        Aes256Siv::new_from_slice(key).map_err(|e| Error::Crypto(format!("bad SIV key: {e}")))?;
    cipher
        .encrypt(associated.iter().copied(), plaintext)
        .map_err(|e| Error::Crypto(format!("SIV encryption failed: {e}")))
}

/// AES-256-SIV decryption with associated data.
pub fn siv_decrypt(key: &[u8], wrapped: &[u8], associated: &[&[u8]]) -> Result<Vec<u8>> {
    if key.len() != CLASS_KEY_LEN {
        return Err(Error::Crypto(format!("bad SIV key length {}", key.len())));
    }
    let mut cipher =
        Aes256Siv::new_from_slice(key).map_err(|e| Error::Crypto(format!("bad SIV key: {e}")))?;
    cipher
        .decrypt(associated.iter().copied(), wrapped)
        .map_err(|_| Error::Crypto("SIV decryption failed (wrong key or data)".into()))
}

/// Decrypt an item record's `data`: a random IV (16 bytes) followed by the
/// SIV-wrapped payload, with the IV as the first associated-data element.
pub fn decrypt_item(item_key: &[u8], data: &[u8], aad: &[&[u8]]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(Error::Crypto("item data too short".into()));
    }
    let (iv, body) = data.split_at(16);
    let mut headers: Vec<&[u8]> = Vec::with_capacity(aad.len() + 1);
    headers.push(iv);
    headers.extend_from_slice(aad);
    let plaintext = siv_decrypt(item_key, body, &headers)?;
    strip_iso7816_padding(&plaintext)
}

/// The inverse of [`decrypt_item`].
pub fn encrypt_item(item_key: &[u8], plaintext: &[u8], aad: &[&[u8]]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    let mut headers: Vec<&[u8]> = Vec::with_capacity(aad.len() + 1);
    headers.push(&iv);
    headers.extend_from_slice(aad);
    let mut out = iv.to_vec();
    out.extend_from_slice(&siv_encrypt(item_key, &pad_iso7816(plaintext), &headers)?);
    Ok(out)
}

/// Decrypt an SF-ECIES blob (the TLKShare's `wrappedkey`) with the peer's P-384 key.
///
/// The blob is `ephemeral sender public key || AES-GCM ciphertext || tag`. The shared
/// secret goes through X9.63-KDF with the *ephemeral public key* as the shared info,
/// and the 48 bytes it yields are the 32-byte key followed by a 16-byte IV.
///
/// The IV is 16 bytes, not the usual 12, so GCM's J0 is computed the long way (the
/// AES-GCM spec's non-96-bit case) - which is what Apple's SecurityFoundation does.
pub fn ecies_decrypt(
    private_key: &SecretKey,
    ephemeral_sender_pub: &[u8],
    ciphertext: &[u8],
    auth_code: &[u8],
) -> Result<Vec<u8>> {
    let pub_key = PublicKey::from_sec1_bytes(ephemeral_sender_pub)
        .map_err(|e| Error::Crypto(format!("bad ephemeral key: {e}")))?;
    let shared = diffie_hellman(private_key.to_nonzero_scalar(), pub_key.as_affine());
    let derived = x963_kdf(
        shared.raw_secret_bytes().as_slice(),
        ephemeral_sender_pub,
        48,
    );
    let key = &derived[..32];
    let iv = &derived[32..48];

    let cipher =
        Aes256Gcm16::new_from_slice(key).map_err(|e| Error::Crypto(format!("bad key: {e}")))?;
    let nonce = aes_gcm::Nonce::<U16>::from_slice(iv);
    let mut buf = ciphertext.to_vec();
    buf.extend_from_slice(auth_code);
    if buf.len() < 16 {
        return Err(Error::Crypto("ECIES ciphertext too short".into()));
    }
    let (body, tag) = buf.split_at(buf.len() - 16);
    let mut body = body.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, &[], &mut body, aes_gcm::Tag::from_slice(tag))
        .map_err(|_| Error::Crypto("ECIES decryption failed".into()))?;
    Ok(body)
}

/// Sign with the peer's P-384 signing key (ECDSA over SHA-384).
pub fn sign_sha384(key: &SecretKey, data: &[u8]) -> Result<Vec<u8>> {
    let signing = SigningKey::from_bytes(&key.to_bytes())
        .map_err(|e| Error::Crypto(format!("bad signing key: {e}")))?;
    // p384's ECDSA signs with SHA-384, which is what Apple's peer signatures use.
    let sig: Signature = signing.sign(data);
    Ok(sig.to_bytes().to_vec())
}

/// Verify a P-384 ECDSA-SHA384 signature.
pub fn verify_sha384(key: &VerifyingKey, data: &[u8], signature: &[u8]) -> bool {
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(data, &sig).is_ok()
}

/// The uncompressed public point (`0x04 || X || Y`), the way SecKey hands it over.
pub fn public_x963(key: &SecretKey) -> Vec<u8> {
    key.public_key().to_encoded_point(false).as_bytes().to_vec()
}

/// The SubjectPublicKeyInfo DER of a public key.
pub fn public_spki(key: &SecretKey) -> Vec<u8> {
    use p384::pkcs8::EncodePublicKey;
    key.public_key()
        .to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .unwrap_or_default()
}

/// The external representation of a full EC key: `0x04 || X || Y || D`.
pub fn private_x963(key: &SecretKey) -> Vec<u8> {
    let mut out = public_x963(key);
    out.extend_from_slice(&key.to_bytes());
    out
}

/// Rebuild a key from its external representation.
pub fn load_private_x963(blob: &[u8]) -> Result<SecretKey> {
    if blob.len() < 97 {
        return Err(Error::Crypto("private key too short".into()));
    }
    let d = &blob[97..];
    SecretKey::from_slice(d).map_err(|e| Error::Crypto(format!("bad private key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x963_kdf_known_vector() {
        // NIST/SEC1 ANSI-X9.63 KDF (SHA-256) vector, no SharedInfo.
        let z = hex::decode("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08").unwrap();
        let out = x963_kdf(&z, b"", 16);
        assert_eq!(hex::encode(out), "443024c3dae66b95e6f5670601558f71");
    }

    #[test]
    fn x963_kdf_length_and_counter() {
        let out = x963_kdf(b"secret", b"info", 48);
        assert_eq!(out.len(), 48);
        assert_eq!(x963_kdf(b"secret", b"info", 32), out[..32]);
    }

    #[test]
    fn iso7816_padding_roundtrip() {
        for len in 0..40usize {
            let data = vec![0xa5u8; len];
            let padded = pad_iso7816(&data);
            assert_eq!(padded.len() % 16, 0);
            assert_eq!(strip_iso7816_padding(&padded).unwrap(), data);
        }
    }

    #[test]
    fn siv_roundtrip_with_several_headers() {
        let key = [7u8; 64];
        let plaintext = b"the secret payload";
        let headers: Vec<&[u8]> = vec![b"one", b"two", b"three"];
        let wrapped = siv_encrypt(&key, plaintext, &headers).unwrap();
        let out = siv_decrypt(&key, &wrapped, &headers).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn siv_is_deterministic() {
        let key = [7u8; 64];
        let a = siv_encrypt(&key, b"x", &[]).unwrap();
        let b = siv_encrypt(&key, b"x", &[]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn siv_rejects_a_wrong_header() {
        let key = [7u8; 64];
        let wrapped = siv_encrypt(&key, b"x", &[b"one"]).unwrap();
        assert!(siv_decrypt(&key, &wrapped, &[b"two"]).is_err());
    }

    #[test]
    fn item_roundtrip() {
        let key = [9u8; 64];
        let aad: Vec<&[u8]> = vec![b"uuid", b"encver"];
        let enc = encrypt_item(&key, b"hunter2", &aad).unwrap();
        assert_eq!(enc.len() % 16, 0);
        let dec = decrypt_item(&key, &enc, &aad).unwrap();
        assert_eq!(dec, b"hunter2");
    }

    #[test]
    fn item_tampering_is_detected() {
        let key = [9u8; 64];
        let aad: Vec<&[u8]> = vec![b"uuid"];
        let enc = encrypt_item(&key, b"hunter2", &aad).unwrap();
        assert!(decrypt_item(&key, &enc, &[b"other"]).is_err());
    }

    #[test]
    fn p384_sign_verify() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::random(&mut rng);
        let data = b"peer permanent info";
        let sig = sign_sha384(&key, data).unwrap();
        let vk = *SigningKey::from_bytes(&key.to_bytes())
            .unwrap()
            .verifying_key();
        assert!(verify_sha384(&vk, data, &sig));
        assert!(!verify_sha384(&vk, b"other", &sig));
    }

    #[test]
    fn private_key_roundtrip() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::random(&mut rng);
        let blob = private_x963(&key);
        assert_eq!(blob.len(), 145);
        let back = load_private_x963(&blob).unwrap();
        assert_eq!(private_x963(&back), blob);
    }
}
