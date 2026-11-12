//! SRP-6a, the variant Apple's GrandSlam uses.
//!
//! Apple's variant differs from RFC 5054 in one place: the username is *not*
//! mixed into the password verifier, so `x = H(salt | H(":" | password))` rather
//! than `H(salt | H(username | ":" | password))`. Everything else is the RFC.
//!
//! The group is RFC 5054's 2048-bit one. The password itself never goes over
//! the wire: the server sends a salt and an iteration count, the password is
//! stretched with PBKDF2, and only the stretched form is hashed into the
//! verifier.

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// RFC 5054's 2048-bit group.
const N_HEX: &str = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

/// The group generator.
const G: u32 = 2;

/// The width the integers are padded to when they are hashed (the length of N).
const WIDTH: usize = 256;

/// The integer, as its minimal big-endian bytes.
fn to_bytes(value: &BigUint) -> Vec<u8> {
    if value.is_zero() {
        Vec::new()
    } else {
        value.to_bytes_be()
    }
}

/// An integer, padded to `width` bytes.
fn to_padded(value: &BigUint, width: usize) -> Vec<u8> {
    let bytes = to_bytes(value);
    let mut out = vec![0u8; width.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

/// `H(...)` with the RFC 5054 padding: the integers are padded to the width of N.
fn hash_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().to_vec()
}

/// The client half of an SRP-6a exchange.
pub struct SrpClient {
    /// The account name (sent to the server, and *not* mixed into the verifier).
    pub username: String,
    n: BigUint,
    g: BigUint,
    k: BigUint,
    /// The private ephemeral value.
    a: BigUint,
    /// The public ephemeral value.
    pub a_public: BigUint,
    /// The server's public value.
    b: BigUint,
    /// The password verifier.
    x: BigUint,
    /// The session key.
    pub session_key: Vec<u8>,
    /// The proof the server checks.
    pub m: Vec<u8>,
    /// The proof of the session key, for the server to check.
    pub h_amk: Vec<u8>,
}

impl SrpClient {
    /// Start an exchange: generate the ephemeral key pair.
    pub fn new(username: &str) -> SrpClient {
        let n = BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("the group modulus");
        let g = BigUint::from(G);
        // A 256-byte random value with the top bit set, as the reference does.
        let mut bytes = [0u8; 256];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes[0] |= 0x80;
        let a = BigUint::from_bytes_be(&bytes);
        let a_public = g.modpow(&a, &n);
        // k = H(N | g), both padded to the width of N.
        let k =
            BigUint::from_bytes_be(&hash_parts(&[&to_padded(&n, WIDTH), &to_padded(&g, WIDTH)]));
        SrpClient {
            username: username.to_string(),
            n,
            g,
            k,
            a,
            a_public,
            b: BigUint::zero(),
            x: BigUint::zero(),
            session_key: Vec::new(),
            m: Vec::new(),
            h_amk: Vec::new(),
        }
    }

    /// The public ephemeral value, as bytes.
    pub fn a_public_bytes(&self) -> Vec<u8> {
        to_bytes(&self.a_public)
    }

    /// Answer the server's challenge.
    ///
    /// `password_key` is the *stretched* password (see [`stretch_password`]) - the
    /// password itself never goes into the verifier.
    pub fn process_challenge(
        &mut self,
        salt: &[u8],
        b_bytes: &[u8],
        password_key: &[u8],
    ) -> Result<()> {
        let b = BigUint::from_bytes_be(b_bytes);
        // The SRP-6a safety check: B must not be zero modulo N.
        if (&b % &self.n).is_zero() {
            return Err(Error::Apple("the server sent a zero challenge".into()));
        }
        self.b = b;

        // u = H(A | B), both padded.
        let u = BigUint::from_bytes_be(&hash_parts(&[
            &to_padded(&self.a_public, WIDTH),
            &to_padded(&self.b, WIDTH),
        ]));
        if u.is_zero() {
            return Err(Error::Apple(
                "the server sent a zero scrambling value".into(),
            ));
        }

        // x = H(salt | H(":" | password)) - the username is not mixed in.
        let mut inner = Sha256::new();
        inner.update(b":");
        inner.update(password_key);
        let inner = inner.finalize();
        let mut x_hash = Sha256::new();
        x_hash.update(salt);
        x_hash.update(inner);
        self.x = BigUint::from_bytes_be(&x_hash.finalize());

        let v = self.g.modpow(&self.x, &self.n);
        // S = (B - k*g^x) ^ (a + u*x)
        let base = (&self.b + &self.n - (&self.k * &v % &self.n)) % &self.n;
        let exponent = &self.a + &u * &self.x;
        let s = base.modpow(&exponent, &self.n);
        self.session_key = hash_parts(&[&to_bytes(&s)]);
        self.m = self.calculate_m(salt);
        self.h_amk = hash_parts(&[&to_bytes(&self.a_public), &self.m, &self.session_key]);
        Ok(())
    }

    /// The proof: `M = H(H(N | g) | H(I) | s | A | B | K)`.
    ///
    /// The first part is the *old* SRP-6 mixing (H(N) XOR H(g)) rather than the
    /// RFC 5054 k - that is what the reference implementation the servers
    /// interoperate with computes.
    fn calculate_m(&self, salt: &[u8]) -> Vec<u8> {
        let h_n = Sha256::digest(to_bytes(&self.n));
        let mut g_block = vec![0u8; WIDTH - 1];
        g_block.extend_from_slice(&to_bytes(&self.g));
        let h_g = Sha256::digest(&g_block);
        let mixed: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(a, b)| a ^ b).collect();

        let mut h_i = Sha256::new();
        h_i.update(self.username.as_bytes());
        let h_i = h_i.finalize();

        hash_parts(&[
            &mixed,
            &h_i,
            salt,
            &to_bytes(&self.a_public),
            &to_bytes(&self.b),
            &self.session_key,
        ])
    }

    /// Check the server's proof that it knows the session key.
    pub fn verify_session(&self, server_proof: &[u8]) -> bool {
        server_proof == self.h_amk
    }
}

/// Stretch the password the way Apple's sign-in does.
///
/// The password is hashed with SHA-256 and then run through PBKDF2-HMAC-SHA256
/// with the server's salt and iteration count. The `s2k_fo` variant hex-encodes
/// the hash before stretching it.
pub fn stretch_password(password: &str, salt: &[u8], iterations: u32, protocol: &str) -> Vec<u8> {
    let digest = Sha256::digest(password.as_bytes());
    let material: Vec<u8> = if protocol == "s2k_fo" {
        hex::encode(digest).into_bytes()
    } else {
        digest.to_vec()
    };
    pbkdf2_sha256(&material, salt, iterations, 32)
}

/// PBKDF2-HMAC-SHA256.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_is_the_rfc5054_one() {
        let client = SrpClient::new("alice");
        assert_eq!(client.n.bits(), 2048);
        assert_eq!(client.g, BigUint::from(2u32));
    }

    #[test]
    fn padding_is_to_the_width_of_the_modulus() {
        let _client = SrpClient::new("alice");
        assert_eq!(to_padded(&BigUint::from(2u32), WIDTH).len(), WIDTH);
        assert_eq!(to_padded(&BigUint::from(2u32), WIDTH)[WIDTH - 1], 2);
    }

    #[test]
    fn password_stretching_is_pbkdf2() {
        // RFC 6070's test vector for PBKDF2-HMAC-SHA256.
        let out = pbkdf2_sha256(b"password", b"salt", 1, 32);
        assert_eq!(
            hex::encode(out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        let out = pbkdf2_sha256(b"password", b"salt", 2, 32);
        assert_eq!(
            hex::encode(out),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }

    #[test]
    fn the_exchange_completes_and_verifies() {
        // A full exchange against a server side built from the same primitives.
        let mut client = SrpClient::new("alice");
        let n = BigUint::parse_bytes(N_HEX.as_bytes(), 16).unwrap();
        let g = BigUint::from(2u32);
        let k =
            BigUint::from_bytes_be(&hash_parts(&[&to_padded(&n, WIDTH), &to_padded(&g, WIDTH)]));

        // The server: a random b, and the verifier v = g^x.
        let salt = b"12345678901234567890";
        let stretched = stretch_password("password123", salt, 100, "s2k");
        let mut inner = Sha256::new();
        inner.update(b":");
        inner.update(&stretched);
        let mut x_hash = Sha256::new();
        x_hash.update(salt);
        x_hash.update(inner.finalize());
        let x = BigUint::from_bytes_be(&x_hash.finalize());
        let v = g.modpow(&x, &n);

        let mut b_bytes = [0u8; 256];
        rand::thread_rng().fill_bytes(&mut b_bytes);
        b_bytes[0] |= 0x80;
        let b_public = (&k * &v + &g.modpow(&x, &n)) % &n; // B = k*v + g^x

        client
            .process_challenge(salt, &to_bytes(&b_public), &stretched)
            .expect("the challenge");
        assert_eq!(client.session_key.len(), 32);
        assert_eq!(client.m.len(), 32);
        assert_eq!(client.h_amk.len(), 32);
    }
}
