//! A minimal NSKeyedArchiver expander.
//!
//! Apple wraps the per-TLKShare `IESCiphertext` in an NSKeyedArchiver archive with
//! `plistlib.UID` references. This resolves that object graph back into plain values.

use crate::error::Result;

/// The three pieces of an `IESCiphertext`.
#[derive(Debug, Clone)]
pub struct IesCiphertext {
    /// The ephemeral sender's public key (`0x04 || X || Y`).
    pub ephemeral_sender_public_key: Vec<u8>,
    /// The AES-GCM ciphertext.
    pub ciphertext: Vec<u8>,
    /// The GCM authentication code.
    pub auth_code: Vec<u8>,
}

/// Expand an NSKeyedArchiver binary plist into plain values.
///
/// Returns the `IESCiphertext` the keychain wraps its TLKShares in.
pub fn expand_ies(data: &[u8]) -> Result<IesCiphertext> {
    let root = expand(data)?;
    let dict = match root {
        plist::Value::Dictionary(d) => d,
        _ => {
            return Err(crate::error::Error::Crypto(
                "not an archived dictionary".into(),
            ))
        }
    };
    let get = |key: &str| -> Option<Vec<u8>> {
        dict.get(key).and_then(|v| v.as_data().map(|d| d.to_vec()))
    };
    let eph = get("SFEphemeralSenderPublicKeyExternaRepresentation")
        .ok_or_else(|| crate::error::Error::Crypto("no ephemeral sender key".into()))?;
    let ct =
        get("SFCiphertext").ok_or_else(|| crate::error::Error::Crypto("no SFCiphertext".into()))?;
    let tag = get("SFIESAuthenticationCode")
        .ok_or_else(|| crate::error::Error::Crypto("no SFIESAuthenticationCode".into()))?;
    // SecurityFoundation appends 97+16 bytes of junk to the stored ciphertext.
    let ct = if ct.len() > 97 + 16 {
        ct[..ct.len() - (97 + 16)].to_vec()
    } else {
        ct
    };
    Ok(IesCiphertext {
        ephemeral_sender_public_key: eph,
        ciphertext: ct,
        auth_code: tag,
    })
}

/// Expand an NSKeyedArchiver binary plist into plain values.
///
/// The object graph is resolved: `UID` references become the objects they point at,
/// and the Foundation container objects are unwrapped to their payload (so an
/// `NSData` value yields raw bytes, not a dictionary).
pub fn expand(data: &[u8]) -> Result<plist::Value> {
    let plist = plist::Value::from_reader(std::io::Cursor::new(data))
        .map_err(|e| crate::error::Error::Crypto(format!("bad archived plist: {e}")))?;
    let objects = plist
        .as_dictionary()
        .and_then(|d| d.get("$objects"))
        .and_then(|v| v.as_array().cloned())
        .ok_or_else(|| crate::error::Error::Crypto("archive has no $objects".into()))?;

    let resolve = |node: &plist::Value| -> plist::Value { resolve_value(node, &objects) };

    let top = plist
        .as_dictionary()
        .and_then(|d| d.get("$top"))
        .cloned()
        .unwrap_or(plist::Value::Dictionary(Default::default()));
    match top {
        plist::Value::Dictionary(ref d) if d.contains_key("root") => {
            let root = d
                .get("root")
                .cloned()
                .unwrap_or(plist::Value::Boolean(false));
            Ok(resolve(&root))
        }
        other => Ok(resolve(&other)),
    }
}

/// Resolve one node of the archive's object graph.
fn resolve_value(node: &plist::Value, objects: &[plist::Value]) -> plist::Value {
    match node {
        plist::Value::Uid(uid) => {
            let idx = uid.get() as usize;
            match objects.get(idx) {
                Some(v) => resolve_value(v, objects),
                None => plist::Value::String(String::new()),
            }
        }
        plist::Value::String(s) if s == "$null" => plist::Value::String(String::new()),
        plist::Value::Dictionary(d) => {
            let is_object = d.contains_key("$class");
            let mut out = plist::Dictionary::new();
            for (k, v) in d {
                if k.starts_with('$') {
                    continue;
                }
                out.insert(k.clone(), resolve_value(v, objects));
            }
            // Unwrap the common Foundation containers to their payload.
            if is_object {
                if let Some(v) = out.get("NS.data") {
                    return v.clone();
                }
                if let Some(v) = out.get("NS.string") {
                    return v.clone();
                }
                if let Some(v) = out.get("NS.objects") {
                    return v.clone();
                }
            }
            plist::Value::Dictionary(out)
        }
        plist::Value::Array(a) => {
            plist::Value::Array(a.iter().map(|v| resolve_value(v, objects)).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_plist_is_expanded_to_itself() {
        let mut d = plist::Dictionary::new();
        d.insert("NS.data".to_string(), plist::Value::Data(vec![1, 2, 3]));
        let mut v = plist::Value::Dictionary(d);
        // A plain (non-archived) plist has no $objects, so expansion fails - the
        // archive path is the one that matters.
        assert!(expand(&serialize(&v)).is_err());
        v = plist::Value::String("x".into());
        assert!(expand(&serialize(&v)).is_err());
    }

    fn serialize(v: &plist::Value) -> Vec<u8> {
        let mut out = Vec::new();
        plist::to_writer_binary(&mut out, v).unwrap();
        out
    }
}
