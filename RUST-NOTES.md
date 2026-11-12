# The protocol, in Rust

What this client talks to, and the pins that matter. The Python implementation
(`iCloud-Keychain-for-Linux`) is the reference for the findings; the numbers below
were checked against live Apple servers.

## The pieces

| | |
| --- | --- |
| `anisette` | Apple's servers want `X-Apple-I-MD*` headers that only a real machine can produce. The anisette server produces them. Two endpoints matter: the server root (the machine data) and `/v3/client_info` (the identity and the user agent). |
| `gsa` | The sign-in: SRP-6a, then the two-factor factors. |
| `icloud` | `loginDelegates` (the long-lived token), `get_account_settings` (the service URLs and the CloudKit token), `ckAppInit` (the per-container user id). |
| `octagon` | The trust circle: two P-384 key pairs and a peer id derived from a signed permanent info. |
| `ckks` | The records: the `Passwords` view and the other keychain zones. |
| `keychain` | The unwrap chain: TLKShare -> TLK -> class key -> item key -> item. |

## The record protocol

The CloudKit messages are protobuf, but CloudKitDaemon's schema is not published, so
the field numbers are pinned by hand. They were reconstructed from CloudKitDaemon's
binary (`doug-leith/ios-protobuf-decoding`, `ckdp.proto`).

```
CKDPRecordSaveRequest { record = 1; merge = 2; etag = 4; saveSemantics = 6;
                         zoneProtectionInfoTag = 7; recordProtectionInfoTag = 8; }
CKDPRecordSaveResponse { etag = 2; timeStatistics = 3; serverFields = 4; }
CKDPRecord { etag = 1; recordIdentifier = 2; type = 3; createdBy = 4;
              timeStatistics = 5; fields = 7; modifiedBy = 9; modifiedByDevice = 11;
              protectionInfo = 13; permission = 15; }
```

The rule that makes it all work: **the field number of the request equals the
operation type.** `210` is `recordSaveRequest` (posted to
`/ckdatabase/api/client/record/save`), `211` is `recordRetrieveRequest`, `213` is
`recordRetrieveChangesRequest` (`/ckdatabase/api/client/record/sync`).

### The keychain's zones carry no protection info

A zone retrieve of the keychain's zones returns a `Zone` with nothing but a
`zoneIdentifier` - no `protectionInfo`, no `recordProtectionInfo` - and no item
record carries one either. The keychain does its own encryption with the class
key, so CloudKit never encrypts its records. The two protection-tag fields of the
save request are therefore left unset.

### The item's authenticated data

The item payload is encrypted under the record's own fields, so it cannot be moved
to another record. The associated data is the record's name, the encryption
version, the generation and the class key the item hangs under, sorted by key.

### The item format

An internet-password item: `class` = `inet`, `atyp` = `form`, `agrp` =
`com.apple.cfnetwork`, the secret in `v_Data`, `sha1` = 20 opaque bytes (it is
*not* a hash of the password - items with identical passwords carry different
values), `musr` empty, `pdmn` = `ak`, `ptcl` = `htps`/`http`, `tomb` = 0, and
naive UTC `cdat`/`mdat`.

The newer "Password Manager Metadata" and "Website Metadata" items are *metadata
about* a credential - the password still lives in the classic item, so writing that
one is what stores a password.

### The write path

1. Fetch the view's class key: the `currentkey` record named `classA` points at the
   `synckey` record, whose `wrappedkey` is the class key wrapped with the TLK.
2. Build the item, wrap a fresh 64-byte item key with the class key (AES-256-SIV),
   and encrypt the payload under the record's authenticated data.
3. Save it: `recordSaveRequest` with `saveSemantics = 2` (create) and `merge`.
4. Read it back and decrypt it - a save response is not proof.

An update presents the version tag it read, and changes only the secret and the
modification time; the rest of the login is kept as it was.

## The crypto

| | |
| --- | --- |
| AES-256-SIV | wraps the item key under the class key, and encrypts the payload. Two keys of 32 bytes, so the class key is 64 bytes. |
| X9.63-KDF | derives the ECIES key and IV. |
| SF-ECIES | unwraps a TLKShare: P-384 ECDH, then AES-256-GCM with a **16-byte** IV (not the usual 12 - Apple's SecurityFoundation uses the long one, so GCM's J0 is computed the long way). |
| PBKDF2-HMAC-SHA256 | stretches the password with the salt and iteration count the server sends. The `s2k_fo` variant hex-encodes the hash first. |

### SRP-6a, Apple's variant

RFC 5054's 2048-bit group, with one difference: **the username is not mixed into
the password verifier**, so `x = H(salt | H(":" | password))`. The proof `M`
uses the *old* SRP-6 mixing (`H(N) XOR H(g)`) rather than the RFC 5054 `k`.

## The trust

The client needs the view's class key, and the class key is the TLK wrapped with
the view's top-level key. The top-level key comes from the sponsor's TLKShare:
ECIES-encrypted for this peer, and the peer can only unwrap it with the key it
holds.

A freshly-joined peer is entitled only to the always-on views (WiFi, Home,
Contacts...); the escrow-recovered *sponsor* is entitled to the user-controllable
ones (Passwords, Manatee). So the client asks for both and unions them.

## The TLS root

The sign-in service still chains to Apple's *old* RSA root certificate, which the
system trust stores do not carry (Debian ships the newer G3 root). So the HTTP
client trusts the system's store **and** Apple's root.

## What is not ported yet

The **join**: recovering the escrow bottle and joining the trust circle with a
voucher. The Python implementation does that today; the Rust client reads the
session it wrote, so the two share one sign-in.
