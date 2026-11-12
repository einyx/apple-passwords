//! The iCloud Keychain client core.
//!
//! The protocol this speaks was reverse-engineered from the wire; the findings and
//! the byte-level pins live in the Python implementation's RESEARCH.md. Every module
//! here has a Python counterpart that was verified against live Apple servers, and
//! the two are checked against each other.

pub mod anisette;
pub mod ckks;
pub mod cloudkit;
pub mod crypto;
pub mod cuttlefish;
pub mod device;
pub mod engine;
pub mod error;
pub mod keychain;
pub mod nska;
pub mod octagon;
pub mod proto;
pub mod session;
pub mod totp;
pub mod vault;
pub mod write;

pub use error::{Error, Result};

/// The zone web passwords live in.
pub const PASSWORDS_ZONE: &str = "Passwords";
/// The view inside that zone they live under.
pub const CLASS_A_VIEW: &str = "classA";
