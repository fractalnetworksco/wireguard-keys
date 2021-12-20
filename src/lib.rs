//! This crate allows for working with WireGuard keys. WireGuard uses asymmetric x25519 keys,
//! which are represented by the [Privkey] and [Pubkey] types respectively. Private keys can
//! be generated randomly, and their corresponding public key can be derived. Additionally,
//! WireGuard allows using a preshared key as additional security layer, which is just a random
//! 256-bit value. This is represented by the [Secret] type.
//!
//! For security reasons, this crate uses the [Zeroize] trait to mark all types containing
//! cryyptographically relevant information to be cleared on drop. The [x25519_dalek_fiat]
//! crate is used for x25519 operations.
//!
//! This crate allows for encoding keys in various ways. The crate supports `base64`, which is
//! typically used by WireGuard, but `hex` and `base32` can be enabled as well. Enabling encodings
//! also enables parsing from that encoding.
//!
//! The [serde] feature, which is enabled by default, adds [serialize][serde::Serialize] and
//! [deserialize][serde::Deserialize] support for WireGuard types. How these types are serialized
//! depends on the format: when serializing into human-readable formats, such as
//! JSON, the keys are serialized as base64-encoded strings. However, when
//! serializing to binary formats such as Bincode, keys are serialized as raw bytes.
//!
//! The optional `schema` feature adds information to the types allowing to generate JSON schema
//! from them automatically using schemars.
//!
//! Enabling the `rocket` feature adds the ability to parse any WireGuard types from a HTTP
//! request using the [FromParam][rocket::request::FromParam] trait.

#[macro_use]
mod macros;

use paste::paste;
use rand_core::{OsRng, RngCore};
#[cfg(feature = "rocket")]
use rocket::request::FromParam;
#[cfg(feature = "schema")]
use schemars::JsonSchema;
#[cfg(feature = "serde")]
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use x25519_dalek_fiat::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Possible errors that can be generated when parsing WireGuard keys.
#[derive(Error, Debug)]
pub enum ParseError {
    /// Error decoding base64
    #[cfg(feature = "base64")]
    #[error("base64 decoding error")]
    Base64(#[from] base64::DecodeError),
    /// Error decoding hex
    #[cfg(feature = "hex")]
    #[error("hex decoding errro")]
    Hex(#[from] hex::FromHexError),
    /// Error decoding base32
    #[cfg(feature = "base32")]
    #[error("base32 decoding error")]
    Base32Error,
    /// Illegal length
    #[error("length mismatch")]
    Length,
}

/// Length (in bytes) of a WireGuard public key (ed25519).
pub const PUBKEY_LEN: usize = 32;

/// Length (in bytes) of a WireGuard private key (ed25519).
pub const PRIVKEY_LEN: usize = 32;

/// Length (in bytes) of a WireGuard preshared key.
pub const SECRET_LEN: usize = 32;

/// WireGuard public key.
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub struct Pubkey([u8; PUBKEY_LEN]);

impl_new!(Pubkey, PUBKEY_LEN);
impl_display!(Pubkey);
impl_deref!(Pubkey, PUBKEY_LEN);
#[cfg(feature = "hex")]
impl_hex!(Pubkey);
#[cfg(feature = "base64")]
impl_base64!(Pubkey);
#[cfg(feature = "base32")]
impl_base32!(Pubkey);
impl_parse!(Pubkey);
#[cfg(feature = "serde")]
impl_serde!(Pubkey, "WireGuard public key");
#[cfg(feature = "rocket")]
impl_rocket!(Pubkey);

impl Pubkey {
    #[cfg(test)]
    fn generate() -> Pubkey {
        Privkey::generate().pubkey()
    }
}

#[test]
fn test_pubkey_from_slice() {
    let slice = [0; 3];
    match Pubkey::try_from(&slice[..]) {
        Err(ParseError::Length) => {}
        _ => assert!(false),
    }
    let slice = [0; PUBKEY_LEN];
    match Pubkey::try_from(&slice[..]) {
        Ok(_) => {}
        _ => assert!(false),
    }
}

impl TryFrom<&[u8]> for Pubkey {
    type Error = ParseError;
    fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
        if key.len() != PUBKEY_LEN {
            Err(ParseError::Length)
        } else {
            let mut data = [0; PUBKEY_LEN];
            data[0..PUBKEY_LEN].copy_from_slice(&key[0..PUBKEY_LEN]);
            Ok(Pubkey(data))
        }
    }
}

/// WireGuard private key.
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub struct Privkey([u8; PRIVKEY_LEN]);

impl_display!(Privkey);
impl_new!(Privkey, PRIVKEY_LEN);
impl_deref!(Privkey, PRIVKEY_LEN);
#[cfg(feature = "hex")]
impl_hex!(Privkey);
#[cfg(feature = "base64")]
impl_base64!(Privkey);
#[cfg(feature = "base32")]
impl_base32!(Privkey);
impl_parse!(Privkey);
#[cfg(feature = "serde")]
impl_serde!(Privkey, "WireGuard private key");
#[cfg(feature = "rocket")]
impl_rocket!(Privkey);

impl Privkey {
    /// Generate new private key using the kernel randomness generator.
    pub fn generate() -> Self {
        let private_key = StaticSecret::new(OsRng);
        Privkey(private_key.to_bytes())
    }

    /// Attempt to check if this private key is valid.
    pub fn valid(&self) -> bool {
        if self.0 == [0; PRIVKEY_LEN] {
            return false;
        }

        let private_key = StaticSecret::from(self.0.clone());
        self.0 == private_key.to_bytes()
    }

    /// Generate the corresponding public key for this private key.
    pub fn pubkey(&self) -> Pubkey {
        let private_key = StaticSecret::from(self.0.clone());
        let public_key: PublicKey = (&private_key).into();
        Pubkey(public_key.to_bytes())
    }
}

#[test]
fn test_privkey_from_slice() {
    let slice = [0; 3];
    match Privkey::try_from(&slice[..]) {
        Err(ParseError::Length) => {}
        _ => assert!(false),
    }
    let slice = [0; PRIVKEY_LEN];
    match Privkey::try_from(&slice[..]) {
        Ok(_) => {}
        _ => assert!(false),
    }
}

impl TryFrom<&[u8]> for Privkey {
    type Error = ParseError;
    fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
        if key.len() != PUBKEY_LEN {
            Err(ParseError::Length)
        } else {
            let mut data = [0; PUBKEY_LEN];
            data[0..PUBKEY_LEN].copy_from_slice(&key[0..PUBKEY_LEN]);
            Ok(Privkey(data))
        }
    }
}

#[test]
fn test_wireguard_privkey() {
    let key = Privkey::new([0; PRIVKEY_LEN]);
    assert_eq!(key.valid(), false);
    let key = Privkey::new([255; PRIVKEY_LEN]);
    assert_eq!(key.valid(), false);
    let key = Privkey::generate();
    assert_eq!(key.valid(), true);
    // always generate same pubkey
    assert_eq!(key.pubkey(), key.pubkey());
}

/// WireGuard preshared key.
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub struct Secret([u8; SECRET_LEN]);

impl_new!(Secret, SECRET_LEN);
impl_display!(Secret);
impl_deref!(Secret, SECRET_LEN);
#[cfg(feature = "hex")]
impl_hex!(Secret);
#[cfg(feature = "base64")]
impl_base64!(Secret);
#[cfg(feature = "base32")]
impl_base32!(Secret);
impl_parse!(Secret);
#[cfg(feature = "serde")]
impl_serde!(Secret, "WireGuard preshared key");
#[cfg(feature = "rocket")]
impl_rocket!(Secret);

impl Secret {
    /// Generate new random preshared key using the system randomness generator.
    pub fn generate() -> Self {
        let mut data = [0; SECRET_LEN];
        OsRng.fill_bytes(&mut data);
        Secret(data)
    }
}

#[test]
fn test_secret_from_slice() {
    let slice = [0; 3];
    match Secret::try_from(&slice[..]) {
        Err(ParseError::Length) => {}
        _ => assert!(false),
    }
    let slice = [0; PRIVKEY_LEN];
    match Secret::try_from(&slice[..]) {
        Ok(_) => {}
        _ => assert!(false),
    }
}

impl TryFrom<&[u8]> for Secret {
    type Error = ParseError;
    fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
        if key.len() != PUBKEY_LEN {
            Err(ParseError::Length)
        } else {
            let mut data = [0; PUBKEY_LEN];
            data[0..PUBKEY_LEN].copy_from_slice(&key[0..PUBKEY_LEN]);
            Ok(Secret(data))
        }
    }
}
