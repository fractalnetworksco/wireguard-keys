use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::string::ToString;
use thiserror::Error;
use x25519_dalek_fiat::{PublicKey, StaticSecret};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct WireguardPubkey([u8; 32]);

#[derive(Error, Debug)]
pub enum WireguardFromError {
    #[error("base64 decoding error")]
    Base64(#[from] base64::DecodeError),
    #[error("length mismatch")]
    Length,
}

const WIREGUARD_PUBKEY_LEN: usize = 32;
const WIREGUARD_PRIVKEY_LEN: usize = 32;
const WIREGUARD_SECRET_LEN: usize = 32;

impl WireguardPubkey {
    pub fn new(data: [u8; WIREGUARD_PUBKEY_LEN]) -> Self {
        WireguardPubkey(data)
    }

    pub fn raw(self) -> [u8; WIREGUARD_PUBKEY_LEN] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn from_base64(data: &str) -> Result<Self, base64::DecodeError> {
        let data = base64::decode(data)?;
        Ok(data.as_slice().into())
    }

    pub fn from_base64_urlsafe(data: &str) -> Result<Self, base64::DecodeError> {
        let data = base64::decode_config(data, base64::URL_SAFE)?;
        Ok(data.as_slice().into())
    }
}

impl From<&[u8]> for WireguardPubkey {
    fn from(key: &[u8]) -> Self {
        let mut data = [0; WIREGUARD_PUBKEY_LEN];
        let len = key.len().max(WIREGUARD_PUBKEY_LEN);
        data[0..len].copy_from_slice(&key[0..len]);
        WireguardPubkey(data)
    }
}

impl TryFrom<&str> for WireguardPubkey {
    type Error = WireguardFromError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let data = base64::decode(value)?;
        if data.len() != WIREGUARD_PUBKEY_LEN {
            return Err(WireguardFromError::Length);
        }
        let mut key = [0; WIREGUARD_PUBKEY_LEN];
        key.copy_from_slice(&data);
        Ok(WireguardPubkey(key))
    }
}

impl FromStr for WireguardPubkey {
    type Err = WireguardFromError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // try decoding as base64
        let data = base64::decode(value);

        // if that fails, try decoding as url-safe base64
        let data = data.or_else(|_| base64::decode_config(value, base64::URL_SAFE));

        let data = data?;

        // make sure the length fits
        if data.len() != WIREGUARD_PUBKEY_LEN {
            return Err(WireguardFromError::Length);
        }
        let mut key = [0; WIREGUARD_PUBKEY_LEN];
        key.copy_from_slice(&data);
        Ok(WireguardPubkey(key))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct WireguardPrivkey([u8; WIREGUARD_PRIVKEY_LEN]);

impl WireguardPrivkey {
    pub fn new(data: [u8; WIREGUARD_PRIVKEY_LEN]) -> Self {
        WireguardPrivkey(data)
    }

    pub fn raw(self) -> [u8; WIREGUARD_PRIVKEY_LEN] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn generate() -> Self {
        let private_key = StaticSecret::new(OsRng);
        WireguardPrivkey(private_key.to_bytes())
    }

    pub fn valid(&self) -> bool {
        if self.0 == [0; WIREGUARD_PRIVKEY_LEN] {
            return false;
        }

        let private_key = StaticSecret::from(self.0.clone());
        self.0 == private_key.to_bytes()
    }

    pub fn pubkey(&self) -> WireguardPubkey {
        let private_key = StaticSecret::from(self.0.clone());
        let public_key: PublicKey = (&private_key).into();
        WireguardPubkey(public_key.to_bytes())
    }

    pub fn from_base64(data: &str) -> Result<Self, base64::DecodeError> {
        let data = base64::decode(data)?;
        Ok(data.as_slice().into())
    }

    pub fn from_base64_urlsafe(data: &str) -> Result<Self, base64::DecodeError> {
        let data = base64::decode_config(data, base64::URL_SAFE)?;
        Ok(data.as_slice().into())
    }
}

impl From<&[u8]> for WireguardPrivkey {
    fn from(key: &[u8]) -> Self {
        let mut data = [0; WIREGUARD_PRIVKEY_LEN];
        let len = key.len().max(WIREGUARD_PRIVKEY_LEN);
        data[0..len].copy_from_slice(&key[0..len]);
        WireguardPrivkey(data)
    }
}

impl TryFrom<&str> for WireguardPrivkey {
    type Error = WireguardFromError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // try decoding as base64
        let data = base64::decode(value);

        // if that fails, try decoding as url-safe base64
        let data = data.or_else(|_| base64::decode_config(value, base64::URL_SAFE));

        let data = data?;

        // make sure the length fits
        if data.len() != WIREGUARD_PRIVKEY_LEN {
            return Err(WireguardFromError::Length);
        }
        let mut key = [0; WIREGUARD_PRIVKEY_LEN];
        key.copy_from_slice(&data);
        Ok(WireguardPrivkey(key))
    }
}

impl FromStr for WireguardPrivkey {
    type Err = WireguardFromError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let data = base64::decode(value)?;
        if data.len() != WIREGUARD_PRIVKEY_LEN {
            return Err(WireguardFromError::Length);
        }
        let mut key = [0; WIREGUARD_PRIVKEY_LEN];
        key.copy_from_slice(&data);
        Ok(WireguardPrivkey(key))
    }
}

#[test]
fn test_wireguard_privkey() {
    let key = WireguardPrivkey::new([0; WIREGUARD_PRIVKEY_LEN]);
    assert_eq!(key.valid(), false);
    let key = WireguardPrivkey::new([255; WIREGUARD_PRIVKEY_LEN]);
    assert_eq!(key.valid(), false);
    let key = WireguardPrivkey::generate();
    assert_eq!(key.valid(), true);
    // always generate same pubkey
    assert_eq!(key.pubkey(), key.pubkey());
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct WireguardSecret([u8; WIREGUARD_SECRET_LEN]);

impl WireguardSecret {
    pub fn new(data: [u8; WIREGUARD_SECRET_LEN]) -> Self {
        WireguardSecret(data)
    }

    pub fn raw(self) -> [u8; WIREGUARD_SECRET_LEN] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn from_base64(data: &str) -> Result<Self, base64::DecodeError> {
        let data = base64::decode(data)?;
        Ok(data.as_slice().into())
    }

    pub fn from_base64_urlsafe(data: &str) -> Result<Self, base64::DecodeError> {
        let data = base64::decode_config(data, base64::URL_SAFE)?;
        Ok(data.as_slice().into())
    }
}

impl From<&[u8]> for WireguardSecret {
    fn from(key: &[u8]) -> Self {
        let mut data = [0; WIREGUARD_SECRET_LEN];
        let len = key.len().max(WIREGUARD_SECRET_LEN);
        data[0..len].copy_from_slice(&key[0..len]);
        WireguardSecret(data)
    }
}

impl TryFrom<&str> for WireguardSecret {
    type Error = WireguardFromError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // try decoding as base64
        let data = base64::decode(value);

        // if that fails, try decoding as url-safe base64
        let data = data.or_else(|_| base64::decode_config(value, base64::URL_SAFE));

        let data = data?;

        // make sure the length fits
        if data.len() != WIREGUARD_SECRET_LEN {
            return Err(WireguardFromError::Length);
        }
        let mut key = [0; WIREGUARD_SECRET_LEN];
        key.copy_from_slice(&data);
        Ok(WireguardSecret(key))
    }
}

impl FromStr for WireguardSecret {
    type Err = WireguardFromError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let data = base64::decode(value)?;
        if data.len() != WIREGUARD_SECRET_LEN {
            return Err(WireguardFromError::Length);
        }
        let mut key = [0; WIREGUARD_SECRET_LEN];
        key.copy_from_slice(&data);
        Ok(WireguardSecret(key))
    }
}

pub trait ToBase64 {
    fn data(&self) -> &[u8];

    fn to_base64(&self) -> String {
        base64::encode(self.data())
    }

    fn to_base64_urlsafe(&self) -> String {
        base64::encode_config(&self.data(), base64::URL_SAFE)
    }
}

impl ToBase64 for WireguardSecret {
    fn data(&self) -> &[u8] {
        self.as_slice()
    }
}

impl ToBase64 for WireguardPrivkey {
    fn data(&self) -> &[u8] {
        self.as_slice()
    }
}

impl ToBase64 for WireguardPubkey {
    fn data(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Display for WireguardSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl Display for WireguardPubkey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl Display for WireguardPrivkey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}
