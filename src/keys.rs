use rand_core::OsRng;
#[cfg(feature = "with-serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use thiserror::Error;
use x25519_dalek_fiat::{PublicKey, StaticSecret};
#[cfg(feature = "with-rocket")]
use rocket::request::FromParam;

#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pubkey([u8; 32]);

#[derive(Error, Debug)]
pub enum WireguardParseError {
    #[error("base64 decoding error")]
    Base64(#[from] base64::DecodeError),
    #[error("hex decoding errro")]
    Hex(#[from] hex::FromHexError),
    #[error("length mismatch")]
    Length,
}

const PUBKEY_LEN: usize = 32;
const PRIVKEY_LEN: usize = 32;
const SECRET_LEN: usize = 32;

impl Pubkey {
    pub fn new(data: [u8; PUBKEY_LEN]) -> Self {
        Pubkey(data)
    }

    pub fn raw(self) -> [u8; PUBKEY_LEN] {
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

    pub fn from_hex(data: &str) -> Result<Self, hex::FromHexError> {
        let data = hex::decode(data)?;
        Ok(data.as_slice().into())
    }

    pub fn parse(data: &str) -> Result<Self, WireguardParseError> {
        let ret = match data.len() {
            64 => Self::from_hex(data)?,
            44 => Self::from_base64(data).or_else(|_| Self::from_base64_urlsafe(data))?,
            _ => Err(WireguardParseError::Length)?,
        };
        Ok(ret)
    }
}

impl From<&[u8]> for Pubkey {
    fn from(key: &[u8]) -> Self {
        let mut data = [0; PUBKEY_LEN];
        let len = key.len().max(PUBKEY_LEN);
        data[0..len].copy_from_slice(&key[0..len]);
        Pubkey(data)
    }
}

impl TryFrom<&str> for Pubkey {
    type Error = WireguardParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let data = base64::decode(value)?;
        if data.len() != PUBKEY_LEN {
            return Err(WireguardParseError::Length);
        }
        let mut key = [0; PUBKEY_LEN];
        key.copy_from_slice(&data);
        Ok(Pubkey(key))
    }
}

#[cfg(feature = "with-rocket")]
impl<'r> FromParam<'r> for Pubkey {
    type Error = WireguardParseError;

    fn from_param(param: &'r str) -> Result<Self, Self::Error> {
        Pubkey::parse(param)
    }
}

impl FromStr for Pubkey {
    type Err = WireguardParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // try decoding as base64
        let data = base64::decode(value);

        // if that fails, try decoding as url-safe base64
        let data = data.or_else(|_| base64::decode_config(value, base64::URL_SAFE));

        let data = data?;

        // make sure the length fits
        if data.len() != PUBKEY_LEN {
            return Err(WireguardParseError::Length);
        }
        let mut key = [0; PUBKEY_LEN];
        key.copy_from_slice(&data);
        Ok(Pubkey(key))
    }
}

#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Privkey([u8; PRIVKEY_LEN]);

impl Privkey {
    pub fn new(data: [u8; PRIVKEY_LEN]) -> Self {
        Privkey(data)
    }

    pub fn raw(self) -> [u8; PRIVKEY_LEN] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn generate() -> Self {
        let private_key = StaticSecret::new(OsRng);
        Privkey(private_key.to_bytes())
    }

    pub fn valid(&self) -> bool {
        if self.0 == [0; PRIVKEY_LEN] {
            return false;
        }

        let private_key = StaticSecret::from(self.0.clone());
        self.0 == private_key.to_bytes()
    }

    pub fn pubkey(&self) -> Pubkey {
        let private_key = StaticSecret::from(self.0.clone());
        let public_key: PublicKey = (&private_key).into();
        Pubkey(public_key.to_bytes())
    }

    pub fn from_base64(data: &str) -> Result<Self, base64::DecodeError> {
        let data = base64::decode(data)?;
        Ok(data.as_slice().into())
    }

    pub fn from_base64_urlsafe(data: &str) -> Result<Self, base64::DecodeError> {
        let data = base64::decode_config(data, base64::URL_SAFE)?;
        Ok(data.as_slice().into())
    }

    pub fn from_hex(data: &str) -> Result<Self, hex::FromHexError> {
        let data = hex::decode(data)?;
        Ok(data.as_slice().into())
    }

    pub fn parse(data: &str) -> Result<Self, WireguardParseError> {
        let ret = match data.len() {
            64 => Self::from_hex(data)?,
            44 => Self::from_base64(data).or_else(|_| Self::from_base64_urlsafe(data))?,
            _ => Err(WireguardParseError::Length)?,
        };
        Ok(ret)
    }
}

impl From<&[u8]> for Privkey {
    fn from(key: &[u8]) -> Self {
        let mut data = [0; PRIVKEY_LEN];
        let len = key.len().max(PRIVKEY_LEN);
        data[0..len].copy_from_slice(&key[0..len]);
        Privkey(data)
    }
}

impl TryFrom<&str> for Privkey {
    type Error = WireguardParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // try decoding as base64
        let data = base64::decode(value);

        // if that fails, try decoding as url-safe base64
        let data = data.or_else(|_| base64::decode_config(value, base64::URL_SAFE));

        let data = data?;

        // make sure the length fits
        if data.len() != PRIVKEY_LEN {
            return Err(WireguardParseError::Length);
        }
        let mut key = [0; PRIVKEY_LEN];
        key.copy_from_slice(&data);
        Ok(Privkey(key))
    }
}

impl FromStr for Privkey {
    type Err = WireguardParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let data = base64::decode(value)?;
        if data.len() != PRIVKEY_LEN {
            return Err(WireguardParseError::Length);
        }
        let mut key = [0; PRIVKEY_LEN];
        key.copy_from_slice(&data);
        Ok(Privkey(key))
    }
}

#[cfg(feature = "with-rocket")]
impl<'r> FromParam<'r> for Privkey {
    type Error = WireguardParseError;

    fn from_param(param: &'r str) -> Result<Self, Self::Error> {
        Privkey::parse(param)
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

#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Secret([u8; SECRET_LEN]);

impl Secret {
    pub fn new(data: [u8; SECRET_LEN]) -> Self {
        Secret(data)
    }

    pub fn raw(self) -> [u8; SECRET_LEN] {
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

    pub fn from_hex(data: &str) -> Result<Self, hex::FromHexError> {
        let data = hex::decode(data)?;
        Ok(data.as_slice().into())
    }

    pub fn parse(data: &str) -> Result<Self, WireguardParseError> {
        let ret = match data.len() {
            64 => Self::from_hex(data)?,
            44 => Self::from_base64(data).or_else(|_| Self::from_base64_urlsafe(data))?,
            _ => Err(WireguardParseError::Length)?,
        };
        Ok(ret)
    }
}

impl From<&[u8]> for Secret {
    fn from(key: &[u8]) -> Self {
        let mut data = [0; SECRET_LEN];
        let len = key.len().max(SECRET_LEN);
        data[0..len].copy_from_slice(&key[0..len]);
        Secret(data)
    }
}

impl TryFrom<&str> for Secret {
    type Error = WireguardParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // try decoding as base64
        let data = base64::decode(value);

        // if that fails, try decoding as url-safe base64
        let data = data.or_else(|_| base64::decode_config(value, base64::URL_SAFE));

        let data = data?;

        // make sure the length fits
        if data.len() != SECRET_LEN {
            return Err(WireguardParseError::Length);
        }
        let mut key = [0; SECRET_LEN];
        key.copy_from_slice(&data);
        Ok(Secret(key))
    }
}

impl FromStr for Secret {
    type Err = WireguardParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let data = base64::decode(value)?;
        if data.len() != SECRET_LEN {
            return Err(WireguardParseError::Length);
        }
        let mut key = [0; SECRET_LEN];
        key.copy_from_slice(&data);
        Ok(Secret(key))
    }
}

#[cfg(feature = "with-rocket")]
impl<'r> FromParam<'r> for Secret {
    type Error = WireguardParseError;

    fn from_param(param: &'r str) -> Result<Self, Self::Error> {
        Secret::parse(param)
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

impl ToBase64 for Secret {
    fn data(&self) -> &[u8] {
        self.as_slice()
    }
}

impl ToBase64 for Privkey {
    fn data(&self) -> &[u8] {
        self.as_slice()
    }
}

impl ToBase64 for Pubkey {
    fn data(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Display for Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl Display for Pubkey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl Display for Privkey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}
