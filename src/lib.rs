use rand_core::{OsRng, RngCore};
#[cfg(feature = "rocket")]
use rocket::request::FromParam;
#[cfg(feature = "schema")]
use schemars::JsonSchema;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use thiserror::Error;
use x25519_dalek_fiat::{PublicKey, StaticSecret};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pubkey([u8; 32]);

#[derive(Error, Debug)]
pub enum ParseError {
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

    pub fn from_base64(data: &str) -> Result<Self, ParseError> {
        let data = base64::decode(data)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn from_base64_urlsafe(data: &str) -> Result<Self, ParseError> {
        let data = base64::decode_config(data, base64::URL_SAFE)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn from_hex(data: &str) -> Result<Self, ParseError> {
        let data = hex::decode(data)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn parse(data: &str) -> Result<Self, ParseError> {
        let ret = match data.len() {
            64 => Self::from_hex(data)?,
            44 => Self::from_base64(data).or_else(|_| Self::from_base64_urlsafe(data))?,
            _ => Err(ParseError::Length)?,
        };
        Ok(ret)
    }
}

#[test]
fn test_pubkey_parse() {
    let pubkey = Privkey::generate().pubkey();
    let mut pubkey_hex = pubkey.to_hex();
    assert_eq!(Pubkey::parse(&pubkey_hex).unwrap(), pubkey);
    let pubkey_base64 = pubkey.to_base64();
    assert_eq!(Pubkey::parse(&pubkey_base64).unwrap(), pubkey);
    let pubkey_base64_url = pubkey.to_base64_urlsafe();
    assert_eq!(Pubkey::parse(&pubkey_base64_url).unwrap(), pubkey);
}

#[test]
fn test_pubkey_parse_invalid() {
    match Pubkey::parse("") {
        Err(ParseError::Length) => {}
        _ => assert!(false),
    }
    match Pubkey::parse("abc") {
        Err(ParseError::Length) => {}
        _ => assert!(false),
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
        Ok(pubkey) => {}
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

impl TryFrom<&str> for Pubkey {
    type Error = ParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Pubkey::parse(value)
    }
}

#[cfg(feature = "rocket")]
impl<'r> FromParam<'r> for Pubkey {
    type Error = ParseError;

    fn from_param(param: &'r str) -> Result<Self, Self::Error> {
        Pubkey::parse(param)
    }
}

impl FromStr for Pubkey {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // try decoding as base64
        let data = base64::decode(value);

        // if that fails, try decoding as url-safe base64
        let data = data.or_else(|_| base64::decode_config(value, base64::URL_SAFE));

        let data = data?;

        // make sure the length fits
        if data.len() != PUBKEY_LEN {
            return Err(ParseError::Length);
        }
        let mut key = [0; PUBKEY_LEN];
        key.copy_from_slice(&data);
        Ok(Pubkey(key))
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
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

    pub fn from_base64(data: &str) -> Result<Self, ParseError> {
        let data = base64::decode(data)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn from_base64_urlsafe(data: &str) -> Result<Self, ParseError> {
        let data = base64::decode_config(data, base64::URL_SAFE)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn from_hex(data: &str) -> Result<Self, ParseError> {
        let data = hex::decode(data)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn parse(data: &str) -> Result<Self, ParseError> {
        let ret = match data.len() {
            64 => Self::from_hex(data)?,
            44 => Self::from_base64(data).or_else(|_| Self::from_base64_urlsafe(data))?,
            _ => Err(ParseError::Length)?,
        };
        Ok(ret)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[test]
fn test_privkey_parse() {
    let privkey = Privkey::generate();
    let mut privkey_hex = privkey.to_hex();
    assert_eq!(Privkey::parse(&privkey_hex).unwrap(), privkey);
    let privkey_base64 = privkey.to_base64();
    assert_eq!(Privkey::parse(&privkey_base64).unwrap(), privkey);
    let privkey_base64_url = privkey.to_base64_urlsafe();
    assert_eq!(Privkey::parse(&privkey_base64_url).unwrap(), privkey);
}

#[test]
fn test_privkey_parse_invalid() {
    match Privkey::parse("") {
        Err(ParseError::Length) => {}
        _ => assert!(false),
    }
    match Privkey::parse("abc") {
        Err(ParseError::Length) => {}
        _ => assert!(false),
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
        Ok(pubkey) => {}
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

impl TryFrom<&str> for Privkey {
    type Error = ParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Privkey::parse(value)
    }
}

impl FromStr for Privkey {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Privkey::parse(value)
    }
}

#[cfg(feature = "rocket")]
impl<'r> FromParam<'r> for Privkey {
    type Error = ParseError;

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

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
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

    pub fn generate() -> Self {
        let mut data = [0; SECRET_LEN];
        OsRng.fill_bytes(&mut data);
        Secret(data)
    }

    pub fn from_base64(data: &str) -> Result<Self, ParseError> {
        let data = base64::decode(data)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn from_base64_urlsafe(data: &str) -> Result<Self, ParseError> {
        let data = base64::decode_config(data, base64::URL_SAFE)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn from_hex(data: &str) -> Result<Self, ParseError> {
        let data = hex::decode(data)?;
        Ok(data.as_slice().try_into()?)
    }

    pub fn parse(data: &str) -> Result<Self, ParseError> {
        let ret = match data.len() {
            64 => Self::from_hex(data)?,
            44 => Self::from_base64(data).or_else(|_| Self::from_base64_urlsafe(data))?,
            _ => Err(ParseError::Length)?,
        };
        Ok(ret)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[test]
fn test_secret_parse() {
    let secret = Secret::generate();
    let mut secret_hex = secret.to_hex();
    assert_eq!(Secret::parse(&secret_hex).unwrap(), secret);
    let secret_base64 = secret.to_base64();
    assert_eq!(Secret::parse(&secret_base64).unwrap(), secret);
    let secret_base64_url = secret.to_base64_urlsafe();
    assert_eq!(Secret::parse(&secret_base64_url).unwrap(), secret);
}

#[test]
fn test_secret_parse_invalid() {
    match Secret::parse("") {
        Err(ParseError::Length) => {}
        _ => assert!(false),
    }
    match Secret::parse("abc") {
        Err(ParseError::Length) => {}
        _ => assert!(false),
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
        Ok(pubkey) => {}
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

impl TryFrom<&str> for Secret {
    type Error = ParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Secret::parse(value)
    }
}

impl FromStr for Secret {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Secret::parse(value)
    }
}

#[cfg(feature = "rocket")]
impl<'r> FromParam<'r> for Secret {
    type Error = ParseError;

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
