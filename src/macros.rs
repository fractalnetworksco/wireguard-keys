#[cfg(feature = "serde")]
macro_rules! impl_serde {
    ($type:ty, $mesg:literal) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    let encoded: String = self.to_string();
                    (&encoded).serialize(serializer)
                } else {
                    self.0.serialize(serializer)
                }
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    struct KeyVisitor;

                    impl<'de> Visitor<'de> for KeyVisitor {
                        type Value = $type;

                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str($mesg)
                        }

                        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                        where
                            E: Error,
                        {
                            <$type>::from_str(s).map_err(Error::custom)
                        }
                    }

                    deserializer.deserialize_str(KeyVisitor)
                } else {
                    let data: [u8; 32] = <[u8; 32]>::deserialize(deserializer)?;
                    Ok(<$type>::new(data))
                }
            }
        }

        paste! {
            #[test]
            fn [<test_ $type:lower _serde>]() {
                use serde_test::{assert_tokens, Configure, Token};
                let example = "yG+Xc4BmcF/j5ChWkOloirX6nWxjWqN3p2nihDtGVW4=";
                let key = <$type>::from_str(example).unwrap();
                assert_tokens(&key.readable(), &[Token::Str(example)]);
                let mut tokens = vec![Token::Tuple { len: 32 }];
                for byte in &key.0 {
                    tokens.push(Token::U8(*byte));
                }
                tokens.push(Token::TupleEnd);
                assert_tokens(&key.compact(), &tokens);
            }
        }
    };
}

#[cfg(feature = "hex")]
macro_rules! impl_hex {
    ($type:ty) => {
        impl $type {
            /// Parse key from hex.
            pub fn from_hex(data: &str) -> Result<Self, ParseError> {
                let data = hex::decode(data)?;
                Ok(data.as_slice().try_into()?)
            }

            /// Encode key as hex.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }
    };
}

#[cfg(feature = "base32")]
macro_rules! impl_base32 {
    ($type:ty) => {
        impl $type {
            /// Base32 alphabet to use.
            const BASE32_ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: true };

            /// Parse key from base32.
            pub fn from_base32(data: &str) -> Result<Self, ParseError> {
                let data =
                    base32::decode(Self::BASE32_ALPHABET, data).ok_or(ParseError::Base32Error)?;
                Ok(data.as_slice().try_into()?)
            }

            /// Encode key as base32.
            pub fn to_base32(&self) -> String {
                base32::encode(Self::BASE32_ALPHABET, &self.0)
            }
        }
    };
}

#[cfg(feature = "base64")]
macro_rules! impl_base64 {
    ($type:ty) => {
        impl $type {
            /// Parse key from base64.
            pub fn from_base64(data: &str) -> Result<Self, ParseError> {
                let data = base64::decode(data)?;
                Ok(data.as_slice().try_into()?)
            }

            /// Parse key from base64 with urlsafe encoding.
            pub fn from_base64_urlsafe(data: &str) -> Result<Self, ParseError> {
                let data = base64::decode_config(data, base64::URL_SAFE)?;
                Ok(data.as_slice().try_into()?)
            }

            /// Encode key as base64.
            pub fn to_base64(&self) -> String {
                base64::encode(&self.0)
            }

            /// Encode key as base64 with urlsafe encoding.
            pub fn to_base64_urlsafe(&self) -> String {
                base64::encode_config(&self.0, base64::URL_SAFE)
            }
        }
    };
}

macro_rules! impl_parse {
    ($type:ty) => {
        impl $type {
            /// Try parsing from string.
            pub fn parse(data: &str) -> Result<Self, ParseError> {
                let ret = match data.len() {
                    #[cfg(feature = "hex")]
                    64 => Self::from_hex(data)?,
                    #[cfg(feature = "base64")]
                    44 => Self::from_base64(data).or_else(|_| Self::from_base64_urlsafe(data))?,
                    #[cfg(feature = "base32")]
                    56 => Self::from_base32(data)?,
                    _ => Err(ParseError::Length)?,
                };
                Ok(ret)
            }
        }

        impl TryFrom<&str> for $type {
            type Error = ParseError;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                <$type>::parse(value)
            }
        }

        impl FromStr for $type {
            type Err = ParseError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                <$type>::parse(value)
            }
        }

        paste! {
            #[test]
            fn [<test_ $type:lower _parse>]() {
                let value = <$type>::generate();
                #[cfg(feature = "hex")]
                {
                    let value_hex = value.to_hex();
                    assert_eq!(<$type>::parse(&value_hex).unwrap(), value);
                }
                #[cfg(feature = "base64")]
                {
                    let value_base64 = value.to_base64();
                    assert_eq!(<$type>::parse(&value_base64).unwrap(), value);
                    let value_base64_url = value.to_base64_urlsafe();
                    assert_eq!(<$type>::parse(&value_base64_url).unwrap(), value);
                }
                #[cfg(feature = "base32")]
                {
                    let value_base32 = value.to_base32();
                    assert_eq!(<$type>::parse(&value_base32).unwrap(), value);
                }
            }

            #[test]
            fn [<test_ $type:lower _parse_invalid>]() {
                match <$type>::parse("") {
                    Err(ParseError::Length) => {}
                    _ => assert!(false),
                }
                match <$type>::parse("abc") {
                    Err(ParseError::Length) => {}
                    _ => assert!(false),
                }
            }
        }
    };
}

#[cfg(feature = "rocket")]
macro_rules! impl_rocket {
    ($type:ty) => {
        impl<'r> FromParam<'r> for $type {
            type Error = ParseError;

            fn from_param(param: &'r str) -> Result<Self, Self::Error> {
                <$type>::parse(param)
            }
        }
    };
}

macro_rules! impl_new {
    ($type:ty, $len:expr) => {
        impl $type {
            /// Create new from existing data. Warning: this function does not check
            /// if the passed data is valid.
            pub fn new(data: [u8; $len]) -> Self {
                Self(data)
            }
        }
    };
}

macro_rules! impl_deref {
    ($type:ty, $len:expr) => {
        impl std::ops::Deref for $type {
            type Target = [u8; $len];
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

macro_rules! impl_display {
    ($type:ty) => {
        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                #[cfg(feature = "base64")]
                return write!(f, "{}", self.to_base64());
                #[cfg(all(not(feature = "base64"), feature = "hex"))]
                return write!(f, "{}", self.to_hex());
                #[cfg(all(not(feature = "base64"), not(feature = "hex"), feature = "base32"))]
                return write!(f, "{}", self.to_base32());
                #[cfg(all(
                    not(feature = "base64"),
                    not(feature = "hex"),
                    not(feature = "base32")
                ))]
                return unimplemented!();
            }
        }

        paste! {
            #[cfg(any(feature = "base64", feature = "hex", feature = "base32"))]
            #[test]
            fn [<test_ $type:lower _display>]() {
                let value = <$type>::generate();
                let display = value.to_string();
                let parsed = <$type>::parse(&display).unwrap();
                assert_eq!(value, parsed);
            }
        }
    };
}
