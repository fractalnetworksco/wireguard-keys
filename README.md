# WireGuard Keys

This is a utility crate for parsing, encoding and generating x25519 keys that are used by WireGuard.
It exports custom types that can be used to store any of these keys, and it has an integration with
`serde` to be able to serialize and deserialize them.

You can use this crate if you want to generate private keys for use with WireGuard, or if you want
to encode and parse WireGuard keys (such as reading them from JSON documents).

Resources:
- Documentation: [nightly][rustdoc], [latest release][docs]
- Crates.io [wireguard-keys][cratesio]

## Example code

Generating private and public x25519 keys, and preshared keys for use with WireGuard.

```rust
use wireguard_keys::{Privkey, Pubkey};

// generate private key
let privkey = Privkey::generate();

// generate public key from private key
let pubkey: Pubkey = privkey.pubkey();

// generate secret
let secret = Secret::generate();
```

Encoding and parsing keys.

```rust
use wireguard_keys::{Privkey, Pubkey};

// can export.
Privkey::generate().to_string() // => "INBg4AAN7tRyXTyXMEYFP93oBWfRYvH5oty03+H32nY="

// can parse
let privkey = Privkey::from_str("INBg4AAN7tRyXTyXMEYFP93oBWfRYvH5oty03+H32nY=").unwrap();
```

## Optional features

These optional features can be enabled:

- `serde`: serialization and deserialization capabilities (enabled by default).
- `hex`: convert to and from hex (enabled by default).
- `base64`: convert to and from base64 (enabled by default).
- `base32`: convert to and from base32.
- `rocket`: ability to parse WireGuard keys from HTTP requests in Rocket.
- `schema`: ability to generate JSON schemas from the types.

[rustdoc]: https://fractalnetworks.gitlab.io/libraries/wireguard-keys/doc/wireguard_keys
[docs]: https://docs.rs
[cratesio]: https://crates.io/crates/wireguard-keys
