# WireGuard Keys

This is a utility crate for parsing, encoding and generating x25519 keys that are used by WireGuard.
It exports custom types that can be used to store any of these keys, and it has an integration with
`serde` to be able to serialize and deserialize them.

Resources:
- [Documentation (main branch)][rustdoc]
- [Documentation (latest release)][docs]

## Optional Features

These optional features can be enabled:

- `serde`: serialization and deserialization capabilities (enabled by default).
- `hex`: convert to and from hex (enabled by default).
- `base64`: convert to and from base64 (enabled by default).
- `base32`: convert to and from base32.
- `rocket`: ability to parse WireGuard keys from HTTP requests in Rocket.
- `schema`: ability to generate JSON schemas from the types.

[rustdoc]: https://fractalnetworks.gitlab.io/wireguard-keys/doc/wireguard_keys
[docs]: https://docs.rs
