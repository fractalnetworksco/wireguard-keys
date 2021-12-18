# WireGuard Keys

This is a utility crate containing data structures relating to WireGuard. There are
no builds for it, but the RustDoc documentation is published on every commit.

Resources:
- [Source Documentation][rustdoc]

To build this, you want to run `make setup-git` because it will use your SSH keys instead of asking for git credentials (and possibly requiring 2-factor authentication).

## Features

By default, this crate only provides types for WireGuard keys (Pubkey, Privkey, Secret).
These optional features can be enabled:

- `serde`: serialization and deserialization capabilities (enabled by default).
- `hex`: convert to and from hex (enabled by default).
- `base64`: convert to and from base64 (enabled by default).
- `base32`: convert to and from base32.
- `rocket`: ability to parse WireGuard keys from HTTP requests in Rocket.
- `schema`: ability to generate JSON schemas from the types.

[rustdoc]: https://fractalnetworks.gitlab.io/wireguard-keys/doc/wireguard_keys
