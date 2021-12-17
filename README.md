# WireGuard Util

This is a utility crate containing data structures relating to WireGuard. There are
no builds for it, but the RustDoc documentation is published on every commit.

Resources:
- [Source Documentation][rustdoc]

[rustdoc]: https://fractalnetworks.gitlab.io/wireguard-util/doc/wireguard_util

To build this, you want to run `make setup-git` because it will use your SSH keys instead of asking for git credentials (and possibly requiring 2-factor authentication).

## Features

By default, this crate only provides types for WireGuard keys (pubkey, privkey, secret).
These optional features can be enabled:

- `serde`: add serialization and deserialization capabilities.
- `rocket`: add the ability to parse WireGuard keys from HTTP requests in Rocket.
- `schema`: add the ability to generate JSON schemas from the types.
