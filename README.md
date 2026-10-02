# crowsi-credential-runtime

Execute a registered provider adapter inside the credential-custody boundary.

## What you can do

- Consume one authorized credential-use lease.
- Return provider results without exporting the secret.

## Current scope

Only registered adapters and exact authorized operations are eligible. The runtime is not a general secret-export interface.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Examples and interface details

## Public Unix IPC contract

The client writes two 4-byte big-endian length-prefixed JSON frames on one Unix
stream, then half-closes its write side:

1. `crowsi://local-control/ipc-envelope/v2`;
2. `crowsi://credential-runtime/use-request/v1`.

The server writes one
`crowsi://credential-runtime/use-receipt/v1` frame and half-closes. The receipt
contains metadata with `contains_secret_values: false` and one bounded
operation output. It never contains a credential or lease token.

`CredentialRuntimeClient::exchange` implements this sequence.
`FrameTransport` and `UnixFrameTransport` expose the framing to independent
clients; `MemoryFrameTransport` is available only for tests or the explicit
`test-support` feature.

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Detailed documentation](docs) · [Implementation and public interfaces](src) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
