# Using crowsi-credential-runtime

Execute a registered provider adapter inside the credential-custody boundary.

## Before you start

Only registered adapters and exact authorized operations are eligible. The runtime is not a general secret-export interface.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Consume one authorized credential-use lease.
- Return provider results without exporting the secret.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
