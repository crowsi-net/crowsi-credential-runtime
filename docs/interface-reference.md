# crowsi-credential-runtime interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

## Responsibility

- `crowsi-local-control-bridge` authenticates the Unix peer, verifies the PA
  authorization, and durably consumes its reservation.
- This crate verifies the second frame against the resulting `DispatchTicket`,
  issues and consumes one broker lease, invokes one trusted executor, and emits
  a secret-free audit event.
- A provider adapter such as Zixcel implements `CredentialOperationExecutor`.
  Hatter remains a client and does not receive credential material.

The request binds a service-pairwise subject, device, workload, grant, tenant, service, purpose,
audience, host, resource, action, proof key, provider-input schema and digest,
operation, expected result schema, and TTL. The PA control request's
`body_sha256` must equal `credential_use_body_sha256(request)`. The same
resource, action, and proof key are used to create `LeaseBinding`.

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

## Operation outputs

- `BearerHeader` and `OpaqueSecret` must return `ExecutorOutput::completed()`;
  the runtime creates a fixed JSON result, so an adapter cannot use these
  operations as an arbitrary secret-export channel.
- `Sign` may return `ExecutorOutput::derived(...)`. Its schema must exactly
  equal the request's expected output schema. This supports results such as
  `zixcel://aws/sign-response/v1` with final SigV4 headers.
- Inputs and outputs are bounded, zeroized on drop, redacted from `Debug`, and
  rejected if they contain the raw credential bytes. Audit events retain only
  schemas, digests, sizes, binding digests, and timestamps.

Provider executors remain trusted code. They must not encode or fragment secret
material into a derived output, telemetry, errors, or side channels. See
[SECURITY.md](../SECURITY.md) and [docs/CONTRACT.md](../docs/CONTRACT.md).

## Composition

Construct a broker with an approved store, register a purpose-specific
executor and audit sink, then pass `CredentialRuntimeHandler` to
`LocalControlServer`. No permissive binary or fallback authority is included.
The listener, bridge, runtime handler, broker, and executor must run in the same
dedicated process so peer evidence and borrowed secret use cannot be detached.

## Verify

Dependencies on sibling Crowsi contracts resolve to the canonical local source
registry with exact version pins. Independent releases replace local paths with
the approved private Cargo registry; copied package sources are rejected.
