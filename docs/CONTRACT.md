# Credential use contract

## Authorization sequence

1. The client obtains one PA authorization for action `use-credential`, purpose
   `credential-runtime-use`, the hashed credential resource, and the canonical
   use-request body digest.
2. The client sends that authorization envelope and the use request on one Unix
   stream, then sends EOF.
3. Local Control Bridge attests the kernel peer and durably consumes the PA
   request/reservation before creating a `DispatchTicket`.
4. Credential Runtime compares every identity and request binding, issues a
   short lease, consumes it once, and invokes the registered executor.
5. The runtime records a payload-free audit event and returns the bounded
   operation result with a metadata-only receipt.

## Stable schemas

- request: `crowsi://credential-runtime/use-request/v1`
- receipt/result envelope: `crowsi://credential-runtime/use-receipt/v1`
- audit: `crowsi://credential-runtime/audit-event/v1`

Unknown JSON fields, frames over 64 KiB, operation inputs over 32 KiB, operation
outputs over 16 KiB, trailing frames, missing EOF, and I/O deadlines over 30
seconds are rejected.

## Executor registration

Provider code implements `CredentialOperationExecutor` and is compiled into the
purpose-specific daemon. `CredentialOperationContext` exposes borrowed public
metadata and operation input; `SecretValue` is borrowed separately and is
accessible only through a closure. `ExecutorOutput::completed()` is required
for bearer-header injection and opaque server-side use. A sign executor uses
`ExecutorOutput::derived(schema, content_type, payload)` and the schema must be
the exact expected URI declared in the request.

The client-facing API never transports raw credentials. Zixcel may register an
AWS executor in its authenticated workload process; Hatter sends only the
request and consumes the one-time derived response.

The three `fixtures/aws-sign-*.json` files are the normative cross-repository
request, PA control request, and receipt example. Their body and result digests
are covered by the Rust test suite; consumers must not substitute the older
generic HTTP or `use-response/v1` prototype contract.

## Versioning

Any field removal, binding relaxation, output-policy change, or framing change
requires a new schema URI. Additive fields also require a new version because
all current structures deny unknown fields. Canonical dependency updates must
retain exact version pins and pass the complete offline test suite.
