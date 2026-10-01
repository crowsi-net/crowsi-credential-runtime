# Security policy

## Invariants

- The only production entry is an authenticated `DispatchTicket` created by
  `crowsi-local-control-bridge` from the same Unix stream.
- PA `body_sha256`, the canonical runtime request, ticket resource, and broker
  lease binding must match exactly. Any mismatch fails closed before use.
- Leases last at most 300 seconds and are consumed once. The bridge also keeps
  durable replay state, so restarting this runtime does not restore authority.
- Credentials are borrowed only by an in-process, registered executor through
  `SecretValue::expose`; they have no `Debug` or `Serialize` implementation.
- Bearer and opaque operations return only a runtime-generated completion body.
  Sign results are bounded and accepted only under the exact requested schema.
- Operation input, derived output, IPC buffers, and executor payload buffers
  are zeroized on drop. Raw credential bytes in input or output are rejected.
- Receipts contain safe credential metadata for the authorized caller. Audit
  events contain only digests for credential and identity references, and no
  secret, lease token, PA authorization, provider input, or output payload.
- Storage, entropy, clock, audit, transport, adapter, and validation errors deny
  the operation. There is no environment-variable or plaintext-file fallback.

## Trusted adapter rule

An executor is inside the credential trust boundary. The runtime blocks direct
raw-byte copying, but no generic API can prove that malicious trusted code did
not transform or exfiltrate a secret. Review and pin each adapter, restrict its
network destinations, run it under a dedicated identity, and test its output
schema. Never register dynamically supplied code.

AWS-style adapters should accept a canonical bounded sign request and return
only the exact declared sign-response schema. Bind method, URI, signed headers,
body digest, region, service, audience, and expiry in the operation input. Do
not return the long-lived secret access key.

## Deployment

Use an owner-only Unix socket directory and finite I/O deadlines. Compose the
runtime with the bridge and broker in one process. Require an OS-backed or
managed credential store, a durable bridge database, trusted time, executable
digest attestation, sender-constrained PA authorization, and a durable audit
sink. Keep provider egress allow-listed by Crowsi policy.

On disclosure or adapter compromise, revoke the pairwise subject/device/workload/grant
leases, advance the applicable subject/service/device/session bridge epoch,
isolate provider egress, rotate
the provider credential, and retain only metadata audit evidence.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
