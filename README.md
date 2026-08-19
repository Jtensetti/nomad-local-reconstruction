# nomad-local-reconstruction

Local candidate ordering, decoder orchestration and exact-byte verification for the Nomad experiments.

The package performs no network I/O. It accepts a small decoder interface so the verification layer does not depend on a particular coding implementation.

## Implemented

- local candidate ordering by basin distance, with caller-provided score as a tie-breaker,
- decoder readiness/orchestration,
- SHA-256 commitment checking,
- Ed25519 verification over `nomad-object-v1 || content_hash`,
- rejection of hash/signature tampering and signatures from the wrong domain.

## Scope limits

The verifier assumes the caller already knows the expected public key and content commitment. It does not define SiteID resolution, key rotation, revocation, object metadata, coded-symbol authentication or pollution resistance. A malicious fragment set can still waste decoder work or prevent reconstruction before exact-byte verification is reached.

```bash
go test -race ./...
go vet ./...
```
