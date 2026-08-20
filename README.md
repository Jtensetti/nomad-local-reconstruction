# nomad-local-reconstruction

Local candidate ordering, decoder orchestration and exact-byte verification for the Nomad experiments.

The package performs no network I/O. It accepts a small decoder interface so the verification layer does not depend on a particular coding implementation.

## Implemented

- deterministic local candidate ordering by basin distance, score, and opaque ID,
- decoder readiness/orchestration,
- SHA-256 commitment checking,
- Ed25519 verification over `nomad-object-v1 || content_hash`,
- a fixed signed manifest binding length, basin, generation, commitment, key, and object signature,
- rejection of hash/signature tampering and signatures from the wrong domain.

## Scope limits

The manifest is self-authenticating to its embedded publisher key; it does not
prove that this key belongs to a human-facing SiteID. SiteID resolution, key
rotation and revocation require a separate specification. Coded-symbol
authentication and pollution resistance also remain out of scope. A malicious
fragment set can still waste decoder work or prevent reconstruction before
exact-byte verification is reached.

```bash
go test -race ./...
go vet ./...
```
