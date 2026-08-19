# nomad-local-reconstruction

Local-only candidate ranking, reconstruction orchestration and exact object verification for Nomad research.

The package deliberately accepts a `Decoder` interface instead of depending on a particular network-coding repository. That keeps local selection isolated and lets integration tests inject RLNC, erasure coding or other decoders without changing the security boundary.

Implemented:

- local opaque-candidate ranking by basin proximity,
- decoder interface,
- reconstruction threshold handling,
- SHA-256 root verification,
- Ed25519 publisher-signature verification,
- tamper tests.

`Rank` and `Reconstruct` are local operations: no method emits a query or feedback to the network.

```bash
go test ./...
go test -race ./...
go vet ./...
go run ./cmd/reconstruct-demo
```
