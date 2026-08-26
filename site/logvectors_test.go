package site

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-local-reconstruction/site/transparency"
)

const logCorpusPath = "testdata/site-log-corpus.json"

// logCorpusSeed is a published conformance seed.
//
// It is in the source deliberately, and it is not a credential: it exists so
// anybody can regenerate this corpus byte for byte and check that their
// implementation agrees. It signs nothing outside testdata, authenticates
// nothing, and a deployment that used it would be signing with a key printed in
// a public repository. Published test keys are how RFC 8032 and every
// conformance suite work; hiding this one would make the corpus unreproducible
// without making anything safer.
const logCorpusSeed = "nomad-site-log-conformance-seed"

const logCorpusOrigin = "nomad.example/site-descriptor-log"

func logCorpusKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, logCorpusSeed)
	return ed25519.NewKeyFromSeed(seed)
}

// TestPublishedLogCorpusMatches regenerates the corpus and compares it to the
// committed file. Run with NOMAD_WRITE_VECTORS=1 to refresh after an
// intentional, reviewed encoding change.
func TestPublishedLogCorpusMatches(t *testing.T) {
	f := newSiteFixture(t)
	corpus, err := BuildLogCorpus(logCorpusOrigin, logCorpusKey(t), f.Genesis, testBase)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	if os.Getenv("NOMAD_WRITE_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(logCorpusPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(logCorpusPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("regenerated the published log corpus")
		return
	}

	committed, err := os.ReadFile(logCorpusPath)
	if err != nil {
		t.Fatalf("read the committed corpus: %v", err)
	}
	if string(committed) != string(encoded) {
		t.Fatal("the published log corpus no longer matches what this code produces. " +
			"If the encoding changed on purpose, regenerate with NOMAD_WRITE_VECTORS=1 " +
			"and review the diff -- a corpus that drifts silently is a corpus no second " +
			"implementation can rely on")
	}
}

// The corpus has to be right, not merely stable. A file that both the emitter
// and the comparison agree on can still be wrong in the same way twice, so
// every vector in it is checked here against the verifiers rather than against
// the builder that wrote it.
func TestThePublishedLogCorpusIsInternallySound(t *testing.T) {
	raw, err := os.ReadFile(logCorpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus LogCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Version != LogCorpusVersion {
		t.Fatalf("corpus version is %q", corpus.Version)
	}
	logKey, err := hex.DecodeString(corpus.LogPublicKeyHex)
	if err != nil || len(logKey) != ed25519.PublicKeySize {
		t.Fatalf("corpus log key: %v", err)
	}

	// The RFC 6962 vectors, which are the corpus's own claim to interoperate.
	var reference transparency.Tree
	for _, encoded := range corpus.ReferenceLeavesHex {
		leaf, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		reference.Append(leaf)
	}
	for size, want := range corpus.ReferenceRootsHex {
		root, err := reference.Root(uint64(size))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(root[:]) != want {
			t.Fatalf("reference root at size %d is %x, corpus says %s", size, root, want)
		}
	}

	// Entries: the log-entry construction and its leaf hash.
	for _, entry := range corpus.Entries {
		payload, err := hex.DecodeString(entry.PayloadHex)
		if err != nil {
			t.Fatal(err)
		}
		built := LogEntry(payload)
		if hex.EncodeToString(built) != entry.LogEntryHex {
			t.Fatalf("%s: log entry is %x, corpus says %s", entry.Name, built, entry.LogEntryHex)
		}
		leaf := transparency.HashLeaf(built)
		if hex.EncodeToString(leaf[:]) != entry.LeafHashHex {
			t.Fatalf("%s: leaf hash disagrees with the corpus", entry.Name)
		}
	}

	for _, checkpoint := range corpus.Checkpoints {
		document, err := base64.StdEncoding.DecodeString(checkpoint.DocumentJSONBase64)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := transparency.DecodeCheckpoint(document)
		if err != nil {
			t.Fatalf("checkpoint at size %d does not decode: %v", checkpoint.Size, err)
		}
		verified, err := transparency.VerifyCheckpoint(decoded, corpus.Origin, logKey)
		if err != nil {
			t.Fatalf("checkpoint at size %d does not verify: %v", checkpoint.Size, err)
		}
		if verified.Size != checkpoint.Size {
			t.Fatalf("checkpoint claims size %d, carries %d", checkpoint.Size, verified.Size)
		}
		if hex.EncodeToString(verified.Root[:]) != checkpoint.RootHex {
			t.Fatalf("checkpoint at size %d carries a root the corpus disagrees with",
				checkpoint.Size)
		}
		message := transparency.CheckpointSigningMessage(corpus.Origin, verified.Size,
			verified.Root, decoded.Time)
		if hex.EncodeToString(message) != checkpoint.SigningMessageHex {
			t.Fatalf("checkpoint at size %d: the published signing preimage is not the one "+
				"that was signed", checkpoint.Size)
		}
	}

	for _, item := range corpus.Inclusion {
		entry, err := hex.DecodeString(item.EntryHex)
		if err != nil {
			t.Fatal(err)
		}
		if err := transparency.VerifyInclusion(
			transparency.InclusionProof{Index: item.Index, Size: item.Size,
				Path: decodePath(t, item.PathHex)},
			entry, decodeRootHex(t, item.RootHex)); err != nil {
			t.Fatalf("inclusion %d of %d does not verify: %v", item.Index, item.Size, err)
		}
	}

	for _, item := range corpus.Consistency {
		if err := transparency.VerifyConsistency(
			transparency.ConsistencyProof{Old: item.Old, New: item.New,
				Path: decodePath(t, item.PathHex)},
			decodeRootHex(t, item.OldRootHex), decodeRootHex(t, item.NewRootHex)); err != nil {
			t.Fatalf("consistency %d to %d does not verify: %v", item.Old, item.New, err)
		}
	}

	// The refusals must actually be refused. A corpus of negative cases that
	// something accepts is worse than no corpus: it publishes an assurance
	// that is not there.
	if len(corpus.Refusals) < 10 {
		t.Fatalf("the corpus carries only %d refusals", len(corpus.Refusals))
	}
	// The corpus names a machine tag rather than prose, because the second
	// implementation writes its refusals in its own words. Each side maps its
	// own messages onto the tag; what is compared across implementations is the
	// tag, and what is compared here is that this implementation's message
	// really is about the tagged thing. Without that, almost every case passes
	// on a later check -- an edited root also breaks the signature -- and the
	// check under test could be deleted with nothing noticing.
	expected := map[string]string{
		"version":   "unrecognised checkpoint version",
		"origin":    "is from log",
		"signature": "signature",
		"time":      "checkpoint time",
		"root":      "checkpoint root",
		"duplicate": "duplicate member",
		"unknown":   "unknown field",
	}
	for _, refusal := range corpus.Refusals {
		document, err := base64.StdEncoding.DecodeString(refusal.DocumentJSONBase64)
		if err != nil {
			t.Fatal(err)
		}
		want, known := expected[refusal.Because]
		if !known {
			t.Fatalf("%q is published as refused for %q, which is not a reason this "+
				"implementation knows how to produce", refusal.Name, refusal.Because)
		}
		decoded, err := transparency.DecodeCheckpoint(document)
		if err == nil {
			_, err = transparency.VerifyCheckpoint(decoded, corpus.Origin, logKey)
		}
		if err == nil {
			t.Errorf("%q was accepted; the corpus publishes it as refused for its %s",
				refusal.Name, refusal.Because)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q was refused for %q rather than its %s", refusal.Name, err,
				refusal.Because)
		}
	}
}

func decodePath(t *testing.T, encoded []string) [][32]byte {
	t.Helper()
	path := make([][32]byte, 0, len(encoded))
	for _, value := range encoded {
		path = append(path, decodeRootHex(t, value))
	}
	return path
}

func decodeRootHex(t *testing.T, encoded string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad 32-byte hex %q: %v", encoded, err)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}
