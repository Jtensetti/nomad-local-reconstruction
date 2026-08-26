package site

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Jtensetti/nomad-local-reconstruction/site/transparency"
)

// The descriptor log's published conformance corpus.
//
// Every object here is one a verifier who is not the log has to read: the log
// entry, the signed checkpoint, and the two proof shapes. An implementation
// only the log's own code can parse is a log nobody can check, which would
// leave the distribution property true only for the party it is meant to
// constrain.
//
// The corpus carries preimages, not just results. Reproducing a root from a
// path requires producing every intermediate byte exactly, so a second
// implementation that agrees on these has agreed on the encoding rather than on
// a summary of it.

// LogCorpusVersion is the frozen label for the published log corpus.
const LogCorpusVersion = "nomad-site-log-corpus-v1"

// LogCorpusEntry is one entry as it appears in the log.
type LogCorpusEntry struct {
	Name string `json:"name"`
	// PayloadHex is the bytes handed to the log. For a descriptor entry this
	// is the encoded descriptor; the short synthetic entries exist so the
	// proof vectors below stay readable.
	PayloadHex  string `json:"payload_hex"`
	LogEntryHex string `json:"log_entry_hex"`
	LeafHashHex string `json:"leaf_hash_hex"`
}

// LogCorpusCheckpoint is a signed head with its signing preimage.
type LogCorpusCheckpoint struct {
	Size               uint64 `json:"size"`
	RootHex            string `json:"root_hex"`
	SigningMessageHex  string `json:"signing_message_hex"`
	DocumentJSONBase64 string `json:"document_json_base64"`
}

// LogCorpusInclusion is one inclusion proof and everything needed to check it.
type LogCorpusInclusion struct {
	Index    uint64   `json:"index"`
	Size     uint64   `json:"size"`
	EntryHex string   `json:"entry_hex"`
	PathHex  []string `json:"path_hex"`
	RootHex  string   `json:"root_hex"`
}

// LogCorpusConsistency is one consistency proof and its two heads.
type LogCorpusConsistency struct {
	Old        uint64   `json:"old"`
	New        uint64   `json:"new"`
	PathHex    []string `json:"path_hex"`
	OldRootHex string   `json:"old_root_hex"`
	NewRootHex string   `json:"new_root_hex"`
}

// LogCorpusRefusal is a document every implementation must refuse.
//
// Two implementations that both accept everything also interoperate. These are
// what makes the agreement mean something, and each names what must be caught
// rather than only that something must be.
type LogCorpusRefusal struct {
	Name               string `json:"name"`
	Because            string `json:"because"`
	DocumentJSONBase64 string `json:"document_json_base64"`
}

// LogCorpus is the published corpus.
type LogCorpus struct {
	Version string `json:"version"`
	Origin  string `json:"origin"`
	// LogPublicKeyHex is a conformance key. It signs nothing in production and
	// authenticates nothing outside this file.
	LogPublicKeyHex string `json:"log_public_key_hex"`
	// ReferenceLeavesHex and ReferenceRootsHex are RFC 6962's own published
	// vectors, root sizes 0..8 in order. They are here so an implementation
	// can establish it agrees with the standard before it tries to agree with
	// this one.
	ReferenceLeavesHex []string               `json:"rfc6962_reference_leaves_hex"`
	ReferenceRootsHex  []string               `json:"rfc6962_reference_roots_hex"`
	Entries            []LogCorpusEntry       `json:"entries"`
	Checkpoints        []LogCorpusCheckpoint  `json:"checkpoints"`
	Inclusion          []LogCorpusInclusion   `json:"inclusion_proofs"`
	Consistency        []LogCorpusConsistency `json:"consistency_proofs"`
	Refusals           []LogCorpusRefusal     `json:"refusals"`
}

var referenceCorpusLeaves = [][]byte{
	{},
	{0x00},
	{0x10},
	{0x20, 0x21},
	{0x30, 0x31},
	{0x40, 0x41, 0x42, 0x43},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
	{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
}

// BuildLogCorpus derives the complete published corpus.
//
// descriptorEncoded is a real encoded descriptor, so the log-entry construction
// is pinned against something a site actually publishes rather than against a
// string chosen to make the vector tidy.
func BuildLogCorpus(origin string, private ed25519.PrivateKey, descriptorEncoded []byte,
	when time.Time) (LogCorpus, error) {
	if len(private) != ed25519.PrivateKeySize {
		return LogCorpus{}, errors.New("corpus signing key is not an Ed25519 private key")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return LogCorpus{}, errors.New("corpus signing key has no public half")
	}

	corpus := LogCorpus{
		Version:         LogCorpusVersion,
		Origin:          origin,
		LogPublicKeyHex: hex.EncodeToString(public),
	}

	var reference transparency.Tree
	for _, leaf := range referenceCorpusLeaves {
		corpus.ReferenceLeavesHex = append(corpus.ReferenceLeavesHex, hex.EncodeToString(leaf))
		reference.Append(leaf)
	}
	for size := uint64(0); size <= reference.Size(); size++ {
		root, err := reference.Root(size)
		if err != nil {
			return LogCorpus{}, err
		}
		corpus.ReferenceRootsHex = append(corpus.ReferenceRootsHex, hex.EncodeToString(root[:]))
	}

	payloads := [][]byte{
		descriptorEncoded,
		[]byte("second entry"),
		[]byte("third entry"),
		[]byte(""),
		[]byte("fifth entry"),
	}
	names := []string{"a genesis descriptor", "a short entry", "another short entry",
		"an empty entry", "a fifth entry"}

	log, err := transparency.NewLog(origin, private)
	if err != nil {
		return LogCorpus{}, err
	}
	var tree transparency.Tree
	for index, payload := range payloads {
		entry := LogEntry(payload)
		leaf := transparency.HashLeaf(entry)
		corpus.Entries = append(corpus.Entries, LogCorpusEntry{
			Name:        names[index],
			PayloadHex:  hex.EncodeToString(payload),
			LogEntryHex: hex.EncodeToString(entry),
			LeafHashHex: hex.EncodeToString(leaf[:]),
		})
		log.Append(entry)
		tree.Append(entry)
	}

	for size := uint64(1); size <= tree.Size(); size++ {
		root, err := tree.Root(size)
		if err != nil {
			return LogCorpus{}, err
		}
		checkpoint, err := log.CheckpointAt(size, when.Add(time.Duration(size)*time.Minute))
		if err != nil {
			return LogCorpus{}, err
		}
		document, err := transparency.EncodeCheckpoint(checkpoint)
		if err != nil {
			return LogCorpus{}, err
		}
		corpus.Checkpoints = append(corpus.Checkpoints, LogCorpusCheckpoint{
			Size:    size,
			RootHex: hex.EncodeToString(root[:]),
			SigningMessageHex: hex.EncodeToString(transparency.CheckpointSigningMessage(
				checkpoint.Origin, checkpoint.Size, root, checkpoint.Time)),
			DocumentJSONBase64: base64.StdEncoding.EncodeToString(document),
		})
	}

	// Every entry against every head it is in, so an implementation that only
	// handles the balanced cases is caught.
	for size := uint64(1); size <= tree.Size(); size++ {
		root, err := tree.Root(size)
		if err != nil {
			return LogCorpus{}, err
		}
		for index := uint64(0); index < size; index++ {
			proof, err := tree.ProveInclusion(index, size)
			if err != nil {
				return LogCorpus{}, err
			}
			corpus.Inclusion = append(corpus.Inclusion, LogCorpusInclusion{
				Index:    index,
				Size:     size,
				EntryHex: hex.EncodeToString(LogEntry(payloads[index])),
				PathHex:  hexPath(proof.Path),
				RootHex:  hex.EncodeToString(root[:]),
			})
		}
	}

	for older := uint64(0); older <= tree.Size(); older++ {
		oldRoot, err := tree.Root(older)
		if err != nil {
			return LogCorpus{}, err
		}
		for newer := older; newer <= tree.Size(); newer++ {
			newRoot, err := tree.Root(newer)
			if err != nil {
				return LogCorpus{}, err
			}
			proof, err := tree.ProveConsistency(older, newer)
			if err != nil {
				return LogCorpus{}, err
			}
			corpus.Consistency = append(corpus.Consistency, LogCorpusConsistency{
				Old:        older,
				New:        newer,
				PathHex:    hexPath(proof.Path),
				OldRootHex: hex.EncodeToString(oldRoot[:]),
				NewRootHex: hex.EncodeToString(newRoot[:]),
			})
		}
	}

	refusals, err := buildLogRefusals(log, when)
	if err != nil {
		return LogCorpus{}, err
	}
	corpus.Refusals = refusals
	return corpus, nil
}

func hexPath(path [][32]byte) []string {
	out := make([]string, 0, len(path))
	for _, hash := range path {
		out = append(out, hex.EncodeToString(hash[:]))
	}
	return out
}

func buildLogRefusals(log *transparency.Log, when time.Time) ([]LogCorpusRefusal, error) {
	good, err := log.Checkpoint(when)
	if err != nil {
		return nil, err
	}
	other, err := log.CheckpointAt(1, when)
	if err != nil {
		return nil, err
	}

	edit := func(change func(*transparency.Checkpoint)) (string, error) {
		copied := good
		change(&copied)
		document, err := transparency.EncodeCheckpoint(copied)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(document), nil
	}

	type candidate struct {
		name    string
		because string
		change  func(*transparency.Checkpoint)
	}
	candidates := []candidate{
		{"an unrecognised version", "version",
			func(c *transparency.Checkpoint) { c.Version = transparency.CheckpointVersion + "x" }},
		{"another origin", "origin",
			func(c *transparency.Checkpoint) { c.Origin = "somewhere.else/log" }},
		{"an edited size", "signature",
			func(c *transparency.Checkpoint) { c.Size++ }},
		{"another head's root", "signature",
			func(c *transparency.Checkpoint) { c.Root = other.Root }},
		{"an edited time", "signature",
			func(c *transparency.Checkpoint) { c.Time = "2030-01-01T00:00:00Z" }},
		{"a time with an offset instead of Z", "time",
			func(c *transparency.Checkpoint) { c.Time = "2026-08-26T14:00:00+01:00" }},
		{"a time with fractional seconds", "time",
			func(c *transparency.Checkpoint) { c.Time = "2026-08-26T12:00:00.500Z" }},
		{"a root in upper-case hex", "root",
			func(c *transparency.Checkpoint) { c.Root = upperHex(c.Root) }},
		{"a root one byte short", "root",
			func(c *transparency.Checkpoint) { c.Root = c.Root[:62] }},
		{"a signature of the wrong length", "signature",
			func(c *transparency.Checkpoint) {
				c.Signature = base64.StdEncoding.EncodeToString(make([]byte, 63))
			}},
		{"a signature with an embedded newline", "signature",
			func(c *transparency.Checkpoint) {
				c.Signature = c.Signature[:40] + "\n" + c.Signature[40:]
			}},
		{"a flipped signature byte", "signature",
			func(c *transparency.Checkpoint) {
				raw := []byte(c.Signature)
				if raw[0] == 'A' {
					raw[0] = 'B'
				} else {
					raw[0] = 'A'
				}
				c.Signature = string(raw)
			}},
	}

	refusals := make([]LogCorpusRefusal, 0, len(candidates)+2)
	for _, item := range candidates {
		document, err := edit(item.change)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", item.name, err)
		}
		refusals = append(refusals, LogCorpusRefusal{
			Name: item.name, Because: item.because, DocumentJSONBase64: document,
		})
	}

	// Two documents no struct can express, so they are assembled as text: a
	// duplicate member and an unknown one. Both are refused by construction
	// rather than by the schema, and both are exactly where two JSON parsers
	// most easily disagree.
	encoded, err := transparency.EncodeCheckpoint(good)
	if err != nil {
		return nil, err
	}
	text := string(encoded)
	refusals = append(refusals,
		LogCorpusRefusal{
			Name: "a duplicate member", Because: "duplicate",
			DocumentJSONBase64: base64.StdEncoding.EncodeToString(
				[]byte(`{"size":99,` + text[1:])),
		},
		LogCorpusRefusal{
			Name: "an unknown member", Because: "unknown",
			DocumentJSONBase64: base64.StdEncoding.EncodeToString(
				[]byte(`{"surprise":1,` + text[1:])),
		})
	return refusals, nil
}

func upperHex(value string) string {
	out := []byte(value)
	for index, char := range out {
		if char >= 'a' && char <= 'f' {
			out[index] = char - ('a' - 'A')
		}
	}
	return string(out)
}
