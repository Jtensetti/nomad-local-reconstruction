package site

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Jtensetti/nomad-local-reconstruction/site/transparency"
)

// The descriptor log's public objects have a consumer that is not the encoder
// that produced them: conformance/reference/nomadsitelog.py, written from
// docs/SITE_IDENTITY.md and RFC 6962 rather than from this repository's Go.
//
// This test is the direction the Python script cannot run: proofs the Python
// implementation built, over a tree this one has never seen, verified here. An
// agreement where Go produced both sides is not an agreement.

type crossLogProofs struct {
	Version    string   `json:"version"`
	EntriesHex []string `json:"entries_hex"`
	Inclusion  []struct {
		Index   uint64   `json:"index"`
		Size    uint64   `json:"size"`
		PathHex []string `json:"path_hex"`
		RootHex string   `json:"root_hex"`
	} `json:"inclusion_proofs"`
	Consistency []struct {
		Old        uint64   `json:"old"`
		New        uint64   `json:"new"`
		PathHex    []string `json:"path_hex"`
		OldRootHex string   `json:"old_root_hex"`
		NewRootHex string   `json:"new_root_hex"`
	} `json:"consistency_proofs"`
}

func TestTheSecondImplementationAgreesAboutTheLog(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available, so the second implementation cannot be run")
	}
	script := filepath.Join("..", "conformance", "reference", "crosscheck_sitelog.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the second implementation is missing: %v", err)
	}
	emitted := filepath.Join(t.TempDir(), "python-proofs.json")

	command := exec.Command(python, script, logCorpusPath, "--emit", emitted)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the second implementation disagreed with the published corpus:\n%s", output)
	}
	t.Logf("second implementation, against the corpus this one published:\n%s", output)

	// Every direction must actually have run. Without this the test passes
	// when a direction is silently skipped, which is how a second
	// implementation stops covering something without anyone noticing.
	for _, direction := range []string{"A:", "B:", "C:", "D:"} {
		if !bytes.Contains(output, []byte(direction)) {
			t.Errorf("direction %s did not run:\n%s", direction, output)
		}
	}
	// A tool that skipped the signatures would report an agreement about
	// encoding while saying nothing about the property the checkpoint exists
	// for, so what it used is asserted rather than logged.
	if !bytes.Contains(output, []byte("signature backend:")) {
		t.Errorf("the second implementation did not say how it checked signatures:\n%s", output)
	}
	if bytes.Contains(output, []byte("signature backend: none")) {
		t.Errorf("the second implementation checked no signatures:\n%s", output)
	}

	raw, err := os.ReadFile(emitted)
	if err != nil {
		t.Fatal(err)
	}
	var produced crossLogProofs
	if err := json.Unmarshal(raw, &produced); err != nil {
		t.Fatal(err)
	}
	if len(produced.Inclusion) < 40 || len(produced.Consistency) < 40 {
		t.Fatalf("the second implementation produced %d inclusion and %d consistency proofs; "+
			"nothing meaningful is being checked",
			len(produced.Inclusion), len(produced.Consistency))
	}

	entries := make([][]byte, 0, len(produced.EntriesHex))
	for _, encoded := range produced.EntriesHex {
		entry, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}

	for _, item := range produced.Inclusion {
		if item.Index >= uint64(len(entries)) {
			t.Fatalf("proof names entry %d of %d", item.Index, len(entries))
		}
		if err := transparency.VerifyInclusion(
			transparency.InclusionProof{Index: item.Index, Size: item.Size,
				Path: decodePath(t, item.PathHex)},
			entries[item.Index], decodeRootHex(t, item.RootHex)); err != nil {
			t.Errorf("an inclusion proof the second implementation built (%d of %d) was "+
				"refused here: %v", item.Index, item.Size, err)
		}
	}
	for _, item := range produced.Consistency {
		if err := transparency.VerifyConsistency(
			transparency.ConsistencyProof{Old: item.Old, New: item.New,
				Path: decodePath(t, item.PathHex)},
			decodeRootHex(t, item.OldRootHex), decodeRootHex(t, item.NewRootHex)); err != nil {
			t.Errorf("a consistency proof the second implementation built (%d to %d) was "+
				"refused here: %v", item.Old, item.New, err)
		}
	}

	// The roots the second implementation computed must be this one's roots.
	// Verifying its proofs against its own roots would only show it is
	// self-consistent.
	var tree transparency.Tree
	for _, entry := range entries {
		tree.Append(entry)
	}
	checked := 0
	for _, item := range produced.Inclusion {
		root, err := tree.Root(item.Size)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(root[:]) != item.RootHex {
			t.Fatalf("at size %d the second implementation computed root %s; this one "+
				"computes %x", item.Size, item.RootHex, root)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no root was compared")
	}
}
