package site

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const vectorPath = "testdata/site-identity-vectors.json"

// TestPublishedVectorsMatch regenerates every vector and compares it to the
// committed file. Run with NOMAD_WRITE_VECTORS=1 to refresh after an
// intentional, reviewed encoding change.
func TestPublishedVectorsMatch(t *testing.T) {
	f := newSiteFixture(t)
	authorizationKey := f.SigningA.Public().(ed25519.PublicKey)

	rotationEncoded, rotation := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := Verify(rotationEncoded, &f.Verified); err != nil {
		t.Fatal(err)
	}
	manifest, _ := buildManifest(t, f.SigningA, "vector object body")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(time.Hour), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}

	generated := make([]Vector, 0, 2)
	genesisVector, err := BuildVector("genesis", f.Verified.Descriptor, authorizationKey, &publication)
	if err != nil {
		t.Fatal(err)
	}
	generated = append(generated, genesisVector)
	rotationVector, err := BuildVector("rotation", rotation, authorizationKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	generated = append(generated, rotationVector)

	encoded, err := json.MarshalIndent(generated, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	if os.Getenv("NOMAD_WRITE_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("regenerated published vectors")
		return
	}

	committed, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("published vectors are missing; regenerate with NOMAD_WRITE_VECTORS=1: %v", err)
	}
	if string(committed) != string(encoded) {
		t.Fatal("published site identity vectors do not match the current encoder")
	}
	var parsed []Vector
	if err := json.Unmarshal(committed, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, vector := range parsed {
		if err := CheckVector(vector); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCanonicalEncodingIsUnambiguousAcrossKeyLists(t *testing.T) {
	f := newSiteFixture(t)
	// Moving a key between the signing and revoked lists must change the
	// preimage: list length prefixes prevent boundary confusion.
	left := f.Verified.Descriptor
	right := left
	right.SigningKeys = []string{encodeKey(f.SigningA)}
	right.RevokedKeys = []string{encodeKey(f.SigningB)}
	leftBytes, err := CanonicalBytes(left)
	if err != nil {
		t.Fatal(err)
	}
	rightBytes, err := CanonicalBytes(right)
	if err != nil {
		t.Fatal(err)
	}
	if string(leftBytes) == string(rightBytes) {
		t.Fatal("canonical encoding must distinguish key list membership")
	}
}

func TestSiteIDDiffersFromDescriptorDigest(t *testing.T) {
	f := newSiteFixture(t)
	digest, err := Digest(f.Verified.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if f.ID == ID(digest) {
		t.Fatal("SiteID and descriptor digest must use distinct domains")
	}
}
