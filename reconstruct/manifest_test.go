package reconstruct

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"math"
	"testing"
)

func TestManifestRoundTripAndExactVerification(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("canonical bytes for a signed Nomad object")
	manifest, err := NewManifest(data, 0x8e41a9, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := manifest.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != ManifestSize {
		t.Fatalf("manifest size = %d", len(wire))
	}
	parsed, err := ParseManifest(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != manifest {
		t.Fatal("manifest round-trip mismatch")
	}
	if err := parsed.VerifyObject(data); err != nil {
		t.Fatal(err)
	}
}

func TestManifestMetadataTamperRejected(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewManifest([]byte("signed metadata"), 7, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := manifest.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	for _, offset := range []int{4, 12, 20, 36, 68, 100, 164} {
		tampered := append([]byte(nil), wire...)
		tampered[offset] ^= 1
		if _, err := ParseManifest(tampered); err == nil {
			t.Fatalf("tamper at offset %d accepted", offset)
		}
	}
}

func TestManifestRejectsWrongObjectLength(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("length committed by signed manifest")
	manifest, err := NewManifest(data, 1, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.VerifyObject(append(append([]byte(nil), data...), 0)); err == nil {
		t.Fatal("expected object length mismatch")
	}
}

func TestRankIsCanonicalAndNaNIsLowestScore(t *testing.T) {
	var lowID, highID [32]byte
	lowID[31] = 1
	highID[31] = 2
	candidates := []Candidate{
		{ID: highID, Basin: 0, Score: 1},
		{ID: lowID, Basin: 0, Score: 1},
		{Basin: 0, Score: math.NaN()},
	}
	got := Rank(candidates, 0)
	if !bytes.Equal(got[0].ID[:], lowID[:]) || !bytes.Equal(got[1].ID[:], highID[:]) || !math.IsNaN(got[2].Score) {
		t.Fatalf("non-canonical order: %#v", got)
	}
}
