package reconstruct

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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

// VerifyEnvelope checks the object signature separately from the manifest
// signature, and the separation is not redundant.
//
// Corrupting the object signature on its own also breaks the manifest
// signature, because signingMessage covers it -- so a test that only flips
// bytes never reaches this check, and a mutation disabling it leaves the suite
// green. The case that does reach it is a manifest a publisher signed
// correctly which attests to an object signature that does not verify: an
// internally consistent document making a false claim.
//
// Without this check the manifest passes, Verifier hands the bad signature to
// the caller, and the failure surfaces later at object verification -- after
// the fragments have been fetched and decoded.
func TestACorrectlySignedManifestCannotVouchForABadObjectSignature(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("an object a publisher means to publish")
	manifest, err := NewManifest(data, 7, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.VerifyEnvelope(); err != nil {
		t.Fatalf("the untampered manifest was refused: %v", err)
	}

	// An object signature over different bytes. Everything else about the
	// manifest stays true, and the publisher signs the result honestly.
	other := sha256.Sum256([]byte("a different object entirely"))
	copy(manifest.ObjectSignature[:], ed25519.Sign(private, SigningMessage(other)))
	copy(manifest.ManifestSignature[:], ed25519.Sign(private, manifest.signingMessage()))

	// The control: the manifest signature really is valid, so what follows is
	// the object-signature check firing and not that one.
	if !ed25519.Verify(public, manifest.signingMessage(), manifest.ManifestSignature[:]) {
		t.Fatal("the fixture's manifest signature is invalid, so this would prove nothing")
	}
	if err := manifest.VerifyEnvelope(); err == nil {
		t.Fatal("a manifest signed correctly by its publisher vouched for an object " +
			"signature that does not verify")
	}
}
