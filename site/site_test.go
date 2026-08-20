package site

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
)

var testBase = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func deterministicKey(t *testing.T, label string) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("nomad-site-test-" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func encodeKey(private ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
}

type siteFixture struct {
	SigningA ed25519.PrivateKey
	SigningB ed25519.PrivateKey
	Rotated  ed25519.PrivateKey
	Rescued  ed25519.PrivateKey
	RecoverA ed25519.PrivateKey
	RecoverB ed25519.PrivateKey
	ID       ID
	Genesis  []byte
	Verified Verified
}

func newSiteFixture(t *testing.T) *siteFixture {
	t.Helper()
	f := &siteFixture{
		SigningA: deterministicKey(t, "signing-a"),
		SigningB: deterministicKey(t, "signing-b"),
		Rotated:  deterministicKey(t, "rotated"),
		Rescued:  deterministicKey(t, "rescued"),
		RecoverA: deterministicKey(t, "recovery-a"),
		RecoverB: deterministicKey(t, "recovery-b"),
	}
	descriptor := Descriptor{
		Version: DescriptorVersion, SiteID: hex.EncodeToString(make([]byte, 32)), Sequence: 0,
		Transition: TransitionGenesis, PreviousDescriptorDigest: hex.EncodeToString(make([]byte, 32)),
		ValidFrom: canonicalTime(testBase), ValidUntil: canonicalTime(testBase.Add(365 * 24 * time.Hour)),
		SigningKeys: []string{encodeKey(f.SigningA), encodeKey(f.SigningB)},
		RevokedKeys: []string{},
		Recovery:    Recovery{Threshold: 2, Keys: []string{encodeKey(f.RecoverA), encodeKey(f.RecoverB)}},
	}
	id, err := DeriveID(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SiteID = hex.EncodeToString(id[:])
	descriptor.Authorizations = authorizeAll(t, descriptor,
		[]ed25519.PrivateKey{f.SigningA, f.SigningB}, []ed25519.PrivateKey{f.RecoverA, f.RecoverB})
	encoded, err := Encode(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.ID, f.Genesis, f.Verified = id, encoded, verified
	return f
}

func canonicalTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func authorizeAll(t *testing.T, descriptor Descriptor, signing, recovery []ed25519.PrivateKey) []Authorization {
	t.Helper()
	authorizations := make([]Authorization, 0, len(signing)+len(recovery))
	for _, key := range signing {
		authorization, err := Authorize(descriptor, "signing", key)
		if err != nil {
			t.Fatal(err)
		}
		authorizations = append(authorizations, authorization)
	}
	for _, key := range recovery {
		authorization, err := Authorize(descriptor, "recovery", key)
		if err != nil {
			t.Fatal(err)
		}
		authorizations = append(authorizations, authorization)
	}
	return authorizations
}

// rotation builds a successor descriptor with the given signing keys,
// authorized by the supplied keys in the given role.
func (f *siteFixture) successor(t *testing.T, previous Verified, transition string, signingKeys []ed25519.PrivateKey, revoked []string, signers []ed25519.PrivateKey, role string) ([]byte, Descriptor) {
	t.Helper()
	keys := make([]string, 0, len(signingKeys))
	for _, key := range signingKeys {
		keys = append(keys, encodeKey(key))
	}
	descriptor := Descriptor{
		Version: DescriptorVersion, SiteID: hex.EncodeToString(f.ID[:]),
		Sequence: previous.Descriptor.Sequence + 1, Transition: transition,
		PreviousDescriptorDigest: hex.EncodeToString(previous.Digest[:]),
		ValidFrom:                canonicalTime(testBase), ValidUntil: canonicalTime(testBase.Add(365 * 24 * time.Hour)),
		SigningKeys: keys, RevokedKeys: revoked,
		Recovery: previous.Descriptor.Recovery,
	}
	for _, signer := range signers {
		authorization, err := Authorize(descriptor, role, signer)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Authorizations = append(descriptor.Authorizations, authorization)
	}
	encoded, err := Encode(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, descriptor
}

func TestSiteIDDerivesFromGenesisAndIsSelfCertifying(t *testing.T) {
	f := newSiteFixture(t)
	derived, err := DeriveID(f.Verified.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if derived != f.ID {
		t.Fatal("SiteID must re-derive from its genesis descriptor")
	}
	// Changing any covered field changes the SiteID.
	altered := f.Verified.Descriptor
	altered.Recovery.Threshold = 1
	other, err := DeriveID(altered)
	if err != nil {
		t.Fatal(err)
	}
	if other == f.ID {
		t.Fatal("SiteID must commit to the recovery policy")
	}
}

func TestGenesisRequiresEverySelfSignature(t *testing.T) {
	f := newSiteFixture(t)
	descriptor := f.Verified.Descriptor
	descriptor.Authorizations = descriptor.Authorizations[:len(descriptor.Authorizations)-1]
	if _, err := VerifyDescriptor(descriptor, nil); err == nil {
		t.Fatal("genesis missing a recovery self-signature must be rejected")
	}
	descriptor = f.Verified.Descriptor
	descriptor.Authorizations = descriptor.Authorizations[1:]
	if _, err := VerifyDescriptor(descriptor, nil); err == nil {
		t.Fatal("genesis missing a signing self-signature must be rejected")
	}
}

func TestGenesisRejectsMismatchedSiteID(t *testing.T) {
	f := newSiteFixture(t)
	descriptor := f.Verified.Descriptor
	wrong := sha256.Sum256([]byte("not-this-site"))
	descriptor.SiteID = hex.EncodeToString(wrong[:])
	if _, err := VerifyDescriptor(descriptor, nil); err == nil {
		t.Fatal("genesis whose site_id is not its own derivation must be rejected")
	}
}

func TestRotationRequiresPreviousSigningMajority(t *testing.T) {
	f := newSiteFixture(t)
	// Authorized by one of two signing keys: not a majority (needs 2).
	encoded, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA}, "signing")
	if _, err := Verify(encoded, &f.Verified); err == nil {
		t.Fatal("rotation below the signing majority must be rejected")
	}
	encoded, _ = f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := Verify(encoded, &f.Verified); err != nil {
		t.Fatalf("rotation with the full signing set must verify: %v", err)
	}
}

func TestRotationCannotBeAuthorizedByRecoveryKeys(t *testing.T) {
	f := newSiteFixture(t)
	encoded, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.RecoverA, f.RecoverB}, "recovery")
	if _, err := Verify(encoded, &f.Verified); err == nil {
		t.Fatal("recovery keys must not authorize a routine rotation")
	}
}

func TestRecoveryRequiresThresholdAndRevokesPriorSigning(t *testing.T) {
	f := newSiteFixture(t)
	revoked := []string{encodeKey(f.SigningA), encodeKey(f.SigningB)}

	// Below threshold.
	encoded, _ := f.successor(t, f.Verified, TransitionRecovery,
		[]ed25519.PrivateKey{f.Rescued}, revoked, []ed25519.PrivateKey{f.RecoverA}, "recovery")
	if _, err := Verify(encoded, &f.Verified); err == nil {
		t.Fatal("recovery below threshold must be rejected")
	}
	// Signing keys cannot substitute for recovery authority.
	encoded, _ = f.successor(t, f.Verified, TransitionRecovery,
		[]ed25519.PrivateKey{f.Rescued}, revoked, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := Verify(encoded, &f.Verified); err == nil {
		t.Fatal("stolen signing keys must not authorize recovery")
	}
	// Recovery that fails to revoke the compromised set.
	encoded, _ = f.successor(t, f.Verified, TransitionRecovery,
		[]ed25519.PrivateKey{f.Rescued}, []string{}, []ed25519.PrivateKey{f.RecoverA, f.RecoverB}, "recovery")
	if _, err := Verify(encoded, &f.Verified); err == nil {
		t.Fatal("recovery must revoke every previously active signing key")
	}
	// Correct recovery.
	encoded, _ = f.successor(t, f.Verified, TransitionRecovery,
		[]ed25519.PrivateKey{f.Rescued}, revoked, []ed25519.PrivateKey{f.RecoverA, f.RecoverB}, "recovery")
	verified, err := Verify(encoded, &f.Verified)
	if err != nil {
		t.Fatalf("valid recovery must verify: %v", err)
	}
	if verified.AuthorizesKey(f.SigningA.Public().(ed25519.PublicKey)) {
		t.Fatal("a revoked signing key must not remain authorized")
	}
	if !verified.AuthorizesKey(f.Rescued.Public().(ed25519.PublicKey)) {
		t.Fatal("the recovered key must be authorized")
	}
}

func TestRevocationIsAbsorbing(t *testing.T) {
	f := newSiteFixture(t)
	revoked := []string{encodeKey(f.SigningA), encodeKey(f.SigningB)}
	encoded, _ := f.successor(t, f.Verified, TransitionRecovery,
		[]ed25519.PrivateKey{f.Rescued}, revoked, []ed25519.PrivateKey{f.RecoverA, f.RecoverB}, "recovery")
	recovered, err := Verify(encoded, &f.Verified)
	if err != nil {
		t.Fatal(err)
	}
	// A later rotation attempting to reinstate a revoked key.
	reinstate, _ := f.successor(t, recovered, TransitionRotation,
		[]ed25519.PrivateKey{f.SigningA}, revoked, []ed25519.PrivateKey{f.Rescued}, "signing")
	if _, err := Verify(reinstate, &recovered); err == nil {
		t.Fatal("a revoked key must never be reinstated")
	}
	// A later rotation quietly dropping the revocation list.
	dropped, _ := f.successor(t, recovered, TransitionRotation,
		[]ed25519.PrivateKey{f.Rescued}, []string{}, []ed25519.PrivateKey{f.Rescued}, "signing")
	if _, err := Verify(dropped, &recovered); err == nil {
		t.Fatal("a descriptor must not drop a previously revoked key")
	}
}

func TestAuthorizationCannotBeReplayedAcrossRoleOrDescriptor(t *testing.T) {
	f := newSiteFixture(t)
	encoded, descriptor := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := Verify(encoded, &f.Verified); err != nil {
		t.Fatal(err)
	}
	// Relabelling a signing authorization as recovery must fail: the role
	// byte is inside the signed message.
	relabelled := descriptor
	relabelled.Authorizations = append([]Authorization(nil), descriptor.Authorizations...)
	relabelled.Authorizations[0].Role = "recovery"
	if _, err := VerifyDescriptor(relabelled, &f.Verified); err == nil {
		t.Fatal("an authorization must not be replayable under a different role")
	}
	// Attributing a valid signature to a different key must fail.
	swapped := descriptor
	swapped.Authorizations = append([]Authorization(nil), descriptor.Authorizations...)
	swapped.Authorizations[0].Key = encodeKey(f.SigningB)
	if _, err := VerifyDescriptor(swapped, &f.Verified); err == nil {
		t.Fatal("an authorization must not be attributable to another key")
	}
	// Transplanting authorizations onto a different descriptor must fail.
	other, otherDescriptor := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rescued}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	_ = other
	transplanted := otherDescriptor
	transplanted.Authorizations = descriptor.Authorizations
	if _, err := VerifyDescriptor(transplanted, &f.Verified); err == nil {
		t.Fatal("authorizations must not transplant between descriptors")
	}
}

func TestChainRejectsRollbackAndForeignGenesis(t *testing.T) {
	f := newSiteFixture(t)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	rotation, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := chain.Append(rotation); err != nil {
		t.Fatal(err)
	}
	// Re-delivering the genesis is idempotent, not a rollback.
	if _, err := chain.Append(f.Genesis); err != nil {
		t.Fatalf("identical re-delivery must be idempotent: %v", err)
	}
	head, err := chain.Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.Descriptor.Sequence != 1 {
		t.Fatal("idempotent re-delivery must not roll the head back")
	}
	// A different site's genesis must not start this chain.
	wrong := sha256.Sum256([]byte("wrong-site"))
	var wrongID ID
	copy(wrongID[:], wrong[:])
	if _, err := NewChain(wrongID, f.Genesis); err == nil {
		t.Fatal("a genesis for another site must be rejected")
	}
}

func TestChainDetectsEquivocationWithTransferableProof(t *testing.T) {
	f := newSiteFixture(t)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := chain.Append(first); err != nil {
		t.Fatal(err)
	}
	// A second, equally valid descriptor at the same sequence.
	second, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rescued}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	_, err = chain.Append(second)
	if !errors.Is(err, ErrEquivocation) {
		t.Fatalf("expected equivocation, got %v", err)
	}
	proof, equivocating := chain.Equivocating()
	if !equivocating {
		t.Fatal("chain must record the equivocation")
	}
	if err := VerifyEquivocationProof(*proof); err != nil {
		t.Fatalf("proof must be independently verifiable: %v", err)
	}
	if _, err := chain.Head(); !errors.Is(err, ErrEquivocation) {
		t.Fatal("an equivocating site must not report a usable head")
	}
}

func TestChainInvalidCompetitorDoesNotPoisonSite(t *testing.T) {
	f := newSiteFixture(t)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	rotation, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := chain.Append(rotation); err != nil {
		t.Fatal(err)
	}
	// A competing descriptor at sequence 1 with insufficient authorization.
	forged, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rescued}, []string{}, []ed25519.PrivateKey{f.SigningA}, "signing")
	if _, err := chain.Append(forged); err == nil {
		t.Fatal("an unauthorized competitor must be rejected")
	} else if errors.Is(err, ErrEquivocation) {
		t.Fatal("an invalid competitor must not count as equivocation")
	}
	if _, equivocating := chain.Equivocating(); equivocating {
		t.Fatal("an invalid competitor must not poison the site")
	}
	if _, err := chain.Head(); err != nil {
		t.Fatal("the chain must remain usable")
	}
}

func TestStrictParsingRejectsAmbiguousEncodings(t *testing.T) {
	f := newSiteFixture(t)
	cases := map[string][]byte{
		"duplicate key":  []byte(strings.Replace(string(f.Genesis), `"sequence": 0,`, `"sequence": 0,`+"\n  "+`"sequence": 1,`, 1)),
		"unknown field":  []byte(strings.Replace(string(f.Genesis), `"version":`, `"extra": 1,`+"\n  "+`"version":`, 1)),
		"trailing data":  append(append([]byte(nil), f.Genesis...), []byte("{}")...),
		"non-canonical":  []byte(strings.Replace(string(f.Genesis), `"valid_from": "`+canonicalTime(testBase)+`"`, `"valid_from": "2026-08-20T12:00:00+00:00"`, 1)),
		"uppercase hex":  []byte(strings.Replace(string(f.Genesis), hex.EncodeToString(f.ID[:]), strings.ToUpper(hex.EncodeToString(f.ID[:])), 1)),
		"empty document": []byte(""),
	}
	for name, encoded := range cases {
		// Guard against a mutation that silently failed to apply: such a
		// case would "pass" while testing nothing.
		if name != "empty document" && string(encoded) == string(f.Genesis) {
			t.Fatalf("%s mutation did not change the document", name)
		}
		if _, err := Verify(encoded, nil); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	// The unmutated document must still verify, so the cases above are
	// rejected for their mutation rather than a fixture defect.
	if _, err := Verify(f.Genesis, nil); err != nil {
		t.Fatalf("baseline genesis must verify: %v", err)
	}
}

func buildManifest(t *testing.T, private ed25519.PrivateKey, body string) (reconstruct.Manifest, []byte) {
	t.Helper()
	data := []byte(body)
	manifest, err := reconstruct.NewManifest(data, 0, private)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, data
}

func TestResolveIdentityStates(t *testing.T) {
	f := newSiteFixture(t)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	manifest, data := buildManifest(t, f.SigningA, "hello from the site")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(time.Hour), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	now := testBase.Add(2 * time.Hour)

	state, err := Resolve(f.ID, chain, &publication, manifest, data, now)
	if err != nil || state != PublisherVerified {
		t.Fatalf("expected PUBLISHER_VERIFIED, got %v (%v)", state, err)
	}

	// No publication: integrity only, never an identity claim.
	if state, err := Resolve(f.ID, chain, nil, manifest, data, now); err != nil || state != ObjectVerified {
		t.Fatalf("expected OBJECT_VERIFIED, got %v (%v)", state, err)
	}

	// No cached chain: unknown, not invalid.
	if state, _ := Resolve(f.ID, nil, &publication, manifest, data, now); state != PublisherUnknown {
		t.Fatalf("expected PUBLISHER_UNKNOWN, got %v", state)
	}

	// Tampered object bytes.
	if state, _ := Resolve(f.ID, chain, &publication, manifest, []byte("tampered"), now); state != PublisherInvalid {
		t.Fatalf("expected PUBLISHER_INVALID for tampered bytes, got %v", state)
	}

	// Publication transplanted onto a different object.
	otherManifest, otherData := buildManifest(t, f.SigningA, "a different object")
	if state, _ := Resolve(f.ID, chain, &publication, otherManifest, otherData, now); state != PublisherInvalid {
		t.Fatalf("expected PUBLISHER_INVALID for transplanted publication, got %v", state)
	}

	// A different site the user did not ask for.
	wrong := sha256.Sum256([]byte("another-site"))
	var wrongID ID
	copy(wrongID[:], wrong[:])
	if state, _ := Resolve(wrongID, chain, &publication, manifest, data, now); state != PublisherInvalid {
		t.Fatalf("expected PUBLISHER_INVALID for a site mismatch, got %v", state)
	}

	// Outside the descriptor validity window.
	if state, _ := Resolve(f.ID, chain, &publication, manifest, data, testBase.Add(400*24*time.Hour)); state != PublisherInvalid {
		t.Fatalf("expected PUBLISHER_INVALID for an expired descriptor, got %v", state)
	}
}

func TestResolveRejectsSupersededDescriptorAndRevokedKey(t *testing.T) {
	f := newSiteFixture(t)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	manifest, data := buildManifest(t, f.SigningA, "published before recovery")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(time.Hour), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	revoked := []string{encodeKey(f.SigningA), encodeKey(f.SigningB)}
	recoveryEncoded, _ := f.successor(t, f.Verified, TransitionRecovery,
		[]ed25519.PrivateKey{f.Rescued}, revoked, []ed25519.PrivateKey{f.RecoverA, f.RecoverB}, "recovery")
	if _, err := chain.Append(recoveryEncoded); err != nil {
		t.Fatal(err)
	}
	now := testBase.Add(2 * time.Hour)
	// After recovery, a publication under the compromised key and superseded
	// descriptor is an invalid identity claim, not an unknown one.
	if state, _ := Resolve(f.ID, chain, &publication, manifest, data, now); state != PublisherInvalid {
		t.Fatalf("expected PUBLISHER_INVALID after recovery, got %v", state)
	}
	// The recovered key publishing under the new descriptor verifies.
	head, err := chain.Head()
	if err != nil {
		t.Fatal(err)
	}
	newManifest, newData := buildManifest(t, f.Rescued, "published after recovery")
	newPublication, err := NewPublication(f.ID, head, newManifest, now, f.Rescued)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := Resolve(f.ID, chain, &newPublication, newManifest, newData, now); err != nil || state != PublisherVerified {
		t.Fatalf("expected PUBLISHER_VERIFIED after recovery, got %v (%v)", state, err)
	}
}

func TestPublicationRejectsUnauthorizedSigner(t *testing.T) {
	f := newSiteFixture(t)
	manifest, _ := buildManifest(t, f.Rotated, "signed by an unlisted key")
	if _, err := NewPublication(f.ID, f.Verified, manifest, testBase, f.Rotated); err == nil {
		t.Fatal("a key absent from the descriptor must not produce a publication")
	}
}
