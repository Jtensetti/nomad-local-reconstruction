package site

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestForeignGenesisCannotBrickASite is the regression for a confirmed
// remote denial of service: Append verified a competing genesis with
// previous == nil, and the genesis branch only checks that a descriptor
// commits to its OWN derived SiteID. An unprivileged attacker could
// therefore generate a valid genesis for their own unrelated site, hand it
// to a victim, and have it recorded as equivocation, permanently disabling
// the victim's site for the cost of one key generation.
func TestForeignGenesisCannotBrickASite(t *testing.T) {
	victim := newSiteFixture(t)
	chain, err := NewChain(victim.ID, victim.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	attacker := newAttackerFixture(t)
	if attacker.ID == victim.ID {
		t.Fatal("fixture must produce a distinct site")
	}
	if _, err := chain.Append(attacker.Genesis); err == nil {
		t.Fatal("a foreign genesis must be rejected")
	} else if errors.Is(err, ErrEquivocation) {
		t.Fatal("a foreign genesis must not be recorded as equivocation")
	}
	if _, equivocating := chain.Equivocating(); equivocating {
		t.Fatal("a foreign genesis must not poison the victim site")
	}
	if _, err := chain.Head(); err != nil {
		t.Fatalf("the victim site must remain usable: %v", err)
	}
}

// newAttackerFixture builds a complete, valid site under keys unrelated to
// the standard fixture.
func newAttackerFixture(t *testing.T) *siteFixture {
	t.Helper()
	f := &siteFixture{
		SigningA: deterministicKey(t, "attacker-signing-a"),
		SigningB: deterministicKey(t, "attacker-signing-b"),
		Rotated:  deterministicKey(t, "attacker-rotated"),
		Rescued:  deterministicKey(t, "attacker-rescued"),
		RecoverA: deterministicKey(t, "attacker-recovery-a"),
		RecoverB: deterministicKey(t, "attacker-recovery-b"),
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

// TestForgedEquivocationProofIsRejected is the regression for a confirmed
// forgery: the proof verifier only parsed both branches and compared
// digests, so anyone could fabricate a "proof" that an honest site was
// equivocating, turning split-view detection into an attacker-controlled
// kill switch.
func TestForgedEquivocationProofIsRejected(t *testing.T) {
	f := newSiteFixture(t)
	real, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")

	// A competitor with no authorizations at all: correctly rejected by
	// VerifyDescriptor, so it must not stand as half of a proof.
	forgedDescriptor := Descriptor{
		Version: DescriptorVersion, SiteID: hex.EncodeToString(f.ID[:]), Sequence: 1,
		Transition: TransitionRotation, PreviousDescriptorDigest: hex.EncodeToString(f.Verified.Digest[:]),
		ValidFrom: canonicalTime(testBase), ValidUntil: canonicalTime(testBase.Add(365 * 24 * time.Hour)),
		SigningKeys: []string{encodeKey(f.Rescued)}, RevokedKeys: []string{},
		Recovery: f.Verified.Descriptor.Recovery,
	}
	forged, err := Encode(forgedDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	proof := EquivocationProof{
		SiteID: f.ID, Sequence: 1,
		Prefix: [][]byte{f.Genesis}, First: real, Second: forged,
	}
	if err := VerifyEquivocationProof(proof); err == nil {
		t.Fatal("a proof whose competitor is unauthorized must be rejected")
	}
	// A proof with no ancestor prefix cannot establish anything either.
	if err := VerifyEquivocationProof(EquivocationProof{SiteID: f.ID, Sequence: 1, First: real, Second: forged}); err == nil {
		t.Fatal("a proof without its ancestor chain must be rejected")
	}
}

func TestGenuineEquivocationProofVerifies(t *testing.T) {
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
	second, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rescued}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := chain.Append(second); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("expected equivocation, got %v", err)
	}
	proof, ok := chain.Equivocating()
	if !ok {
		t.Fatal("chain must record the proof")
	}
	if err := VerifyEquivocationProof(*proof); err != nil {
		t.Fatalf("a genuine proof must verify independently: %v", err)
	}
}

// TestStolenSigningMajorityCannotSeizeRecovery is the regression for the
// threat the sprint names first: nothing constrained the recovery policy
// across a rotation, so a thief holding only the online publishing keys
// could install their own recovery set, revoke the real one, and own the
// site permanently.
func TestStolenSigningMajorityCannotSeizeRecovery(t *testing.T) {
	f := newSiteFixture(t)
	attackerRecovery := deterministicKey(t, "attacker-recovery")

	build := func(revoked []string, recovery Recovery, extraSigners []ed25519.PrivateKey) []byte {
		descriptor := Descriptor{
			Version: DescriptorVersion, SiteID: hex.EncodeToString(f.ID[:]), Sequence: 1,
			Transition: TransitionRotation, PreviousDescriptorDigest: hex.EncodeToString(f.Verified.Digest[:]),
			ValidFrom: canonicalTime(testBase), ValidUntil: canonicalTime(testBase.Add(3650 * 24 * time.Hour)),
			SigningKeys: []string{encodeKey(f.Rotated)}, RevokedKeys: revoked,
			Recovery: recovery,
		}
		for _, signer := range append([]ed25519.PrivateKey{f.SigningA, f.SigningB}, extraSigners...) {
			authorization, err := Authorize(descriptor, "signing", signer)
			if err != nil {
				t.Fatal(err)
			}
			descriptor.Authorizations = append(descriptor.Authorizations, authorization)
		}
		for _, key := range append([]ed25519.PrivateKey{f.Rotated}, extraSigners...) {
			authorization, err := Authorize(descriptor, "signing", key)
			if err != nil {
				t.Fatal(err)
			}
			descriptor.Authorizations = append(descriptor.Authorizations, authorization)
		}
		encoded, err := Encode(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	hijack := Recovery{Threshold: 1, Keys: []string{encodeKey(attackerRecovery)}}
	seizure := build([]string{encodeKey(f.RecoverA), encodeKey(f.RecoverB)}, hijack, nil)
	if _, err := Verify(seizure, &f.Verified); err == nil {
		t.Fatal("a stolen signing majority must not replace the offline recovery policy")
	}
	// The milder variant: swap the recovery set without revoking anything.
	swap := build([]string{}, hijack, nil)
	if _, err := Verify(swap, &f.Verified); err == nil {
		t.Fatal("a rotation must not silently swap the recovery policy")
	}
	// A rotation that leaves the recovery policy alone is fine.
	ordinary := build([]string{}, f.Verified.Descriptor.Recovery, nil)
	if _, err := Verify(ordinary, &f.Verified); err != nil {
		t.Fatalf("an ordinary rotation must still verify: %v", err)
	}
}

// TestBase64IsNotMalleable is the regression for a parser differential:
// Go's Strict() base64 still ignores CR and LF, so one key had many wire
// spellings that all produced the same SiteID and digest, and a stricter
// second implementation would have disagreed.
func TestBase64IsNotMalleable(t *testing.T) {
	f := newSiteFixture(t)
	original := f.Verified.Descriptor.SigningKeys[0]
	for name, mutated := range map[string]string{
		"lf inside":   original[:8] + "\n" + original[8:],
		"cr inside":   original[:8] + "\r" + original[8:],
		"crlf inside": original[:8] + "\r\n" + original[8:],
		"leading lf":  "\n" + original,
		"trailing lf": original + "\n",
	} {
		if _, err := decodeBase64(mutated, ed25519.PublicKeySize); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
		document := strings.Replace(string(f.Genesis), original, mutated, -1)
		if _, err := Verify([]byte(document), nil); err == nil {
			t.Fatalf("a descriptor with %s in a key must be rejected", name)
		}
	}
	if _, err := decodeBase64(original, ed25519.PublicKeySize); err != nil {
		t.Fatalf("the canonical encoding must still be accepted: %v", err)
	}
}

// TestRevocationBudgetDoesNotFreezeAChain is the regression for a terminal
// availability bug: revoked keys shared the eight-key active bound while
// revocation is absorbing, so a site became permanently unrotatable after
// eight revocations, and an eight-key site got exactly one recovery ever.
func TestRevocationBudgetDoesNotFreezeAChain(t *testing.T) {
	f := newSiteFixture(t)
	previous := f.Verified
	revoked := []string{}
	current := []ed25519.PrivateKey{f.SigningA, f.SigningB}

	for round := 0; round < 12; round++ {
		next := deterministicKey(t, "rotation-round-"+string(rune('a'+round)))
		for _, key := range current {
			revoked = append(revoked, encodeKey(key))
		}
		encoded, _ := f.successor(t, previous, TransitionRotation,
			[]ed25519.PrivateKey{next}, append([]string(nil), revoked...), current, "signing")
		verified, err := Verify(encoded, &previous)
		if err != nil {
			t.Fatalf("round %d must remain rotatable: %v", round, err)
		}
		previous = verified
		current = []ed25519.PrivateKey{next}
	}
	if len(previous.Descriptor.RevokedKeys) <= maxKeys {
		t.Fatal("the test must actually exceed the active-key bound")
	}
}

// TestRevocationIsAbsorbingProperty is the property the sprint contract
// requires: along any accepted chain, a revoked key never becomes valid
// again and the sequence only increases.
func TestRevocationIsAbsorbingProperty(t *testing.T) {
	f := newSiteFixture(t)
	previous := f.Verified
	revoked := map[string]bool{}
	current := []ed25519.PrivateKey{f.SigningA, f.SigningB}
	lastSequence := previous.Descriptor.Sequence

	for round := 0; round < 6; round++ {
		next := deterministicKey(t, "absorbing-round-"+string(rune('a'+round)))
		list := []string{}
		for key := range revoked {
			list = append(list, key)
		}
		for _, key := range current {
			revoked[encodeKey(key)] = true
			list = append(list, encodeKey(key))
		}
		encoded, _ := f.successor(t, previous, TransitionRotation,
			[]ed25519.PrivateKey{next}, list, current, "signing")
		verified, err := Verify(encoded, &previous)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if verified.Descriptor.Sequence != lastSequence+1 {
			t.Fatal("sequence must increase by exactly one")
		}
		lastSequence = verified.Descriptor.Sequence
		for key := range revoked {
			decoded, err := base64.StdEncoding.DecodeString(key)
			if err != nil {
				t.Fatal(err)
			}
			if verified.AuthorizesKey(decoded) {
				t.Fatalf("round %d: a revoked key became valid again", round)
			}
		}
		previous = verified
		current = []ed25519.PrivateKey{next}
	}
}

func TestUnboundedAuthorizationsRejected(t *testing.T) {
	f := newSiteFixture(t)
	descriptor := f.Verified.Descriptor
	filler := deterministicKey(t, "filler")
	for index := 0; index < 4*maxKeys+1; index++ {
		authorization, err := Authorize(descriptor, "signing", filler)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Authorizations = append(descriptor.Authorizations, authorization)
	}
	if _, err := VerifyDescriptor(descriptor, nil); err == nil {
		t.Fatal("an oversized authorization list must be rejected before signature work")
	}
}

func TestNewKeysMustProvePossession(t *testing.T) {
	f := newSiteFixture(t)
	unheld := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	descriptor := Descriptor{
		Version: DescriptorVersion, SiteID: hex.EncodeToString(f.ID[:]), Sequence: 1,
		Transition: TransitionRotation, PreviousDescriptorDigest: hex.EncodeToString(f.Verified.Digest[:]),
		ValidFrom: canonicalTime(testBase), ValidUntil: canonicalTime(testBase.Add(365 * 24 * time.Hour)),
		SigningKeys: []string{unheld}, RevokedKeys: []string{},
		Recovery: f.Verified.Descriptor.Recovery,
	}
	for _, signer := range []ed25519.PrivateKey{f.SigningA, f.SigningB} {
		authorization, err := Authorize(descriptor, "signing", signer)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Authorizations = append(descriptor.Authorizations, authorization)
	}
	if _, err := VerifyDescriptor(descriptor, &f.Verified); err == nil {
		t.Fatal("a key nobody holds must not be installable")
	}
}

func TestResolveReportsFailedClaimsAsInvalidNotUnknown(t *testing.T) {
	f := newSiteFixture(t)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	manifest, data := buildManifest(t, f.SigningA, "an object")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(time.Hour), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	now := testBase.Add(2 * time.Hour)

	// Naming a descriptor this chain cannot contain is a contradicted claim,
	// not an absent one: an attacker must not be able to choose UNKNOWN.
	unknownDigest := publication
	unknownDigest.DescriptorDigest = hex.EncodeToString(make([]byte, 32))
	message, err := publicationSigningMessage(unknownDigest)
	if err != nil {
		t.Fatal(err)
	}
	unknownDigest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.SigningA, message))
	if state, _ := Resolve(f.ID, chain, &unknownDigest, manifest, data, now); state != PublisherInvalid {
		t.Fatalf("expected PUBLISHER_INVALID for a descriptor outside the chain, got %v", state)
	}

	// A structurally broken claim is invalid even with no cached chain.
	broken := publication
	broken.Version = "not-a-version"
	if state, _ := Resolve(f.ID, nil, &broken, manifest, data, now); state != PublisherInvalid {
		t.Fatalf("expected PUBLISHER_INVALID for a malformed claim, got %v", state)
	}
	// A well-formed claim with genuinely no cached chain is unknown.
	if state, _ := Resolve(f.ID, nil, &publication, manifest, data, now); state != PublisherUnknown {
		t.Fatalf("expected PUBLISHER_UNKNOWN with no cached chain, got %v", state)
	}
}

func TestRotationDoesNotInvalidateEarlierPublications(t *testing.T) {
	f := newSiteFixture(t)
	w := newWitnessedSite(t, 24*time.Hour)
	chain := w.chain(t, f.ID, f.Genesis, testBase.Add(time.Hour))
	manifest, data := buildManifest(t, f.SigningA, "published before rotation")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(time.Hour), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	// A routine rotation that adds a key and revokes nothing.
	rotation, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.SigningA, f.SigningB, f.Rotated}, []string{},
		[]ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	w.appendTo(t, chain, rotation, testBase.Add(2*time.Hour))
	state, err := Resolve(f.ID, chain, &publication, manifest, data, testBase.Add(2*time.Hour))
	if err != nil || state != PublisherVerified {
		t.Fatalf("a routine rotation must not invalidate earlier publications, got %v (%v)", state, err)
	}
}

func TestChainIsRaceFreeUnderConcurrentUse(t *testing.T) {
	f := newSiteFixture(t)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	rotation, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{}, []ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			if worker%2 == 0 {
				_, _ = chain.Append(rotation)
				return
			}
			_, _ = chain.Head()
			_ = chain.SiteID()
			_, _ = chain.Equivocating()
			_, _ = chain.DescriptorByDigest(f.Verified.Digest)
		}(worker)
	}
	group.Wait()
	if _, equivocating := chain.Equivocating(); equivocating {
		t.Fatal("concurrent appends of one descriptor must not look like equivocation")
	}
}

// A proof is an accusation anyone can publish, and a chain that acts on one
// stops accepting the site's descriptors. So the ways a proof can be
// fabricated matter as much as the way a genuine one is built: each of these
// takes a proof the chain itself produced and breaks exactly one field.
func genuineProof(t *testing.T) (*EquivocationProof, *siteFixture) {
	t.Helper()
	f := newSiteFixture(t)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, []string{},
		[]ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := chain.Append(first); err != nil {
		t.Fatal(err)
	}
	second, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rescued}, []string{},
		[]ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := chain.Append(second); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("the fixture did not equivocate: %v", err)
	}
	proof, ok := chain.Equivocating()
	if !ok {
		t.Fatal("the chain recorded no proof, so there is nothing to break")
	}
	if err := VerifyEquivocationProof(*proof); err != nil {
		t.Fatalf("the unmodified proof must verify, or these negatives prove nothing: %v", err)
	}
	return proof, f
}

// The framing attack the proof format has to survive: one descriptor named
// twice. Both branches parse, both are authorized, both carry the claimed
// sequence and site -- and nothing was equivocated.
func TestAProofNamingOneDescriptorTwiceIsNotEvidenceOfEquivocation(t *testing.T) {
	proof, _ := genuineProof(t)
	forged := *proof
	forged.Second = forged.First
	if err := VerifyEquivocationProof(forged); err == nil {
		t.Fatal("a proof whose two branches are the same descriptor was accepted")
	} else if !strings.Contains(err.Error(), "identical") {
		t.Fatalf("refused for %q rather than for naming one descriptor twice", err)
	}
}

// A proof carrying another site's identifier must not verify against this
// site's descriptors. Without this a proof against any site could be
// relabelled to accuse another.
func TestAProofClaimingAnotherSiteIsRefused(t *testing.T) {
	proof, _ := genuineProof(t)
	forged := *proof
	forged.SiteID[0] ^= 0xff
	if err := VerifyEquivocationProof(forged); err == nil {
		t.Fatal("a proof naming a site its genesis does not derive was accepted")
	} else if !strings.Contains(err.Error(), "claimed site") {
		t.Fatalf("refused for %q rather than for the site it names", err)
	}
}

// A proof at the genesis sequence carries no prefix, so nothing above has
// already tied its branches to the site it names. That is the one place the
// site check on the branches themselves can fire, and without it a proof
// built from someone else's genesis descriptors would accuse this site.
func TestAGenesisProofBuiltFromAnotherSitesDescriptorsIsRefused(t *testing.T) {
	accused := newSiteFixture(t)
	other := otherSiteGenesis(t)
	forged := EquivocationProof{
		SiteID: accused.ID, Sequence: 0,
		First: other, Second: accused.Genesis,
	}
	if err := VerifyEquivocationProof(forged); err == nil {
		t.Fatal("a genesis proof built from another site's descriptor was accepted")
	} else if !strings.Contains(err.Error(), "claimed site") {
		t.Fatalf("refused for %q rather than for the site its branches belong to", err)
	}
}

// otherSiteGenesis builds a second site. newSiteFixture is fully
// deterministic, so two calls to it are one site twice, which would make the
// proof above fail on its identical-branches check instead of the one being
// tested.
func otherSiteGenesis(t *testing.T) []byte {
	t.Helper()
	signing := deterministicKey(t, "other-site-signing")
	recovery := deterministicKey(t, "other-site-recovery")
	descriptor := Descriptor{
		Version: DescriptorVersion, SiteID: hex.EncodeToString(make([]byte, 32)), Sequence: 0,
		Transition: TransitionGenesis, PreviousDescriptorDigest: hex.EncodeToString(make([]byte, 32)),
		ValidFrom: canonicalTime(testBase), ValidUntil: canonicalTime(testBase.Add(365 * 24 * time.Hour)),
		SigningKeys: []string{encodeKey(signing)}, RevokedKeys: []string{},
		Recovery: Recovery{Threshold: 1, Keys: []string{encodeKey(recovery)}},
	}
	id, err := DeriveID(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SiteID = hex.EncodeToString(id[:])
	descriptor.Authorizations = authorizeAll(t, descriptor,
		[]ed25519.PrivateKey{signing}, []ed25519.PrivateKey{recovery})
	encoded, err := Encode(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(encoded, nil); err != nil {
		t.Fatalf("the second site's genesis must verify on its own: %v", err)
	}
	return encoded
}
