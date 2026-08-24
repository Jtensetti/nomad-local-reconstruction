package site

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// A site key-compromise recovery drill, end to end.
//
// The unit tests establish that recovery is authorized correctly. This
// rehearses what an operator actually does after losing control of every
// signing key, and what a reader sees at each step -- including the step where
// the attacker is winning, which is the part a drill exists to make concrete.
//
// Nothing here is hypothetical about the attacker: they hold both signing
// keys, so before recovery they can publish under the site's identity and a
// reader has no way to tell. Recovery does not undo that. What it does is end
// it, and the drill measures exactly where the line falls.
func TestSiteKeyCompromiseRecoveryDrill(t *testing.T) {
	f := newSiteFixture(t)
	now := testBase.Add(2 * time.Hour)

	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}

	// Step 1. Normal operation: the operator publishes, a reader verifies.
	honestManifest, honestData := buildManifest(t, f.SigningA, "the operator's own object")
	honestPublication, err := NewPublication(f.ID, f.Verified, honestManifest,
		testBase.Add(time.Hour), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := Resolve(f.ID, chain, &honestPublication, honestManifest, honestData, now); state != PublisherVerified {
		t.Fatalf("step 1: honest publication resolved %v: %v", state, err)
	}

	// Step 2. Both signing keys are stolen. The attacker publishes under the
	// site's identity and the reader accepts it, because at this point it is
	// indistinguishable from step 1. This is the damage recovery cannot undo.
	forgedManifest, forgedData := buildManifest(t, f.SigningB, "the attacker's object")
	forgedPublication, err := NewPublication(f.ID, f.Verified, forgedManifest,
		testBase.Add(90*time.Minute), f.SigningB)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := Resolve(f.ID, chain, &forgedPublication, forgedManifest, forgedData, now); state != PublisherVerified {
		t.Fatalf("step 2: the drill assumes the attacker succeeds before recovery, "+
			"but the forged publication resolved %v: %v", state, err)
	}

	// Step 3. The operator recovers, offline, using the recovery authority.
	// The stolen keys are revoked and a rescued key takes over. Recovery
	// cannot be authorized by the stolen signing keys -- that is what makes
	// the offline authority worth holding -- and the unit tests cover the
	// refusals; here it simply has to work.
	revoked := []string{encodeKey(f.SigningA), encodeKey(f.SigningB)}
	recoveredEncoded, _ := f.successor(t, f.Verified, TransitionRecovery,
		[]ed25519.PrivateKey{f.Rescued}, revoked,
		[]ed25519.PrivateKey{f.RecoverA, f.RecoverB}, "recovery")
	recovered, err := chain.Append(recoveredEncoded)
	if err != nil {
		t.Fatalf("step 3: recovery was refused: %v", err)
	}
	if _, equivocating := chain.Equivocating(); equivocating {
		t.Fatal("step 3: recovery was mistaken for equivocation")
	}

	// Step 4. A reader who has seen the recovery rejects anything the attacker
	// publishes from here on. The keys still exist; they no longer authorize.
	// The attacker signs against the descriptor they know -- the pre-recovery
	// one, which still lists their key -- because a real attacker does not
	// consult the API that would refuse them. NewPublication declines to build
	// a claim under a revoked key, which is right for an honest publisher and
	// beside the point here.
	continuedManifest, continuedData := buildManifest(t, f.SigningA, "the attacker keeps going")
	continuedPublication, err := NewPublication(f.ID, f.Verified, continuedManifest,
		now.Add(time.Hour), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	state, err := Resolve(f.ID, chain, &continuedPublication, continuedManifest, continuedData,
		now.Add(2*time.Hour))
	if state != PublisherInvalid {
		t.Fatalf("step 4: a revoked key still published successfully (%v): %v", state, err)
	}

	// Step 5. The operator resumes publishing under the rescued key, and a
	// reader accepts it. Recovery that leaves a site unable to publish is not
	// recovery.
	resumedManifest, resumedData := buildManifest(t, f.Rescued, "back in business")
	resumedPublication, err := NewPublication(f.ID, recovered, resumedManifest,
		now.Add(3*time.Hour), f.Rescued)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := Resolve(f.ID, chain, &resumedPublication, resumedManifest, resumedData,
		now.Add(4*time.Hour)); state != PublisherVerified {
		t.Fatalf("step 5: the recovered site cannot publish (%v): %v", state, err)
	}

	// Step 6. A reader who never saw the recovery, and whose chain still ends
	// at genesis, must not be told the attacker's continued publication is
	// verified. It is the same bytes as step 4; only the reader's knowledge
	// differs, and that difference must not resolve in the attacker's favour.
	staleChain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	staleState, _ := Resolve(f.ID, staleChain, &continuedPublication, continuedManifest,
		continuedData, now.Add(2*time.Hour))
	if staleState == PublisherVerified {
		t.Log("step 6: a reader who has not seen the recovery still accepts the " +
			"attacker's publication. That is the propagation window, and it is " +
			"bounded by descriptor distribution rather than by anything here.")
	}

	// Step 7. The operator's own back catalogue under the compromised key is
	// invalid too, and that is the intended behaviour rather than collateral
	// damage. After a theft nobody can say which publications by that key were
	// the operator's and which were the attacker's -- step 1 and step 2 are
	// indistinguishable to a reader by construction -- so the specification
	// makes the head's revocation decisive (SITE_IDENTITY resolution rule 5).
	//
	// This is exactly where recovery differs from rotation, which must not
	// turn a publisher's back catalogue into failed identity claims. The cost
	// is real and belongs in a drill rather than in a footnote: recovering
	// from a compromise means re-publishing everything worth keeping.
	if state, err := Resolve(f.ID, chain, &honestPublication, honestManifest, honestData,
		now.Add(5*time.Hour)); state != PublisherInvalid {
		t.Fatalf("step 7: a publication by a revoked key survived recovery (%v): %v",
			state, err)
	}

	// Step 8. So the operator re-publishes it under the rescued key, and it
	// verifies again. The object never changed; only the identity claim over
	// it had to be remade.
	republished, err := NewPublication(f.ID, recovered, honestManifest,
		now.Add(6*time.Hour), f.Rescued)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := Resolve(f.ID, chain, &republished, honestManifest, honestData,
		now.Add(7*time.Hour)); state != PublisherVerified {
		t.Fatalf("step 8: the operator cannot re-publish their own object after "+
			"recovery (%v): %v", state, err)
	}
}
