package site

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-local-reconstruction/site/transparency"
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

	w := newWitnessedSite(t, 24*time.Hour)
	chain := w.chain(t, f.ID, f.Genesis, testBase.Add(time.Hour))

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
	recovered := w.appendTo(t, chain, recoveredEncoded, now)
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

	// Step 6. What happens to a reader who has not been handed the recovery.
	//
	// Before descriptors were distributed through a log this was the drill's
	// open end: such a reader accepted the attacker's publication, and nothing
	// bounded how long that lasted. It is bounded now, and by how much depends
	// on how the reader follows the log. Both ways are privacy-safe for the
	// same reason: neither does anything that depends on what the user reads.
	//
	// 6a. A reader that follows the log's entries, on a cadence of its own,
	// gets the recovery as soon as it syncs. The attacker cannot withhold it,
	// because getting a descriptor accepted at all means putting it somewhere
	// the site's owner and every reader can see. This is the strong outcome,
	// and it costs bandwidth proportional to the log rather than to what the
	// reader cares about -- which is exactly why it leaks nothing.
	follower := w.newReader(t, 24*time.Hour)
	followerChain := follower.chain(t, f.ID, f.Genesis, now)
	follower.appendTo(t, followerChain, recoveredEncoded, now)
	if state, _ := Resolve(f.ID, followerChain, &continuedPublication, continuedManifest,
		continuedData, now.Add(2*time.Hour)); state != PublisherInvalid {
		t.Fatalf("step 6a: a reader following the log still accepted the attacker (%v)", state)
	}

	// 6b. A reader that follows only checkpoints, and that the attacker can
	// keep away from the log entirely, is the weaker case. Inside its freshness
	// window the attacker still wins: this is the residual exposure, and the
	// drill states it rather than hiding it.
	const window = 6 * time.Hour
	isolated := w.newReader(t, window)
	isolatedChain := isolated.chain(t, f.ID, f.Genesis, now)
	if state, _ := Resolve(f.ID, isolatedChain, &continuedPublication, continuedManifest,
		continuedData, now.Add(time.Hour)); state != PublisherVerified {
		t.Fatalf("step 6b: the drill assumes the attacker still wins inside the window, "+
			"but the reader resolved %v", state)
	}

	// Once the window lapses the reader stops issuing a verdict at all. It does
	// not fall back to accepting, and it does not retry harder because somebody
	// is waiting: a retry driven by a reader's private activity would be an
	// observable event that depends on it, which is worse than losing a verdict.
	lapsed := now.Add(window + time.Second)
	state, err = Resolve(f.ID, isolatedChain, &continuedPublication, continuedManifest,
		continuedData, lapsed)
	if state != PublisherUnknown {
		t.Fatalf("step 6b: past the freshness window the reader resolved %v, and the "+
			"attacker's window is supposed to close", state)
	}
	if !errors.Is(err, ErrStaleDistribution) {
		t.Fatalf("step 6b: the reason given is not staleness: %v", err)
	}

	// And if the attacker answers by serving that reader a forged log rather
	// than none, it has to sign a second head at a size the reader already
	// holds, which is transferable evidence rather than a private branch.
	forged, err := transparency.NewLog(testLogOrigin, w.private)
	if err != nil {
		t.Fatal(err)
	}
	forged.Append(LogEntry(f.Genesis))
	forged.Append(LogEntry([]byte("an entry the honest log never carried")))
	held, _ := isolated.distribution.Head()
	forgedCheckpoint, err := forged.CheckpointAt(held.Size, lapsed)
	if err != nil {
		t.Fatal(err)
	}
	err = isolated.distribution.Refresh(forgedCheckpoint,
		transparency.ConsistencyProof{Old: held.Size, New: held.Size}, lapsed)
	var split *transparency.SplitViewProof
	if !errors.As(err, &split) {
		t.Fatalf("step 6b: a forged log did not produce a split-view proof: %v", err)
	}
	if err := transparency.VerifySplitView(split, w.public); err != nil {
		t.Fatalf("step 6b: the evidence does not verify for a third party: %v", err)
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
