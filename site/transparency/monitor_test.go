package transparency

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testOrigin = "nomad.example/site-log"

var testEpoch = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func newTestLog(t *testing.T) (*Log, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	return log, public, private
}

func newTestMonitor(t *testing.T, public ed25519.PublicKey, window time.Duration) *Monitor {
	t.Helper()
	monitor, err := NewMonitor(testOrigin, public, window)
	if err != nil {
		t.Fatal(err)
	}
	return monitor
}

// followLog brings a monitor to a log's current head, doing what a reader does:
// ask for the head, ask for a proof from what it holds, and verify both.
func followLog(t *testing.T, monitor *Monitor, log *Log, now time.Time) {
	t.Helper()
	checkpoint, err := log.Checkpoint(now)
	if err != nil {
		t.Fatal(err)
	}
	var held uint64
	if head, ok := monitor.Head(); ok {
		held = head.Size
	}
	proof, err := log.ProveConsistency(held, log.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(checkpoint, proof, now); err != nil {
		t.Fatalf("a reader could not follow an honest log: %v", err)
	}
}

// The property the criterion asks for, stated as one test: a descriptor the
// attacker showed to one reader alone cannot be accepted, because it is not in
// the log and therefore has no proof.
func TestADescriptorOutsideTheLogCannotBeAccepted(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("the real descriptor"))
	monitor := newTestMonitor(t, public, time.Hour)
	followLog(t, monitor, log, testEpoch)

	// The honest path first, so the refusal below is not a verifier that
	// refuses everything.
	proof, err := log.ProveInclusion([]byte("the real descriptor"), log.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Accept([]byte("the real descriptor"), proof, testEpoch); err != nil {
		t.Fatalf("a logged descriptor was refused: %v", err)
	}

	// The attacker's descriptor, shown to this reader only. There is no proof
	// it can offer, and the best it can do is reuse one.
	if err := monitor.Accept([]byte("the attacker's descriptor"), proof, testEpoch); err == nil {
		t.Fatal("a descriptor that was never logged was accepted")
	}
	if _, err := log.ProveInclusion([]byte("the attacker's descriptor"), log.Size()); err == nil {
		t.Fatal("the log produced a proof for an entry it does not hold")
	}
}

// An attacker who partitions a reader gets a window, not forever. This is the
// bound the criterion says is missing.
func TestAPartitionedReaderGoesStaleAndStopsAccepting(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("descriptor"))
	const window = time.Hour
	monitor := newTestMonitor(t, public, window)
	followLog(t, monitor, log, testEpoch)

	proof, err := log.ProveInclusion([]byte("descriptor"), log.Size())
	if err != nil {
		t.Fatal(err)
	}

	for _, elapsed := range []time.Duration{0, window / 2, window} {
		if err := monitor.Accept([]byte("descriptor"), proof, testEpoch.Add(elapsed)); err != nil {
			t.Fatalf("inside the window at %s: %v", elapsed, err)
		}
		if !monitor.Fresh(testEpoch.Add(elapsed)) {
			t.Fatalf("the reader reports stale inside the window at %s", elapsed)
		}
	}
	for _, elapsed := range []time.Duration{window + time.Second, 24 * time.Hour} {
		err := monitor.Accept([]byte("descriptor"), proof, testEpoch.Add(elapsed))
		if !errors.Is(err, ErrStale) {
			t.Fatalf("outside the window at %s the reader did not go stale: %v", elapsed, err)
		}
		if monitor.Fresh(testEpoch.Add(elapsed)) {
			t.Fatalf("the reader reports fresh outside the window at %s", elapsed)
		}
	}

	// And the partition ending restores it, so staleness is a bound and not a
	// one-way door.
	followLog(t, monitor, log, testEpoch.Add(48*time.Hour))
	if err := monitor.Accept([]byte("descriptor"), proof, testEpoch.Add(48*time.Hour)); err != nil {
		t.Fatalf("a reader that caught up was still refused: %v", err)
	}
}

// A log that could date its head in the future would hand every reader a
// permanent and false freshness, which would remove the bound entirely.
func TestAFutureDatedCheckpointIsRefused(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("descriptor"))
	monitor := newTestMonitor(t, public, time.Hour)

	future, err := log.Checkpoint(testEpoch.Add(365 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := log.ProveConsistency(0, log.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(future, proof, testEpoch); err == nil {
		t.Fatal("a checkpoint dated a year ahead was accepted")
	}

	// Ordinary clock skew is tolerated, because refusing it would make the log
	// unusable rather than safe.
	skewed, err := log.Checkpoint(testEpoch.Add(maxClockSkew / 2))
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(skewed, proof, testEpoch); err != nil {
		t.Fatalf("a checkpoint inside the skew allowance was refused: %v", err)
	}
}

func TestALogCannotRollBackOrRewind(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	log.Append([]byte("second"))
	monitor := newTestMonitor(t, public, time.Hour)
	followLog(t, monitor, log, testEpoch)

	older, err := log.CheckpointAt(1, testEpoch.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(older, ConsistencyProof{Old: 2, New: 1}, testEpoch.Add(time.Minute)); err == nil {
		t.Fatal("a reader moved back to a smaller head")
	}

	// A head at the same size with an earlier timestamp is a rewind of the
	// clock rather than of the tree, and buys an attacker the same thing.
	stale, err := log.Checkpoint(testEpoch.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(stale, ConsistencyProof{Old: 2, New: 2}, testEpoch); err == nil {
		t.Fatal("a reader accepted a checkpoint dated before the one it holds")
	}
}

// A log that claims the reader held nothing would hand it any branch at all.
func TestTheReaderSuppliesItsOwnHeldSize(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	log.Append([]byte("second"))
	monitor := newTestMonitor(t, public, time.Hour)
	followLog(t, monitor, log, testEpoch)

	log.Append([]byte("third"))
	head, err := log.Checkpoint(testEpoch.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	wildcard, err := log.ProveConsistency(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(head, wildcard, testEpoch.Add(time.Minute)); err == nil {
		t.Fatal("a proof claiming the reader held nothing was accepted")
	}

	// Both ends of the range are checked, and each is checked on its own. A
	// wrong starting point and a wrong ending point are different attacks, and
	// a proof with one of them right is not half-acceptable. Each of these is
	// also refused further down by the proof itself, so the reason is asserted:
	// otherwise the range check could be removed with nothing noticing.
	honest, err := log.ProveConsistency(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	for name, proof := range map[string]ConsistencyProof{
		"a wrong starting size": {Old: 1, New: 3, Path: honest.Path},
		"a wrong ending size":   {Old: 2, New: 2, Path: honest.Path},
		"both wrong":            {Old: 0, New: 9, Path: honest.Path},
	} {
		err := monitor.Update(head, proof, testEpoch.Add(time.Minute))
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if !strings.Contains(err.Error(), "this reader holds") {
			t.Fatalf("%s was refused for %q rather than its range", name, err)
		}
	}

	// And the same on a reader that holds nothing at all.
	fresh := newTestMonitor(t, public, time.Hour)
	for name, proof := range map[string]ConsistencyProof{
		"a non-zero starting size": {Old: 2, New: 3},
		"a wrong ending size":      {Old: 0, New: 2},
	} {
		err := fresh.Update(head, proof, testEpoch.Add(time.Minute))
		if err == nil {
			t.Fatalf("%s was accepted by a reader holding nothing", name)
		}
		if !strings.Contains(err.Error(), "holds no checkpoint") {
			t.Fatalf("%s was refused for %q rather than its range", name, err)
		}
	}

	// The proof the reader's own state demands does work.
	if err := monitor.Update(head, honest, testEpoch.Add(time.Minute)); err != nil {
		t.Fatalf("the correct proof was refused: %v", err)
	}
}

// The end-to-end equivocation story: a forked log cannot advance a reader, the
// reader demands a checkpoint at the size it holds, and what comes back is
// transferable evidence.
func TestAForkedLogIsCaughtAndTheEvidenceIsTransferable(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	honest, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	honest.Append([]byte("first"))
	honest.Append([]byte("the descriptor the site owner published"))

	monitor := newTestMonitor(t, public, time.Hour)
	followLog(t, monitor, honest, testEpoch)

	// The same key, a different second entry: a log serving one reader a
	// private branch.
	forked, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	forked.Append([]byte("first"))
	forked.Append([]byte("the attacker's descriptor"))
	forked.Append([]byte("filler"))

	forkedHead, err := forked.Checkpoint(testEpoch.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	forkedProof, err := forked.ProveConsistency(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	err = monitor.Update(forkedHead, forkedProof, testEpoch.Add(time.Minute))
	if err == nil {
		t.Fatal("a reader followed a fork of the log it was watching")
	}
	if !strings.Contains(err.Error(), "demand a signed checkpoint at size 2") {
		t.Fatalf("the refusal does not tell the reader how to establish which: %v", err)
	}

	// The reader does exactly that.
	demanded, err := forked.CheckpointAt(2, testEpoch.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	err = monitor.Update(demanded, ConsistencyProof{Old: 2, New: 2}, testEpoch.Add(2*time.Minute))
	var split *SplitViewProof
	if !errors.As(err, &split) {
		t.Fatalf("the second head at size 2 did not produce a split-view proof: %v", err)
	}
	if !errors.Is(err, ErrSplitView) {
		t.Fatalf("the error does not identify itself as equivocation: %v", err)
	}

	// Transferable: a third party with only the log's public key and this
	// document can confirm the log equivocated.
	encoded, err := json.Marshal(split)
	if err != nil {
		t.Fatal(err)
	}
	var relayed SplitViewProof
	if err := json.Unmarshal(encoded, &relayed); err != nil {
		t.Fatal(err)
	}
	if err := VerifySplitView(&relayed, public); err != nil {
		t.Fatalf("a third party could not verify the equivocation: %v", err)
	}

	// The reader's held head does not move to the fork.
	head, ok := monitor.Head()
	if !ok || head.Size != 2 {
		t.Fatalf("the reader's head moved: %+v", head)
	}
	honestRoot, err := honest.tree.Root(2)
	if err != nil {
		t.Fatal(err)
	}
	if head.Root != honestRoot {
		t.Fatal("the reader's head is not the honest log's")
	}
}

func TestVerifySplitViewFailsClosed(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stranger, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	left, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	left.Append([]byte("a"))
	right, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	right.Append([]byte("b"))

	first, err := left.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	second, err := right.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	genuine := &SplitViewProof{Origin: testOrigin, Size: 1, First: first, Second: second}
	if err := VerifySplitView(genuine, public); err != nil {
		t.Fatalf("genuine evidence was refused: %v", err)
	}

	sameRoot := &SplitViewProof{Origin: testOrigin, Size: 1, First: first, Second: first}
	wrongSize := &SplitViewProof{Origin: testOrigin, Size: 2, First: first, Second: second}
	wrongOrigin := &SplitViewProof{Origin: "somewhere.else/log", Size: 1, First: first, Second: second}
	tampered := *genuine
	tampered.Second.Size = 2

	for name, candidate := range map[string]*SplitViewProof{
		"no proof":                              nil,
		"the same root twice":                   sameRoot,
		"a size the checkpoints do not name":    wrongSize,
		"an origin the checkpoints do not name": wrongOrigin,
		"a checkpoint edited after signing":     &tampered,
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifySplitView(candidate, public); err == nil {
				t.Fatalf("evidence with %s was accepted", name)
			}
		})
	}
	// An accusation against the wrong key proves nothing, however genuine the
	// underlying equivocation.
	if err := VerifySplitView(genuine, stranger); err == nil {
		t.Fatal("equivocation was confirmed against a key that did not sign it")
	}
}

// Two signatures over the same head are how a quiet log keeps readers fresh,
// and must not read as equivocation.
func TestAReSignedHeadIsNotEquivocation(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("descriptor"))
	monitor := newTestMonitor(t, public, time.Hour)
	followLog(t, monitor, log, testEpoch)

	for minute := 1; minute <= 3; minute++ {
		when := testEpoch.Add(time.Duration(minute) * 30 * time.Minute)
		again, err := log.Checkpoint(when)
		if err != nil {
			t.Fatal(err)
		}
		if err := monitor.Update(again, ConsistencyProof{Old: 1, New: 1}, when); err != nil {
			t.Fatalf("a re-signed head was refused: %v", err)
		}
		if !monitor.Fresh(when) {
			t.Fatal("re-signing did not refresh the reader")
		}
	}
}

func TestInclusionMustBeAgainstTheHeldHead(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	log.Append([]byte("second"))
	monitor := newTestMonitor(t, public, time.Hour)
	followLog(t, monitor, log, testEpoch)

	log.Append([]byte("third"))
	// A proof against a head the reader has not verified says nothing about
	// the log the reader is watching, even though the log is honest.
	newer, err := log.ProveInclusion([]byte("first"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Accept([]byte("first"), newer, testEpoch); err == nil {
		t.Fatal("a proof against an unverified head was accepted")
	}

	held, err := log.ProveInclusion([]byte("first"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Accept([]byte("first"), held, testEpoch); err != nil {
		t.Fatalf("a proof against the held head was refused: %v", err)
	}
}

func TestAnotherLogsCheckpointIsRefused(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("descriptor"))

	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := NewLog("somewhere.else/log", otherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	elsewhere.Append([]byte("descriptor"))

	monitor := newTestMonitor(t, public, time.Hour)
	foreign, err := elsewhere.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := elsewhere.ProveConsistency(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(foreign, proof, testEpoch); err == nil {
		t.Fatal("a checkpoint from another log was accepted")
	}

	// Same origin, wrong key: a log that could be impersonated by anyone who
	// picked its name would authenticate nothing.
	impostor, err := NewLog(testOrigin, otherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	impostor.Append([]byte("descriptor"))
	forged, err := impostor.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(forged, proof, testEpoch); err == nil {
		t.Fatal("a checkpoint signed by a key that is not the log's was accepted")
	}

	// The positive control.
	followLog(t, monitor, log, testEpoch)
}

// Every way a checkpoint can be wrong, each with the reason it must be refused
// for.
//
// The reason is asserted, not just the refusal. Nearly every case here also
// fails a *later* check -- an edited root breaks the signature, a malformed time
// breaks the signature, a short root breaks the signature -- so a table that
// only asked "did this error" would pass with the check under test deleted. A
// mutation campaign found exactly that: six refusals could be turned into
// unconditional acceptance without a single test noticing.
func TestVerifyCheckpointFailsClosed(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	log.Append([]byte("second"))
	good, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	other, err := log.CheckpointAt(1, testEpoch)
	if err != nil {
		t.Fatal(err)
	}

	edit := func(change func(*Checkpoint)) Checkpoint {
		copied := good
		change(&copied)
		return copied
	}

	cases := map[string]struct {
		checkpoint Checkpoint
		because    string
	}{
		"an unrecognised version": {edit(func(c *Checkpoint) {
			c.Version = CheckpointVersion + "x"
		}), "unrecognised checkpoint version"},
		"no version": {edit(func(c *Checkpoint) {
			c.Version = ""
		}), "unrecognised checkpoint version"},
		"another origin": {edit(func(c *Checkpoint) {
			c.Origin = "somewhere.else/log"
		}), "is from log"},
		"an edited size": {edit(func(c *Checkpoint) {
			c.Size = 3
		}), "signature does not verify"},
		"another head's root": {edit(func(c *Checkpoint) {
			c.Root = other.Root
		}), "signature does not verify"},
		"an edited time": {edit(func(c *Checkpoint) {
			c.Time = "2026-08-26T13:00:00Z"
		}), "signature does not verify"},
		"a non-canonical time": {edit(func(c *Checkpoint) {
			c.Time = "2026-08-26T14:00:00+01:00"
		}), "checkpoint time"},
		"a time that is not RFC3339": {edit(func(c *Checkpoint) {
			c.Time = "26 August 2026"
		}), "checkpoint time"},
		"a root in upper-case hex": {edit(func(c *Checkpoint) {
			c.Root = strings.ToUpper(c.Root)
		}), "checkpoint root"},
		// Valid hex, one byte short. It also breaks the signature, which is
		// why the reason matters: without it this passes with the length check
		// removed.
		"a truncated root": {edit(func(c *Checkpoint) {
			c.Root = c.Root[:62]
		}), "checkpoint root"},
		"a root that is not hex": {edit(func(c *Checkpoint) {
			c.Root = strings.Repeat("z", 64)
		}), "checkpoint root"},
		"no signature": {edit(func(c *Checkpoint) {
			c.Signature = ""
		}), "canonical Ed25519 signature"},
		"a signature that is not base64": {edit(func(c *Checkpoint) {
			c.Signature = strings.Repeat("!", 88)
		}), "canonical Ed25519 signature"},
		// Well-formed base64 of the wrong length. Go's ed25519.Verify would
		// also refuse it, so without the reason this passes with the length
		// check gone.
		"a signature of the wrong length": {edit(func(c *Checkpoint) {
			c.Signature = base64.StdEncoding.EncodeToString(make([]byte, 63))
		}), "canonical Ed25519 signature"},
		// Base64 decoding ignores line breaks, so this decodes to exactly the
		// right 64 bytes and verifies -- but it is a second spelling of one
		// signature, and one document with two spellings is how two verifiers
		// come to disagree about what was signed.
		"a signature with an embedded newline": {edit(func(c *Checkpoint) {
			c.Signature = c.Signature[:40] + "\n" + c.Signature[40:]
		}), "canonical base64 form"},
		"a flipped signature byte": {edit(func(c *Checkpoint) {
			raw := []byte(c.Signature)
			if raw[0] == 'A' {
				raw[0] = 'B'
			} else {
				raw[0] = 'A'
			}
			c.Signature = string(raw)
		}), "signature does not verify"},
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyCheckpoint(candidate.checkpoint, testOrigin, public)
			if err == nil {
				t.Fatalf("a checkpoint with %s verified", name)
			}
			if !strings.Contains(err.Error(), candidate.because) {
				t.Fatalf("a checkpoint with %s was refused, but for %q rather than %q; a "+
					"refusal that comes from a later check leaves the one under test "+
					"untested", name, err.Error(), candidate.because)
			}
		})
	}

	if _, err := VerifyCheckpoint(good, "", public); err == nil {
		t.Error("a checkpoint verified with no expected origin named")
	}
	if _, err := VerifyCheckpoint(good, testOrigin, public[:16]); err == nil {
		t.Error("a checkpoint verified against a key of the wrong length")
	}
	if _, err := VerifyCheckpoint(good, testOrigin, public); err != nil {
		t.Fatalf("the unmodified checkpoint was refused: %v", err)
	}
}

// Bounds are checked at the bound, not near it. An off-by-one in a limit is
// invisible to a test that only tries a value far outside it.
func TestLimitsHoldExactlyAtTheirBoundary(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	longest := strings.Repeat("x", maxOriginBytes)
	if _, err := NewLog(longest, private); err != nil {
		t.Errorf("an origin of exactly %d bytes was refused: %v", maxOriginBytes, err)
	}
	if _, err := NewLog(longest+"x", private); err == nil {
		t.Errorf("an origin of %d bytes was accepted", maxOriginBytes+1)
	}
	tree := &Tree{}
	tree.Append([]byte("entry"))
	if _, err := SignCheckpoint(longest, tree, 1, testEpoch, private); err != nil {
		t.Errorf("signing under an origin of exactly %d bytes failed: %v", maxOriginBytes, err)
	}
	if _, err := SignCheckpoint(longest+"x", tree, 1, testEpoch, private); err == nil {
		t.Errorf("signing under an origin of %d bytes succeeded", maxOriginBytes+1)
	}

	// A document of exactly the size limit is inside it. The padding goes in
	// the origin, which DecodeCheckpoint does not itself bound -- the point
	// here is the document limit, not the origin limit.
	build := func(origin string) []byte {
		encoded, err := json.Marshal(Checkpoint{
			Version: CheckpointVersion, Origin: origin, Size: 1,
			Root:      strings.Repeat("ab", 32),
			Time:      "2026-08-26T12:00:00Z",
			Signature: base64.StdEncoding.EncodeToString(make([]byte, 64)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	padding := maxCheckpointBytes - len(build(""))
	if padding < 1 {
		t.Fatal("the empty document already exceeds the limit")
	}
	if _, err := DecodeCheckpoint(build(strings.Repeat("y", padding))); err != nil {
		t.Errorf("a document of exactly %d bytes was refused: %v", maxCheckpointBytes, err)
	}
	oversize := build(strings.Repeat("y", padding+1))
	if len(oversize) != maxCheckpointBytes+1 {
		t.Fatalf("the oversize document is %d bytes", len(oversize))
	}
	if _, err := DecodeCheckpoint(oversize); err == nil {
		t.Errorf("a document of %d bytes was accepted", maxCheckpointBytes+1)
	}

	// The same bound on the way out. EncodeCheckpoint is exported and takes
	// whatever it is handed, so it carries its own limit rather than trusting
	// that everything reaching it came from SignCheckpoint.
	atLimit := Checkpoint{Version: CheckpointVersion, Origin: strings.Repeat("y", padding),
		Size: 1, Root: strings.Repeat("ab", 32), Time: "2026-08-26T12:00:00Z",
		Signature: base64.StdEncoding.EncodeToString(make([]byte, 64))}
	if _, err := EncodeCheckpoint(atLimit); err != nil {
		t.Errorf("encoding a document of exactly %d bytes failed: %v", maxCheckpointBytes, err)
	}
	past := atLimit
	past.Origin += "y"
	if _, err := EncodeCheckpoint(past); err == nil {
		t.Errorf("a document of %d bytes was encoded", maxCheckpointBytes+1)
	}
}

// A reader that has never verified a checkpoint holds no view of the log at
// all, which is the most stale it can possibly be. It must refuse rather than
// treat "nothing yet" as "nothing wrong".
func TestAReaderThatHasNeverSyncedAcceptsNothing(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("descriptor"))
	monitor := newTestMonitor(t, public, time.Hour)

	proof, err := log.ProveInclusion([]byte("descriptor"), 1)
	if err != nil {
		t.Fatal(err)
	}
	err = monitor.Accept([]byte("descriptor"), proof, testEpoch)
	if !errors.Is(err, ErrStale) {
		t.Fatalf("a reader with no checkpoint accepted a logged entry: %v", err)
	}
	if monitor.Fresh(testEpoch) {
		t.Fatal("a reader with no checkpoint reports itself fresh")
	}
	if _, held := monitor.Head(); held {
		t.Fatal("a reader with no checkpoint reports a head")
	}

	// And once it has synced, the same call works, so the refusal above is
	// about the missing checkpoint and not about the proof.
	followLog(t, monitor, log, testEpoch)
	if err := monitor.Accept([]byte("descriptor"), proof, testEpoch); err != nil {
		t.Fatalf("after syncing the same entry was refused: %v", err)
	}
}

// The split-view memory is bounded, so a reader that follows a log for months
// does not grow without limit. What the bound must not cost is the case the
// escalation path depends on: the size the reader currently holds.
func TestTheSplitViewMemoryIsBoundedButKeepsTheHeldHead(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	monitor := newTestMonitor(t, public, 100*24*time.Hour)
	for step := 0; step < maxRememberedHeads*2; step++ {
		log.Append([]byte(fmt.Sprintf("entry %d", step)))
		followLog(t, monitor, log, testEpoch.Add(time.Duration(step)*time.Minute))
	}
	// Exactly the bound, not merely no more than it. A test that only asked
	// for "no more than" passes on an eviction that is one too eager, and a
	// bound that quietly holds one fewer head than it claims is a bound nobody
	// can reason about.
	if len(monitor.heads) != maxRememberedHeads {
		t.Fatalf("the reader remembers %d heads after %d updates; the bound is %d",
			len(monitor.heads), maxRememberedHeads*2, maxRememberedHeads)
	}
	if len(monitor.order) != len(monitor.heads) {
		t.Fatalf("the eviction order carries %d sizes for %d heads",
			len(monitor.order), len(monitor.heads))
	}

	// Re-signing the same head must not consume the bound, or a quiet log
	// would evict a reader's memory just by keeping it fresh.
	held, ok := monitor.Head()
	if !ok {
		t.Fatal("the reader holds no head")
	}
	before := len(monitor.order)
	for again := 0; again < 10; again++ {
		when := testEpoch.Add(time.Duration(again+1) * 24 * time.Hour)
		checkpoint, err := log.Checkpoint(when)
		if err != nil {
			t.Fatal(err)
		}
		if err := monitor.Update(checkpoint,
			ConsistencyProof{Old: held.Size, New: held.Size}, when); err != nil {
			t.Fatal(err)
		}
	}
	if len(monitor.order) != before {
		t.Fatalf("re-signing one head moved the eviction order from %d to %d entries",
			before, len(monitor.order))
	}

	// The held size is still remembered, so a second head at it is still
	// caught. This is the step that turns a failed consistency proof into
	// evidence, and a bound that dropped it would break the escalation.
	forked, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	for step := uint64(0); step < held.Size; step++ {
		forked.Append([]byte(fmt.Sprintf("a different entry %d", step)))
	}
	competing, err := forked.CheckpointAt(held.Size, testEpoch.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	err = monitor.Update(competing, ConsistencyProof{Old: held.Size, New: held.Size},
		testEpoch.Add(30*24*time.Hour))
	var split *SplitViewProof
	if !errors.As(err, &split) {
		t.Fatalf("a second head at the held size did not produce a split-view proof: %v", err)
	}
	if err := VerifySplitView(split, public); err != nil {
		t.Fatalf("the evidence does not verify: %v", err)
	}
}

// The duplicate-member scan walks the whole document, including arrays and
// nested objects a checkpoint never contains. It runs on the raw bytes before
// any schema check, so a hostile document reaches it first, and a bug that
// stopped the walk early would leave the scan reporting on the first member
// alone.
func TestTheDuplicateScanWalksTheWholeDocument(t *testing.T) {
	// The limit is checked at the limit. A document nested far past it is
	// refused by an off-by-one bound as readily as by the right one.
	nest := func(levels int) []byte {
		return []byte(`{"version":` + strings.Repeat("[", levels) +
			strings.Repeat("]", levels) + `}`)
	}
	if _, err := DecodeCheckpoint(nest(maxCheckpointDepth + 1)); err == nil {
		t.Fatal("a document past the depth limit was accepted")
	} else if !strings.Contains(err.Error(), "nested too deeply") {
		t.Fatalf("a document past the depth limit was refused for %q rather than its depth", err)
	}
	if _, err := DecodeCheckpoint(nest(maxCheckpointDepth)); err == nil {
		t.Fatal("a checkpoint whose version is a nest of arrays was accepted")
	} else if strings.Contains(err.Error(), "nested too deeply") {
		t.Fatalf("a document at exactly the depth limit was refused for its depth: %v", err)
	}

	// A duplicate after a member whose value is a container: the scan has to
	// come back up and keep going to find it.
	late := `{"origin":[1,2,{"a":1}],"version":"x","size":1,"size":2}`
	if _, err := DecodeCheckpoint([]byte(late)); err == nil {
		t.Fatal("a duplicate member after a nested value was accepted")
	} else if !strings.Contains(err.Error(), "duplicate member") {
		t.Fatalf("refused for %q rather than the duplicate", err)
	}

	// Nesting that stops mid-array must fail rather than be walked past.
	for name, broken := range map[string]string{
		"a truncated array":    `{"version":[1,2`,
		"a truncated object":   `{"version":{"a":`,
		"a non-string key":     "{\"version\":1,}",
		"an unclosed document": `{"version":"x"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCheckpoint([]byte(broken)); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

// A signing message that did not separate its fields could be satisfied by a
// different checkpoint: move a byte from the origin into the time and the
// signature still covers the same bytes. Length prefixes are what stop that,
// and this test is what shows they are there.
func TestTheSigningMessageCannotBeReflowed(t *testing.T) {
	var root [32]byte
	root[0] = 0x7f
	left := checkpointSigningMessage("nomad.example/ab", 1, root, "2026-08-26T12:00:00Z")
	right := checkpointSigningMessage("nomad.example/a", 1, root, "b2026-08-26T12:00:00Z")
	if string(left) == string(right) {
		t.Fatal("two different checkpoints produce the same signing message")
	}
	// Every byte of the size, not just the low ones. A length-prefix writer
	// that stopped one byte early would produce identical messages for sizes
	// that differ only above 2^56, and a log could then present a head of one
	// size under a signature made for another.
	for _, size := range []uint64{1, 256, 1 << 32, 1 << 56, 1 << 63, ^uint64(0)} {
		if string(checkpointSigningMessage("origin", 0, root, "t")) ==
			string(checkpointSigningMessage("origin", size, root, "t")) {
			t.Fatalf("size %d produces the same signing message as size 0", size)
		}
	}
}

// A split-view proof must name the size both of its checkpoints actually carry.
// Checking only one of them would let a proof be assembled from two heads of
// genuinely different sizes, which is an ordinary append rather than
// equivocation.
func TestSplitViewChecksBothCheckpointSizes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	log.Append([]byte("a"))
	log.Append([]byte("b"))
	one, err := log.CheckpointAt(1, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	two, err := log.CheckpointAt(2, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	// Two honest heads of different sizes. Their roots differ, as they must,
	// and that is not equivocation.
	for name, proof := range map[string]*SplitViewProof{
		"the first checkpoint at another size":  {Origin: testOrigin, Size: 2, First: one, Second: two},
		"the second checkpoint at another size": {Origin: testOrigin, Size: 1, First: one, Second: two},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifySplitView(proof, public); err == nil {
				t.Fatalf("an ordinary append was confirmed as equivocation via %s", name)
			}
		})
	}
}

func TestDecodeCheckpointRefusesMalformedDocuments(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("descriptor"))
	good, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCheckpoint(good)
	if err != nil {
		t.Fatal(err)
	}

	duplicated := strings.Replace(string(encoded), `{"version"`,
		fmt.Sprintf(`{"size":%d,"version"`, good.Size+1), 1)

	for name, candidate := range map[string][]byte{
		"an unknown member":    []byte(strings.Replace(string(encoded), `"origin"`, `"surprise"`, 1)),
		"a duplicate member":   []byte(duplicated),
		"trailing content":     append(append([]byte(nil), encoded...), []byte("{}")...),
		"not JSON":             []byte("this is not a checkpoint"),
		"a truncated document": encoded[:len(encoded)/2],
		"a document over the size limit": []byte(`{"version":"` +
			strings.Repeat("x", maxCheckpointBytes) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCheckpoint(candidate); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}

	decoded, err := DecodeCheckpoint(encoded)
	if err != nil {
		t.Fatalf("a published checkpoint did not decode: %v", err)
	}
	if _, err := VerifyCheckpoint(decoded, testOrigin, public); err != nil {
		t.Fatalf("a round-tripped checkpoint did not verify: %v", err)
	}
}

func TestConstructorsRefuseUnusableConfiguration(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewLog("", private); err == nil {
		t.Error("a log with no origin was built")
	}
	if _, err := NewLog(strings.Repeat("x", maxOriginBytes+1), private); err == nil {
		t.Error("a log with an unbounded origin was built")
	}
	if _, err := NewLog(testOrigin, private[:16]); err == nil {
		t.Error("a log was built on a key that is not an Ed25519 private key")
	}
	if _, err := NewMonitor("", public, time.Hour); err == nil {
		t.Error("a monitor with no origin was built")
	}
	if _, err := NewMonitor(testOrigin, public[:16], time.Hour); err == nil {
		t.Error("a monitor was built on a key that is not an Ed25519 public key")
	}
	for _, window := range []time.Duration{0, -time.Hour} {
		if _, err := NewMonitor(testOrigin, public, window); err == nil {
			t.Errorf("a monitor was built with a freshness window of %s", window)
		}
	}
}

// A log that grew every time somebody re-submitted the same descriptor would
// make its size meaningless, and every reader's consistency proof would churn.
func TestReappendingAnEntryDoesNotGrowTheLog(t *testing.T) {
	log, public, _ := newTestLog(t)
	first := log.Append([]byte("descriptor"))
	again := log.Append([]byte("descriptor"))
	if first != again {
		t.Fatalf("the same entry was logged at %d and %d", first, again)
	}
	if log.Size() != 1 {
		t.Fatalf("the log holds %d entries after two appends of one", log.Size())
	}
	monitor := newTestMonitor(t, public, time.Hour)
	followLog(t, monitor, log, testEpoch)
	proof, err := log.ProveInclusion([]byte("descriptor"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Accept([]byte("descriptor"), proof, testEpoch); err != nil {
		t.Fatal(err)
	}
}

// Equivocation is absorbing. A reader that refused the offending checkpoint but
// carried on would let an attacker step around the detection by advancing to a
// size the reader holds no second head for -- which is the whole attack, run
// once more with a different number.
func TestEquivocationEndsTheReadersRelationshipWithTheLog(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	honest, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	honest.Append([]byte("first"))
	monitor := newTestMonitor(t, public, 24*time.Hour)
	followLog(t, monitor, honest, testEpoch)

	forked, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	forked.Append([]byte("a different first"))
	competing, err := forked.Checkpoint(testEpoch.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	err = monitor.Update(competing, ConsistencyProof{Old: 1, New: 1}, testEpoch.Add(time.Minute))
	var split *SplitViewProof
	if !errors.As(err, &split) {
		t.Fatalf("no split-view proof: %v", err)
	}
	if found, equivocating := monitor.Equivocating(); !equivocating || found != split {
		t.Fatal("the reader does not report itself as holding equivocation evidence")
	}

	// The honest log's own next checkpoint is refused too. That is the point:
	// there is no branch this reader is entitled to prefer any more, and
	// "prefer the one I saw first" is a rule an attacker chooses the order for.
	honest.Append([]byte("second"))
	next, err := honest.Checkpoint(testEpoch.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := honest.ProveConsistency(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(next, proof, testEpoch.Add(2*time.Minute)); !errors.Is(err,
		ErrSplitView) {
		t.Fatalf("a reader that found equivocation accepted a later checkpoint: %v", err)
	}

	// And it accepts no further entries, including ones genuinely in the log
	// it was following.
	inclusion, err := honest.ProveInclusion([]byte("first"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Accept([]byte("first"), inclusion, testEpoch.Add(2*time.Minute)); !errors.Is(
		err, ErrSplitView) {
		t.Fatalf("a reader that found equivocation accepted an entry: %v", err)
	}
}
