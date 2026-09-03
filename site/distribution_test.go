package site

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-local-reconstruction/site/transparency"
)

const testLogOrigin = "nomad.example/descriptor-log"

// witnessedSite is a running descriptor log and one reader watching it.
//
// The reader is driven the way a deployment drives it: descriptors are logged,
// the reader refreshes its checkpoint on a cadence that has nothing to do with
// what anyone is reading, and every inclusion proof is taken against the head
// the reader has actually verified.
type witnessedSite struct {
	log          *transparency.Log
	distribution *Distribution
	public       ed25519.PublicKey
	private      ed25519.PrivateKey
}

func newWitnessedSite(t *testing.T, window time.Duration) *witnessedSite {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := transparency.NewLog(testLogOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	distribution, err := NewDistribution(testLogOrigin, public, window)
	if err != nil {
		t.Fatal(err)
	}
	return &witnessedSite{log: log, distribution: distribution, public: public, private: private}
}

// newReader is a second reader of the same log, with its own view.
//
// Each reader holds its own checkpoint, because the whole value of a held
// checkpoint is that it advances in one order for one reader. Two readers that
// shared one could not be partitioned from each other, which is the situation
// the drill needs to be able to build.
func (w *witnessedSite) newReader(t *testing.T, window time.Duration) *witnessedSite {
	t.Helper()
	distribution, err := NewDistribution(testLogOrigin, w.public, window)
	if err != nil {
		t.Fatal(err)
	}
	return &witnessedSite{log: w.log, distribution: distribution,
		public: w.public, private: w.private}
}

// publish puts a descriptor in the log, which is what the site operator does.
func (w *witnessedSite) publish(t *testing.T, encoded []byte) {
	t.Helper()
	w.log.Append(LogEntry(encoded))
}

// sync is the scheduled checkpoint refresh. It takes no argument describing
// what anybody is reading, because it must not have one.
func (w *witnessedSite) sync(t *testing.T, now time.Time) {
	t.Helper()
	checkpoint, err := w.log.Checkpoint(now)
	if err != nil {
		t.Fatal(err)
	}
	var held uint64
	if head, ok := w.distribution.Head(); ok {
		held = head.Size
	}
	proof, err := w.log.ProveConsistency(held, w.log.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.distribution.Refresh(checkpoint, proof, now); err != nil {
		t.Fatalf("a reader could not follow an honest log: %v", err)
	}
}

// proofFor is the inclusion proof that travels with a publication.
func (w *witnessedSite) proofFor(t *testing.T, encoded []byte) transparency.InclusionProof {
	t.Helper()
	head, ok := w.distribution.Head()
	if !ok {
		t.Fatal("the reader holds no checkpoint")
	}
	proof, err := w.log.ProveInclusion(LogEntry(encoded), head.Size)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// chain publishes a genesis, syncs, and builds a witnessed chain from it.
func (w *witnessedSite) chain(t *testing.T, id ID, genesis []byte, now time.Time) *Chain {
	t.Helper()
	w.publish(t, genesis)
	w.sync(t, now)
	chain, err := NewWitnessedChain(id, genesis, w.proofFor(t, genesis), w.distribution, now)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// appendTo publishes a successor, syncs and accepts it.
func (w *witnessedSite) appendTo(t *testing.T, chain *Chain, encoded []byte, now time.Time) Verified {
	t.Helper()
	w.publish(t, encoded)
	w.sync(t, now)
	verified, err := chain.AppendWitnessed(encoded, w.proofFor(t, encoded), now)
	if err != nil {
		t.Fatalf("a logged descriptor was refused: %v", err)
	}
	return verified
}

// The property PROD-15 asks for, as one test: a descriptor the attacker showed
// to this reader alone cannot enter the chain, because it is not in the log.
func TestAnUnloggedDescriptorCannotEnterAWitnessedChain(t *testing.T) {
	f := newSiteFixture(t)
	now := testBase.Add(time.Hour)
	w := newWitnessedSite(t, 24*time.Hour)
	chain := w.chain(t, f.ID, f.Genesis, now)

	rotated, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, nil,
		[]ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")

	// The attacker has a structurally valid descriptor and no way to get it
	// into the log. The best proof it can offer is one for an entry that is
	// there.
	stolen := w.proofFor(t, f.Genesis)
	if _, err := chain.AppendWitnessed(rotated, stolen, now); err == nil {
		t.Fatal("a descriptor that was never logged was accepted into the chain")
	}

	// The same bytes, once logged, are accepted. Without this the refusal
	// above would be satisfied by a chain that accepts nothing.
	w.appendTo(t, chain, rotated, now)
	head, err := chain.Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.Descriptor.Sequence != 1 {
		t.Fatalf("the chain head is at sequence %d", head.Descriptor.Sequence)
	}
}

// Neither method may quietly do the other's job: that is how a gate stops
// applying in exactly the deployment that needed it.
func TestTheWitnessedAndUnwitnessedPathsDoNotSubstituteForEachOther(t *testing.T) {
	f := newSiteFixture(t)
	now := testBase.Add(time.Hour)
	w := newWitnessedSite(t, 24*time.Hour)

	witnessed := w.chain(t, f.ID, f.Genesis, now)
	rotated, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, nil,
		[]ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	w.publish(t, rotated)
	w.sync(t, now)
	if _, err := witnessed.Append(rotated); err == nil {
		t.Fatal("a witnessed chain accepted a descriptor through the unwitnessed path")
	}

	plain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(mustErr(t, func() error {
		_, err := plain.AppendWitnessed(rotated, w.proofFor(t, rotated), now)
		return err
	}), ErrUnwitnessed) {
		t.Fatal("an unwitnessed chain accepted a descriptor through the witnessed path")
	}
	if witnessed.Witnessed() == plain.Witnessed() {
		t.Fatal("the two chains do not report different witnessing")
	}
	if _, err := NewWitnessedChain(f.ID, f.Genesis, w.proofFor(t, f.Genesis), nil, now); err == nil {
		t.Fatal("a witnessed chain was built with no log view")
	}
}

func mustErr(t *testing.T, run func() error) error {
	t.Helper()
	err := run()
	if err == nil {
		t.Fatal("expected an error")
	}
	return err
}

// A chain built without a log view can never reach a publisher verdict. This is
// the structural half of the property: forgetting to wire up distribution
// cannot silently return the system to the state PROD-15 describes.
func TestAnUnwitnessedChainCannotReachAPublisherVerdict(t *testing.T) {
	f := newSiteFixture(t)
	now := testBase.Add(2 * time.Hour)
	chain, err := NewChain(f.ID, f.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	manifest, data := buildManifest(t, f.SigningA, "an object")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(time.Hour), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	state, err := Resolve(f.ID, chain, &publication, manifest, data, now)
	if state != PublisherUnknown {
		t.Fatalf("an unwitnessed chain resolved %v", state)
	}
	if !errors.Is(err, ErrUnwitnessed) {
		t.Fatalf("the reason given is not the missing log view: %v", err)
	}

	// A contradicted claim is still invalid without a log view. Suppressing a
	// detected contradiction because a checkpoint is missing would trade a true
	// negative for an absence, which is strictly worse for the reader.
	wrong := publication
	wrong.ObjectRoot = wrong.ManifestDigest
	if state, _ := Resolve(f.ID, chain, &wrong, manifest, data, now); state != PublisherInvalid {
		t.Fatalf("a contradicted claim resolved %v on an unwitnessed chain", state)
	}
}

// The bound the criterion asks for: an attacker who partitions a reader from
// the log buys a freshness window, not indefinite acceptance.
func TestAPartitionedReaderLosesThePublisherVerdict(t *testing.T) {
	f := newSiteFixture(t)
	const window = 6 * time.Hour
	start := testBase.Add(time.Hour)
	w := newWitnessedSite(t, window)
	chain := w.chain(t, f.ID, f.Genesis, start)

	manifest, data := buildManifest(t, f.SigningA, "an object")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(30*time.Minute), f.SigningA)
	if err != nil {
		t.Fatal(err)
	}

	if state, err := Resolve(f.ID, chain, &publication, manifest, data, start); state != PublisherVerified {
		t.Fatalf("a witnessed, fresh reader resolved %v: %v", state, err)
	}
	if state, err := Resolve(f.ID, chain, &publication, manifest, data,
		start.Add(window)); state != PublisherVerified {
		t.Fatalf("at the edge of the window the reader resolved %v: %v", state, err)
	}

	past := start.Add(window + time.Second)
	state, err := Resolve(f.ID, chain, &publication, manifest, data, past)
	if state != PublisherUnknown {
		t.Fatalf("past the window the reader resolved %v", state)
	}
	if !errors.Is(err, ErrStaleDistribution) {
		t.Fatalf("the reason given is not staleness: %v", err)
	}

	// A stale reader also stops accepting new descriptors, or an attacker
	// could partition a reader and then feed it a branch at leisure.
	rotated, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, nil,
		[]ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	w.publish(t, rotated)
	if _, err := chain.AppendWitnessed(rotated, transparency.InclusionProof{}, past); !errors.Is(err,
		ErrStaleDistribution) {
		t.Fatalf("a stale reader accepted a descriptor: %v", err)
	}

	// The partition ending restores the verdict, so this is a bound and not a
	// one-way door.
	w.sync(t, past)
	if state, err := Resolve(f.ID, chain, &publication, manifest, data, past); state != PublisherVerified {
		t.Fatalf("after catching up the reader resolved %v: %v", state, err)
	}
}

// A log entry must not be readable as anything else, or an attacker who could
// get some other kind of entry logged would get a descriptor accepted with it.
func TestLogEntriesAreDomainSeparatedAndUnambiguous(t *testing.T) {
	first := LogEntry([]byte("aa"))
	second := LogEntry([]byte("a"))
	if string(first) == string(second)+"a" {
		t.Fatal("two descriptors of different lengths produce colliding entries")
	}
	if string(LogEntry(nil)) == "" {
		t.Fatal("an empty descriptor produces an empty entry")
	}
	entry := LogEntry([]byte("descriptor"))
	if string(entry[:len(logEntryDomain)]) != logEntryDomain {
		t.Fatal("the entry is not domain-separated")
	}
}

// The shape this is specified to run in: a refresh on a fixed cadence in one
// goroutine, reads driven by whatever the user is doing in another. If that is
// a data race, the documentation describes a deployment the code cannot
// support.
func TestADistributionSurvivesItsOwnDeploymentShape(t *testing.T) {
	f := newSiteFixture(t)
	start := testBase.Add(time.Hour)
	w := newWitnessedSite(t, 24*time.Hour)
	chain := w.chain(t, f.ID, f.Genesis, start)
	manifest, data := buildManifest(t, f.SigningA, "an object")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(30*time.Minute),
		f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	proof := w.proofFor(t, f.Genesis)

	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			now := start.Add(time.Duration(worker) * time.Minute)
			switch worker % 4 {
			case 0:
				// The scheduled refresh. It is deliberately racing the reads:
				// that is what a cadence does.
				checkpoint, err := w.log.Checkpoint(now)
				if err != nil {
					t.Error(err)
					return
				}
				held, ok := w.distribution.Head()
				var size uint64
				if ok {
					size = held.Size
				}
				consistency, err := w.log.ProveConsistency(size, w.log.Size())
				if err != nil {
					t.Error(err)
					return
				}
				_ = w.distribution.Refresh(checkpoint, consistency, now)
			case 1:
				_, _ = Resolve(f.ID, chain, &publication, manifest, data, now)
			case 2:
				_ = w.distribution.Fresh(now)
				_, _ = w.distribution.Head()
			default:
				_ = w.distribution.Witness(f.Genesis, proof, now)
			}
		}(worker)
	}
	group.Wait()

	// And it still works afterwards, so the test is not passing because every
	// goroutine failed quietly.
	w.sync(t, start.Add(time.Hour))
	if state, err := Resolve(f.ID, chain, &publication, manifest, data,
		start.Add(time.Hour)); state != PublisherVerified {
		t.Fatalf("after concurrent use the reader resolved %v: %v", state, err)
	}
}

// A site whose log served two histories stops reaching a publisher verdict,
// and reports evidence rather than absence.
//
// It is PUBLISHER_INVALID rather than PUBLISHER_UNKNOWN for the same reason a
// forked descriptor chain is: the reader is not missing information, it is
// holding proof that the information it has cannot be trusted. Reporting that
// as "unknown" would tell somebody nothing is wrong.
func TestALogThatEquivocatedEndsTheVerdictForItsSites(t *testing.T) {
	f := newSiteFixture(t)
	now := testBase.Add(time.Hour)
	w := newWitnessedSite(t, 24*time.Hour)
	chain := w.chain(t, f.ID, f.Genesis, now)

	manifest, data := buildManifest(t, f.SigningA, "an object")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(30*time.Minute),
		f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := Resolve(f.ID, chain, &publication, manifest, data, now); state != PublisherVerified {
		t.Fatalf("before the fork the reader resolved %v: %v", state, err)
	}

	forked, err := transparency.NewLog(testLogOrigin, w.private)
	if err != nil {
		t.Fatal(err)
	}
	forked.Append(LogEntry([]byte("a descriptor the honest log never carried")))
	held, _ := w.distribution.Head()
	competing, err := forked.CheckpointAt(held.Size, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	err = w.distribution.Refresh(competing,
		transparency.ConsistencyProof{Old: held.Size, New: held.Size}, now.Add(time.Minute))
	var split *transparency.SplitViewProof
	if !errors.As(err, &split) {
		t.Fatalf("no split-view proof: %v", err)
	}
	if found, equivocating := w.distribution.Equivocating(); !equivocating || found != split {
		t.Fatal("the distribution does not report itself as holding evidence")
	}

	state, err := Resolve(f.ID, chain, &publication, manifest, data, now.Add(2*time.Minute))
	if state != PublisherInvalid {
		t.Fatalf("after the log equivocated the reader resolved %v", state)
	}
	if !errors.Is(err, transparency.ErrSplitView) {
		t.Fatalf("the reason given is not the equivocation: %v", err)
	}

	// Refreshing the log honestly does not clear it, and no further descriptor
	// is accepted. The state is absorbing on both paths.
	w.publish(t, f.Genesis)
	if err := w.distribution.Refresh(competing,
		transparency.ConsistencyProof{Old: held.Size, New: held.Size},
		now.Add(3*time.Minute)); !errors.Is(err, transparency.ErrSplitView) {
		t.Fatalf("a later refresh cleared the equivocation: %v", err)
	}
	rotated, _ := f.successor(t, f.Verified, TransitionRotation,
		[]ed25519.PrivateKey{f.Rotated}, nil,
		[]ed25519.PrivateKey{f.SigningA, f.SigningB}, "signing")
	if _, err := chain.AppendWitnessed(rotated, transparency.InclusionProof{},
		now.Add(3*time.Minute)); !errors.Is(err, transparency.ErrSplitView) {
		t.Fatalf("a descriptor was accepted after the log equivocated: %v", err)
	}
}

// The freeze, at the boundary where it decides a publisher verdict.
//
// The site's signing key is compromised and the owner publishes a recovery
// descriptor revoking it. A colluding log withholds that descriptor from one
// targeted reader by re-signing the head from just before it with a current
// timestamp -- which is indistinguishable from an honest quiet log, so nothing
// the reader can check locally rejects it. The reader stays fresh, keeps the
// pre-recovery chain, and keeps resolving the attacker's publications as coming
// from a verified publisher, for as long as the log keeps re-signing.
//
// Requiring witness cosignatures ends it: the witness moved to the head that
// carries the recovery and will not sign the old one at a new date, so the
// reader refuses, goes stale, and stops issuing a verdict at all.
//
// PublisherUnknown is the right answer here and not a lesser one. The reader
// genuinely does not know; saying so is the whole point.
func TestACosignedReaderCannotBeFrozenBeforeARecovery(t *testing.T) {
	f := newSiteFixture(t)
	const window = time.Hour
	start := testBase.Add(time.Hour)

	witnessKeyPublic, witnessKeyPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logPublic, logPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := transparency.NewLog(testLogOrigin, logPrivate)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := transparency.NewWitness("witness-one", witnessKeyPrivate, testLogOrigin,
		logPublic, window)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := transparency.NewWitnessPolicy(1,
		map[string]ed25519.PublicKey{"witness-one": witnessKeyPublic})
	if err != nil {
		t.Fatal(err)
	}

	// Bring both readers to the genesis, on a head the witness cosigned then.
	log.Append(LogEntry(f.Genesis))
	genesisHead, err := log.CheckpointAt(log.Size(), start)
	if err != nil {
		t.Fatal(err)
	}
	genesisProof, err := log.ProveConsistency(0, log.Size())
	if err != nil {
		t.Fatal(err)
	}
	cosignature, err := witness.Cosign(genesisHead, genesisProof, start)
	if err != nil {
		t.Fatal(err)
	}
	genesisHead.Cosignatures = []transparency.Cosignature{cosignature}

	unguarded, err := NewDistribution(testLogOrigin, logPublic, window)
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := NewCosignedDistribution(testLogOrigin, logPublic, window, policy)
	if err != nil {
		t.Fatal(err)
	}
	for name, reader := range map[string]*Distribution{"unguarded": unguarded, "guarded": guarded} {
		if err := reader.Refresh(genesisHead, genesisProof, start); err != nil {
			t.Fatalf("the %s reader could not start at the genesis: %v", name, err)
		}
	}
	inclusion, err := log.ProveInclusion(LogEntry(f.Genesis), log.Size())
	if err != nil {
		t.Fatal(err)
	}
	unguardedChain, err := NewWitnessedChain(f.ID, f.Genesis, inclusion, unguarded, start)
	if err != nil {
		t.Fatal(err)
	}
	guardedChain, err := NewWitnessedChain(f.ID, f.Genesis, inclusion, guarded, start)
	if err != nil {
		t.Fatal(err)
	}

	// A publication signed by the key that is about to be compromised.
	manifest, data := buildManifest(t, f.SigningA, "an object")
	publication, err := NewPublication(f.ID, f.Verified, manifest, testBase.Add(30*time.Minute),
		f.SigningA)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := Resolve(f.ID, unguardedChain, &publication, manifest, data, start); state != PublisherVerified {
		t.Fatalf("before the compromise the reader resolved %v: %v", state, err)
	}

	// The compromise, and the owner's answer to it. The log takes the recovery
	// and the witness follows it; only the targeted reader is held back.
	recovery, _ := f.successor(t, f.Verified, TransitionRecovery,
		[]ed25519.PrivateKey{f.Rescued},
		[]string{encodeKey(f.SigningA), encodeKey(f.SigningB)},
		[]ed25519.PrivateKey{f.RecoverA, f.RecoverB}, "recovery")
	log.Append(LogEntry(recovery))
	frozenAt := log.Size() - 1
	if _, err := witness.Cosign(mustCheckpoint(t, log, start.Add(time.Minute)),
		mustConsistency(t, log, frozenAt, log.Size()), start.Add(time.Minute)); err != nil {
		t.Fatalf("the witness could not follow the log past the recovery: %v", err)
	}

	// The log re-dates the pre-recovery head for hours. The unguarded reader
	// stays fresh and keeps its verdict on a key that has been revoked.
	now := start
	for round := 0; round < 24; round++ {
		now = now.Add(30 * time.Minute)
		stale, err := log.CheckpointAt(frozenAt, now)
		if err != nil {
			t.Fatal(err)
		}
		proof := mustConsistency(t, log, frozenAt, frozenAt)
		if err := unguarded.Refresh(stale, proof, now); err != nil {
			t.Fatalf("round %d: the unguarded reader refused the re-dated head, so this "+
				"test's comparison proves nothing: %v", round, err)
		}
		if state, err := Resolve(f.ID, unguardedChain, &publication, manifest, data,
			now); state != PublisherVerified {
			t.Fatalf("round %d: the frozen reader resolved %v: %v", round, state, err)
		}

		// The same head, offered to the reader that requires a cosignature.
		if err := guarded.Refresh(stale, proof, now); err == nil {
			t.Fatalf("round %d: the guarded reader accepted a head no witness would sign", round)
		}
	}

	// The unguarded reader has been held a full day behind a revocation while
	// reporting a verified publisher throughout. The guarded one ran out of
	// freshness and says it does not know.
	state, err := Resolve(f.ID, guardedChain, &publication, manifest, data, now)
	if state != PublisherUnknown {
		t.Fatalf("the guarded reader resolved %v rather than admitting it was cut off", state)
	}
	if !errors.Is(err, ErrStaleDistribution) {
		t.Fatalf("the reason given is not staleness: %v", err)
	}
}

func mustCheckpoint(t *testing.T, log *transparency.Log, now time.Time) transparency.Checkpoint {
	t.Helper()
	checkpoint, err := log.Checkpoint(now)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func mustConsistency(t *testing.T, log *transparency.Log, old, size uint64) transparency.ConsistencyProof {
	t.Helper()
	proof, err := log.ProveConsistency(old, size)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
