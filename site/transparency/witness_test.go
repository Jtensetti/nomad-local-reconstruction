package transparency

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"
)

func newTestWitness(t *testing.T, name string, logKey ed25519.PublicKey) *Witness {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := NewWitness(name, private, testOrigin, logKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return witness
}

// cosign brings a witness to a log's head and returns its signature, doing what
// a witness does on its own schedule: ask for the head, ask for a proof from
// what it holds, check both, then sign.
func cosign(t *testing.T, witness *Witness, log *Log, now time.Time) Cosignature {
	t.Helper()
	checkpoint, err := log.Checkpoint(now)
	if err != nil {
		t.Fatal(err)
	}
	var held uint64
	if head, ok := witness.Head(); ok {
		held = head.Size
	}
	proof, err := log.ProveConsistency(held, log.Size())
	if err != nil {
		t.Fatal(err)
	}
	cosignature, err := witness.Cosign(checkpoint, proof, now)
	if err != nil {
		t.Fatalf("an honest witness would not refuse an honest log: %v", err)
	}
	return cosignature
}

func policyOf(t *testing.T, threshold int, witnesses ...*Witness) *WitnessPolicy {
	t.Helper()
	keys := make(map[string]ed25519.PublicKey, len(witnesses))
	for _, witness := range witnesses {
		keys[witness.Name()] = witness.Public()
	}
	policy, err := NewWitnessPolicy(threshold, keys)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// forkLog builds a second log over the same key that has served a different
// history: the same size, a different root, every signature genuine. This is
// the attack the whole file exists for, and it is what a log operator who
// wanted to show two readers two worlds would actually construct.
func forkLog(t *testing.T, private ed25519.PrivateKey, entries ...string) *Log {
	t.Helper()
	log, err := NewLog(testOrigin, private)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		log.Append([]byte(entry))
	}
	return log
}

// The motivating attack, end to end.
//
// A log serves reader A one history and reader B another. Both are internally
// consistent, every signature is the log's own, and neither reader is ever
// shown the other's branch -- so neither Monitor has anything to compare
// against and both accept. That is the case tree.go says needs witnesses, and
// this is the test that it now fails.
func TestALogCannotServeTwoReadersTwoHistoriesOnceWitnessesCosign(t *testing.T) {
	real, public, private := newTestLog(t)
	real.Append([]byte("the site's real descriptor"))
	real.Append([]byte("its real rotation"))

	// The same log key, a different second entry: same size, different root.
	fork := forkLog(t, private, "the site's real descriptor", "the attacker's rotation")

	realHead, err := real.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	forkHead, err := fork.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	// Vacuity: if the two branches were the same head this test would pass
	// while demonstrating nothing at all.
	if realHead.Size != forkHead.Size {
		t.Fatalf("the fixture is not a split view: sizes %d and %d", realHead.Size, forkHead.Size)
	}
	if realHead.Root == forkHead.Root {
		t.Fatal("the fixture is not a split view: both branches have the same root")
	}

	// Both branches are genuinely signed by the log, so a reader checking only
	// signatures has no way to prefer either.
	if _, err := VerifyCheckpoint(forkHead, testOrigin, public); err != nil {
		t.Fatalf("the attacker's branch is not even well-formed, so this proves nothing: %v", err)
	}

	// Without witnesses, reader B accepts the attacker's branch. This is the
	// state of the world before this file existed, asserted so that the
	// comparison below is a real one.
	unwitnessed := newTestMonitor(t, public, time.Hour)
	forkProof, err := fork.ProveConsistency(0, fork.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := unwitnessed.Update(forkHead, forkProof, testEpoch); err != nil {
		t.Fatalf("a reader with no witness policy should have accepted the fork, and this "+
			"test's comparison depends on it: %v", err)
	}

	// Now the witness. It follows the real log first, which is the ordinary
	// case: the witness is watching the log continuously and the attacker's
	// branch arrives afterwards.
	witness := newTestWitness(t, "witness-one", public)
	cosignature := cosign(t, witness, real, testEpoch)
	realHead.Cosignatures = []Cosignature{cosignature}

	policy := policyOf(t, 1, witness)
	readerA, err := NewCosignedMonitor(testOrigin, public, time.Hour, policy)
	if err != nil {
		t.Fatal(err)
	}
	realProof, err := real.ProveConsistency(0, real.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := readerA.Update(realHead, realProof, testEpoch); err != nil {
		t.Fatalf("reader A could not follow the cosigned real log: %v", err)
	}

	// The attacker cannot get the second branch cosigned: the witness has
	// already signed a different root at this size, and says so with evidence.
	if _, err := witness.Cosign(forkHead, forkProof, testEpoch); !errors.Is(err, ErrSplitView) {
		t.Fatalf("the witness signed a second branch, or refused without evidence: %v", err)
	}
	var proof *SplitViewProof
	if !errors.As(func() error { _, err := witness.Cosign(forkHead, forkProof, testEpoch); return err }(), &proof) {
		t.Fatal("the witness refused without producing transferable evidence")
	}
	if err := VerifySplitView(proof, public); err != nil {
		t.Fatalf("the evidence does not check out against the log's key: %v", err)
	}

	// So reader B, which requires the same witness, refuses the branch the
	// unwitnessed reader accepted.
	readerB, err := NewCosignedMonitor(testOrigin, public, time.Hour, policy)
	if err != nil {
		t.Fatal(err)
	}
	err = readerB.Update(forkHead, forkProof, testEpoch)
	if !errors.Is(err, ErrUnderwitnessed) {
		t.Fatalf("reader B accepted a branch no witness would sign: %v", err)
	}
}

func TestACosignedHeadIsAcceptedAndAdvances(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	witness := newTestWitness(t, "witness-one", public)
	monitor, err := NewCosignedMonitor(testOrigin, public, time.Hour, policyOf(t, 1, witness))
	if err != nil {
		t.Fatal(err)
	}

	for round, entry := range []string{"", "second", "third"} {
		if entry != "" {
			log.Append([]byte(entry))
		}
		now := testEpoch.Add(time.Duration(round) * time.Minute)
		cosignature := cosign(t, witness, log, now)
		checkpoint, err := log.Checkpoint(now)
		if err != nil {
			t.Fatal(err)
		}
		checkpoint.Cosignatures = []Cosignature{cosignature}
		var held uint64
		if head, ok := monitor.Head(); ok {
			held = head.Size
		}
		proof, err := log.ProveConsistency(held, log.Size())
		if err != nil {
			t.Fatal(err)
		}
		if err := monitor.Update(checkpoint, proof, now); err != nil {
			t.Fatalf("round %d: a cosigned honest head was refused: %v", round, err)
		}
	}
	head, held := monitor.Head()
	if !held || head.Size != 3 {
		t.Fatalf("the reader did not follow the log to size 3: %+v", head)
	}
}

func TestAnUncosignedHeadIsRefusedRatherThanWarnedAbout(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	witness := newTestWitness(t, "witness-one", public)
	monitor, err := NewCosignedMonitor(testOrigin, public, time.Hour, policyOf(t, 1, witness))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := log.ProveConsistency(0, log.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Update(checkpoint, proof, testEpoch); !errors.Is(err, ErrUnderwitnessed) {
		t.Fatalf("an uncosigned head was not refused: %v", err)
	}
	if _, held := monitor.Head(); held {
		t.Fatal("the reader kept a head it had refused")
	}
}

func TestTheThresholdCountsDistinctWitnesses(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	one := newTestWitness(t, "witness-one", public)
	two := newTestWitness(t, "witness-two", public)
	three := newTestWitness(t, "witness-three", public)
	policy := policyOf(t, 2, one, two, three)

	first := cosign(t, one, log, testEpoch)
	second := cosign(t, two, log, testEpoch)
	checkpoint, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeRoot(checkpoint.Root)
	if err != nil {
		t.Fatal(err)
	}

	checkpoint.Cosignatures = []Cosignature{first}
	if err := policy.Verify(checkpoint, root); !errors.Is(err, ErrUnderwitnessed) {
		t.Fatalf("one of two required witnesses was enough: %v", err)
	}
	checkpoint.Cosignatures = []Cosignature{first, second}
	if err := policy.Verify(checkpoint, root); err != nil {
		t.Fatalf("two of two required witnesses was not enough: %v", err)
	}
	_ = three

	// One witness listed twice is one party, and must not reach a threshold of
	// two on its own.
	checkpoint.Cosignatures = []Cosignature{first, first}
	if err := policy.Verify(checkpoint, root); err == nil {
		t.Fatal("one witness repeated satisfied a threshold of two")
	} else if !strings.Contains(err.Error(), "twice") {
		t.Fatalf("the refusal does not say what was wrong: %v", err)
	}
}

// A cosignature that does not verify, from a witness the reader trusts, is
// somebody forging in that witness's name. Counting it as merely "not enough
// signatures" would hide an active attack behind a quantity problem.
func TestAForgedCosignatureFromATrustedWitnessIsAHardFailure(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	one := newTestWitness(t, "witness-one", public)
	two := newTestWitness(t, "witness-two", public)
	policy := policyOf(t, 1, one, two)

	checkpoint, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeRoot(checkpoint.Root)
	if err != nil {
		t.Fatal(err)
	}
	// witness-two's genuine signature, presented under witness-one's name.
	stolen := cosign(t, two, log, testEpoch)
	checkpoint.Cosignatures = []Cosignature{{Witness: one.Name(), Signature: stolen.Signature}}
	err = policy.Verify(checkpoint, root)
	if err == nil {
		t.Fatal("a cosignature in the wrong witness's name was accepted")
	}
	if errors.Is(err, ErrUnderwitnessed) {
		t.Fatalf("a forgery was reported as a shortage of signatures: %v", err)
	}
	if !strings.Contains(err.Error(), one.Name()) {
		t.Fatalf("the refusal does not name the witness whose name was forged: %v", err)
	}
}

// What the witness name inside the signing message earns: a cosignature states
// who made it, not merely that some pinned key made it. Rebinding the same key
// to a different name does not carry the old statement over -- so a witness
// retired under one identity and re-registered under another cannot have its
// past signatures counted as the new party's.
func TestACosignatureDoesNotTransferToAnotherNameForTheSameKey(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	witness := newTestWitness(t, "old-name", public)
	cosignature := cosign(t, witness, log, testEpoch)

	renamed, err := NewWitnessPolicy(1, map[string]ed25519.PublicKey{
		"new-name": witness.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeRoot(checkpoint.Root)
	if err != nil {
		t.Fatal(err)
	}
	// Vacuity: under its own name the same signature must count, or this test
	// would pass for any reason at all.
	checkpoint.Cosignatures = []Cosignature{cosignature}
	if err := policyOf(t, 1, witness).Verify(checkpoint, root); err != nil {
		t.Fatalf("the cosignature does not even verify under its own name: %v", err)
	}

	checkpoint.Cosignatures = []Cosignature{{
		Witness:   "new-name",
		Signature: cosignature.Signature,
	}}
	if err := renamed.Verify(checkpoint, root); err == nil {
		t.Fatal("a cosignature made under one name counted under another")
	}
}

func TestACosignatureFromAnUnpinnedWitnessIsIgnoredNotRefused(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	pinned := newTestWitness(t, "witness-one", public)
	stranger := newTestWitness(t, "somebody-else", public)
	policy := policyOf(t, 1, pinned)

	checkpoint, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeRoot(checkpoint.Root)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Cosignatures = []Cosignature{cosign(t, stranger, log, testEpoch)}
	if err := policy.Verify(checkpoint, root); !errors.Is(err, ErrUnderwitnessed) {
		t.Fatalf("a stranger's cosignature counted toward the threshold: %v", err)
	}
	checkpoint.Cosignatures = append(checkpoint.Cosignatures, cosign(t, pinned, log, testEpoch))
	if err := policy.Verify(checkpoint, root); err != nil {
		t.Fatalf("a stranger's cosignature alongside a pinned one was refused: %v", err)
	}
}

// A log holding one key registers that key as a witness and tries to satisfy
// its own threshold with the signature it already makes.
//
// What stops it is that the two signing messages cannot be equal: the witness
// message carries a length-prefixed name where the log's carries the origin.
// The distinct domain would stop it too, and is kept for that reason, but it is
// not what does the work here -- with the domains made identical this test
// still passes, which is why the claim is written this way round.
func TestTheLogsOwnSignatureIsNotACosignature(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	checkpoint, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeRoot(checkpoint.Root)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewWitnessPolicy(1, map[string]ed25519.PublicKey{"the-log-itself": public})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Cosignatures = []Cosignature{
		{Witness: "the-log-itself", Signature: checkpoint.Signature},
	}
	if err := policy.Verify(checkpoint, root); err == nil {
		t.Fatal("the log's own signature counted as a witness cosignature")
	}
}

// A cosignature is over the head *and its time*. Without that a log could
// collect one cosignature and keep re-dating the same head forever, and every
// reader would stay fresh on a witness statement made once, long ago.
func TestACosignatureDoesNotSurviveRedatingTheSameHead(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	witness := newTestWitness(t, "witness-one", public)
	policy := policyOf(t, 1, witness)
	cosignature := cosign(t, witness, log, testEpoch)

	later, err := log.Checkpoint(testEpoch.Add(48 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeRoot(later.Root)
	if err != nil {
		t.Fatal(err)
	}
	later.Cosignatures = []Cosignature{cosignature}
	if err := policy.Verify(later, root); err == nil {
		t.Fatal("a cosignature made at one time verified on the same head re-dated to another")
	}
}

// Cosignatures are attached after the log signs, so they must not be inside
// what the log signed -- otherwise no witness could ever attach one.
func TestAttachingCosignaturesDoesNotDisturbTheLogsOwnSignature(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	witness := newTestWitness(t, "witness-one", public)
	checkpoint, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Cosignatures = []Cosignature{cosign(t, witness, log, testEpoch)}
	if _, err := VerifyCheckpoint(checkpoint, testOrigin, public); err != nil {
		t.Fatalf("attaching a cosignature broke the log's signature: %v", err)
	}
	encoded, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCheckpoint(encoded)
	if err != nil {
		t.Fatalf("a cosigned checkpoint does not survive a round trip: %v", err)
	}
	if len(decoded.Cosignatures) != 1 || decoded.Cosignatures[0] != checkpoint.Cosignatures[0] {
		t.Fatalf("the cosignature did not survive the round trip: %+v", decoded.Cosignatures)
	}
}

// A witness signs only what its own Monitor accepted. If it ever signs first
// and checks afterwards, its signature stops meaning anything.
func TestAWitnessSignsNothingItsMonitorRefused(t *testing.T) {
	log, public, private := newTestLog(t)
	log.Append([]byte("first"))
	log.Append([]byte("second"))

	for _, scenario := range []struct {
		name  string
		build func(t *testing.T) (Checkpoint, ConsistencyProof, time.Time)
	}{
		{"a head dated far in the future", func(t *testing.T) (Checkpoint, ConsistencyProof, time.Time) {
			checkpoint, err := log.Checkpoint(testEpoch.Add(24 * time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			proof, err := log.ProveConsistency(0, log.Size())
			if err != nil {
				t.Fatal(err)
			}
			return checkpoint, proof, testEpoch
		}},
		{"a head from another log's key", func(t *testing.T) (Checkpoint, ConsistencyProof, time.Time) {
			other, _, _ := newTestLog(t)
			other.Append([]byte("first"))
			checkpoint, err := other.Checkpoint(testEpoch)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := other.ProveConsistency(0, other.Size())
			if err != nil {
				t.Fatal(err)
			}
			return checkpoint, proof, testEpoch
		}},
		{"a proof that does not start where the witness holds", func(t *testing.T) (Checkpoint, ConsistencyProof, time.Time) {
			checkpoint, err := log.Checkpoint(testEpoch)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := log.ProveConsistency(1, log.Size())
			if err != nil {
				t.Fatal(err)
			}
			return checkpoint, proof, testEpoch
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			witness := newTestWitness(t, "witness-one", public)
			checkpoint, proof, now := scenario.build(t)
			if _, err := witness.Cosign(checkpoint, proof, now); err == nil {
				t.Fatal("the witness signed a head its monitor had to refuse")
			}
			if _, held := witness.Head(); held {
				t.Fatal("the witness moved to a head it refused to sign")
			}
		})
	}

	// And a witness that has caught the log equivocating signs nothing further,
	// including heads that would otherwise be perfectly fine.
	witness := newTestWitness(t, "witness-one", public)
	cosign(t, witness, log, testEpoch)
	fork := forkLog(t, private, "first", "different second")
	forkHead, err := fork.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	forkProof, err := fork.ProveConsistency(0, fork.Size())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Cosign(forkHead, forkProof, testEpoch); !errors.Is(err, ErrSplitView) {
		t.Fatalf("the witness did not catch the fork: %v", err)
	}
	log.Append([]byte("an honest third entry"))
	honest, err := log.Checkpoint(testEpoch.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	honestProof, err := log.ProveConsistency(2, log.Size())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Cosign(honest, honestProof, testEpoch.Add(time.Minute)); !errors.Is(err, ErrSplitView) {
		t.Fatalf("a witness that had caught the log equivocating went on signing: %v", err)
	}
}

func TestAWitnessPolicyRefusesTheShapesThatWouldMakeItDecorative(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name      string
		threshold int
		keys      map[string]ed25519.PublicKey
		mustSay   string
	}{
		{"no witnesses at all", 1, map[string]ed25519.PublicKey{}, "no witnesses"},
		{"a threshold of zero", 0, map[string]ed25519.PublicKey{"a": public}, "below one"},
		{"a threshold nobody can reach", 2, map[string]ed25519.PublicKey{"a": public}, "never be reached"},
		{"one key under two names", 2,
			map[string]ed25519.PublicKey{"a": public, "b": public}, "share a key"},
		{"a key that is not a key", 1,
			map[string]ed25519.PublicKey{"a": public[:16]}, "not an Ed25519"},
		{"a witness with no name", 1, map[string]ed25519.PublicKey{"": public}, "no name"},
		{"a witness name past the bound", 1,
			map[string]ed25519.PublicKey{strings.Repeat("n", maxWitnessNameBytes+1): other}, "over the"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			_, err := NewWitnessPolicy(scenario.threshold, scenario.keys)
			if err == nil {
				t.Fatal("the policy was accepted")
			}
			if !strings.Contains(err.Error(), scenario.mustSay) {
				t.Fatalf("the refusal does not say why: %v", err)
			}
		})
	}
}

func TestTheCosignatureListIsBounded(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("first"))
	witness := newTestWitness(t, "witness-one", public)
	policy := policyOf(t, 1, witness)
	checkpoint, err := log.Checkpoint(testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeRoot(checkpoint.Root)
	if err != nil {
		t.Fatal(err)
	}
	real := cosign(t, witness, log, testEpoch)
	// Padding named for witnesses nobody pins: individually free to ignore,
	// which is exactly why the count itself has to be bounded.
	filler := Cosignature{Witness: "nobody", Signature: base64.StdEncoding.EncodeToString(
		make([]byte, ed25519.SignatureSize))}
	checkpoint.Cosignatures = append([]Cosignature{real}, make([]Cosignature, maxCosignatures)...)
	for index := 1; index < len(checkpoint.Cosignatures); index++ {
		checkpoint.Cosignatures[index] = filler
	}
	if err := policy.Verify(checkpoint, root); err == nil {
		t.Fatal("a checkpoint past the cosignature bound was accepted")
	}
}

// A cosigned monitor must be asked for. If NewCosignedMonitor quietly built the
// weaker reader when handed no policy, every caller that forgot one would get
// the reader that cannot see a private branch, and nothing would say so.
func TestACosignedMonitorCannotBeBuiltWithoutAPolicy(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCosignedMonitor(testOrigin, public, time.Hour, nil); err == nil {
		t.Fatal("a cosigned monitor was built with no witness policy")
	}
}

// Verification is a pure function of bytes the reader already has and keys it
// pinned in advance. If anything in this package ever reached the network, a
// reader checking a publisher's identity would emit a packet that depends on
// what the user is reading, which the core invariant forbids outright. The
// cheapest durable way to hold that is to refuse the import.
func TestNothingInThisPackageCanReachTheNetwork(t *testing.T) {
	set := token.NewFileSet()
	packages, err := parser.ParseDir(set, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"net": true, "net/http": true, "net/url": true, "os/exec": true}
	found := 0
	for _, pkg := range packages {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			found++
			for _, imported := range file.Imports {
				path := strings.Trim(imported.Path.Value, `"`)
				if forbidden[path] || strings.HasPrefix(path, "net/") {
					t.Errorf("%s imports %s: checkpoint verification must not be able to "+
						"make a network call, because a reader making one at read time "+
						"would leak what it is reading", name, path)
				}
			}
			ast.Inspect(file, func(ast.Node) bool { return true })
		}
	}
	if found == 0 {
		t.Fatal("no non-test files were scanned, so this check proved nothing")
	}
}

// The freeze, and what cosigning does to it.
//
// A log does not have to forge anything to defeat a revocation. It withholds:
// the site owner publishes a recovery descriptor revoking a compromised key,
// and the log keeps serving one targeted reader the head from just before it.
// The reader's freshness window does not expire, because the log re-signs that
// same head with a current timestamp every time -- which is exactly what an
// honest quiet log does, so nothing local can tell the two apart. Measured
// below: a hundred rounds over four days, the reader fresh throughout and one
// entry behind the whole time.
//
// Cosignatures end the *targeted* version. A witness following the log moves to
// the head containing the recovery, and will not go back; the stale head can
// still be re-dated, but no witness will sign the new date, so a reader
// requiring a threshold refuses it and goes stale rather than staying frozen.
//
// What this does not do, stated plainly: it does not make freezing impossible.
// A log that freezes a threshold of the witnesses as well as the reader still
// wins. What it costs the attacker is discrimination -- it can no longer hold
// one reader back while everyone else moves on, and to hold the witnesses back
// it has to stop serving the recovery to the parties whose published heads the
// site owner is watching. Targeted and invisible becomes global and visible.
func TestCosigningEndsATargetedFreezeThatFreshnessDoesNot(t *testing.T) {
	log, public, _ := newTestLog(t)
	log.Append([]byte("the genesis descriptor"))

	const frozenSize = 1
	frozen := newTestMonitor(t, public, time.Hour)
	followLog(t, frozen, log, testEpoch)

	// The owner publishes the recovery. The log has it and simply does not
	// serve it to this reader.
	log.Append([]byte("the recovery descriptor revoking the compromised key"))

	redate := func(t *testing.T, now time.Time) (Checkpoint, ConsistencyProof) {
		t.Helper()
		stale, err := log.CheckpointAt(frozenSize, now)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := log.ProveConsistency(frozenSize, frozenSize)
		if err != nil {
			t.Fatal(err)
		}
		return stale, proof
	}

	// Without witnesses the freeze holds for as long as the log cares to keep
	// re-signing. This arm is the comparison the next one is measured against.
	now := testEpoch
	for round := 0; round < 100; round++ {
		now = now.Add(time.Hour)
		stale, proof := redate(t, now)
		if err := frozen.Update(stale, proof, now); err != nil {
			t.Fatalf("round %d: the re-dated head was refused, so this arm proves nothing: %v",
				round, err)
		}
		if !frozen.Fresh(now) {
			t.Fatalf("round %d: the reader went stale on its own", round)
		}
	}
	head, held := frozen.Head()
	if !held || head.Size != frozenSize {
		t.Fatalf("the reader did not stay frozen at size %d: %+v", frozenSize, head)
	}
	if log.Size() == frozenSize {
		t.Fatal("the log never moved on, so nothing was being withheld")
	}

	// Now the same log against a reader that requires a witness.
	//
	// The guarded reader starts where the frozen one did, on a head the witness
	// genuinely cosigned at that time. That matters: the refusal below has to
	// be about the re-dating, not about the reader having started somewhere it
	// could never have been.
	witness := newTestWitness(t, "witness-one", public)
	policy := policyOf(t, 1, witness)
	guarded, err := NewCosignedMonitor(testOrigin, public, time.Hour, policy)
	if err != nil {
		t.Fatal(err)
	}
	first, err := log.CheckpointAt(frozenSize, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	earlyProof, err := log.ProveConsistency(0, frozenSize)
	if err != nil {
		t.Fatal(err)
	}
	earlyCosignature, err := witness.Cosign(first, earlyProof, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	first.Cosignatures = []Cosignature{earlyCosignature}
	if err := guarded.Update(first, earlyProof, testEpoch); err != nil {
		t.Fatalf("the guarded reader could not start where the frozen one did: %v", err)
	}

	// The witness then follows the log honestly and reaches the head carrying
	// the recovery. Nothing about this depends on the guarded reader; the
	// witness is on its own schedule.
	cosign(t, witness, log, testEpoch.Add(time.Minute))
	if head, _ := witness.Head(); head.Size != log.Size() {
		t.Fatalf("the witness did not reach the real head: %d against %d", head.Size, log.Size())
	}

	// The log tries the same trick. It can re-date the head, but the witness
	// that has moved on will not sign the new date, and the old cosignature
	// does not carry over to it.
	later := testEpoch.Add(2 * time.Hour)
	stale, proof := redate(t, later)

	// Carrying the cosignature it already has does not help: that signature is
	// over the old date. The reader refuses, and names the witness rather than
	// reporting a shortage -- a cosignature attributed to a trusted witness
	// that does not verify is the log misbehaving, not the log being short of
	// signatures.
	stale.Cosignatures = []Cosignature{earlyCosignature}
	err = guarded.Update(stale, proof, later)
	if err == nil {
		t.Fatal("a re-dated stale head carrying a stale cosignature was accepted")
	}
	if errors.Is(err, ErrUnderwitnessed) {
		t.Fatalf("a replayed cosignature was reported as a shortage of signatures: %v", err)
	}
	if !strings.Contains(err.Error(), witness.Name()) {
		t.Fatalf("the refusal does not name the witness: %v", err)
	}

	// And carrying none at all is the shortage.
	stale.Cosignatures = nil
	if err := guarded.Update(stale, proof, later); !errors.Is(err, ErrUnderwitnessed) {
		t.Fatalf("a re-dated stale head with no cosignature at all was accepted: %v", err)
	}
	if _, err := witness.Cosign(stale, proof, later); err == nil {
		t.Fatal("a witness that had moved past this head signed it again")
	}

	// And the freshness window now does what it was supposed to: with no
	// cosignable head to move to, the reader goes stale and stops reaching a
	// verdict rather than sitting frozen and confident.
	if guarded.Fresh(later.Add(time.Hour + time.Second)) {
		t.Fatal("the guarded reader stayed fresh with nothing it could accept")
	}
}
