package transparency

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// ErrStale is returned when a reader's view of the log is older than its
// freshness window.
//
// It is not a transport error and must not be retried into silence. A reader
// that cannot obtain a recent checkpoint has no way to tell whether it is being
// shown the log everyone else sees, and the only safe answer is to stop
// treating publications as identity-verified.
var ErrStale = errors.New("no fresh log checkpoint")

// ErrSplitView is returned when the log has signed two different heads at one
// size. It always carries a SplitViewProof.
var ErrSplitView = errors.New("log equivocation")

// SplitViewProof is transferable evidence that a log equivocated: two
// checkpoints of the same size, signed by the same key, with different roots.
//
// Anyone holding the log's public key can check it, which is what makes it
// evidence rather than an accusation. A reader that finds one has learned
// something no honest log can produce, so the correct response is to stop
// trusting the log rather than to pick a branch.
type SplitViewProof struct {
	Origin string     `json:"origin"`
	Size   uint64     `json:"size"`
	First  Checkpoint `json:"first"`
	Second Checkpoint `json:"second"`
}

func (proof *SplitViewProof) Error() string {
	return fmt.Sprintf("log %q signed two heads at size %d: %s and %s",
		proof.Origin, proof.Size, proof.First.Root, proof.Second.Root)
}

func (proof *SplitViewProof) Unwrap() error { return ErrSplitView }

// VerifySplitView checks equivocation evidence against the log's key.
func VerifySplitView(proof *SplitViewProof, logKey ed25519.PublicKey) error {
	if proof == nil {
		return errors.New("no proof")
	}
	first, err := VerifyCheckpoint(proof.First, proof.Origin, logKey)
	if err != nil {
		return fmt.Errorf("first checkpoint: %w", err)
	}
	second, err := VerifyCheckpoint(proof.Second, proof.Origin, logKey)
	if err != nil {
		return fmt.Errorf("second checkpoint: %w", err)
	}
	if first.Size != proof.Size || second.Size != proof.Size {
		return fmt.Errorf("the proof claims size %d but the checkpoints are %d and %d",
			proof.Size, first.Size, second.Size)
	}
	if first.Root == second.Root {
		// Two signatures over the same head are not equivocation. A log may
		// re-sign its head as often as it likes; that is how a quiet log keeps
		// its readers fresh.
		return errors.New("both checkpoints name the same root, which is not equivocation")
	}
	return nil
}

// maxClockSkew is how far into the future a checkpoint may be dated.
//
// Without a bound, a log could sign a head dated next year and every reader
// would consider itself fresh forever, which turns the freshness window into
// decoration. With one, a log that wants a reader to stay fresh has to keep
// signing.
const maxClockSkew = 5 * time.Minute

// Monitor is the reader's side of the log.
//
// It holds the most recent checkpoint it has verified and refuses to move to
// one that is not an append of it. It is not safe for concurrent use; a reader
// that shares one across goroutines must serialise access, because the whole
// value of the held checkpoint is that it advances in one order.
type Monitor struct {
	origin    string
	logKey    ed25519.PublicKey
	freshness time.Duration
	latest    *SignedCheckpoint
	// heads is the sizes this reader has seen a signed root for, which is what
	// lets it produce a split-view proof rather than only a refusal.
	//
	// It is bounded. Remembering every head a log ever showed would be a slow
	// leak in the one component designed to run for months against a log that
	// advances continuously. The bound costs the ability to notice equivocation
	// at a head more than maxRememberedHeads updates old, and keeps the case
	// that matters: the reader's own held size is always the most recent entry,
	// so demanding a checkpoint at it -- the step that turns a failed
	// consistency proof into evidence -- always works.
	heads map[uint64]Checkpoint
	// order is insertion order over heads, oldest first, for eviction.
	order []uint64
	// policy is the pinned witness set, when the reader requires one. Nil
	// means this reader counts only what it has seen itself, which catches a
	// log that equivocates *to it* and not one that serves it a private branch
	// consistently. NewCosignedMonitor is how a reader asks for the stronger
	// property; the weaker one is not reached by a fallback, only by asking
	// for it.
	policy *WitnessPolicy
	// split is the evidence that this log served two histories, once found.
	//
	// It is absorbing, like the descriptor chain's equivocation state and for
	// the same reason: a log that has served two histories has no branch a
	// reader is entitled to prefer. A reader that refused the offending
	// checkpoint but carried on would let an attacker step around the detection
	// by simply advancing to a size the reader has no second head for.
	split *SplitViewProof
}

// maxRememberedHeads bounds the split-view memory. Large enough that a reader
// syncing hourly keeps five days of heads; small enough to be a fixed cost.
const maxRememberedHeads = 128

// NewMonitor builds a reader for one log.
//
// freshness is how long a checkpoint remains usable. It is a policy choice
// with a real cost on both sides: too short and a reader stalls whenever the
// log is briefly unreachable, too long and an attacker who can partition a
// reader has that long to serve it a private branch.
func NewMonitor(origin string, logKey ed25519.PublicKey, freshness time.Duration) (*Monitor, error) {
	if origin == "" {
		return nil, errors.New("a monitor with no origin would accept any log's checkpoints")
	}
	if len(logKey) != ed25519.PublicKeySize {
		return nil, errors.New("log key is not an Ed25519 public key")
	}
	if freshness <= 0 {
		return nil, errors.New("a freshness window of zero or less would leave a reader " +
			"permanently stale")
	}
	return &Monitor{
		origin:    origin,
		logKey:    logKey,
		freshness: freshness,
		heads:     map[uint64]Checkpoint{},
	}, nil
}

// NewCosignedMonitor builds a reader that requires witness cosignatures.
//
// This is the reader that can detect a log serving it a private branch. Without
// a policy a Monitor can only catch a log that shows one reader two histories;
// with one, every head it accepts carries statements from parties that are not
// the log, and a log that wants two branches has to corrupt a threshold of them.
//
// Requiring cosignatures costs availability, on purpose: a head that cannot be
// cosigned is refused rather than accepted with a warning, the reader goes
// stale, and publications stop reaching an identity verdict. That is the
// invariant's own ordering -- lose the verdict rather than accept an
// unverifiable one -- and it must not be softened into a fallback.
func NewCosignedMonitor(origin string, logKey ed25519.PublicKey, freshness time.Duration,
	policy *WitnessPolicy) (*Monitor, error) {
	if policy == nil {
		return nil, errors.New("a cosigned monitor needs a witness policy; use NewMonitor " +
			"deliberately if this reader is to count only what it has seen itself")
	}
	monitor, err := NewMonitor(origin, logKey, freshness)
	if err != nil {
		return nil, err
	}
	monitor.policy = policy
	return monitor, nil
}

// Equivocating reports the evidence that this log served two histories, if this
// reader has found any. Once it has, the reader accepts nothing further from
// the log.
func (monitor *Monitor) Equivocating() (*SplitViewProof, bool) {
	return monitor.split, monitor.split != nil
}

// Head is the checkpoint this reader currently holds, if any.
func (monitor *Monitor) Head() (SignedCheckpoint, bool) {
	if monitor.latest == nil {
		return SignedCheckpoint{}, false
	}
	return *monitor.latest, true
}

// Fresh reports whether the held checkpoint is inside the freshness window.
func (monitor *Monitor) Fresh(now time.Time) bool {
	return monitor.latest != nil && !now.After(monitor.latest.Time.Add(monitor.freshness))
}

// Update moves the reader to a newer checkpoint.
//
// proof must be a consistency proof from the size the reader currently holds
// to the size the new checkpoint names. The reader supplies its own held size
// rather than trusting the proof's: a proof that could name its own starting
// point would let a log claim the reader had held nothing and hand it any
// branch at all.
//
// A checkpoint at a size the reader has already seen a different root for is
// equivocation, and the returned error carries the proof.
func (monitor *Monitor) Update(checkpoint Checkpoint, proof ConsistencyProof, now time.Time) error {
	if monitor.split != nil {
		return monitor.split
	}
	verified, err := VerifyCheckpoint(checkpoint, monitor.origin, monitor.logKey)
	if err != nil {
		return err
	}
	if verified.Time.After(now.Add(maxClockSkew)) {
		return fmt.Errorf("checkpoint is dated %s, which is more than %s ahead of now; a "+
			"future-dated head would make a reader permanently and falsely fresh",
			verified.Time.Format(time.RFC3339), maxClockSkew)
	}
	if previous, seen := monitor.heads[verified.Size]; seen {
		if previous.Root != checkpoint.Root {
			// Only checkpoints whose signatures already verified reach here, so
			// this cannot be manufactured by anyone who is not the log.
			monitor.split = &SplitViewProof{
				Origin: monitor.origin,
				Size:   verified.Size,
				First:  previous,
				Second: checkpoint,
			}
			return monitor.split
		}
	}

	// After the split-view check and before anything is remembered. A head the
	// witnesses did not cosign is not accepted, but a head that equivocates
	// against one already held is evidence whether it was cosigned or not, and
	// the evidence is worth more than the refusal.
	if monitor.policy != nil {
		if err := monitor.policy.Verify(checkpoint, verified.Root); err != nil {
			return err
		}
	}

	if monitor.latest != nil {
		if verified.Size < monitor.latest.Size {
			return fmt.Errorf("the log offered size %d after this reader held %d; a log that "+
				"shrinks has rewritten history", verified.Size, monitor.latest.Size)
		}
		if verified.Time.Before(monitor.latest.Time) {
			return fmt.Errorf("checkpoint is dated %s, before the %s this reader already holds",
				verified.Time.Format(time.RFC3339), monitor.latest.Time.Format(time.RFC3339))
		}
		if proof.Old != monitor.latest.Size || proof.New != verified.Size {
			return fmt.Errorf("the consistency proof runs %d to %d; this reader holds %d and "+
				"was offered %d", proof.Old, proof.New, monitor.latest.Size, verified.Size)
		}
		if err := VerifyConsistency(proof, monitor.latest.Root, verified.Root); err != nil {
			// The reader now knows the log is not appending to what it holds,
			// but cannot yet prove it to anyone else: a bad proof and a forked
			// log look the same from here. The next step is to demand a signed
			// checkpoint at the size already held, which either matches -- and
			// the proof was merely broken -- or equivocates, and the branch
			// above turns it into evidence.
			return fmt.Errorf("%w; demand a signed checkpoint at size %d to establish which",
				err, monitor.latest.Size)
		}
	} else if proof.Old != 0 || proof.New != verified.Size {
		return fmt.Errorf("this reader holds no checkpoint, so the proof must run 0 to %d, "+
			"not %d to %d", verified.Size, proof.Old, proof.New)
	}

	monitor.remember(verified.Size, checkpoint)
	monitor.latest = &verified
	return nil
}

func (monitor *Monitor) remember(size uint64, checkpoint Checkpoint) {
	if _, seen := monitor.heads[size]; !seen {
		monitor.order = append(monitor.order, size)
	}
	monitor.heads[size] = checkpoint
	for len(monitor.order) > maxRememberedHeads {
		delete(monitor.heads, monitor.order[0])
		monitor.order = monitor.order[1:]
	}
}

// Accept checks that an entry is in the log the reader is watching.
//
// It is the gate the criterion asks for. An entry the attacker showed to one
// reader alone is not in the log and has no proof, so it does not pass here. An
// entry that is in the log is one the real site owner can see and recover from.
// And a reader whose view has gone stale stops accepting anything, so a split
// view costs the attacker a freshness window rather than lasting indefinitely.
func (monitor *Monitor) Accept(entry []byte, proof InclusionProof, now time.Time) error {
	if monitor.split != nil {
		return monitor.split
	}
	if monitor.latest == nil {
		return fmt.Errorf("%w: this reader has never verified a checkpoint", ErrStale)
	}
	if !monitor.Fresh(now) {
		return fmt.Errorf("%w: the held checkpoint is dated %s and the window is %s",
			ErrStale, monitor.latest.Time.Format(time.RFC3339), monitor.freshness)
	}
	if proof.Size != monitor.latest.Size {
		return fmt.Errorf("the inclusion proof is against a tree of %d; this reader holds %d, "+
			"and a proof against any other head says nothing about the log it is watching",
			proof.Size, monitor.latest.Size)
	}
	return VerifyInclusion(proof, entry, monitor.latest.Root)
}

// Log is the publishing side: a tree plus the signing key that heads it.
//
// It is here rather than in a separate package because a log that cannot
// produce the proofs a monitor demands is not a log, and keeping the two
// together means the tests exercise the pair a deployment actually runs.
type Log struct {
	origin  string
	private ed25519.PrivateKey
	tree    Tree
	entries [][]byte
	// index maps an entry to where it was logged. A linear scan would make
	// appending n entries cost O(n^2), which is a real limit on a structure
	// whose whole purpose is to keep growing.
	index map[string]uint64
}

// NewLog builds an empty log.
func NewLog(origin string, private ed25519.PrivateKey) (*Log, error) {
	if origin == "" {
		return nil, errors.New("a log with no origin could have its checkpoints replayed as " +
			"another log's")
	}
	if len(origin) > maxOriginBytes {
		return nil, fmt.Errorf("origin is %d bytes, over the %d limit", len(origin), maxOriginBytes)
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("log signing key is not an Ed25519 private key")
	}
	return &Log{origin: origin, private: private, index: map[string]uint64{}}, nil
}

// Origin names the log.
func (log *Log) Origin() string { return log.origin }

// Size is the number of entries.
func (log *Log) Size() uint64 { return log.tree.Size() }

// Append adds an entry and returns its index. Appending an entry the log
// already holds returns the existing index rather than logging it twice: a log
// that grew every time somebody re-submitted the same descriptor would make its
// own size meaningless as a measure of what has been published.
func (log *Log) Append(entry []byte) uint64 {
	if at, exists := log.index[string(entry)]; exists {
		return at
	}
	log.entries = append(log.entries, append([]byte(nil), entry...))
	at := log.tree.Append(entry)
	log.index[string(entry)] = at
	return at
}

// Checkpoint signs the log's current head.
func (log *Log) Checkpoint(now time.Time) (Checkpoint, error) {
	return SignCheckpoint(log.origin, &log.tree, log.tree.Size(), now, log.private)
}

// CheckpointAt signs a head the log has previously reached. It is what a reader
// demands when a consistency proof fails, and what turns a suspicion into a
// split-view proof.
func (log *Log) CheckpointAt(size uint64, now time.Time) (Checkpoint, error) {
	return SignCheckpoint(log.origin, &log.tree, size, now, log.private)
}

// ProveInclusion produces the proof for an entry against the log's head.
func (log *Log) ProveInclusion(entry []byte, size uint64) (InclusionProof, error) {
	at, exists := log.index[string(entry)]
	if !exists {
		return InclusionProof{}, errors.New("the log does not hold that entry")
	}
	return log.tree.ProveInclusion(at, size)
}

// ProveConsistency produces the proof between two heads.
func (log *Log) ProveConsistency(old, new uint64) (ConsistencyProof, error) {
	return log.tree.ProveConsistency(old, new)
}
