package site

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Jtensetti/nomad-local-reconstruction/site/transparency"
)

// A chain makes rollback and equivocation detectable by a reader who sees both
// branches. Nothing in it makes anyone see both branches, so a reader shown
// only the attacker's descriptor accepts it for as long as the attacker can
// keep the real one away -- which is indefinitely. Distribution is the other
// half: a descriptor counts only if it is in a public log, and a reader whose
// view of that log has gone stale stops treating publications as
// identity-verified.
//
// # Why this does not leak what the user reads
//
// The obvious implementation would fetch a checkpoint, or an inclusion proof,
// when the user opens a site. That would make an externally observable network
// event depend on private activity, which the core invariant forbids outright.
// Two things keep it out:
//
//   - The inclusion proof travels with the publication, over the same path as
//     the object. Reading a site therefore fetches nothing extra, and a reader
//     that has the object already has the proof.
//   - Checkpoints are refreshed on a fixed cadence that does not depend on what
//     the user is reading, has read, or is about to read. Refresh runs whether
//     or not anyone opens a site.
//
// It follows that a failed refresh must not be retried harder because a user is
// waiting: that would be exactly the private-state-dependent catch-up traffic
// the invariant rules out. A reader whose refresh fails goes stale and says so.
// Losing the identity verdict is the cheaper of the two failures.

const logEntryDomain = "nomad-site-log-entry-v1"

// LogEntry is the exact byte string a descriptor occupies in the log.
//
// The domain prefix and the length keep a descriptor from colliding with any
// other kind of entry a log might one day carry, and stop two entries from
// being read as one.
func LogEntry(encoded []byte) []byte {
	out := make([]byte, 0, len(logEntryDomain)+8+len(encoded))
	out = append(out, logEntryDomain...)
	out = appendUint64(out, uint64(len(encoded)))
	return append(out, encoded...)
}

// Distribution is a reader's view of the log that carries a site's descriptors.
//
// It is safe for concurrent use, and has to be: the shape this is specified to
// run in has a refresh on a fixed cadence in one goroutine and reads driven by
// whatever the user is doing in another. A version that left the caller to
// serialise it would be a data race in the deployment its own documentation
// describes.
//
// The lock is here rather than in transparency.Monitor because the Monitor's
// invariant is that its held checkpoint advances in one order, and that is a
// property of a single reader. Wrapping it is what makes one reader usable from
// several goroutines; sharing a Monitor between readers is still wrong.
type Distribution struct {
	mu      sync.Mutex
	monitor *transparency.Monitor
}

// NewDistribution builds a reader for one descriptor log.
//
// origin and logKey are the out-of-band trust decision about which log this
// reader watches, in the same way NewChain's expected SiteID is the out-of-band
// trust decision about which site it is following. freshness is how long a
// checkpoint remains usable, and is a policy choice with a cost at both ends:
// too short and a reader loses its verdict whenever the log is briefly
// unreachable, too long and an attacker who can partition a reader has that
// long to serve it a private branch.
func NewDistribution(origin string, logKey ed25519.PublicKey,
	freshness time.Duration) (*Distribution, error) {
	monitor, err := transparency.NewMonitor(origin, logKey, freshness)
	if err != nil {
		return nil, err
	}
	return &Distribution{monitor: monitor}, nil
}

// NewCosignedDistribution builds a reader that requires witness cosignatures on
// every checkpoint it accepts.
//
// NewDistribution's reader can catch a log that shows *it* two histories. It
// cannot catch the attack that actually matters, because that attack never
// shows one reader two branches: the log serves this reader a self-consistent
// history containing the attacker's descriptor and everyone else the real one.
// Every signature verifies, every proof checks out, and the reader has nothing
// to compare against.
//
// A policy makes each checkpoint carry statements from parties that are not the
// log, and an honest witness signs at most one root per size. The cosignatures
// ride inside the checkpoint this reader already fetches on its fixed cadence,
// so this costs no traffic at all and nothing here varies with what the user is
// reading -- the trust set is pinned in advance rather than discovered, which
// is what keeps a read from turning into a lookup.
//
// It costs availability instead: a head no threshold of witnesses cosigned is
// refused, the reader goes stale, and publications stop reaching an identity
// verdict. That ordering is the invariant's -- lose the verdict rather than
// accept one that cannot be checked -- and it is deliberately not a fallback.
func NewCosignedDistribution(origin string, logKey ed25519.PublicKey,
	freshness time.Duration, policy *transparency.WitnessPolicy) (*Distribution, error) {
	monitor, err := transparency.NewCosignedMonitor(origin, logKey, freshness, policy)
	if err != nil {
		return nil, err
	}
	return &Distribution{monitor: monitor}, nil
}

// Refresh moves the reader to a newer log checkpoint.
//
// This is the call that runs on a fixed cadence. It must never be driven by
// what the user is reading.
func (distribution *Distribution) Refresh(checkpoint transparency.Checkpoint,
	proof transparency.ConsistencyProof, now time.Time) error {
	distribution.mu.Lock()
	defer distribution.mu.Unlock()
	return distribution.monitor.Update(checkpoint, proof, now)
}

// Fresh reports whether the reader's view is inside its window.
func (distribution *Distribution) Fresh(now time.Time) bool {
	distribution.mu.Lock()
	defer distribution.mu.Unlock()
	return distribution.monitor.Fresh(now)
}

// Equivocating reports the evidence that this log served two histories, if this
// reader has found any. It is absorbing: a reader that has found one accepts no
// further checkpoint and no further descriptor from that log, so a site whose
// log has equivocated stops reaching a publisher verdict rather than following
// whichever branch it was shown.
func (distribution *Distribution) Equivocating() (*transparency.SplitViewProof, bool) {
	distribution.mu.Lock()
	defer distribution.mu.Unlock()
	return distribution.monitor.Equivocating()
}

// Head is the checkpoint the reader currently holds, if any.
func (distribution *Distribution) Head() (transparency.SignedCheckpoint, bool) {
	distribution.mu.Lock()
	defer distribution.mu.Unlock()
	return distribution.monitor.Head()
}

// Witness checks that a descriptor is in the log this reader is watching.
//
// A descriptor the attacker showed to one reader alone is not in the log and
// has no proof, so it does not pass. A descriptor that does pass is one the
// site's real owner can see, which is what makes a recovery possible at all.
func (distribution *Distribution) Witness(encoded []byte,
	proof transparency.InclusionProof, now time.Time) error {
	distribution.mu.Lock()
	defer distribution.mu.Unlock()
	return distribution.monitor.Accept(LogEntry(encoded), proof, now)
}

// ErrUnwitnessed is returned when a chain was built without a log view.
//
// It is not an error about the descriptors, which may be perfectly valid. It
// says the reader has no way to know whether it is the only one being shown
// them, and so cannot reach a publisher verdict.
var ErrUnwitnessed = errors.New("descriptor chain is not witnessed by a transparency log")

// ErrStaleDistribution is returned when the reader's view of the log is older
// than its freshness window.
var ErrStaleDistribution = errors.New("view of the descriptor log is stale")

// requireUsable is the gate every witnessed acceptance goes through.
//
// Freshness is not the only way a log view stops being usable. A reader that
// has caught its log serving two histories has a perfectly current checkpoint
// and no reason to believe any of it, so equivocation is checked first: a
// verdict that survived the discovery would make the detection decorative.
func (distribution *Distribution) requireUsable(now time.Time) error {
	if distribution == nil {
		return ErrUnwitnessed
	}
	distribution.mu.Lock()
	defer distribution.mu.Unlock()
	if proof, equivocating := distribution.monitor.Equivocating(); equivocating {
		return proof
	}
	if !distribution.monitor.Fresh(now) {
		head, held := distribution.monitor.Head()
		if !held {
			return fmt.Errorf("%w: no checkpoint has ever been verified", ErrStaleDistribution)
		}
		return fmt.Errorf("%w: the held checkpoint is dated %s", ErrStaleDistribution,
			head.Time.Format(time.RFC3339))
	}
	return nil
}
