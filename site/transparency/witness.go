package transparency

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Witness cosigning: the part of split-view detection a single reader cannot do
// for itself.
//
// A Monitor catches a log that shows *it* two different roots at one size. It
// cannot catch the attack that matters more, because that attack never shows
// one reader two branches: the log serves reader A a self-consistent history
// containing the attacker's descriptor and reader B the real one, forever.
// Both readers verify every signature, every consistency proof and every
// inclusion proof, and neither has anything to compare against. tree.go says so
// in as many words -- preventing it "needs more than one log, or witnesses".
//
// This is the witness half.
//
// A witness is a party that watches the log with a Monitor of its own and signs
// only what that Monitor accepted. Because a Monitor refuses a second root at a
// size it already holds, an honest witness will cosign at most one branch: the
// first it saw. A log that wants to serve two branches must therefore get a
// threshold of witnesses to sign both, and a reader that requires a threshold
// of cosignatures on every checkpoint is holding a statement from parties that
// are not the log.
//
// # Why this adds no network traffic at all
//
// The cosignatures travel inside the checkpoint. The reader already fetches
// checkpoints on a fixed cadence that does not depend on what the user is
// reading -- distribution.go is explicit about why -- and a cosigned checkpoint
// is the same fetch carrying a few hundred more bytes. Verification is a pure
// function of the checkpoint bytes and a key set the reader pinned in advance:
// no lookup, no second connection, no witness contacted at read time, nothing
// that varies with private activity. A design that asked witnesses at read time
// would be a textbook violation of the invariant, which is why the trust set is
// pinned rather than discovered.
//
// The witnesses themselves talk to the log on their own fixed schedule, and
// they are not readers of anyone's private activity.

const (
	// witnessDomain separates a cosignature from the log's own signature, so a
	// log holding one key cannot present the signature it already makes as a
	// witness cosignature and satisfy a threshold by itself.
	//
	// It is not what stops that today, and saying otherwise would be wrong: the
	// witness message carries a length-prefixed witness name where the log's
	// carries the origin, so the two are already structurally disjoint and
	// remain so even with identical domains -- measured, not assumed. The
	// domain stays because that disjointness is an argument about the current
	// field layout, and this makes the two signature spaces separate without
	// depending on the argument holding after the next change to either.
	witnessDomain = "nomad-site-log-witness-signature-v1"

	// maxCosignatures bounds the verification work an attacker can buy with
	// attacker-supplied bytes, on the same principle as the descriptor's
	// authorization bound.
	maxCosignatures = 16

	// maxWitnessNameBytes keeps a name from making the signing message or the
	// checkpoint arbitrarily large. Sixteen cosignatures with names at this
	// bound stay well inside maxCheckpointBytes.
	maxWitnessNameBytes = 64
)

// Cosignature is one witness's statement about a checkpoint.
//
// It is not a second opinion about the log's signature, which the witness also
// checked; it is the statement that this head is consistent with everything the
// witness has seen from this log, and that the witness has signed no other root
// at this size.
type Cosignature struct {
	Witness   string `json:"witness"`
	Signature string `json:"signature"`
}

// WitnessSigningMessage is the exact byte string a witness signs.
//
// Exported for the conformance corpus, like the log's own. The witness name is
// inside the message so a cosignature is bound to the identity that made it and
// cannot be re-presented as another witness's, and the time is inside it so a
// log cannot keep one cosignature alive by re-dating the same head: a log that
// wants readers to stay fresh has to keep getting cosigned.
func WitnessSigningMessage(witness, origin string, size uint64, root [32]byte, when string) []byte {
	out := make([]byte, 0, len(witnessDomain)+len(witness)+len(origin)+len(when)+64)
	out = appendString(out, witnessDomain)
	out = appendString(out, witness)
	out = appendString(out, origin)
	out = appendUint64(out, size)
	out = append(out, root[:]...)
	out = appendString(out, when)
	return out
}

// WitnessPolicy is the reader's pinned trust decision: which witnesses count
// and how many are required.
//
// Pinned, not discovered. A policy the checkpoint carried would let the log
// nominate its own witnesses, which is the same as having none.
type WitnessPolicy struct {
	threshold int
	keys      map[string]ed25519.PublicKey
}

// NewWitnessPolicy builds a trust set.
func NewWitnessPolicy(threshold int, keys map[string]ed25519.PublicKey) (*WitnessPolicy, error) {
	if len(keys) == 0 {
		return nil, errors.New("a witness policy with no witnesses would require nothing")
	}
	if len(keys) > maxCosignatures {
		return nil, fmt.Errorf("a policy of %d witnesses is over the %d a checkpoint can carry",
			len(keys), maxCosignatures)
	}
	if threshold < 1 {
		return nil, errors.New("a witness threshold below one would accept an uncosigned checkpoint")
	}
	if threshold > len(keys) {
		return nil, fmt.Errorf("a threshold of %d over %d witnesses can never be reached",
			threshold, len(keys))
	}
	copied := make(map[string]ed25519.PublicKey, len(keys))
	seen := make(map[string]string, len(keys))
	for name, key := range keys {
		if name == "" {
			return nil, errors.New("a witness with no name cannot be told from another")
		}
		if len(name) > maxWitnessNameBytes {
			return nil, fmt.Errorf("witness name is %d bytes, over the %d limit",
				len(name), maxWitnessNameBytes)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("witness %q: key is not an Ed25519 public key", name)
		}
		// One key under two names is one party counted twice, which turns a
		// threshold of two into a threshold of one without anything looking
		// wrong. The whole value of the threshold is that the signers are
		// different parties.
		if other, duplicate := seen[string(key)]; duplicate {
			return nil, fmt.Errorf("witnesses %q and %q share a key, so a threshold "+
				"would count one party twice", other, name)
		}
		seen[string(key)] = name
		copied[name] = append(ed25519.PublicKey(nil), key...)
	}
	return &WitnessPolicy{threshold: threshold, keys: copied}, nil
}

// Threshold is how many distinct pinned witnesses a checkpoint needs.
func (policy *WitnessPolicy) Threshold() int { return policy.threshold }

// Witnesses names the pinned trust set, sorted, for reports and tests.
func (policy *WitnessPolicy) Witnesses() []string {
	names := make([]string, 0, len(policy.keys))
	for name := range policy.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Verify checks a checkpoint's cosignatures against the pinned set.
//
// root is the already-decoded root from the log signature's own verification,
// so this cannot be reached with a root the log did not sign.
//
// A cosignature from a witness this reader does not pin is ignored rather than
// refused: a log may reasonably carry signatures for a wider set than any one
// reader trusts. A cosignature from a witness it *does* pin that does not
// verify is a hard failure, not merely one that fails to count -- somebody is
// forging in the name of a trusted party, and treating that as "not quite
// enough signatures" would hide it.
func (policy *WitnessPolicy) Verify(checkpoint Checkpoint, root [32]byte) error {
	if policy == nil {
		return errors.New("no witness policy")
	}
	if len(checkpoint.Cosignatures) > maxCosignatures {
		return fmt.Errorf("checkpoint carries %d cosignatures, over the %d limit",
			len(checkpoint.Cosignatures), maxCosignatures)
	}
	counted := make(map[string]struct{}, len(checkpoint.Cosignatures))
	for _, cosignature := range checkpoint.Cosignatures {
		key, pinned := policy.keys[cosignature.Witness]
		if !pinned {
			continue
		}
		// One witness listed twice is one party counted twice.
		if _, already := counted[cosignature.Witness]; already {
			return fmt.Errorf("witness %q appears twice, which would count one party twice",
				cosignature.Witness)
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(cosignature.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize {
			return fmt.Errorf("witness %q: cosignature is not a canonical Ed25519 signature",
				cosignature.Witness)
		}
		if base64.StdEncoding.EncodeToString(signature) != cosignature.Signature {
			return fmt.Errorf("witness %q: cosignature is not in canonical base64 form",
				cosignature.Witness)
		}
		message := WitnessSigningMessage(cosignature.Witness, checkpoint.Origin,
			checkpoint.Size, root, checkpoint.Time)
		if !ed25519.Verify(key, message, signature) {
			// Two things land here and the message must not pick one: a forgery
			// in this witness's name, and a genuine cosignature this witness
			// made over a different head or a different time, lifted onto this
			// one. The second is what a log does when it re-dates a head it can
			// no longer get cosigned, and calling it a forgery would send an
			// operator hunting a key compromise that has not happened.
			//
			// Either way it is the log misbehaving and either way the head is
			// refused, so the distinction is diagnostic rather than a decision.
			return fmt.Errorf("witness %q: the cosignature does not verify over this head at "+
				"this time; it is either forged or a genuine cosignature of another head "+
				"replayed onto this one", cosignature.Witness)
		}
		counted[cosignature.Witness] = struct{}{}
	}
	if len(counted) < policy.threshold {
		return fmt.Errorf("%w: %d of the %d pinned witnesses cosigned this head, and the "+
			"policy requires %d", ErrUnderwitnessed, len(counted), len(policy.keys),
			policy.threshold)
	}
	return nil
}

// ErrUnderwitnessed is returned when a checkpoint does not carry enough
// cosignatures from the reader's pinned witnesses.
//
// It is not a transport error and must not be retried into silence, for the
// same reason ErrStale must not: a reader that cannot obtain a cosigned head
// has no evidence it is being shown the log everyone else sees.
var ErrUnderwitnessed = errors.New("checkpoint is not cosigned by enough witnesses")

// Witness watches a log and signs only heads its own Monitor accepted.
//
// The Monitor is the whole mechanism. It refuses a head that shrinks, one that
// is not an append of what the witness holds, one dated in the future, and --
// the property that makes this worth doing -- a second root at a size it has
// already signed, for which it produces transferable evidence instead.
//
// The witness's Monitor is deliberately not itself cosign-gated: a witness that
// required other witnesses' signatures before forming its own opinion would
// make the trust set circular, and the first witness could never start.
type Witness struct {
	name    string
	private ed25519.PrivateKey
	monitor *Monitor
}

// NewWitness builds a witness for one log.
func NewWitness(name string, private ed25519.PrivateKey, origin string,
	logKey ed25519.PublicKey, freshness time.Duration) (*Witness, error) {
	if name == "" {
		return nil, errors.New("a witness with no name cannot be told from another")
	}
	if len(name) > maxWitnessNameBytes {
		return nil, fmt.Errorf("witness name is %d bytes, over the %d limit",
			len(name), maxWitnessNameBytes)
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("witness key is not an Ed25519 private key")
	}
	monitor, err := NewMonitor(origin, logKey, freshness)
	if err != nil {
		return nil, err
	}
	return &Witness{name: name, private: append(ed25519.PrivateKey(nil), private...),
		monitor: monitor}, nil
}

// Name is the identity this witness signs under.
func (witness *Witness) Name() string { return witness.name }

// Public is the key a reader pins to count this witness.
func (witness *Witness) Public() ed25519.PublicKey {
	return witness.private.Public().(ed25519.PublicKey)
}

// Equivocating reports the evidence this witness found, if any. A witness that
// has caught the log serving two histories signs nothing further.
func (witness *Witness) Equivocating() (*SplitViewProof, bool) {
	return witness.monitor.Equivocating()
}

// Head is the checkpoint this witness currently holds.
func (witness *Witness) Head() (SignedCheckpoint, bool) { return witness.monitor.Head() }

// Cosign advances the witness to a head and signs it.
//
// proof must be a consistency proof from the size this witness holds. Nothing
// is signed unless the Monitor accepted the head first, so the signature says
// exactly what the Monitor checked and no more.
func (witness *Witness) Cosign(checkpoint Checkpoint, proof ConsistencyProof,
	now time.Time) (Cosignature, error) {
	if err := witness.monitor.Update(checkpoint, proof, now); err != nil {
		return Cosignature{}, err
	}
	head, held := witness.monitor.Head()
	if !held {
		return Cosignature{}, errors.New("the monitor accepted a head and then held none")
	}
	message := WitnessSigningMessage(witness.name, head.Origin, head.Size, head.Root,
		checkpoint.Time)
	return Cosignature{
		Witness:   witness.name,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(witness.private, message)),
	}, nil
}
