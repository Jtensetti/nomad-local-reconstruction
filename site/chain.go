package site

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Jtensetti/nomad-local-reconstruction/site/transparency"
)

// ErrEquivocation reports two distinct valid descriptors at one sequence.
// The affected site is marked EQUIVOCATING; no other site is affected.
var ErrEquivocation = errors.New("site descriptor equivocation")

// EquivocationProof is self-contained and independently checkable by a third
// party: both encoded descriptors verify, and both claim the same sequence.
type EquivocationProof struct {
	SiteID   ID
	Sequence uint64
	// Prefix is the accepted chain from genesis up to Sequence-1, which a
	// third party needs in order to judge whether either branch is
	// authorized. It is empty exactly when Sequence is zero.
	Prefix [][]byte
	First  []byte
	Second []byte
}

func (proof EquivocationProof) Error() string {
	return fmt.Sprintf("%v: site %s sequence %d", ErrEquivocation, proof.SiteID, proof.Sequence)
}

func (proof EquivocationProof) Unwrap() error { return ErrEquivocation }

// Chain is the per-site view of a descriptor history. It holds only the
// accepted chain and never performs I/O of its own; callers supply bytes
// obtained from ordinary cache maintenance, so verification cannot create
// query-dependent network behavior.
type Chain struct {
	mu       sync.Mutex
	siteID   ID
	links    []Verified
	encoded  [][]byte
	equivoke *EquivocationProof
	// distribution is the reader's view of the log that carries this site's
	// descriptors, or nil if the chain was built without one. A chain with no
	// log view can never reach a publisher verdict: see Resolve.
	distribution *Distribution
}

// NewChain starts a chain from a genesis descriptor and pins the SiteID the
// caller intended. Passing the expected SiteID is mandatory: it is the
// out-of-band trust decision, and a genesis descriptor for any other site is
// rejected rather than silently adopted.
func NewChain(expected ID, genesisEncoded []byte) (*Chain, error) {
	verified, err := Verify(genesisEncoded, nil)
	if err != nil {
		return nil, err
	}
	if verified.SiteID != expected {
		return nil, errors.New("genesis descriptor is for a different site")
	}
	return &Chain{
		siteID:  expected,
		links:   []Verified{verified},
		encoded: [][]byte{append([]byte(nil), genesisEncoded...)},
	}, nil
}

// NewWitnessedChain starts a chain whose every descriptor must be in a public
// log, including its genesis.
//
// The genesis is witnessed for the same reason the rest are: an attacker who
// could hand one reader an unlogged genesis would have that reader following a
// site nobody else can see, and every later descriptor would chain correctly
// off it.
func NewWitnessedChain(expected ID, genesisEncoded []byte, proof transparency.InclusionProof,
	distribution *Distribution, now time.Time) (*Chain, error) {
	if distribution == nil {
		return nil, ErrUnwitnessed
	}
	if err := distribution.requireUsable(now); err != nil {
		return nil, err
	}
	if err := distribution.Witness(genesisEncoded, proof, now); err != nil {
		return nil, fmt.Errorf("genesis descriptor is not in the log: %w", err)
	}
	chain, err := NewChain(expected, genesisEncoded)
	if err != nil {
		return nil, err
	}
	chain.distribution = distribution
	return chain, nil
}

// view returns the chain's log view, or nil if it has none.
func (chain *Chain) view() *Distribution {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	return chain.distribution
}

// Witnessed reports whether this chain is gated on a transparency log.
func (chain *Chain) Witnessed() bool {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	return chain.distribution != nil
}

// Append verifies and accepts the next descriptor. Re-delivering an already
// accepted descriptor is idempotent; a lower or equal sequence with a
// different digest is a rollback attempt and is rejected; a distinct valid
// descriptor at an accepted sequence is equivocation.
func (chain *Chain) Append(encoded []byte) (Verified, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.distribution != nil {
		// Silently accepting an unwitnessed descriptor into a witnessed chain
		// would remove the gate for anyone who called the wrong method, which
		// is the kind of fallback that makes a property untrue in exactly the
		// deployments that needed it.
		return Verified{}, errors.New("this chain is witnessed by a transparency log; " +
			"use AppendWitnessed")
	}
	return chain.appendLocked(encoded)
}

// AppendWitnessed accepts the next descriptor only if it is in the log.
//
// The inclusion proof arrives with the descriptor, over the same path. Nothing
// here fetches anything, so accepting a descriptor cannot make a network event
// depend on what the reader was doing.
func (chain *Chain) AppendWitnessed(encoded []byte, proof transparency.InclusionProof,
	now time.Time) (Verified, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.distribution == nil {
		return Verified{}, ErrUnwitnessed
	}
	if err := chain.distribution.requireUsable(now); err != nil {
		return Verified{}, err
	}
	if err := chain.distribution.Witness(encoded, proof, now); err != nil {
		return Verified{}, fmt.Errorf("descriptor is not in the log: %w", err)
	}
	return chain.appendLocked(encoded)
}

func (chain *Chain) appendLocked(encoded []byte) (Verified, error) {
	if chain.equivoke != nil {
		return Verified{}, chain.equivoke
	}
	descriptor, err := Decode(encoded)
	if err != nil {
		return Verified{}, err
	}
	// Pin the site first. A genesis descriptor only proves it commits to its
	// OWN derived SiteID, so without this an unprivileged attacker could
	// hand a victim a perfectly valid genesis for their own unrelated site
	// and have it recorded as equivocation, permanently bricking the victim.
	// A descriptor for another site is simply not part of this chain.
	if descriptor.SiteID != hex.EncodeToString(chain.siteID[:]) {
		return Verified{}, errors.New("descriptor belongs to a different site")
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return Verified{}, err
	}
	tip := chain.links[len(chain.links)-1]

	if descriptor.Sequence <= tip.Descriptor.Sequence {
		index := int(descriptor.Sequence)
		if index >= len(chain.links) {
			return Verified{}, errors.New("descriptor sequence is not part of this chain")
		}
		stored := chain.links[index]
		if stored.Digest == digest {
			return stored, nil
		}
		// A competing descriptor only proves equivocation if it is itself
		// valid at that position. Malformed bytes must not be able to
		// poison a site.
		var previous *Verified
		if index > 0 {
			previous = &chain.links[index-1]
		}
		if _, err := VerifyDescriptor(descriptor, previous); err != nil {
			return Verified{}, fmt.Errorf("superseded or invalid site descriptor rejected: %w", err)
		}
		prefix := make([][]byte, 0, index)
		for _, ancestor := range chain.encoded[:index] {
			prefix = append(prefix, append([]byte(nil), ancestor...))
		}
		proof := &EquivocationProof{
			SiteID: chain.siteID, Sequence: descriptor.Sequence, Prefix: prefix,
			First:  append([]byte(nil), chain.encoded[index]...),
			Second: append([]byte(nil), encoded...),
		}
		chain.equivoke = proof
		return Verified{}, proof
	}

	if descriptor.Sequence != tip.Descriptor.Sequence+1 {
		return Verified{}, errors.New("descriptor sequence must increase by exactly one")
	}
	verified, err := VerifyDescriptor(descriptor, &tip)
	if err != nil {
		return Verified{}, err
	}
	chain.links = append(chain.links, verified)
	chain.encoded = append(chain.encoded, append([]byte(nil), encoded...))
	return verified, nil
}

// Head returns the highest accepted descriptor.
func (chain *Chain) Head() (Verified, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.equivoke != nil {
		return Verified{}, chain.equivoke
	}
	return chain.links[len(chain.links)-1], nil
}

// SiteID returns the pinned site identity.
func (chain *Chain) SiteID() ID {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	return chain.siteID
}

// Equivocating reports the recorded proof, if any.
func (chain *Chain) Equivocating() (*EquivocationProof, bool) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	return chain.equivoke, chain.equivoke != nil
}

// DescriptorByDigest returns an accepted descriptor by its digest.
func (chain *Chain) DescriptorByDigest(digest [32]byte) (Verified, bool) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.equivoke != nil {
		return Verified{}, false
	}
	for _, link := range chain.links {
		if link.Digest == digest {
			return link, true
		}
	}
	return Verified{}, false
}

// VerifyEquivocationProof lets a third party check a proof independently.
//
// Parsing both branches is not enough: a proof that only checks shape can be
// fabricated against any honest site, which would turn split-view detection
// into an attacker-controlled kill switch. Both branches must therefore be
// shown to be genuinely authorized, which for a non-genesis sequence
// requires the ancestor chain back to genesis. Prefix carries it: prefix[0]
// must be the site's genesis and each entry must chain to the next.
func VerifyEquivocationProof(proof EquivocationProof) error {
	if len(proof.Prefix) != int(proof.Sequence) {
		return fmt.Errorf("proof needs the %d ancestor descriptors back to genesis", proof.Sequence)
	}
	var previous *Verified
	for index, encoded := range proof.Prefix {
		verified, err := Verify(encoded, previous)
		if err != nil {
			return fmt.Errorf("proof ancestor %d: %w", index, err)
		}
		if index == 0 {
			derived, err := DeriveID(verified.Descriptor)
			if err != nil {
				return err
			}
			if derived != proof.SiteID {
				return errors.New("proof genesis does not derive the claimed site")
			}
		}
		if verified.SiteID != proof.SiteID {
			return errors.New("proof ancestor belongs to another site")
		}
		copyVerified := verified
		previous = &copyVerified
	}

	first, err := Verify(proof.First, previous)
	if err != nil {
		return fmt.Errorf("first descriptor is not a valid competitor: %w", err)
	}
	second, err := Verify(proof.Second, previous)
	if err != nil {
		return fmt.Errorf("second descriptor is not a valid competitor: %w", err)
	}
	if first.Descriptor.Sequence != proof.Sequence || second.Descriptor.Sequence != proof.Sequence {
		return errors.New("proof descriptors do not share the claimed sequence")
	}
	if first.SiteID != proof.SiteID || second.SiteID != proof.SiteID {
		return errors.New("proof descriptors do not share the claimed site")
	}
	if first.Digest == second.Digest {
		return errors.New("proof descriptors are identical")
	}
	return nil
}
