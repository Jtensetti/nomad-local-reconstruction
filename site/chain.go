package site

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// ErrEquivocation reports two distinct valid descriptors at one sequence.
// The affected site is marked EQUIVOCATING; no other site is affected.
var ErrEquivocation = errors.New("site descriptor equivocation")

// EquivocationProof is self-contained and independently checkable by a third
// party: both encoded descriptors verify, and both claim the same sequence.
type EquivocationProof struct {
	SiteID   ID
	Sequence uint64
	First    []byte
	Second   []byte
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

// Append verifies and accepts the next descriptor. Re-delivering an already
// accepted descriptor is idempotent; a lower or equal sequence with a
// different digest is a rollback attempt and is rejected; a distinct valid
// descriptor at an accepted sequence is equivocation.
func (chain *Chain) Append(encoded []byte) (Verified, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.equivoke != nil {
		return Verified{}, chain.equivoke
	}
	descriptor, err := Decode(encoded)
	if err != nil {
		return Verified{}, err
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
		proof := &EquivocationProof{
			SiteID: chain.siteID, Sequence: descriptor.Sequence,
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
func VerifyEquivocationProof(proof EquivocationProof) error {
	first, err := Decode(proof.First)
	if err != nil {
		return fmt.Errorf("first descriptor: %w", err)
	}
	second, err := Decode(proof.Second)
	if err != nil {
		return fmt.Errorf("second descriptor: %w", err)
	}
	if first.Sequence != proof.Sequence || second.Sequence != proof.Sequence {
		return errors.New("proof descriptors do not share the claimed sequence")
	}
	if first.SiteID != second.SiteID || first.SiteID != hex.EncodeToString(proof.SiteID[:]) {
		return errors.New("proof descriptors do not share the claimed site")
	}
	firstDigest, err := Digest(first)
	if err != nil {
		return err
	}
	secondDigest, err := Digest(second)
	if err != nil {
		return err
	}
	if firstDigest == secondDigest {
		return errors.New("proof descriptors are identical")
	}
	return nil
}
