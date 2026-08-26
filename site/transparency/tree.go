// Package transparency is the distribution half of publisher identity.
//
// The chain in the parent package makes rollback and equivocation *detectable
// by a reader who sees both branches*. It does not make anyone see both
// branches. A reader who has been shown only the attacker's descriptor accepts
// it, indefinitely, and nothing in the chain bounds how long that lasts. That
// gap is what this package closes.
//
// Descriptors are appended to a public log. A reader accepts a descriptor only
// with an inclusion proof against a signed checkpoint it holds, and only while
// that checkpoint is fresh. Three properties follow, and each answers a
// different attack:
//
//   - **Inclusion.** A descriptor the attacker showed only to one reader is
//     not in the log, so it has no proof, so it is not accepted. To be
//     accepted it must be published where the real site owner can see it --
//     which is what makes a recovery possible at all.
//   - **Consistency.** A log cannot rewrite its own history: every new
//     checkpoint must be consistent with the last one the reader verified.
//     This is rollback resistance at the distribution layer, mirroring the
//     chain's at the identity layer.
//   - **Freshness.** A reader that has not obtained a new checkpoint within
//     its window stops treating publications as identity-verified. This is
//     the bound the criterion asks for: a split view costs the attacker a
//     window, not forever.
//
// The hashing is RFC 6962's: a leaf is H(0x00 || entry) and an interior node
// is H(0x01 || left || right). The prefixes are the whole reason the structure
// is safe -- without them a leaf could be presented as an interior node and a
// proof could be forged -- so they are named here rather than left as magic
// numbers.
//
// What this does not do: it does not make the log honest. A log that signs two
// checkpoints of the same size with different roots has equivocated, and this
// package produces the proof rather than preventing it. Preventing it needs
// more than one log, or witnesses, which is a deployment decision recorded in
// the specification.
package transparency

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// HashLeaf is the hash of one log entry.
func HashLeaf(entry []byte) [32]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte{leafPrefix})
	_, _ = digest.Write(entry)
	var out [32]byte
	copy(out[:], digest.Sum(nil))
	return out
}

// HashNode is the hash of an interior node.
func HashNode(left, right [32]byte) [32]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte{nodePrefix})
	_, _ = digest.Write(left[:])
	_, _ = digest.Write(right[:])
	var out [32]byte
	copy(out[:], digest.Sum(nil))
	return out
}

// Tree is an append-only Merkle tree over log entries.
//
// It keeps every leaf hash rather than only the frontier, because a log has to
// answer inclusion and consistency proofs for entries it accepted long ago. A
// production log would page this to storage; the shape of the proofs does not
// change.
type Tree struct {
	leaves [][32]byte
}

// Append adds one entry and returns its index.
func (tree *Tree) Append(entry []byte) uint64 {
	tree.leaves = append(tree.leaves, HashLeaf(entry))
	return uint64(len(tree.leaves) - 1)
}

// Size is the number of entries.
func (tree *Tree) Size() uint64 { return uint64(len(tree.leaves)) }

// Root is the tree head over the first size entries.
//
// An empty tree hashes to the empty string's SHA-256, per RFC 6962. That is a
// real value rather than a zero: a checkpoint over an empty log must be
// distinguishable from an uninitialised one.
func (tree *Tree) Root(size uint64) ([32]byte, error) {
	if size > tree.Size() {
		return [32]byte{}, fmt.Errorf("tree has %d entries, asked for a root over %d",
			tree.Size(), size)
	}
	return rootOf(tree.leaves[:size]), nil
}

func rootOf(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256(nil)
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	split := int(largestPowerOfTwoBelow(uint64(len(leaves))))
	return HashNode(rootOf(leaves[:split]), rootOf(leaves[split:]))
}

// largestPowerOfTwoBelow is RFC 6962's k: the largest power of two strictly
// less than n. The split is not the midpoint, and using the midpoint would
// produce a different tree that no other implementation would agree with.
//
// It takes a uint64 and is computed rather than searched. The obvious loop --
// double a counter until it passes n -- silently overflows on a size near the
// top of the range, after which the counter is negative, the comparison never
// ends and the verifier spins forever building an unbounded slice. Sizes come
// out of proofs, and proofs come from whoever is talking to the reader, so that
// loop is a denial of service reachable by anyone who can hand a reader a
// document.
func largestPowerOfTwoBelow(n uint64) uint64 {
	if n < 2 {
		return 1
	}
	return uint64(1) << (bits.Len64(n-1) - 1)
}

// InclusionProof is the path from one leaf to the root of a tree of a given
// size.
type InclusionProof struct {
	Index uint64     `json:"index"`
	Size  uint64     `json:"size"`
	Path  [][32]byte `json:"path"`
}

// ProveInclusion builds the path for one entry against a tree head.
func (tree *Tree) ProveInclusion(index, size uint64) (InclusionProof, error) {
	if size > tree.Size() {
		return InclusionProof{}, fmt.Errorf("tree has %d entries, asked about %d",
			tree.Size(), size)
	}
	if index >= size {
		return InclusionProof{}, fmt.Errorf("entry %d is not in a tree of %d", index, size)
	}
	path := inclusionPath(tree.leaves[:size], index)
	return InclusionProof{Index: index, Size: size, Path: path}, nil
}

func inclusionPath(leaves [][32]byte, index uint64) [][32]byte {
	if len(leaves) <= 1 {
		return nil
	}
	split := largestPowerOfTwoBelow(uint64(len(leaves)))
	if index < split {
		return append(inclusionPath(leaves[:split], index), rootOf(leaves[split:]))
	}
	return append(inclusionPath(leaves[split:], index-split), rootOf(leaves[:split]))
}

// VerifyInclusion recomputes the root from an entry and a path.
//
// It takes the entry rather than its hash, so a caller cannot accidentally
// pass an interior node hash and have it accepted as a leaf.
//
// The path is ordered leaf to root, which is the order RFC 6962's SUBPROOF
// emits. The splits, though, are only knowable from the top down: the shape of
// the tree at size n is decided at the head. So the descent is done first,
// recording which side the entry falls on at each level, and the path is then
// applied in the opposite order. Consuming the path top-down instead happens to
// work whenever the sides read the same forwards and backwards, which is why
// getting this wrong survives casual testing.
func VerifyInclusion(proof InclusionProof, entry []byte, root [32]byte) error {
	if proof.Size == 0 {
		return errors.New("an inclusion proof against an empty tree proves nothing")
	}
	if proof.Index >= proof.Size {
		return fmt.Errorf("entry %d is not in a tree of %d", proof.Index, proof.Size)
	}
	sides := descend(proof.Index, proof.Size)
	if len(proof.Path) != len(sides) {
		return fmt.Errorf("inclusion path has %d hashes; entry %d of %d needs %d",
			len(proof.Path), proof.Index, proof.Size, len(sides))
	}
	computed := HashLeaf(entry)
	for step := range sides {
		sibling := proof.Path[step]
		if sides[len(sides)-1-step] {
			computed = HashNode(sibling, computed)
		} else {
			computed = HashNode(computed, sibling)
		}
	}
	if computed != root {
		return errors.New("inclusion proof does not reach the checkpoint root")
	}
	return nil
}

// descend records, from the tree head downwards, whether the entry lies in the
// right half at each split. The result is one entry per level, head first.
func descend(index, size uint64) []bool {
	var sides []bool
	for size > 1 {
		split := largestPowerOfTwoBelow(size)
		if index < split {
			sides = append(sides, false)
			size = split
			continue
		}
		sides = append(sides, true)
		index -= split
		size -= split
	}
	return sides
}

// ConsistencyProof shows that a tree of size Old is a prefix of one of size
// New: the log appended and did not rewrite.
type ConsistencyProof struct {
	Old  uint64     `json:"old"`
	New  uint64     `json:"new"`
	Path [][32]byte `json:"path"`
}

// ProveConsistency builds the proof between two tree heads.
func (tree *Tree) ProveConsistency(old, new uint64) (ConsistencyProof, error) {
	if old > new || new > tree.Size() {
		return ConsistencyProof{}, fmt.Errorf("cannot prove %d to %d in a tree of %d",
			old, new, tree.Size())
	}
	if old == 0 {
		// Everything is consistent with an empty log, and the empty proof
		// says so. A verifier must not be able to use this as a wildcard: it
		// only applies when the reader genuinely held no checkpoint.
		return ConsistencyProof{Old: 0, New: new}, nil
	}
	return ConsistencyProof{Old: old, New: new,
		Path: consistencyPath(tree.leaves[:new], old, true)}, nil
}

func consistencyPath(leaves [][32]byte, old uint64, wholeSubtree bool) [][32]byte {
	size := uint64(len(leaves))
	if old == size {
		if wholeSubtree {
			return nil
		}
		return [][32]byte{rootOf(leaves)}
	}
	split := largestPowerOfTwoBelow(uint64(len(leaves)))
	if old <= split {
		return append(consistencyPath(leaves[:split], old, wholeSubtree), rootOf(leaves[split:]))
	}
	return append(consistencyPath(leaves[split:], old-split, false), rootOf(leaves[:split]))
}

// VerifyConsistency checks that oldRoot is the head of a prefix of newRoot.
//
// Like the inclusion path, the consistency path is ordered deepest first while
// the splits are only knowable from the head down, so the descent is recorded
// and then replayed in reverse.
func VerifyConsistency(proof ConsistencyProof, oldRoot, newRoot [32]byte) error {
	if proof.Old > proof.New {
		return fmt.Errorf("a log cannot shrink from %d to %d", proof.Old, proof.New)
	}
	if proof.Old == 0 {
		if len(proof.Path) != 0 {
			return errors.New("a proof from an empty log carries no path")
		}
		// Everything is consistent with an empty log, so this branch checks
		// nothing about the new root and must not become a wildcard. A caller
		// that held a real checkpoint and was handed Old: 0 would otherwise be
		// told its rollback was fine. Requiring the empty root here means such
		// a proof can only be used by a reader that genuinely held nothing.
		if oldRoot != sha256.Sum256(nil) {
			return errors.New("a proof claiming an empty earlier log was offered against a " +
				"non-empty head, which would let a rewrite pass as a first sight")
		}
		return nil
	}
	if proof.Old == proof.New {
		if len(proof.Path) != 0 {
			return errors.New("a proof between equal sizes carries no path")
		}
		if oldRoot != newRoot {
			return errors.New("the log reports two roots at one size")
		}
		return nil
	}

	sides := descendConsistency(proof.Old, proof.New)
	// A proof whose old head is a complete subtree of the new tree omits its
	// first hash, because the verifier already holds it: it is the old root.
	// That is exactly the case where the descent never turned right.
	seeded := !isPowerOfTwo(proof.Old)
	expected := len(sides)
	if seeded {
		expected++
	}
	if len(proof.Path) != expected {
		return fmt.Errorf("consistency path has %d hashes; %d to %d needs %d",
			len(proof.Path), proof.Old, proof.New, expected)
	}

	path := proof.Path
	var left, right [32]byte
	if seeded {
		left, right = path[0], path[0]
		path = path[1:]
	} else {
		left, right = oldRoot, oldRoot
	}
	for step := range sides {
		sibling := path[step]
		if sides[len(sides)-1-step] {
			left = HashNode(sibling, left)
			right = HashNode(sibling, right)
			continue
		}
		right = HashNode(right, sibling)
	}
	if left != oldRoot {
		return errors.New("the log's earlier head is not a prefix of its current one, " +
			"so it rewrote history rather than appending")
	}
	if right != newRoot {
		// When the old size is a complete subtree the reader's own head seeds
		// the computation, so the check above is vacuous and this is where a
		// fork surfaces. What cannot be distinguished here is a log that
		// rewrote history from a path that was corrupted in transit, and the
		// message says so rather than asserting the stronger of the two.
		return errors.New("the log's current head is not an extension of the head this " +
			"reader holds: either it rewrote history rather than appending, or the proof " +
			"was corrupted")
	}
	return nil
}

// descendConsistency records which side the old tree's boundary falls on at
// each split, head first, stopping where the old tree becomes a whole subtree.
func descendConsistency(old, size uint64) []bool {
	var sides []bool
	for old != size {
		split := largestPowerOfTwoBelow(size)
		if old <= split {
			sides = append(sides, false)
			size = split
			continue
		}
		sides = append(sides, true)
		old -= split
		size -= split
	}
	return sides
}

func isPowerOfTwo(n uint64) bool { return n != 0 && n&(n-1) == 0 }
