package transparency

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// referenceLeaves and referenceRoots are RFC 6962's published test vectors.
//
// They are here because a log is only useful if a second implementation agrees
// with it. Every other test in this file could pass against a self-consistent
// tree that nobody else can verify; these are the ones that would fail if the
// prefixes, the split rule or the empty-tree hash drifted from the standard.
var referenceLeaves = [][]byte{
	{},
	{0x00},
	{0x10},
	{0x20, 0x21},
	{0x30, 0x31},
	{0x40, 0x41, 0x42, 0x43},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
	{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
}

var referenceRoots = []string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func referenceTree(t *testing.T) *Tree {
	t.Helper()
	tree := &Tree{}
	for _, leaf := range referenceLeaves {
		tree.Append(leaf)
	}
	return tree
}

func TestRootsMatchRFC6962(t *testing.T) {
	tree := referenceTree(t)
	for size := uint64(0); size <= uint64(len(referenceLeaves)); size++ {
		root, err := tree.Root(size)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if got := hex.EncodeToString(root[:]); got != referenceRoots[size] {
			t.Errorf("size %d root is %s, and RFC 6962 says %s; a log no other "+
				"implementation agrees with proves nothing to anyone else",
				size, got, referenceRoots[size])
		}
	}
}

func TestTheSplitIsRFC6962sAndNotTheMidpoint(t *testing.T) {
	// The values a midpoint split would give for odd sizes differ, and the
	// difference is silent: both produce a tree, only one is interoperable.
	for n, want := range map[uint64]uint64{2: 1, 3: 2, 4: 2, 5: 4, 6: 4, 7: 4, 8: 4, 9: 8,
		1000: 512, 1 << 40: 1 << 39, (1 << 63) + 1: 1 << 63, ^uint64(0): 1 << 63} {
		if got := largestPowerOfTwoBelow(n); got != want {
			t.Errorf("largestPowerOfTwoBelow(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestRootOverAnUnbuiltSizeIsRefused(t *testing.T) {
	tree := &Tree{}
	tree.Append([]byte("one"))
	if _, err := tree.Root(2); err == nil {
		t.Fatal("a root was produced over entries the tree does not have")
	}
}

func TestEveryEntryProvesInclusionAtEverySize(t *testing.T) {
	tree := referenceTree(t)
	checked := 0
	for size := uint64(1); size <= tree.Size(); size++ {
		root, err := tree.Root(size)
		if err != nil {
			t.Fatal(err)
		}
		for index := uint64(0); index < size; index++ {
			proof, err := tree.ProveInclusion(index, size)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			if err := VerifyInclusion(proof, referenceLeaves[index], root); err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			checked++
		}
	}
	if checked != 36 {
		t.Fatalf("checked %d proofs, expected 36; the loop is not covering what it claims", checked)
	}
}

// An inclusion proof must fail for every way it can be wrong. A verifier that
// accepted any of these would accept a descriptor that is not in the log, which
// is the entire property the log exists to provide.
func TestInclusionFailsClosed(t *testing.T) {
	tree := referenceTree(t)
	const size = 7
	root, err := tree.Root(size)
	if err != nil {
		t.Fatal(err)
	}
	good, err := tree.ProveInclusion(3, size)
	if err != nil {
		t.Fatal(err)
	}

	otherRoot, err := tree.Root(8)
	if err != nil {
		t.Fatal(err)
	}
	tampered := good
	tampered.Path = append([][32]byte(nil), good.Path...)
	tampered.Path[1][0] ^= 0x01

	shortened := good
	shortened.Path = good.Path[:len(good.Path)-1]

	lengthened := good
	lengthened.Path = append(append([][32]byte(nil), good.Path...), [32]byte{})

	reordered := good
	reordered.Path = append([][32]byte(nil), good.Path...)
	reordered.Path[0], reordered.Path[1] = reordered.Path[1], reordered.Path[0]

	wrongIndex := good
	wrongIndex.Index = 4

	outOfRange := good
	outOfRange.Index = size

	emptyTree := InclusionProof{Index: 0, Size: 0}

	cases := map[string]struct {
		proof InclusionProof
		entry []byte
		root  [32]byte
	}{
		"another entry at the same index": {good, referenceLeaves[4], root},
		"a tampered sibling":              {tampered, referenceLeaves[3], root},
		"a truncated path":                {shortened, referenceLeaves[3], root},
		"an over-long path":               {lengthened, referenceLeaves[3], root},
		"a reordered path":                {reordered, referenceLeaves[3], root},
		"a different index":               {wrongIndex, referenceLeaves[3], root},
		"an index outside the tree":       {outOfRange, referenceLeaves[3], root},
		"a root from another size":        {good, referenceLeaves[3], otherRoot},
		"an empty tree":                   {emptyTree, referenceLeaves[0], root},
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifyInclusion(candidate.proof, candidate.entry, candidate.root); err == nil {
				t.Fatalf("an inclusion proof with %s was accepted", name)
			}
		})
	}

	// The positive control. Without it every refusal above is satisfied by a
	// verifier that refuses everything.
	if err := VerifyInclusion(good, referenceLeaves[3], root); err != nil {
		t.Fatalf("the unmodified proof was refused: %v", err)
	}
}

// The prefixes are the reason a leaf cannot be passed off as an interior node.
// Without them the concatenation of two leaf hashes would hash to the same
// value as the node above them, and a two-entry log's root would verify as a
// one-entry log containing that concatenation -- an entry nobody ever logged.
func TestAnInteriorNodeCannotBePresentedAsALeaf(t *testing.T) {
	tree := &Tree{}
	tree.Append([]byte("first"))
	tree.Append([]byte("second"))
	root, err := tree.Root(2)
	if err != nil {
		t.Fatal(err)
	}

	forged := append(append([]byte(nil), tree.leaves[0][:]...), tree.leaves[1][:]...)
	if err := VerifyInclusion(InclusionProof{Index: 0, Size: 1}, forged, root); err == nil {
		t.Fatal("the concatenation of two leaf hashes verified as a single logged entry")
	}

	// The control for the control: an unprefixed hash of the same bytes does
	// reach the root, which is what makes the attack real and the prefix
	// necessary rather than decorative.
	if unprefixed := sha256.Sum256(forged); unprefixed == root {
		t.Fatal("the node hash is unprefixed; a forged leaf would be accepted")
	}
	if withNodePrefix := HashNode(tree.leaves[0], tree.leaves[1]); withNodePrefix != root {
		t.Fatal("the root is not the node hash of its two leaves")
	}
}

// An index at the tree size is outside it. On a one-entry tree the arithmetic
// happens to work out to the same root, so a range check that let this through
// would accept a proof for an entry that does not exist -- and every other size
// is caught by the path length instead, which is a different check.
func TestAnIndexAtTheTreeSizeIsOutsideIt(t *testing.T) {
	tree := &Tree{}
	tree.Append([]byte("the only entry"))
	root, err := tree.Root(1)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInclusion(InclusionProof{Index: 1, Size: 1}, []byte("the only entry"), root)
	if err == nil {
		t.Fatal("entry 1 of a one-entry tree verified")
	}
	if !strings.Contains(err.Error(), "is not in a tree of") {
		t.Fatalf("refused for %q rather than the index being out of range", err)
	}
	if err := VerifyInclusion(InclusionProof{Index: 0, Size: 1},
		[]byte("the only entry"), root); err != nil {
		t.Fatalf("entry 0 of a one-entry tree was refused: %v", err)
	}
}

func TestProveInclusionRefusesEntriesItCannotProve(t *testing.T) {
	tree := referenceTree(t)
	if _, err := tree.ProveInclusion(0, tree.Size()+1); err == nil {
		t.Error("a proof was produced against a size the tree has not reached")
	}
	if _, err := tree.ProveInclusion(5, 5); err == nil {
		t.Error("a proof was produced for an entry outside the named size")
	}
}

func TestEveryPairOfSizesProvesConsistency(t *testing.T) {
	tree := referenceTree(t)
	checked := 0
	for older := uint64(0); older <= tree.Size(); older++ {
		oldRoot, err := tree.Root(older)
		if err != nil {
			t.Fatal(err)
		}
		for newer := older; newer <= tree.Size(); newer++ {
			newRoot, err := tree.Root(newer)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := tree.ProveConsistency(older, newer)
			if err != nil {
				t.Fatalf("%d to %d: %v", older, newer, err)
			}
			if err := VerifyConsistency(proof, oldRoot, newRoot); err != nil {
				t.Fatalf("%d to %d: %v", older, newer, err)
			}
			checked++
		}
	}
	if checked != 45 {
		t.Fatalf("checked %d proofs, expected 45", checked)
	}
}

// A log that rewrites its own history is the rollback attack at the
// distribution layer. No proof it can offer may make a fork look like an
// append.
//
// Both held sizes are exercised because the verifier reaches the refusal by
// different routes: at a complete-subtree size the reader's own head seeds the
// computation and the fork surfaces at the new root, while at any other size
// the path supplies the seed and the earlier head is reconstructed and
// compared. A test that used only one would leave half the check unexercised.
func TestAForkedLogCannotProveConsistency(t *testing.T) {
	honest := referenceTree(t)

	forked := &Tree{}
	for index, leaf := range referenceLeaves {
		if index == 2 {
			forked.Append([]byte("an entry the log substituted later"))
			continue
		}
		forked.Append(leaf)
	}
	forkedRoot, err := forked.Root(8)
	if err != nil {
		t.Fatal(err)
	}

	for _, held := range []uint64{3, 4} {
		t.Run(fmt.Sprintf("held size %d", held), func(t *testing.T) {
			oldRoot, err := honest.Root(held)
			if err != nil {
				t.Fatal(err)
			}
			// The forked log builds the best proof it can: a genuine proof
			// from its own size to its own head.
			proof, err := forked.ProveConsistency(held, 8)
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyConsistency(proof, oldRoot, forkedRoot)
			if err == nil {
				t.Fatal("a log that replaced a logged entry proved it had only appended")
			}
			if !strings.Contains(err.Error(), "rewrote history") {
				t.Fatalf("the failure does not name the rewrite: %v", err)
			}

			// The forked log is internally consistent, so the refusal above
			// comes from the reader's held root and not from a broken proof.
			forkedOld, err := forked.Root(held)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(proof, forkedOld, forkedRoot); err != nil {
				t.Fatalf("the forked log's own proof does not verify against its own roots: %v", err)
			}
		})
	}
}

func TestConsistencyFailsClosed(t *testing.T) {
	tree := referenceTree(t)
	root3, err := tree.Root(3)
	if err != nil {
		t.Fatal(err)
	}
	root7, err := tree.Root(7)
	if err != nil {
		t.Fatal(err)
	}
	root8, err := tree.Root(8)
	if err != nil {
		t.Fatal(err)
	}
	good, err := tree.ProveConsistency(3, 7)
	if err != nil {
		t.Fatal(err)
	}

	tampered := good
	tampered.Path = append([][32]byte(nil), good.Path...)
	tampered.Path[0][0] ^= 0x01

	shortened := good
	shortened.Path = good.Path[:len(good.Path)-1]

	lengthened := good
	lengthened.Path = append(append([][32]byte(nil), good.Path...), [32]byte{})

	shrinking := ConsistencyProof{Old: 7, New: 3, Path: good.Path}

	// A log that answers every challenge with "you held nothing" would erase
	// rollback resistance entirely.
	wildcard := ConsistencyProof{Old: 0, New: 7}

	// Two roots at one size is equivocation, not consistency.
	sameSize := ConsistencyProof{Old: 7, New: 7}

	emptyWithPath := ConsistencyProof{Old: 0, New: 7, Path: good.Path}
	sameSizeWithPath := ConsistencyProof{Old: 7, New: 7, Path: good.Path}

	cases := map[string]struct {
		proof            ConsistencyProof
		oldRoot, newRoot [32]byte
	}{
		"a tampered path":                       {tampered, root3, root7},
		"a truncated path":                      {shortened, root3, root7},
		"an over-long path":                     {lengthened, root3, root7},
		"a shrinking log":                       {shrinking, root7, root3},
		"a claim of no earlier head":            {wildcard, root3, root7},
		"an empty proof with a path":            {emptyWithPath, root3, root7},
		"two roots at one size":                 {sameSize, root7, root8},
		"an equal-size proof w/ path":           {sameSizeWithPath, root7, root7},
		"a new root from another size":          {good, root3, root8},
		"an earlier root that is not the log's": {good, root8, root7},
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifyConsistency(candidate.proof, candidate.oldRoot, candidate.newRoot); err == nil {
				t.Fatalf("a consistency proof with %s was accepted", name)
			}
		})
	}

	if err := VerifyConsistency(good, root3, root7); err != nil {
		t.Fatalf("the unmodified proof was refused: %v", err)
	}
	// A reader that genuinely held nothing is the one caller the Old: 0 branch
	// is for, and it must still work.
	empty, err := tree.ProveConsistency(0, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(empty, sha256.Sum256(nil), root7); err != nil {
		t.Fatalf("a first-sight proof was refused: %v", err)
	}
}

func TestProveConsistencyRefusesImpossibleRanges(t *testing.T) {
	tree := referenceTree(t)
	if _, err := tree.ProveConsistency(5, 3); err == nil {
		t.Error("a proof was produced for a shrinking log")
	}
	if _, err := tree.ProveConsistency(3, tree.Size()+1); err == nil {
		t.Error("a proof was produced past the end of the tree")
	}
}

// A log of realistic size, checked exhaustively at the boundaries where the
// power-of-two split changes shape. Small hand-picked sizes can miss an
// off-by-one that only appears when a subtree becomes complete.
func TestProofsHoldAcrossSubtreeBoundaries(t *testing.T) {
	tree := &Tree{}
	entries := make([][]byte, 0, 130)
	for index := 0; index < 130; index++ {
		entry := []byte(fmt.Sprintf("descriptor %d", index))
		entries = append(entries, entry)
		tree.Append(entry)
	}
	for _, size := range []uint64{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 130} {
		root, err := tree.Root(size)
		if err != nil {
			t.Fatal(err)
		}
		for _, index := range []uint64{0, size / 3, size / 2, size - 1} {
			proof, err := tree.ProveInclusion(index, size)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			if err := VerifyInclusion(proof, entries[index], root); err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
		}
		for _, older := range []uint64{1, size / 2, size - 1, size} {
			if older > size {
				continue
			}
			oldRoot, err := tree.Root(older)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := tree.ProveConsistency(older, size)
			if err != nil {
				t.Fatalf("%d to %d: %v", older, size, err)
			}
			if err := VerifyConsistency(proof, oldRoot, root); err != nil {
				t.Fatalf("%d to %d: %v", older, size, err)
			}
		}
	}
}

// Sizes come out of proofs, and proofs come from whoever is talking to the
// reader. A verifier that could be made to spin on one is a denial of service
// anybody can reach, so the extremes have to return -- and return an answer,
// not a hang.
//
// This test is written with a deadline because the failure it guards against
// is non-termination, and a test that simply called the function would hang
// with it rather than reporting.
func TestHostileSizesTerminate(t *testing.T) {
	tree := referenceTree(t)
	root, err := tree.Root(8)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, size := range []uint64{1 << 32, 1 << 62, 1<<63 - 1, 1 << 63, ^uint64(0)} {
			if err := VerifyInclusion(InclusionProof{Index: 0, Size: size},
				referenceLeaves[0], root); err == nil {
				t.Errorf("an inclusion proof claiming a tree of %d was accepted", size)
			}
			if err := VerifyConsistency(ConsistencyProof{Old: 3, New: size},
				root, root); err == nil {
				t.Errorf("a consistency proof claiming a tree of %d was accepted", size)
			}
			if err := VerifyConsistency(ConsistencyProof{Old: size - 1, New: size},
				root, root); err == nil {
				t.Errorf("a consistency proof from %d was accepted", size-1)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a verifier did not terminate on a hostile size")
	}
}
