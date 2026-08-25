package site

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	StoreVersion             = "nomad-site-store-v1"
	AnchorVersion            = "nomad-site-anchor-v1"
	MaximumStoredDescriptors = 4096
	maximumProofFileBytes    = 2 * MaximumFileBytes
)

var ErrNoSiteState = errors.New("no durable site state")

// Anchor is the compact, derived state a networkless materializer can expose
// to a browser trust boundary. It is not a substitute for the descriptor
// chain: the durable store remains authoritative and re-verifies that chain
// on every load. Equivocating is absorbing for this store.
type Anchor struct {
	Version             string `json:"version"`
	SiteID              string `json:"site_id"`
	HeadSequence        uint64 `json:"head_sequence"`
	HeadDigest          string `json:"head_digest"`
	Equivocating        bool   `json:"equivocating"`
	EquivocationSequence uint64 `json:"equivocation_sequence,omitempty"`
	FirstDigest         string `json:"first_digest,omitempty"`
	SecondDigest        string `json:"second_digest,omitempty"`
}

// DurableStore persists the accepted SiteID view as immutable descriptor
// files plus, when necessary, one immutable equivocation record. The files on
// disk are the source of truth; no acceptance decision depends on process
// memory surviving a restart.
type DurableStore struct {
	root string
	mu   sync.Mutex
}

type durableEquivocationRecord struct {
	Version  string `json:"version"`
	SiteID   string `json:"site_id"`
	Sequence uint64 `json:"sequence"`
	Second   string `json:"second"`
}

func OpenDurableStore(root string) (*DurableStore, error) {
	if root == "" {
		return nil, errors.New("site store root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("site store root must be a real directory")
	}
	return &DurableStore{root: root}, nil
}

// Accept verifies one descriptor against the complete durable history before
// it changes state. Re-delivery of an already accepted descriptor is
// idempotent. A valid competing descriptor at an accepted sequence is written
// durably as equivocation evidence before ErrEquivocation is returned.
func (store *DurableStore) Accept(expected ID, encoded []byte) (Verified, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Verified{}, errors.New("site descriptor is empty or too large")
	}

	chain, err := store.loadLocked(expected)
	if errors.Is(err, ErrNoSiteState) {
		verified, verifyErr := Verify(encoded, nil)
		if verifyErr != nil {
			return Verified{}, verifyErr
		}
		if verified.SiteID != expected {
			return Verified{}, errors.New("genesis descriptor is for a different site")
		}
		if verified.Descriptor.Sequence != 0 || verified.Descriptor.Transition != TransitionGenesis {
			return Verified{}, errors.New("first durable descriptor must be genesis sequence zero")
		}
		if initErr := store.initializeLocked(expected, encoded); initErr != nil {
			// A concurrent initializer may have won. Never overwrite it: reload
			// and evaluate this descriptor against the state that actually won.
			chain, err = store.loadLocked(expected)
			if err != nil {
				return Verified{}, fmt.Errorf("initialize durable site state: %w", initErr)
			}
			return store.acceptIntoLoadedLocked(expected, chain, encoded)
		}
		return verified, nil
	}
	if err != nil {
		return Verified{}, err
	}
	return store.acceptIntoLoadedLocked(expected, chain, encoded)
}

func (store *DurableStore) acceptIntoLoadedLocked(expected ID, chain *Chain, encoded []byte) (Verified, error) {
	descriptor, err := Decode(encoded)
	if err != nil {
		return Verified{}, err
	}
	if descriptor.SiteID != expected.String() {
		return Verified{}, errors.New("descriptor belongs to a different site")
	}

	before := len(chain.links)
	verified, appendErr := chain.Append(encoded)
	if appendErr != nil {
		var proof *EquivocationProof
		if errors.As(appendErr, &proof) {
			if err := store.persistEquivocationLocked(expected, proof); err != nil {
				if errors.Is(err, os.ErrExist) {
					reloaded, loadErr := store.loadLocked(expected)
					if loadErr == nil {
						if stored, ok := reloaded.Equivocating(); ok {
							return Verified{}, stored
						}
					}
				}
				return Verified{}, fmt.Errorf("persist site equivocation before returning it: %w", err)
			}
		}
		return Verified{}, appendErr
	}

	// An already accepted descriptor changed no state and must not rewrite
	// immutable history. Only the exact next sequence grows the durable chain.
	if len(chain.links) == before {
		return verified, nil
	}
	if len(chain.links) != before+1 || int(descriptor.Sequence) != before {
		return Verified{}, errors.New("accepted descriptor did not extend the chain by exactly one")
	}
	if before >= MaximumStoredDescriptors {
		return Verified{}, errors.New("site descriptor store capacity reached")
	}
	path := descriptorPath(store.siteDirectory(expected), descriptor.Sequence)
	if err := writeImmutableFile(path, encoded, 0o600); err != nil {
		return Verified{}, fmt.Errorf("persist accepted site descriptor: %w", err)
	}
	return verified, nil
}

// Load re-verifies the complete stored chain and any durable equivocation
// record. A truncated, reordered, modified, symlinked or non-contiguous state
// fails closed instead of being repaired or silently rolled back.
func (store *DurableStore) Load(expected ID) (*Chain, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked(expected)
}

func (store *DurableStore) loadLocked(expected ID) (*Chain, error) {
	directory := store.siteDirectory(expected)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSiteState
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("site state must be a real directory")
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	type descriptorEntry struct {
		sequence uint64
		path     string
	}
	descriptors := make([]descriptorEntry, 0, len(entries))
	proofPath := ""
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".site-store-") {
			// An interrupted immutable write can leave only its fully-written
			// temporary inode. It was never linked into the accepted namespace.
			continue
		}
		if name == "equivocation.json" {
			if entry.IsDir() {
				return nil, errors.New("equivocation record is not a regular file")
			}
			proofPath = filepath.Join(directory, name)
			continue
		}
		sequence, ok := parseDescriptorFileName(name)
		if !ok {
			return nil, fmt.Errorf("unexpected file in site state: %s", name)
		}
		if entry.IsDir() {
			return nil, errors.New("descriptor entry is not a regular file")
		}
		descriptors = append(descriptors, descriptorEntry{sequence: sequence, path: filepath.Join(directory, name)})
	}
	if len(descriptors) == 0 {
		return nil, errors.New("site state directory contains no genesis descriptor")
	}
	if len(descriptors) > MaximumStoredDescriptors {
		return nil, errors.New("site state contains too many descriptors")
	}
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].sequence < descriptors[j].sequence })
	for index, entry := range descriptors {
		if entry.sequence != uint64(index) {
			return nil, errors.New("site descriptor files are not contiguous from sequence zero")
		}
	}

	genesis, err := readBoundedRegular(descriptors[0].path, MaximumFileBytes)
	if err != nil {
		return nil, err
	}
	chain, err := NewChain(expected, genesis)
	if err != nil {
		return nil, fmt.Errorf("load durable genesis: %w", err)
	}
	for _, entry := range descriptors[1:] {
		encoded, err := readBoundedRegular(entry.path, MaximumFileBytes)
		if err != nil {
			return nil, err
		}
		if _, err := chain.Append(encoded); err != nil {
			return nil, fmt.Errorf("load durable descriptor %d: %w", entry.sequence, err)
		}
	}

	if proofPath != "" {
		proof, err := store.loadEquivocationLocked(expected, chain, proofPath)
		if err != nil {
			return nil, err
		}
		chain.equivoke = proof
	}
	return chain, nil
}

// Anchor returns a compact representation of the durable accepted head. It
// deliberately reports equivocation rather than choosing a branch.
func (store *DurableStore) Anchor(expected ID) (Anchor, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	chain, err := store.loadLocked(expected)
	if err != nil {
		return Anchor{}, err
	}
	if len(chain.links) == 0 {
		return Anchor{}, errors.New("durable chain has no head")
	}
	head := chain.links[len(chain.links)-1]
	anchor := Anchor{
		Version:      AnchorVersion,
		SiteID:       expected.String(),
		HeadSequence: head.Descriptor.Sequence,
		HeadDigest:   hex.EncodeToString(head.Digest[:]),
	}
	if proof, ok := chain.Equivocating(); ok {
		anchor.Equivocating = true
		anchor.EquivocationSequence = proof.Sequence
		first, firstErr := descriptorDigestFromEncodedAt(chain, proof.Sequence, proof.First)
		second, secondErr := descriptorDigestFromEncodedAt(chain, proof.Sequence, proof.Second)
		if firstErr != nil || secondErr != nil {
			return Anchor{}, errors.New("durable equivocation proof no longer verifies")
		}
		anchor.FirstDigest = hex.EncodeToString(first[:])
		anchor.SecondDigest = hex.EncodeToString(second[:])
	}
	return anchor, nil
}

func EncodeAnchor(anchor Anchor) ([]byte, error) {
	if anchor.Version != AnchorVersion {
		return nil, errors.New("unsupported site anchor version")
	}
	if _, err := decodeHex(anchor.SiteID, 32); err != nil {
		return nil, errors.New("invalid anchor SiteID")
	}
	if _, err := decodeHex(anchor.HeadDigest, 32); err != nil {
		return nil, errors.New("invalid anchor head digest")
	}
	if anchor.Equivocating {
		if _, err := decodeHex(anchor.FirstDigest, 32); err != nil {
			return nil, errors.New("invalid anchor first equivocation digest")
		}
		if _, err := decodeHex(anchor.SecondDigest, 32); err != nil {
			return nil, errors.New("invalid anchor second equivocation digest")
		}
		if anchor.FirstDigest == anchor.SecondDigest {
			return nil, errors.New("anchor equivocation digests are identical")
		}
	} else if anchor.EquivocationSequence != 0 || anchor.FirstDigest != "" || anchor.SecondDigest != "" {
		return nil, errors.New("non-equivocating anchor carries equivocation fields")
	}
	return json.Marshal(anchor)
}

func (store *DurableStore) initializeLocked(expected ID, genesis []byte) error {
	temporary, err := os.MkdirTemp(store.root, ".site-init-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	if err := writeImmutableFile(descriptorPath(temporary, 0), genesis, 0o600); err != nil {
		return err
	}
	target := store.siteDirectory(expected)
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncDirectory(store.root)
}

func (store *DurableStore) persistEquivocationLocked(expected ID, proof *EquivocationProof) error {
	if proof == nil || proof.SiteID != expected {
		return errors.New("equivocation proof is for a different site")
	}
	if err := VerifyEquivocationProof(*proof); err != nil {
		return fmt.Errorf("refuse to persist invalid equivocation proof: %w", err)
	}
	record := durableEquivocationRecord{
		Version: StoreVersion,
		SiteID: expected.String(),
		Sequence: proof.Sequence,
		Second: base64.StdEncoding.EncodeToString(proof.Second),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(encoded) > maximumProofFileBytes {
		return errors.New("equivocation record exceeds size bound")
	}
	return writeImmutableFile(filepath.Join(store.siteDirectory(expected), "equivocation.json"), encoded, 0o600)
}

func (store *DurableStore) loadEquivocationLocked(expected ID, chain *Chain, path string) (*EquivocationProof, error) {
	encoded, err := readBoundedRegular(path, maximumProofFileBytes)
	if err != nil {
		return nil, err
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return nil, err
	}
	var record durableEquivocationRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode durable equivocation record: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing durable equivocation record data")
	}
	if record.Version != StoreVersion || record.SiteID != expected.String() {
		return nil, errors.New("durable equivocation record belongs to another store or site")
	}
	if record.Sequence >= uint64(len(chain.links)) {
		return nil, errors.New("durable equivocation record points beyond the accepted chain")
	}
	second, err := decodeStoredBytes(record.Second, MaximumFileBytes)
	if err != nil {
		return nil, err
	}
	prefix := make([][]byte, record.Sequence)
	for index := uint64(0); index < record.Sequence; index++ {
		prefix[index] = append([]byte(nil), chain.encoded[index]...)
	}
	proof := &EquivocationProof{
		SiteID: expected, Sequence: record.Sequence, Prefix: prefix,
		First: append([]byte(nil), chain.encoded[record.Sequence]...), Second: second,
	}
	if err := VerifyEquivocationProof(*proof); err != nil {
		return nil, fmt.Errorf("durable equivocation proof failed re-verification: %w", err)
	}
	return proof, nil
}

func descriptorDigestFromEncodedAt(chain *Chain, sequence uint64, encoded []byte) ([32]byte, error) {
	var previous *Verified
	if sequence > 0 {
		if sequence-1 >= uint64(len(chain.links)) {
			return [32]byte{}, errors.New("equivocation sequence exceeds chain")
		}
		copyPrevious := chain.links[sequence-1]
		previous = &copyPrevious
	}
	verified, err := Verify(encoded, previous)
	if err != nil {
		return [32]byte{}, err
	}
	return verified.Digest, nil
}

func (store *DurableStore) siteDirectory(expected ID) string {
	return filepath.Join(store.root, expected.String())
}

func descriptorPath(directory string, sequence uint64) string {
	return filepath.Join(directory, fmt.Sprintf("%020d.site.json", sequence))
}

func parseDescriptorFileName(name string) (uint64, bool) {
	const suffix = ".site.json"
	if !strings.HasSuffix(name, suffix) {
		return 0, false
	}
	prefix := strings.TrimSuffix(name, suffix)
	if len(prefix) != 20 {
		return 0, false
	}
	sequence, err := strconv.ParseUint(prefix, 10, 64)
	if err != nil || fmt.Sprintf("%020d", sequence) != prefix {
		return 0, false
	}
	return sequence, true
}

func readBoundedRegular(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > int64(limit) {
		return nil, errors.New("durable site file has invalid type or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > limit {
		return nil, errors.New("durable site file exceeds size bound")
	}
	return encoded, nil
}

// writeImmutableFile first fsyncs a private temporary inode, then links it
// into the accepted namespace with link(2). Link creation is atomic and does
// not replace an existing target, unlike rename on Unix. A crash can leave a
// .site-store-* temporary entry; loadLocked ignores only that unaccepted name.
func writeImmutableFile(path string, encoded []byte, mode os.FileMode) error {
	if len(encoded) == 0 {
		return errors.New("refuse to persist empty durable site file")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".site-store-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func decodeStoredBytes(encoded string, limit int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > limit {
		return nil, errors.New("durable equivocation bytes have invalid base64 or size")
	}
	if base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("durable equivocation base64 is not canonical")
	}
	return decoded, nil
}
