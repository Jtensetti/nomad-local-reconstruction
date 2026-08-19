package reconstruct

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sort"
)

type BasinScore struct {
	Basin uint64
	Score float64
}

type Candidate struct {
	ID    [32]byte
	Basin uint64
	Score float64
}

// Rank orders opaque candidates locally. Network nodes do not receive the
// final user-selected ordering.
func Rank(c []Candidate, target uint64) []Candidate {
	out := append([]Candidate(nil), c...)
	sort.SliceStable(out, func(i, j int) bool {
		di := hamming(out[i].Basin, target)
		dj := hamming(out[j].Basin, target)
		if di == dj {
			return out[i].Score > out[j].Score
		}
		return di < dj
	})
	return out
}

func hamming(a, b uint64) int {
	x := a ^ b
	n := 0
	for x != 0 {
		x &= x - 1
		n++
	}
	return n
}

type Decoder interface {
	Add(fragment []byte) error
	Ready() bool
	Decode() ([]byte, error)
}

type Verifier struct {
	Root      [32]byte
	PublicKey ed25519.PublicKey
	Signature []byte
}

func (v Verifier) Verify(data []byte) error {
	if len(v.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	root := sha256.Sum256(data)
	if root != v.Root {
		return errors.New("content hash mismatch")
	}
	if !ed25519.Verify(v.PublicKey, root[:], v.Signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// Reconstruct consumes already-received fragments using a local decoder and
// verifies the exact recovered object before returning it.
func Reconstruct(dec Decoder, fragments [][]byte, verifier Verifier) ([]byte, error) {
	if dec == nil {
		return nil, errors.New("decoder required")
	}
	for _, f := range fragments {
		if err := dec.Add(f); err != nil {
			return nil, err
		}
		if dec.Ready() {
			break
		}
	}
	if !dec.Ready() {
		return nil, errors.New("insufficient reconstruction potential")
	}
	data, err := dec.Decode()
	if err != nil {
		return nil, err
	}
	if err := verifier.Verify(data); err != nil {
		return nil, err
	}
	return data, nil
}
