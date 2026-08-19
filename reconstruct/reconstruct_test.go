package reconstruct

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

type exactDecoder struct {
	got  [][]byte
	want int
}

func (d *exactDecoder) Add(b []byte) error {
	d.got = append(d.got, append([]byte(nil), b...))
	return nil
}
func (d *exactDecoder) Ready() bool { return len(d.got) >= d.want }
func (d *exactDecoder) Decode() ([]byte, error) {
	if !d.Ready() {
		return nil, errors.New("not ready")
	}
	var out []byte
	for _, b := range d.got[:d.want] {
		out = append(out, b...)
	}
	return out, nil
}

func TestVerifiedLocalReconstruction(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("exact deterministic content")
	root := sha256.Sum256(data)
	sig := ed25519.Sign(priv, root[:])
	d := &exactDecoder{want: 2}
	got, err := Reconstruct(d, [][]byte{data[:10], data[10:]}, Verifier{Root: root, PublicKey: pub, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatal("mismatch")
	}
}

func TestTamperRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte("content")
	root := sha256.Sum256(data)
	sig := ed25519.Sign(priv, root[:])
	d := &exactDecoder{want: 1}
	if _, err := Reconstruct(d, [][]byte{[]byte("tampered")}, Verifier{Root: root, PublicKey: pub, Signature: sig}); err == nil {
		t.Fatal("expected verification error")
	}
}

func TestRankLocal(t *testing.T) {
	c := []Candidate{{Basin: 0xff, Score: .9}, {Basin: 0x00, Score: .1}, {Basin: 0x01, Score: .2}}
	r := Rank(c, 0x00)
	if r[0].Basin != 0x00 || r[1].Basin != 0x01 {
		t.Fatalf("unexpected rank: %#v", r)
	}
}
