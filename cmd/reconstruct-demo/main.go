package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
)

type d struct{ parts [][]byte }

func (x *d) Add(b []byte) error { x.parts = append(x.parts, append([]byte(nil), b...)); return nil }
func (x *d) Ready() bool        { return len(x.parts) >= 2 }
func (x *d) Decode() ([]byte, error) {
	if !x.Ready() {
		return nil, errors.New("not ready")
	}
	return append(append([]byte{}, x.parts[0]...), x.parts[1]...), nil
}

func main() {
	data := []byte("Nomad local reconstruction demo")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := sha256.Sum256(data)
	sig := ed25519.Sign(priv, root[:])
	got, err := reconstruct.Reconstruct(&d{}, [][]byte{data[:10], data[10:]}, reconstruct.Verifier{Root: root, PublicKey: pub, Signature: sig})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(got))
}
