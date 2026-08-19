package reconstruct

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const ManifestSize = 228

var manifestMagic = [4]byte{'N', 'O', 'M', 1}

type GenerationID [16]byte

// Manifest is a fixed, signed description of one exact object generation.
// It authenticates its transport metadata to the embedded publisher key. A
// separate SiteID/key-discovery specification is still required to decide
// whether that publisher key is trusted for a human-facing identity.
type Manifest struct {
	Length            uint64
	Basin             uint64
	Generation        GenerationID
	Root              [32]byte
	PublicKey         [ed25519.PublicKeySize]byte
	ObjectSignature   [ed25519.SignatureSize]byte
	ManifestSignature [ed25519.SignatureSize]byte
}

func NewManifest(data []byte, basin uint64, privateKey ed25519.PrivateKey) (Manifest, error) {
	if len(data) == 0 {
		return Manifest{}, errors.New("object must not be empty")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("invalid private key")
	}
	root := sha256.Sum256(data)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	manifest := Manifest{
		Length:     uint64(len(data)),
		Basin:      basin,
		Generation: GenerationFor(root),
		Root:       root,
	}
	copy(manifest.PublicKey[:], publicKey)
	copy(manifest.ObjectSignature[:], ed25519.Sign(privateKey, SigningMessage(root)))
	copy(manifest.ManifestSignature[:], ed25519.Sign(privateKey, manifest.signingMessage()))
	return manifest, nil
}

func GenerationFor(root [32]byte) GenerationID {
	h := sha256.New()
	h.Write([]byte("nomad-generation-v1"))
	h.Write(root[:])
	sum := h.Sum(nil)
	var generation GenerationID
	copy(generation[:], sum[:len(generation)])
	return generation
}

func (m Manifest) VerifyEnvelope() error {
	if m.Length == 0 {
		return errors.New("invalid zero object length")
	}
	if m.Generation != GenerationFor(m.Root) {
		return errors.New("generation does not match content commitment")
	}
	publicKey := ed25519.PublicKey(m.PublicKey[:])
	if !ed25519.Verify(publicKey, SigningMessage(m.Root), m.ObjectSignature[:]) {
		return errors.New("object signature verification failed")
	}
	if !ed25519.Verify(publicKey, m.signingMessage(), m.ManifestSignature[:]) {
		return errors.New("manifest signature verification failed")
	}
	return nil
}

func (m Manifest) VerifyObject(data []byte) error {
	if err := m.VerifyEnvelope(); err != nil {
		return err
	}
	if uint64(len(data)) != m.Length {
		return errors.New("object length mismatch")
	}
	return m.Verifier().Verify(data)
}

func (m Manifest) Verifier() Verifier {
	return Verifier{
		Root:      m.Root,
		PublicKey: append(ed25519.PublicKey(nil), m.PublicKey[:]...),
		Signature: append([]byte(nil), m.ObjectSignature[:]...),
	}
}

func (m Manifest) MarshalBinary() ([]byte, error) {
	if err := m.VerifyEnvelope(); err != nil {
		return nil, err
	}
	out := make([]byte, ManifestSize)
	copy(out[0:4], manifestMagic[:])
	binary.BigEndian.PutUint64(out[4:12], m.Length)
	binary.BigEndian.PutUint64(out[12:20], m.Basin)
	copy(out[20:36], m.Generation[:])
	copy(out[36:68], m.Root[:])
	copy(out[68:100], m.PublicKey[:])
	copy(out[100:164], m.ObjectSignature[:])
	copy(out[164:228], m.ManifestSignature[:])
	return out, nil
}

func ParseManifest(wire []byte) (Manifest, error) {
	if len(wire) != ManifestSize {
		return Manifest{}, fmt.Errorf("manifest must be exactly %d bytes", ManifestSize)
	}
	if string(wire[:4]) != string(manifestMagic[:]) {
		return Manifest{}, errors.New("unsupported manifest magic or version")
	}
	manifest := Manifest{
		Length: binary.BigEndian.Uint64(wire[4:12]),
		Basin:  binary.BigEndian.Uint64(wire[12:20]),
	}
	copy(manifest.Generation[:], wire[20:36])
	copy(manifest.Root[:], wire[36:68])
	copy(manifest.PublicKey[:], wire[68:100])
	copy(manifest.ObjectSignature[:], wire[100:164])
	copy(manifest.ManifestSignature[:], wire[164:228])
	if err := manifest.VerifyEnvelope(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) signingMessage() []byte {
	msg := make([]byte, 0, len("nomad-manifest-v1")+8+8+16+32+32+64)
	msg = append(msg, []byte("nomad-manifest-v1")...)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], m.Length)
	msg = append(msg, number[:]...)
	binary.BigEndian.PutUint64(number[:], m.Basin)
	msg = append(msg, number[:]...)
	msg = append(msg, m.Generation[:]...)
	msg = append(msg, m.Root[:]...)
	msg = append(msg, m.PublicKey[:]...)
	msg = append(msg, m.ObjectSignature[:]...)
	return msg
}
