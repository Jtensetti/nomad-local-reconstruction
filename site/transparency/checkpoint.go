package transparency

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Jtensetti/nomad-local-reconstruction/internal/strictjson"
)

// CheckpointVersion is the frozen label for a signed log head.
const CheckpointVersion = "nomad-site-log-checkpoint-v1"

const (
	maxCheckpointDepth = 8

	checkpointDomain = "nomad-site-log-checkpoint-signature-v1"
	// maxCheckpointBytes bounds what a reader will parse. A checkpoint is a
	// few hundred bytes; anything near this is a caller trying to make the
	// parser the expensive part.
	maxCheckpointBytes = 4096
	// maxOriginBytes bounds the log's name. It is signed, so an unbounded one
	// would let a log make its own signing message arbitrarily large.
	maxOriginBytes = 255
)

// Checkpoint is a log's signed statement about its own head.
//
// Origin names the log. Without it a checkpoint from one log could be replayed
// as another's, and a reader watching two logs for the same site would accept
// either one's head as the other's -- which would defeat the point of watching
// two.
type Checkpoint struct {
	Version string `json:"version"`
	Origin  string `json:"origin"`
	Size    uint64 `json:"size"`
	// Root is hex, lower case, exactly 32 bytes. Hex rather than base64
	// because a root is quoted in incident reports and compared by eye.
	Root string `json:"root"`
	// Time is when the log signed this head, in canonical UTC RFC3339. It is
	// what a freshness window is measured against, so it is signed: a log that
	// could not be pinned to a time could hand a reader an old head forever.
	Time      string `json:"time"`
	Signature string `json:"signature"`
}

// SignedCheckpoint is a checkpoint whose signature has been verified.
//
// It carries the decoded values so that nothing downstream re-parses the
// wire form, and it cannot be constructed outside this package except by
// VerifyCheckpoint.
type SignedCheckpoint struct {
	Origin string
	Size   uint64
	Root   [32]byte
	Time   time.Time
	// Encoded is the exact bytes that verified, kept so that a reader can
	// hand a third party the evidence rather than a re-serialisation of it.
	Encoded []byte
}

// CheckpointSigningMessage is the exact byte string a log signs.
//
// It is exported because the conformance corpus publishes it. A second
// implementation that reproduces a signature has reproduced every field
// boundary, which is more than a matching signature on its own would show.
func CheckpointSigningMessage(origin string, size uint64, root [32]byte, when string) []byte {
	return checkpointSigningMessage(origin, size, root, when)
}

func checkpointSigningMessage(origin string, size uint64, root [32]byte, when string) []byte {
	out := make([]byte, 0, len(checkpointDomain)+len(origin)+len(when)+64)
	out = appendString(out, checkpointDomain)
	out = appendString(out, origin)
	out = appendUint64(out, size)
	out = append(out, root[:]...)
	out = appendString(out, when)
	return out
}

// appendString and appendUint64 length-prefix every field, so no two distinct
// checkpoints can produce the same signing message by moving a boundary. This
// mirrors the encoding the descriptor package uses for the same reason.
func appendString(out []byte, value string) []byte {
	out = appendUint64(out, uint64(len(value)))
	return append(out, value...)
}

func appendUint64(out []byte, value uint64) []byte {
	return binary.BigEndian.AppendUint64(out, value)
}

// SignCheckpoint produces a signed head over a tree.
func SignCheckpoint(origin string, tree *Tree, size uint64, when time.Time,
	private ed25519.PrivateKey) (Checkpoint, error) {
	if origin == "" {
		return Checkpoint{}, errors.New("a checkpoint with no origin could be replayed as " +
			"another log's")
	}
	if len(origin) > maxOriginBytes {
		return Checkpoint{}, fmt.Errorf("origin is %d bytes, over the %d limit",
			len(origin), maxOriginBytes)
	}
	if len(private) != ed25519.PrivateKeySize {
		return Checkpoint{}, errors.New("log signing key is not an Ed25519 private key")
	}
	root, err := tree.Root(size)
	if err != nil {
		return Checkpoint{}, err
	}
	stamp := when.UTC().Truncate(time.Second).Format(time.RFC3339)
	signature := ed25519.Sign(private, checkpointSigningMessage(origin, size, root, stamp))
	return Checkpoint{
		Version:   CheckpointVersion,
		Origin:    origin,
		Size:      size,
		Root:      hex.EncodeToString(root[:]),
		Time:      stamp,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// VerifyCheckpoint checks a checkpoint against the log's published key.
//
// The origin the caller expects is passed in rather than read from the
// checkpoint, for the same reason a transcript cannot name its own signers: a
// value that authenticates itself authenticates nothing.
func VerifyCheckpoint(checkpoint Checkpoint, expectedOrigin string,
	logKey ed25519.PublicKey) (SignedCheckpoint, error) {
	if checkpoint.Version != CheckpointVersion {
		return SignedCheckpoint{}, fmt.Errorf("unrecognised checkpoint version %q, which is "+
			"refused rather than interpreted", checkpoint.Version)
	}
	if expectedOrigin == "" {
		return SignedCheckpoint{}, errors.New("no expected origin was named, so any log's " +
			"checkpoint would be accepted")
	}
	if checkpoint.Origin != expectedOrigin {
		return SignedCheckpoint{}, fmt.Errorf("checkpoint is from log %q, not %q",
			checkpoint.Origin, expectedOrigin)
	}
	if len(logKey) != ed25519.PublicKeySize {
		return SignedCheckpoint{}, errors.New("log key is not an Ed25519 public key")
	}
	root, err := decodeRoot(checkpoint.Root)
	if err != nil {
		return SignedCheckpoint{}, err
	}
	if err := validateCanonicalTime(checkpoint.Time); err != nil {
		return SignedCheckpoint{}, fmt.Errorf("checkpoint time: %w", err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return SignedCheckpoint{}, errors.New("checkpoint signature is not a canonical " +
			"Ed25519 signature")
	}
	if base64.StdEncoding.EncodeToString(signature) != checkpoint.Signature {
		return SignedCheckpoint{}, errors.New("checkpoint signature is not in canonical " +
			"base64 form")
	}
	message := checkpointSigningMessage(checkpoint.Origin, checkpoint.Size, root, checkpoint.Time)
	if !ed25519.Verify(logKey, message, signature) {
		return SignedCheckpoint{}, errors.New("checkpoint signature does not verify against " +
			"the log's key")
	}
	when, err := time.Parse(time.RFC3339, checkpoint.Time)
	if err != nil {
		return SignedCheckpoint{}, fmt.Errorf("checkpoint time: %w", err)
	}
	encoded, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		return SignedCheckpoint{}, err
	}
	return SignedCheckpoint{
		Origin:  checkpoint.Origin,
		Size:    checkpoint.Size,
		Root:    root,
		Time:    when.UTC(),
		Encoded: encoded,
	}, nil
}

func decodeRoot(encoded string) ([32]byte, error) {
	var root [32]byte
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != len(root) || hex.EncodeToString(raw) != encoded {
		return [32]byte{}, errors.New("checkpoint root is not 32 bytes of canonical lower-case hex")
	}
	copy(root[:], raw)
	return root, nil
}

func validateCanonicalTime(encoded string) error {
	parsed, err := time.Parse(time.RFC3339, encoded)
	if err != nil {
		return errors.New("not RFC3339")
	}
	if parsed.UTC().Format(time.RFC3339) != encoded {
		return errors.New("not canonical UTC RFC3339")
	}
	return nil
}

// EncodeCheckpoint renders a checkpoint for publication.
func EncodeCheckpoint(checkpoint Checkpoint) ([]byte, error) {
	encoded, err := json.Marshal(checkpoint)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxCheckpointBytes {
		return nil, fmt.Errorf("checkpoint is %d bytes, over the %d limit",
			len(encoded), maxCheckpointBytes)
	}
	return encoded, nil
}

// DecodeCheckpoint reads a published checkpoint.
//
// Unknown members, duplicate members and trailing content are refused. A
// duplicate member matters here in a way it does not in a transcript: Go's
// decoder keeps the last occurrence, so a document with two "size" members
// would verify one value and report another to anyone using a different
// parser.
func DecodeCheckpoint(encoded []byte) (Checkpoint, error) {
	if len(encoded) > maxCheckpointBytes {
		return Checkpoint{}, fmt.Errorf("checkpoint is %d bytes, over the %d limit",
			len(encoded), maxCheckpointBytes)
	}
	if err := strictjson.RejectDuplicateKeys(encoded, maxCheckpointDepth); err != nil {
		return Checkpoint{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var checkpoint Checkpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return Checkpoint{}, err
	}
	if decoder.More() {
		return Checkpoint{}, errors.New("trailing content after the checkpoint")
	}
	return checkpoint, nil
}
