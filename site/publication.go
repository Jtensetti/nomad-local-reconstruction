package site

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
)

const (
	PublicationVersion = "nomad-site-publication-v1"
	publicationDomain  = "nomad-site-publication-v1"
)

// Publication binds one exact object and manifest to a site under a named
// descriptor. It is separate from the 228-byte manifest so that object
// integrity and publisher identity remain independently verifiable claims.
type Publication struct {
	Version          string `json:"version"`
	SiteID           string `json:"site_id"`
	DescriptorDigest string `json:"descriptor_digest"`
	SigningKey       string `json:"signing_key"`
	ObjectRoot       string `json:"object_root"`
	ManifestDigest   string `json:"manifest_digest"`
	PublishedAt      string `json:"published_at"`
	Signature        string `json:"signature"`
}

// State is the identity conclusion the client renders. These are distinct
// user-facing outcomes; an identity failure is never reported as absence.
type State int

const (
	// ObjectVerified means the bytes are exactly the signed object but no
	// publisher identity was established.
	ObjectVerified State = iota
	// PublisherVerified means every acceptance condition held.
	PublisherVerified
	// PublisherUnknown means no identity claim could be evaluated locally.
	PublisherUnknown
	// PublisherInvalid means an identity claim was made and failed.
	PublisherInvalid
)

func (s State) String() string {
	switch s {
	case ObjectVerified:
		return "OBJECT_VERIFIED"
	case PublisherVerified:
		return "PUBLISHER_VERIFIED"
	case PublisherUnknown:
		return "PUBLISHER_UNKNOWN"
	case PublisherInvalid:
		return "PUBLISHER_INVALID"
	default:
		return "UNKNOWN"
	}
}

func publicationCanonicalBytes(publication Publication) ([]byte, error) {
	if publication.Version != PublicationVersion {
		return nil, errors.New("unsupported site publication version")
	}
	siteID, err := decodeHex(publication.SiteID, 32)
	if err != nil {
		return nil, errors.New("invalid publication site ID")
	}
	descriptorDigest, err := decodeHex(publication.DescriptorDigest, 32)
	if err != nil {
		return nil, errors.New("invalid publication descriptor digest")
	}
	signingKey, err := decodeBase64(publication.SigningKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, errors.New("invalid publication signing key")
	}
	objectRoot, err := decodeHex(publication.ObjectRoot, 32)
	if err != nil {
		return nil, errors.New("invalid publication object root")
	}
	manifestDigest, err := decodeHex(publication.ManifestDigest, 32)
	if err != nil {
		return nil, errors.New("invalid publication manifest digest")
	}
	if err := validateCanonicalTime(publication.PublishedAt); err != nil {
		return nil, fmt.Errorf("published_at: %w", err)
	}
	canonical := make([]byte, 0, 256)
	canonical = appendString(canonical, publication.Version)
	canonical = append(canonical, siteID...)
	canonical = append(canonical, descriptorDigest...)
	canonical = appendBytes(canonical, signingKey)
	canonical = append(canonical, objectRoot...)
	canonical = append(canonical, manifestDigest...)
	canonical = appendString(canonical, publication.PublishedAt)
	return canonical, nil
}

// PublicationCanonicalBytes exposes the signing preimage for vectors.
func PublicationCanonicalBytes(publication Publication) ([]byte, error) {
	return publicationCanonicalBytes(publication)
}

func publicationSigningMessage(publication Publication) ([]byte, error) {
	canonical, err := publicationCanonicalBytes(publication)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(publicationDomain)+len(canonical))
	message = append(message, publicationDomain...)
	message = append(message, canonical...)
	return message, nil
}

// ManifestDigest is the commitment to the exact manifest bytes.
func ManifestDigest(manifest reconstruct.Manifest) ([32]byte, error) {
	encoded, err := manifest.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// NewPublication builds and signs a publication for one manifest.
func NewPublication(siteID ID, descriptor Verified, manifest reconstruct.Manifest, publishedAt time.Time, private ed25519.PrivateKey) (Publication, error) {
	if len(private) != ed25519.PrivateKeySize {
		return Publication{}, errors.New("publishing private key is required")
	}
	public := private.Public().(ed25519.PublicKey)
	if !descriptor.AuthorizesKey(public) {
		return Publication{}, errors.New("publishing key is not active in the descriptor")
	}
	manifestDigest, err := ManifestDigest(manifest)
	if err != nil {
		return Publication{}, err
	}
	publication := Publication{
		Version: PublicationVersion, SiteID: hex.EncodeToString(siteID[:]),
		DescriptorDigest: hex.EncodeToString(descriptor.Digest[:]),
		SigningKey:       base64.StdEncoding.EncodeToString(public),
		ObjectRoot:       hex.EncodeToString(manifest.Root[:]),
		ManifestDigest:   hex.EncodeToString(manifestDigest[:]),
		PublishedAt:      publishedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	message, err := publicationSigningMessage(publication)
	if err != nil {
		return Publication{}, err
	}
	publication.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))
	return publication, nil
}

func EncodePublication(publication Publication) ([]byte, error) {
	if _, err := publicationCanonicalBytes(publication); err != nil {
		return nil, err
	}
	return json.MarshalIndent(publication, "", "  ")
}

func DecodePublication(encoded []byte) (Publication, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Publication{}, errors.New("site publication is empty or too large")
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return Publication{}, err
	}
	var publication Publication
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&publication); err != nil {
		return Publication{}, fmt.Errorf("decode site publication: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Publication{}, errors.New("trailing site publication data")
	}
	return publication, nil
}

// Resolve decides the identity state for one verified object.
//
// intended is the SiteID the user actually asked for; chain is the client's
// accepted descriptor chain for that site, or nil if none is cached;
// publication is the claim accompanying the object, or nil if absent.
// manifest and data must already have passed exact object verification.
//
// The function performs no I/O and takes no query as input.
func Resolve(intended ID, chain *Chain, publication *Publication, manifest reconstruct.Manifest, data []byte, now time.Time) (State, error) {
	if err := manifest.VerifyObject(data); err != nil {
		return PublisherInvalid, fmt.Errorf("object verification failed: %w", err)
	}
	if publication == nil {
		return ObjectVerified, nil
	}
	if chain == nil {
		return PublisherUnknown, errors.New("no accepted descriptor chain for this site")
	}
	if proof, equivocating := chain.Equivocating(); equivocating {
		return PublisherInvalid, proof
	}
	if chain.SiteID() != intended {
		return PublisherInvalid, errors.New("descriptor chain is for a different site")
	}
	if publication.SiteID != hex.EncodeToString(intended[:]) {
		return PublisherInvalid, errors.New("publication claims a different site")
	}

	claimedRoot, err := decodeHex(publication.ObjectRoot, 32)
	if err != nil {
		return PublisherInvalid, errors.New("invalid publication object root")
	}
	if !bytes.Equal(claimedRoot, manifest.Root[:]) {
		return PublisherInvalid, errors.New("publication is for a different object")
	}
	manifestDigest, err := ManifestDigest(manifest)
	if err != nil {
		return PublisherInvalid, err
	}
	claimedManifest, err := decodeHex(publication.ManifestDigest, 32)
	if err != nil {
		return PublisherInvalid, errors.New("invalid publication manifest digest")
	}
	if !bytes.Equal(claimedManifest, manifestDigest[:]) {
		return PublisherInvalid, errors.New("publication is for a different manifest")
	}

	signingKey, err := decodeBase64(publication.SigningKey, ed25519.PublicKeySize)
	if err != nil {
		return PublisherInvalid, errors.New("invalid publication signing key")
	}
	message, err := publicationSigningMessage(*publication)
	if err != nil {
		return PublisherInvalid, err
	}
	signature, err := decodeBase64(publication.Signature, ed25519.SignatureSize)
	if err != nil {
		return PublisherInvalid, errors.New("invalid publication signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(signingKey), message, signature) {
		return PublisherInvalid, errors.New("publication signature verification failed")
	}

	digestBytes, err := decodeHex(publication.DescriptorDigest, 32)
	if err != nil {
		return PublisherInvalid, errors.New("invalid publication descriptor digest")
	}
	var descriptorDigest [32]byte
	copy(descriptorDigest[:], digestBytes)
	descriptor, found := chain.DescriptorByDigest(descriptorDigest)
	if !found {
		return PublisherUnknown, errors.New("publication names a descriptor this client has not accepted")
	}
	head, err := chain.Head()
	if err != nil {
		return PublisherInvalid, err
	}
	if descriptor.Digest != head.Digest {
		return PublisherInvalid, errors.New("publication names a superseded descriptor")
	}
	if !descriptor.ActiveAt(now) {
		return PublisherInvalid, errors.New("authorizing descriptor is outside its validity window")
	}
	if !descriptor.AuthorizesKey(signingKey) {
		return PublisherInvalid, errors.New("publication signing key is not active in the authorizing descriptor")
	}
	return PublisherVerified, nil
}
