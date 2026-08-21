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
)

const (
	DescriptorVersion = "nomad-site-descriptor-v1"
	MaximumFileBytes  = 1 << 20

	siteIDDomain        = "nomad-siteid-v1"
	descriptorDigestDom = "nomad-site-descriptor-digest-v1"
	authorizationDomain = "nomad-site-authorization-v1"

	TransitionGenesis    = "genesis"
	TransitionRotation   = "rotation"
	TransitionRecovery   = "recovery"
	TransitionRevocation = "revocation"

	RoleSigning  = byte(0x01)
	RoleRecovery = byte(0x02)

	maxKeys = 8
	// maxRevokedKeys is deliberately far larger than maxKeys. Revocation is
	// absorbing, so every ancestor's revocations are carried forward; sharing
	// the active-key bound would make a site permanently unrotatable after
	// eight revocations, and would let a transient signing majority burn the
	// budget to disable the site for good.
	maxRevokedKeys = 1024
)

// ID is a persistent publisher identity: a domain-separated commitment to
// the exact genesis descriptor.
type ID [32]byte

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// Recovery is the offline authority that can replace a signing-key set the
// publisher no longer controls.
type Recovery struct {
	Threshold uint32   `json:"threshold"`
	Keys      []string `json:"keys"`
}

// Authorization is one signature authorizing a descriptor, bound to the
// signer's role and exact key.
type Authorization struct {
	Role      string `json:"role"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

// Descriptor is one link in a site's key-authority chain.
type Descriptor struct {
	Version                  string          `json:"version"`
	SiteID                   string          `json:"site_id"`
	Sequence                 uint64          `json:"sequence"`
	Transition               string          `json:"transition"`
	PreviousDescriptorDigest string          `json:"previous_descriptor_digest"`
	ValidFrom                string          `json:"valid_from"`
	ValidUntil               string          `json:"valid_until"`
	SigningKeys              []string        `json:"signing_keys"`
	RevokedKeys              []string        `json:"revoked_keys"`
	Recovery                 Recovery        `json:"recovery"`
	Authorizations           []Authorization `json:"authorizations"`
}

// Verified is a structurally valid, correctly authorized descriptor.
type Verified struct {
	Descriptor Descriptor
	Digest     [32]byte
	SiteID     ID
	ValidFrom  time.Time
	ValidUntil time.Time
}

var zeroDigestHex = hex.EncodeToString(make([]byte, 32))

// canonicalBytes encodes the descriptor for hashing. When zeroSiteID is set
// the site_id field is replaced by 32 zero bytes, which is the genesis_core
// form used to derive the SiteID itself. Authorizations are always excluded
// so independently produced signatures bind identical bytes.
func canonicalBytes(descriptor Descriptor, zeroSiteID bool) ([]byte, error) {
	if descriptor.Version != DescriptorVersion {
		return nil, errors.New("unsupported site descriptor version")
	}
	switch descriptor.Transition {
	case TransitionGenesis, TransitionRotation, TransitionRecovery, TransitionRevocation:
	default:
		return nil, errors.New("unsupported site transition kind")
	}
	siteID := make([]byte, 32)
	if !zeroSiteID {
		decoded, err := decodeHex(descriptor.SiteID, 32)
		if err != nil {
			return nil, errors.New("invalid site ID encoding")
		}
		siteID = decoded
	}
	previous, err := decodeHex(descriptor.PreviousDescriptorDigest, 32)
	if err != nil {
		return nil, errors.New("invalid previous descriptor digest")
	}
	if err := validateCanonicalTime(descriptor.ValidFrom); err != nil {
		return nil, fmt.Errorf("valid_from: %w", err)
	}
	if err := validateCanonicalTime(descriptor.ValidUntil); err != nil {
		return nil, fmt.Errorf("valid_until: %w", err)
	}
	signing, err := decodeKeyList(descriptor.SigningKeys)
	if err != nil {
		return nil, fmt.Errorf("signing keys: %w", err)
	}
	revoked, err := decodeBoundedKeyList(descriptor.RevokedKeys, maxRevokedKeys)
	if err != nil {
		return nil, fmt.Errorf("revoked keys: %w", err)
	}
	recovery, err := decodeKeyList(descriptor.Recovery.Keys)
	if err != nil {
		return nil, fmt.Errorf("recovery keys: %w", err)
	}
	canonical := make([]byte, 0, 512)
	canonical = appendString(canonical, descriptor.Version)
	canonical = append(canonical, siteID...)
	canonical = appendUint64(canonical, descriptor.Sequence)
	canonical = appendString(canonical, descriptor.Transition)
	canonical = append(canonical, previous...)
	canonical = appendString(canonical, descriptor.ValidFrom)
	canonical = appendString(canonical, descriptor.ValidUntil)
	canonical = appendKeyList(canonical, signing)
	canonical = appendKeyList(canonical, revoked)
	canonical = appendUint32(canonical, descriptor.Recovery.Threshold)
	canonical = appendKeyList(canonical, recovery)
	if err := validCanonicalLength(len(canonical)); err != nil {
		return nil, err
	}
	return canonical, nil
}

// CanonicalBytes exposes the exact digest preimage for published vectors.
func CanonicalBytes(descriptor Descriptor) ([]byte, error) {
	return canonicalBytes(descriptor, false)
}

// GenesisCoreBytes exposes the exact SiteID derivation preimage.
func GenesisCoreBytes(descriptor Descriptor) ([]byte, error) {
	return canonicalBytes(descriptor, true)
}

// DeriveID computes the SiteID committed to by a genesis descriptor.
func DeriveID(descriptor Descriptor) (ID, error) {
	if descriptor.Transition != TransitionGenesis {
		return ID{}, errors.New("site ID derives only from a genesis descriptor")
	}
	if descriptor.Sequence != 0 {
		return ID{}, errors.New("genesis descriptor must have sequence zero")
	}
	if descriptor.PreviousDescriptorDigest != zeroDigestHex {
		return ID{}, errors.New("genesis descriptor must carry the zero previous digest")
	}
	if err := validateStructure(descriptor); err != nil {
		return ID{}, err
	}
	core, err := canonicalBytes(descriptor, true)
	if err != nil {
		return ID{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(siteIDDomain))
	_, _ = h.Write(core)
	var id ID
	copy(id[:], h.Sum(nil))
	return id, nil
}

// Digest computes the descriptor digest that authorizations sign.
func Digest(descriptor Descriptor) ([32]byte, error) {
	canonical, err := canonicalBytes(descriptor, false)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(descriptorDigestDom))
	_, _ = h.Write(canonical)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// AuthorizationMessage binds a descriptor digest, a signer role and the
// exact signing key, so an authorization cannot be replayed as a different
// role, key or descriptor.
func AuthorizationMessage(digest [32]byte, role byte, key []byte) []byte {
	message := make([]byte, 0, len(authorizationDomain)+33+len(key))
	message = append(message, authorizationDomain...)
	message = append(message, digest[:]...)
	message = append(message, role)
	message = append(message, key...)
	return message
}

func roleByte(role string) (byte, error) {
	switch role {
	case "signing":
		return RoleSigning, nil
	case "recovery":
		return RoleRecovery, nil
	default:
		return 0, errors.New("unsupported authorization role")
	}
}

// Authorize produces one authorization for the descriptor.
func Authorize(descriptor Descriptor, role string, private ed25519.PrivateKey) (Authorization, error) {
	if len(private) != ed25519.PrivateKeySize {
		return Authorization{}, errors.New("authorizing private key is required")
	}
	value, err := roleByte(role)
	if err != nil {
		return Authorization{}, err
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return Authorization{}, err
	}
	public := private.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(private, AuthorizationMessage(digest, value, public))
	return Authorization{
		Role: role, Key: base64.StdEncoding.EncodeToString(public),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func Encode(descriptor Descriptor) ([]byte, error) {
	if _, err := Digest(descriptor); err != nil {
		return nil, err
	}
	return json.MarshalIndent(descriptor, "", "  ")
}

// Decode performs strict parsing only: unknown fields, trailing data,
// duplicate JSON keys and oversized input are rejected before any
// signature work, so two conforming parsers cannot disagree.
func Decode(encoded []byte) (Descriptor, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Descriptor{}, errors.New("site descriptor is empty or too large")
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return Descriptor{}, err
	}
	var descriptor Descriptor
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return Descriptor{}, fmt.Errorf("decode site descriptor: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Descriptor{}, errors.New("trailing site descriptor data")
	}
	return descriptor, nil
}

// Verify validates one descriptor completely. previous must be nil exactly
// for a genesis descriptor.
func Verify(encoded []byte, previous *Verified) (Verified, error) {
	descriptor, err := Decode(encoded)
	if err != nil {
		return Verified{}, err
	}
	return VerifyDescriptor(descriptor, previous)
}

func VerifyDescriptor(descriptor Descriptor, previous *Verified) (Verified, error) {
	digest, err := Digest(descriptor)
	if err != nil {
		return Verified{}, err
	}
	if err := validateStructure(descriptor); err != nil {
		return Verified{}, err
	}
	validFrom, _ := time.Parse(time.RFC3339, descriptor.ValidFrom)
	validUntil, _ := time.Parse(time.RFC3339, descriptor.ValidUntil)
	if !validFrom.Before(validUntil) {
		return Verified{}, errors.New("descriptor validity window is empty")
	}

	siteID, err := decodeHex(descriptor.SiteID, 32)
	if err != nil {
		return Verified{}, errors.New("invalid site ID encoding")
	}
	var id ID
	copy(id[:], siteID)

	if descriptor.Transition == TransitionGenesis {
		if previous != nil {
			return Verified{}, errors.New("genesis descriptor cannot follow an existing descriptor")
		}
		derived, err := DeriveID(descriptor)
		if err != nil {
			return Verified{}, err
		}
		if derived != id {
			return Verified{}, errors.New("genesis descriptor does not commit to its own site ID")
		}
		if len(descriptor.RevokedKeys) != 0 {
			return Verified{}, errors.New("genesis descriptor cannot revoke keys")
		}
	} else {
		if previous == nil {
			return Verified{}, errors.New("non-genesis descriptor requires the previous descriptor")
		}
		if id != previous.SiteID {
			return Verified{}, errors.New("descriptor belongs to a different site")
		}
		if descriptor.Sequence != previous.Descriptor.Sequence+1 {
			return Verified{}, errors.New("descriptor sequence must increase by exactly one")
		}
		if descriptor.PreviousDescriptorDigest != hex.EncodeToString(previous.Digest[:]) {
			return Verified{}, errors.New("descriptor does not chain to the previous digest")
		}
		if err := checkRevocationIsAbsorbing(descriptor, *previous); err != nil {
			return Verified{}, err
		}
		if descriptor.Transition == TransitionRecovery {
			if err := requireRecoveryRevokesPriorSigning(descriptor, *previous); err != nil {
				return Verified{}, err
			}
		}
		if err := checkRecoveryPolicyAuthority(descriptor, *previous); err != nil {
			return Verified{}, err
		}
	}

	if err := verifyAuthorizations(descriptor, digest, previous); err != nil {
		return Verified{}, err
	}
	if err := requirePossessionOfNewKeys(descriptor, digest, previous); err != nil {
		return Verified{}, err
	}
	return Verified{Descriptor: descriptor, Digest: digest, SiteID: id, ValidFrom: validFrom, ValidUntil: validUntil}, nil
}

func validateStructure(descriptor Descriptor) error {
	signing, err := decodeKeyList(descriptor.SigningKeys)
	if err != nil {
		return fmt.Errorf("signing keys: %w", err)
	}
	if len(signing) == 0 {
		return errors.New("descriptor requires at least one signing key")
	}
	revoked, err := decodeBoundedKeyList(descriptor.RevokedKeys, maxRevokedKeys)
	if err != nil {
		return fmt.Errorf("revoked keys: %w", err)
	}
	recovery, err := decodeKeyList(descriptor.Recovery.Keys)
	if err != nil {
		return fmt.Errorf("recovery keys: %w", err)
	}
	if len(recovery) == 0 {
		return errors.New("descriptor requires at least one recovery key")
	}
	if descriptor.Recovery.Threshold < 1 || int(descriptor.Recovery.Threshold) > len(recovery) {
		return errors.New("recovery threshold must be between one and the recovery key count")
	}
	if err := requireDistinct(signing, "signing"); err != nil {
		return err
	}
	if err := requireDistinct(revoked, "revoked"); err != nil {
		return err
	}
	if err := requireDistinct(recovery, "recovery"); err != nil {
		return err
	}
	for _, key := range signing {
		if containsKey(revoked, key) {
			return errors.New("a key cannot be both active and revoked")
		}
		if containsKey(recovery, key) {
			return errors.New("recovery keys must be disjoint from signing keys")
		}
	}
	for _, key := range recovery {
		if containsKey(revoked, key) {
			return errors.New("a recovery key cannot be revoked while in use")
		}
	}
	return nil
}

// checkRevocationIsAbsorbing enforces that revocation never reverses: every
// key revoked by an ancestor stays revoked, and no revoked key may reappear
// as an active signing or recovery key.
func checkRevocationIsAbsorbing(descriptor Descriptor, previous Verified) error {
	previousRevoked, err := decodeBoundedKeyList(previous.Descriptor.RevokedKeys, maxRevokedKeys)
	if err != nil {
		return err
	}
	revoked, err := decodeBoundedKeyList(descriptor.RevokedKeys, maxRevokedKeys)
	if err != nil {
		return err
	}
	for _, key := range previousRevoked {
		if !containsKey(revoked, key) {
			return errors.New("descriptor drops a previously revoked key")
		}
	}
	signing, err := decodeKeyList(descriptor.SigningKeys)
	if err != nil {
		return err
	}
	recovery, err := decodeKeyList(descriptor.Recovery.Keys)
	if err != nil {
		return err
	}
	for _, key := range append(append([][]byte{}, signing...), recovery...) {
		if containsKey(previousRevoked, key) {
			return errors.New("descriptor reinstates a revoked key")
		}
	}
	return nil
}

// requirePossessionOfNewKeys makes every key that first appears in this
// descriptor prove it is held. Genesis already requires this of all its
// keys; without the same rule on later transitions a publisher could
// install a signing or recovery key nobody controls, which for a recovery
// key is a one-shot permanent brick of the site.
func requirePossessionOfNewKeys(descriptor Descriptor, digest [32]byte, previous *Verified) error {
	if previous == nil {
		return nil
	}
	known := make(map[string]struct{})
	for _, key := range previous.Descriptor.SigningKeys {
		known[key] = struct{}{}
	}
	for _, key := range previous.Descriptor.Recovery.Keys {
		known[key] = struct{}{}
	}
	check := func(keys []string, role string, roleByte byte) error {
		for _, encoded := range keys {
			if _, seen := known[encoded]; seen {
				continue
			}
			key, err := decodeBase64(encoded, ed25519.PublicKeySize)
			if err != nil {
				return errors.New("invalid key encoding")
			}
			proven := false
			for _, authorization := range descriptor.Authorizations {
				if authorization.Role != role || authorization.Key != encoded {
					continue
				}
				signature, err := decodeBase64(authorization.Signature, ed25519.SignatureSize)
				if err != nil {
					continue
				}
				if ed25519.Verify(ed25519.PublicKey(key), AuthorizationMessage(digest, roleByte, key), signature) {
					proven = true
					break
				}
			}
			if !proven {
				return fmt.Errorf("newly introduced %s key must prove possession", role)
			}
		}
		return nil
	}
	if err := check(descriptor.SigningKeys, "signing", RoleSigning); err != nil {
		return err
	}
	return check(descriptor.Recovery.Keys, "recovery", RoleRecovery)
}

// checkRecoveryPolicyAuthority keeps online publishing authority from
// reaching offline recovery authority. A rotation authorized purely by
// signing keys must leave the recovery policy byte-identical; otherwise a
// stolen signing majority could install its own recovery set, revoke the
// real one, and own the site permanently. Only a transition that carries
// the previous recovery threshold in recovery-role authorizations may change
// the policy or revoke a currently active recovery key.
func checkRecoveryPolicyAuthority(descriptor Descriptor, previous Verified) error {
	unchanged := descriptor.Recovery.Threshold == previous.Descriptor.Recovery.Threshold &&
		len(descriptor.Recovery.Keys) == len(previous.Descriptor.Recovery.Keys)
	if unchanged {
		for index := range descriptor.Recovery.Keys {
			if descriptor.Recovery.Keys[index] != previous.Descriptor.Recovery.Keys[index] {
				unchanged = false
				break
			}
		}
	}
	revoked, err := decodeBoundedKeyList(descriptor.RevokedKeys, maxRevokedKeys)
	if err != nil {
		return err
	}
	previousRecovery, err := decodeKeyList(previous.Descriptor.Recovery.Keys)
	if err != nil {
		return err
	}
	revokesRecovery := false
	for _, key := range previousRecovery {
		if containsKey(revoked, key) {
			revokesRecovery = true
			break
		}
	}
	if unchanged && !revokesRecovery {
		return nil
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return err
	}
	count := 0
	for _, encoded := range previous.Descriptor.Recovery.Keys {
		key, err := decodeBase64(encoded, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("invalid previous recovery key")
		}
		for _, authorization := range descriptor.Authorizations {
			if authorization.Role != "recovery" || authorization.Key != encoded {
				continue
			}
			signature, err := decodeBase64(authorization.Signature, ed25519.SignatureSize)
			if err != nil {
				continue
			}
			if ed25519.Verify(ed25519.PublicKey(key), AuthorizationMessage(digest, RoleRecovery, key), signature) {
				count++
				break
			}
		}
	}
	if count < int(previous.Descriptor.Recovery.Threshold) {
		return fmt.Errorf("changing the recovery policy requires %d previous recovery authorizations, got %d",
			previous.Descriptor.Recovery.Threshold, count)
	}
	return nil
}

func requireRecoveryRevokesPriorSigning(descriptor Descriptor, previous Verified) error {
	previousSigning, err := decodeKeyList(previous.Descriptor.SigningKeys)
	if err != nil {
		return err
	}
	revoked, err := decodeBoundedKeyList(descriptor.RevokedKeys, maxRevokedKeys)
	if err != nil {
		return err
	}
	for _, key := range previousSigning {
		if !containsKey(revoked, key) {
			return errors.New("recovery must revoke every previously active signing key")
		}
	}
	return nil
}

func verifyAuthorizations(descriptor Descriptor, digest [32]byte, previous *Verified) error {
	// Bound the work before any signature verification: an unbounded list
	// would let attacker-supplied bytes buy arbitrary Ed25519 verifications.
	if len(descriptor.Authorizations) > 4*maxKeys {
		return errors.New("too many authorizations")
	}
	verified := make(map[string]struct{}, len(descriptor.Authorizations))
	for _, authorization := range descriptor.Authorizations {
		role, err := roleByte(authorization.Role)
		if err != nil {
			return err
		}
		key, err := decodeBase64(authorization.Key, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("invalid authorization key")
		}
		signature, err := decodeBase64(authorization.Signature, ed25519.SignatureSize)
		if err != nil {
			return errors.New("invalid authorization signature")
		}
		if !ed25519.Verify(ed25519.PublicKey(key), AuthorizationMessage(digest, role, key), signature) {
			return fmt.Errorf("invalid %s authorization for key %s", authorization.Role, authorization.Key)
		}
		identifier := authorization.Role + ":" + string(key)
		if _, exists := verified[identifier]; exists {
			return errors.New("duplicate authorization")
		}
		verified[identifier] = struct{}{}
	}

	switch descriptor.Transition {
	case TransitionGenesis:
		for _, encoded := range descriptor.SigningKeys {
			key, err := decodeBase64(encoded, ed25519.PublicKeySize)
			if err != nil {
				return errors.New("invalid signing key")
			}
			if _, ok := verified["signing:"+string(key)]; !ok {
				return errors.New("genesis requires a self-signature from every signing key")
			}
		}
		for _, encoded := range descriptor.Recovery.Keys {
			key, err := decodeBase64(encoded, ed25519.PublicKeySize)
			if err != nil {
				return errors.New("invalid recovery key")
			}
			if _, ok := verified["recovery:"+string(key)]; !ok {
				return errors.New("genesis requires a self-signature from every recovery key")
			}
		}
		return nil
	case TransitionRotation:
		return requireSigningMajority(verified, *previous)
	case TransitionRecovery:
		return requireRecoveryThreshold(verified, *previous)
	case TransitionRevocation:
		if err := requireSigningMajority(verified, *previous); err == nil {
			return nil
		}
		return requireRecoveryThreshold(verified, *previous)
	default:
		return errors.New("unsupported site transition kind")
	}
}

func requireSigningMajority(verified map[string]struct{}, previous Verified) error {
	count := 0
	for _, encoded := range previous.Descriptor.SigningKeys {
		key, err := decodeBase64(encoded, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("invalid previous signing key")
		}
		if _, ok := verified["signing:"+string(key)]; ok {
			count++
		}
	}
	required := len(previous.Descriptor.SigningKeys)/2 + 1
	if count < required {
		return fmt.Errorf("transition requires %d of %d previous signing keys", required, len(previous.Descriptor.SigningKeys))
	}
	return nil
}

func requireRecoveryThreshold(verified map[string]struct{}, previous Verified) error {
	count := 0
	for _, encoded := range previous.Descriptor.Recovery.Keys {
		key, err := decodeBase64(encoded, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("invalid previous recovery key")
		}
		if _, ok := verified["recovery:"+string(key)]; ok {
			count++
		}
	}
	if count < int(previous.Descriptor.Recovery.Threshold) {
		return fmt.Errorf("transition requires %d previous recovery keys", previous.Descriptor.Recovery.Threshold)
	}
	return nil
}

// ActiveAt reports whether the descriptor authorizes anything at the given
// instant and whether the key is one of its active signing keys.
func (v Verified) ActiveAt(now time.Time) bool {
	return !now.Before(v.ValidFrom) && now.Before(v.ValidUntil)
}

func (v Verified) AuthorizesKey(key []byte) bool {
	signing, err := decodeKeyList(v.Descriptor.SigningKeys)
	if err != nil {
		return false
	}
	revoked, err := decodeBoundedKeyList(v.Descriptor.RevokedKeys, maxRevokedKeys)
	if err != nil {
		return false
	}
	return containsKey(signing, key) && !containsKey(revoked, key)
}

func decodeKeyList(encoded []string) ([][]byte, error) {
	return decodeBoundedKeyList(encoded, maxKeys)
}

func decodeBoundedKeyList(encoded []string, limit int) ([][]byte, error) {
	if len(encoded) > limit {
		return nil, errors.New("key list is too long")
	}
	keys := make([][]byte, 0, len(encoded))
	for _, item := range encoded {
		key, err := decodeBase64(item, ed25519.PublicKeySize)
		if err != nil {
			return nil, errors.New("invalid key encoding")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func requireDistinct(keys [][]byte, label string) error {
	for outer := range keys {
		for inner := outer + 1; inner < len(keys); inner++ {
			if bytes.Equal(keys[outer], keys[inner]) {
				return fmt.Errorf("duplicate %s key", label)
			}
		}
	}
	return nil
}

func containsKey(keys [][]byte, key []byte) bool {
	for _, candidate := range keys {
		if bytes.Equal(candidate, key) {
			return true
		}
	}
	return false
}

func validateCanonicalTime(encoded string) error {
	parsed, err := time.Parse(time.RFC3339, encoded)
	if err != nil {
		return errors.New("invalid RFC3339 time")
	}
	if parsed.UTC().Format(time.RFC3339) != encoded {
		return errors.New("time is not in canonical UTC RFC3339 form")
	}
	return nil
}

// decodeBase64 requires the exact canonical encoding. Go's Strict() mode
// rejects non-zero padding bits but still ignores CR and LF inside the
// input, which would let one key have many wire spellings: the descriptor
// would keep its digest and SiteID while its bytes differed, and a stricter
// second implementation would disagree with this one. Re-encoding and
// comparing settles it, the same discipline decodeHex already uses.
func decodeBase64(encoded string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid base64 or length")
	}
	if base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("base64 is not in canonical form")
	}
	return decoded, nil
}

func decodeHex(encoded string, size int) ([]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != size || encoded != hex.EncodeToString(decoded) {
		return nil, errors.New("invalid canonical hex or length")
	}
	return decoded, nil
}
