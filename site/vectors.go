package site

import (
	"encoding/hex"
	"fmt"
)

// Vector is one published cross-implementation test vector. An independent
// implementation reproduces the preimages first, then the derived values.
type Vector struct {
	Name                 string     `json:"name"`
	Descriptor           Descriptor `json:"descriptor"`
	GenesisCoreHex       string     `json:"genesis_core_preimage_hex,omitempty"`
	SiteIDHex            string     `json:"site_id_hex,omitempty"`
	CanonicalHex         string     `json:"canonical_preimage_hex"`
	DescriptorDigestHex  string     `json:"descriptor_digest_hex"`
	SigningAuthMsgHex    string     `json:"signing_authorization_message_hex"`
	RecoveryAuthMsgHex   string     `json:"recovery_authorization_message_hex"`
	AuthorizationKeyHex  string     `json:"authorization_key_hex"`
	PublicationCanonical string     `json:"publication_canonical_preimage_hex,omitempty"`
}

// BuildVector derives a complete published vector. authorizationKey is the
// public key used in the authorization-message examples; publication is
// optional and, when present, contributes its signing preimage.
func BuildVector(name string, descriptor Descriptor, authorizationKey []byte, publication *Publication) (Vector, error) {
	canonical, err := CanonicalBytes(descriptor)
	if err != nil {
		return Vector{}, err
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return Vector{}, err
	}
	vector := Vector{
		Name: name, Descriptor: descriptor,
		CanonicalHex: hex.EncodeToString(canonical), DescriptorDigestHex: hex.EncodeToString(digest[:]),
		SigningAuthMsgHex:   hex.EncodeToString(AuthorizationMessage(digest, RoleSigning, authorizationKey)),
		RecoveryAuthMsgHex:  hex.EncodeToString(AuthorizationMessage(digest, RoleRecovery, authorizationKey)),
		AuthorizationKeyHex: hex.EncodeToString(authorizationKey),
	}
	if descriptor.Transition == TransitionGenesis {
		core, err := GenesisCoreBytes(descriptor)
		if err != nil {
			return Vector{}, err
		}
		id, err := DeriveID(descriptor)
		if err != nil {
			return Vector{}, err
		}
		vector.GenesisCoreHex = hex.EncodeToString(core)
		vector.SiteIDHex = hex.EncodeToString(id[:])
	}
	if publication != nil {
		preimage, err := PublicationCanonicalBytes(*publication)
		if err != nil {
			return Vector{}, err
		}
		vector.PublicationCanonical = hex.EncodeToString(preimage)
	}
	return vector, nil
}

// CheckVector recomputes every derived value from the vector's own inputs.
func CheckVector(vector Vector) error {
	key, err := hex.DecodeString(vector.AuthorizationKeyHex)
	if err != nil {
		return fmt.Errorf("vector %s: invalid authorization key", vector.Name)
	}
	rebuilt, err := BuildVector(vector.Name, vector.Descriptor, key, nil)
	if err != nil {
		return err
	}
	if rebuilt.CanonicalHex != vector.CanonicalHex {
		return fmt.Errorf("vector %s: canonical preimage mismatch", vector.Name)
	}
	if rebuilt.DescriptorDigestHex != vector.DescriptorDigestHex {
		return fmt.Errorf("vector %s: descriptor digest mismatch", vector.Name)
	}
	if rebuilt.GenesisCoreHex != vector.GenesisCoreHex {
		return fmt.Errorf("vector %s: genesis core preimage mismatch", vector.Name)
	}
	if rebuilt.SiteIDHex != vector.SiteIDHex {
		return fmt.Errorf("vector %s: site ID mismatch", vector.Name)
	}
	if rebuilt.SigningAuthMsgHex != vector.SigningAuthMsgHex {
		return fmt.Errorf("vector %s: signing authorization message mismatch", vector.Name)
	}
	if rebuilt.RecoveryAuthMsgHex != vector.RecoveryAuthMsgHex {
		return fmt.Errorf("vector %s: recovery authorization message mismatch", vector.Name)
	}
	return nil
}
