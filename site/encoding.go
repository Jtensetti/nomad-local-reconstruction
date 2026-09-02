// Package site implements SiteID and publisher identity from nomad-protocol
// docs/SITE_IDENTITY.md: a hash-linked, monotonically sequenced
// SiteDescriptor chain and the SitePublication record that binds one exact
// object to a site. The 228-byte signed manifest in package reconstruct is
// referenced and never modified; object integrity and publisher identity
// remain separate claims.
//
// Nothing in this package performs I/O to a network or takes a reader query
// as input. Identity resolution is a pure function of locally supplied
// material, so it cannot create query-dependent network behavior.
package site

import (
	"encoding/binary"
	"errors"
)

// Canonical binary encoding: fixed field order, big-endian fixed-width
// integers, uint64 length prefixes for byte strings and lists, no floats.
// JSON is transport only and is never hashed or signed directly.

const maxCanonicalBytes = 1 << 20

func appendUint32(out []byte, value uint32) []byte {
	return binary.BigEndian.AppendUint32(out, value)
}

func appendUint64(out []byte, value uint64) []byte {
	return binary.BigEndian.AppendUint64(out, value)
}

func appendBytes(out, value []byte) []byte {
	out = appendUint64(out, uint64(len(value)))
	return append(out, value...)
}

func appendString(out []byte, value string) []byte {
	return appendBytes(out, []byte(value))
}

func appendKeyList(out []byte, keys [][]byte) []byte {
	out = appendUint64(out, uint64(len(keys)))
	for _, key := range keys {
		out = appendBytes(out, key)
	}
	return out
}

func validCanonicalLength(length int) error {
	if length < 0 || length > maxCanonicalBytes {
		return errors.New("canonical field length is outside the supported range")
	}
	return nil
}
