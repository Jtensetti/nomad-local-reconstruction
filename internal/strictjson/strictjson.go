// Package strictjson rejects JSON that two conforming parsers could read
// differently. Both the site descriptor and the transparency checkpoint are
// hashed and signed as bytes, so a document that decodes two ways is a
// differential: one implementation would derive a different SiteID or
// checkpoint digest from the same input.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// MaxElements bounds members per object and elements per array, so hostile
// input cannot exhaust CPU or memory inside the walk.
const MaxElements = 4096

// RejectDuplicateKeys fails on any object containing the same member name
// twice, and on nesting deeper than maxDepth. Go's decoder silently keeps the
// last occurrence of a duplicate, which is exactly the divergence signed bytes
// must not permit.
func RejectDuplicateKeys(encoded []byte, maxDepth int) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	return walkValue(decoder, 0, maxDepth)
}

func walkValue(decoder *json.Decoder, depth, maxDepth int) error {
	if depth > maxDepth {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for count := 0; decoder.More(); count++ {
			if count >= MaxElements {
				return errors.New("JSON object has too many members")
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("unexpected JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkValue(decoder, depth+1, maxDepth); err != nil {
				return err
			}
		}
	case '[':
		for count := 0; decoder.More(); count++ {
			if count >= MaxElements {
				return errors.New("JSON array has too many elements")
			}
			if err := walkValue(decoder, depth+1, maxDepth); err != nil {
				return err
			}
		}
	}
	// The closing delimiter must actually be there. Swallowing io.EOF here
	// would accept a truncated document: decoder.More reports false once the
	// stream is broken, so the loops above exit quietly and the missing
	// bracket is the only remaining evidence.
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return nil
}
