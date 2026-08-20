package site

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// rejectDuplicateKeys walks the raw JSON and fails on any object that
// contains the same member name twice. Go's decoder silently keeps the last
// occurrence, so without this check two conforming parsers could derive
// different SiteIDs from the same bytes. Depth and element counts are
// bounded so hostile input cannot exhaust the stack or CPU here.
func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	return walkValue(decoder, 0)
}

const (
	maxJSONDepth    = 16
	maxJSONElements = 4096
)

func walkValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
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
			if count > maxJSONElements {
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
			if err := walkValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for count := 0; decoder.More(); count++ {
			if count > maxJSONElements {
				return errors.New("JSON array has too many elements")
			}
			if err := walkValue(decoder, depth+1); err != nil {
				return err
			}
		}
	}
	// Consume the matching closing delimiter.
	if _, err := decoder.Token(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
