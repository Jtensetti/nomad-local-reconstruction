package strictjson

import (
	"strings"
	"testing"
)

const testDepth = 8

func TestADuplicateKeyIsRefusedWhereverItSits(t *testing.T) {
	documents := map[string]string{
		"adjacent":        `{"a":1,"a":2}`,
		"after a nest":    `{"n":[1,2,{"x":1}],"a":1,"a":2}`,
		"inside a nest":   `{"n":{"a":1,"a":2}}`,
		"inside an array": `[{"a":1,"a":2}]`,
	}
	for name, document := range documents {
		err := RejectDuplicateKeys([]byte(document), testDepth)
		if err == nil {
			t.Fatalf("%s: a duplicate key was accepted", name)
		}
		if !strings.Contains(err.Error(), "duplicate JSON key") {
			t.Fatalf("%s: refused for %q rather than the duplicate", name, err)
		}
	}
}

// The bound is checked at the bound. A document nested far past it is refused
// by an off-by-one as readily as by the right comparison.
func TestTheDepthBoundBitesAtTheBoundAndNotBefore(t *testing.T) {
	nest := func(levels int) []byte {
		return []byte(`{"a":` + strings.Repeat("[", levels) +
			strings.Repeat("]", levels) + `}`)
	}
	if err := RejectDuplicateKeys(nest(testDepth+1), testDepth); err == nil {
		t.Fatal("a document past the depth bound was accepted")
	} else if !strings.Contains(err.Error(), "nesting is too deep") {
		t.Fatalf("refused for %q rather than its depth", err)
	}
	if err := RejectDuplicateKeys(nest(testDepth-1), testDepth); err != nil {
		t.Fatalf("a document inside the depth bound was refused: %v", err)
	}
}

// Without this bound the walk allocates one map entry per member for as long
// as the caller keeps feeding it. Both callers cap the document size too, but
// the walk must not depend on a caller remembering to.
func TestTheElementBoundBitesForObjectsAndArrays(t *testing.T) {
	members := make([]string, 0, MaxElements+1)
	for index := 0; index <= MaxElements; index++ {
		members = append(members, `"k`+itoa(index)+`":1`)
	}
	object := "{" + strings.Join(members, ",") + "}"
	if err := RejectDuplicateKeys([]byte(object), testDepth); err == nil {
		t.Fatal("an object past the element bound was accepted")
	} else if !strings.Contains(err.Error(), "too many members") {
		t.Fatalf("refused for %q rather than its size", err)
	}

	array := "[" + strings.TrimSuffix(strings.Repeat("1,", MaxElements+1), ",") + "]"
	if err := RejectDuplicateKeys([]byte(array), testDepth); err == nil {
		t.Fatal("an array past the element bound was accepted")
	} else if !strings.Contains(err.Error(), "too many elements") {
		t.Fatalf("refused for %q rather than its size", err)
	}
}

func TestTruncatedDocumentsAreRefusedRatherThanWalkedPast(t *testing.T) {
	for _, document := range []string{`{"a":[1,2`, `{"a":`, `{"a":1`, `[{"a":1}`} {
		if err := RejectDuplicateKeys([]byte(document), testDepth); err == nil {
			t.Fatalf("the truncated document %q was accepted", document)
		}
	}
}

func TestWellFormedDocumentsPass(t *testing.T) {
	for _, document := range []string{
		`{"a":1,"b":[1,2,{"c":3}],"d":{"e":null}}`,
		`[]`, `{}`, `"scalar"`, `123`,
	} {
		if err := RejectDuplicateKeys([]byte(document), testDepth); err != nil {
			t.Fatalf("%s was refused: %v", document, err)
		}
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 8)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
