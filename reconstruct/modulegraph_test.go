package reconstruct

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Local reconstruction links no third-party code at all.
//
// A vulnerability gate scans what is there and a digest pins what is there;
// neither says anything about a module arriving. This does.
//
// It is worth asserting rather than noticing because the current answer is
// zero. A module graph at zero is a claim a reader checks in one line; one at
// four is a list somebody has to keep reviewing, and the difference between
// them should be a decision rather than a diff nobody read.
func TestTheModuleGraphHasNoThirdPartyCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "all").Output()
	if err != nil {
		t.Fatalf("go list -m all: %v", err)
	}
	var third []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		module, _, _ := strings.Cut(line, " ")
		if module == "" || strings.HasPrefix(module, "github.com/Jtensetti/") {
			continue
		}
		third = append(third, module)
	}
	if len(third) > 0 {
		t.Fatalf("this module's graph now contains code from outside the project:\n  %s\n\n"+
			"That is not forbidden, but it is a decision: a module here is code no one "+
			"in this project reviewed. Update this test deliberately, and say in the "+
			"commit who reviewed what.", strings.Join(third, "\n  "))
	}
}

// The control: the same scan against a graph that does contain third-party
// code must report it, or a scan that always found nothing would pass the zero
// case perfectly.
func TestTheThirdPartyScanReportsWhatIsThere(t *testing.T) {
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.test\n\ngo 1.25.0\n\nrequire golang.org/x/sys v0.47.0\n",
		"use.go": "package use\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("go", "list", "-m", "all")
	command.Dir = directory
	command.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	out, err := command.Output()
	if err != nil {
		t.Skipf("the control needs the module cache to resolve golang.org/x/sys: %v", err)
	}
	if !strings.Contains(string(out), "golang.org/x/sys") {
		t.Fatalf("the scan did not report a module that is plainly there:\n%s", out)
	}
}
