package reconstruct

import (
	"errors"
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

// thirdPartyModules is the scan itself, factored out so the control below runs
// this code rather than a second copy of it. `go list -m all` prints the main
// module first; everything after it is a dependency.
func thirdPartyModules(t *testing.T, directory string, environment []string) []string {
	t.Helper()
	command := exec.Command("go", "list", "-m", "all")
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	out, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("go list -m all in %s: %v\n%s", directory, err, exit.Stderr)
		}
		t.Fatalf("go list -m all in %s: %v", directory, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		t.Fatalf("go list -m all named no main module in %s", directory)
	}
	var third []string
	for _, line := range lines[1:] {
		module, _, _ := strings.Cut(line, " ")
		if module == "" {
			continue
		}
		third = append(third, module)
	}
	return third
}

func TestTheModuleGraphHasNoThirdPartyCode(t *testing.T) {
	third := thirdPartyModules(t, ".", nil)
	if len(third) > 0 {
		t.Fatalf("this module's graph now has dependencies, and it had none:\n  %s\n\n"+
			"That is not forbidden, but it is a decision. A third-party module here is "+
			"code no one in this project reviewed; a sibling one couples two "+
			"repositories that are currently independent. Update this test "+
			"deliberately, and say in the commit who reviewed what.",
			strings.Join(third, "\n  "))
	}
}

// The control: the same scan against a graph that does contain a dependency
// must report it, or a scan that always found nothing would pass the zero case
// perfectly.
//
// The fixture requires a second module and replaces it with a local directory,
// so it resolves under GOPROXY=off. The first version named a real dependency
// and skipped when the module cache could not resolve it -- which made the
// control disappear in exactly the environments where nobody was watching.
func TestTheThirdPartyScanReportsWhatIsThere(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "dep"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"go.mod": "module example.test\n\ngo 1.25.0\n\n" +
			"require example.test/dep v1.0.0\n\nreplace example.test/dep => ./dep\n",
		"use.go":     "package use\n",
		"dep/go.mod": "module example.test/dep\n\ngo 1.25.0\n",
		"dep/dep.go": "package dep\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	third := thirdPartyModules(t, directory, []string{"GOFLAGS=-mod=mod", "GOPROXY=off"})
	if len(third) != 1 || third[0] != "example.test/dep" {
		t.Fatalf("the scan did not report the one dependency that is plainly there: %v", third)
	}
}
