package quality

import (
	"context"
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(relative, contents string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".github/workflows/ci.yml", "name: CI\n")
	write("docs/notes.yaml", "notes: []\n")
	write("vendor/locked/dependency.yml", "locked: true\n")
	write(".git/hooks/sample.yml", "sample: true\n")
	write("main.go", "package main\n")

	files, err := YAMLFiles(dir)
	if err != nil {
		t.Fatalf("YAMLFiles: %v", err)
	}
	want := []string{
		filepath.Join(dir, ".github", "workflows", "ci.yml"),
		filepath.Join(dir, "docs", "notes.yaml"),
	}
	if len(files) != len(want) {
		t.Fatalf("files = %+v, want %+v", files, want)
	}
	for index := range want {
		if files[index] != want[index] {
			t.Fatalf("files[%d] = %q, want %q (the deterministic order)", index, files[index], want[index])
		}
	}
}

func TestYAMLFilesError(t *testing.T) {
	if _, err := YAMLFiles(filepath.Join("does", "not", "exist")); err == nil {
		t.Fatal("expected the walk error")
	}
}

func TestYAMLFilesWalkErrorPropagated(t *testing.T) {
	_, err := yamlFiles(".", func(root string, fn iofs.WalkDirFunc) error {
		return fn("docs", fakeEntry{name: "docs", isDir: true}, errors.New("walk boom"))
	})
	if err == nil {
		t.Fatal("expected the walk error to propagate")
	}
}

func TestYAMLFilesSkipsIgnoredDirectories(t *testing.T) {
	files, err := yamlFiles(".", func(root string, fn iofs.WalkDirFunc) error {
		for _, path := range []string{"vendor", "main.yml"} {
			entry := fakeEntry{name: path, isDir: path == "vendor"}
			if err := fn(path, entry, nil); err != nil {
				if errors.Is(err, filepath.SkipDir) {
					continue
				}
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "main.yml" {
		t.Fatalf("files = %+v", files)
	}
}

func TestVerifyYAMLWellformedness(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile(".github/workflows/ci.yml", "name: CI\non: [push]\n")
	fs.addFile("docs/notes.yaml", "notes:\n  - one\n")
	o, _ := fakeOrchestrator(fs)

	// Well-formed documents pass.
	if err := o.verifyYAMLWellformedness([]string{".github/workflows/ci.yml", "docs/notes.yaml"}); err != nil {
		t.Fatalf("verifyYAMLWellformedness: %v", err)
	}

	// A repository without YAML documents is vacuously green.
	if err := o.verifyYAMLWellformedness(nil); err != nil {
		t.Fatalf("verifyYAMLWellformedness must be vacuously green: %v", err)
	}

	// A malformed document fails the gate with its parse error, naming the
	// file.
	fs.addFile("docs/broken.yml", "key: [unclosed\n")
	err := o.verifyYAMLWellformedness([]string{".github/workflows/ci.yml", "docs/broken.yml"})
	if err == nil {
		t.Fatal("expected the parse failure")
	}
	if !strings.Contains(err.Error(), "docs/broken.yml") {
		t.Fatalf("the finding must name the malformed document: %q", err)
	}

	// The read error propagates wrapped.
	if err := o.verifyYAMLWellformedness([]string{"missing.yml"}); err == nil {
		t.Fatal("expected the read failure")
	} else if !strings.Contains(err.Error(), "missing.yml") {
		t.Fatalf("the finding must name the unreadable document: %q", err)
	}
}

func TestOrchestratorPlanCarriesTheYAMLGate(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	o.YAMLFiles = func(string) ([]string, error) { return []string{".github/workflows/ci.yml"}, nil }
	steps, err := o.Plan(context.Background(), ".")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	formatIndex, gateIndex, analysisIndex := -1, -1, -1
	for index, step := range steps {
		switch step.Name {
		case "check Go formatting":
			formatIndex = index
		case "verify YAML wellformedness":
			gateIndex = index
			if len(step.Args) != 1 || step.Args[0] != ".github/workflows/ci.yml" {
				t.Fatalf("the gate step must carry the discovered documents, got %+v", step.Args)
			}
		case "run static analysis":
			analysisIndex = index
		}
	}
	if formatIndex < 0 || gateIndex < 0 || analysisIndex < 0 {
		t.Fatal("the plan must carry the format proof, the YAML gate, and the analysis set")
	}
	if !(formatIndex < gateIndex && gateIndex < analysisIndex) {
		t.Fatalf("the YAML gate follows the format proof and precedes the analysis set: %d, %d, %d", formatIndex, gateIndex, analysisIndex)
	}
}

func TestOrchestratorPlanYAMLFilesError(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.YAMLFiles = func(string) ([]string, error) { return nil, errors.New("boom") }
	if _, err := o.Plan(context.Background(), "."); err == nil {
		t.Fatal("expected the YAML discovery error")
	} else if !strings.Contains(err.Error(), "list YAML documents") {
		t.Fatalf("Plan error = %q", err)
	}
}

func TestOrchestratorRunStepYAMLGate(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("docs/broken.yml", "key: [unclosed\n")
	o, calls := fakeOrchestrator(fs)
	step := Step{Name: "verify YAML wellformedness", Args: []string{"docs/broken.yml"}}
	if err := o.runStep(context.Background(), ".", step); err == nil {
		t.Fatal("expected the malformed-document finding")
	} else if !strings.Contains(err.Error(), "docs/broken.yml") {
		t.Fatalf("error = %q", err)
	}
	// The gate is an in-process proof: no process invocation is recorded.
	for _, call := range *calls {
		t.Fatalf("the gate must not execute a process, got %+v", call)
	}
	// A well-formed document passes through the same interception.
	fs.addFile("docs/notes.yaml", "notes: []\n")
	step.Args = []string{"docs/notes.yaml"}
	if err := o.runStep(context.Background(), ".", step); err != nil {
		t.Fatalf("runStep YAML gate: %v", err)
	}
}
