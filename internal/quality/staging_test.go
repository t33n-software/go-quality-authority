package quality

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stagingState carries the fake seam state of a staging test.
type stagingState struct {
	fs          *virtualFS
	tempCounter int
	tempErr     error
	mkdirErr    error
	writeErr    error
	removeErr   error
	removed     []string
	gitOutput   string
	gitErr      error
}

// stagingOrchestrator binds the orchestrator's staging seams to the fake
// state.
func stagingOrchestrator(state *stagingState) Orchestrator {
	return Orchestrator{
		ExecuteOutput: func(_ context.Context, _ string, executable string, args []string, _ []string) ([]byte, error) {
			if executable == "git" && strings.Join(args, " ") == "ls-files -z" {
				return []byte(state.gitOutput), state.gitErr
			}
			return nil, errors.New("unexpected process invocation")
		},
		ReadFile: state.fs.readFile,
		TempDir: func(pattern string) (string, error) {
			if state.tempErr != nil {
				return "", state.tempErr
			}
			state.tempCounter++
			return fmt.Sprintf("staging-%d", state.tempCounter), nil
		},
		MkdirAll: func(string, os.FileMode) error { return state.mkdirErr },
		WriteFile: func(path string, data []byte, _ os.FileMode) error {
			if state.writeErr != nil {
				return state.writeErr
			}
			state.fs.addFile(path, string(data))
			return nil
		},
		RemoveAll: func(path string) error {
			if state.removeErr != nil {
				return state.removeErr
			}
			state.removed = append(state.removed, path)
			return nil
		},
	}
}

// boundStagingState binds a repository tree with two tracked files and one
// residue file that the tracked-set oracle never lists.
func boundStagingState() *stagingState {
	fs := newVirtualFS()
	fs.addFile("main.tf", "resource \"root\" {}\n")
	fs.addFile("stacks/a/main.tf", "resource \"a\" {}\n")
	fs.addFile(".terraform/residue.tfstate", "residue\n")
	return &stagingState{
		fs:        fs,
		gitOutput: "main.tf\x00stacks/a/main.tf\x00",
	}
}

func TestMaterializeStaging(t *testing.T) {
	state := boundStagingState()
	o := stagingOrchestrator(state)
	unit := &packStaging{scope: "stacks/a"}
	if err := o.materializeStaging(context.Background(), ".", unit); err != nil {
		t.Fatalf("materializeStaging: %v", err)
	}
	if unit.dir != "staging-1" {
		t.Fatalf("unit.dir = %q", unit.dir)
	}
	// The staging carries exactly the tracked files, structure-preserving.
	contents, err := state.fs.readFile(filepath.Join("staging-1", "main.tf"))
	if err != nil || string(contents) != "resource \"root\" {}\n" {
		t.Fatalf("staged main.tf = %q, %v", contents, err)
	}
	contents, err = state.fs.readFile(filepath.Join("staging-1", "stacks", "a", "main.tf"))
	if err != nil || string(contents) != "resource \"a\" {}\n" {
		t.Fatalf("staged stacks/a/main.tf = %q, %v", contents, err)
	}
	// The residue file is never staged: the tracked-set oracle never lists it.
	if _, err := state.fs.readFile(filepath.Join("staging-1", ".terraform", "residue.tfstate")); err == nil {
		t.Fatal("the staging must never carry execution residue")
	}
	// The materialization is lazy: a second call is a no-op.
	if err := o.materializeStaging(context.Background(), ".", unit); err != nil {
		t.Fatalf("materializeStaging reuse: %v", err)
	}
	if state.tempCounter != 1 {
		t.Fatalf("the unit is materialized exactly once, got %d", state.tempCounter)
	}
}

func TestMaterializeStagingTempDirError(t *testing.T) {
	state := boundStagingState()
	state.tempErr = errors.New("boom")
	o := stagingOrchestrator(state)
	unit := &packStaging{scope: "stacks/a"}
	err := o.materializeStaging(context.Background(), ".", unit)
	if err == nil || !strings.Contains(err.Error(), "create the clean staging") {
		t.Fatalf("expected the create finding, got %v", err)
	}
}

func TestMaterializeStagingGitError(t *testing.T) {
	state := boundStagingState()
	state.gitErr = errors.New("boom")
	o := stagingOrchestrator(state)
	unit := &packStaging{scope: "stacks/a"}
	err := o.materializeStaging(context.Background(), ".", unit)
	if err == nil || !strings.Contains(err.Error(), "enumerate the tracked files") {
		t.Fatalf("expected the enumeration finding, got %v", err)
	}
	// A partially materialized staging is never left behind.
	if len(state.removed) != 1 || state.removed[0] != "staging-1" {
		t.Fatalf("the partial staging is released: %+v", state.removed)
	}
}

func TestMaterializeStagingReadError(t *testing.T) {
	state := boundStagingState()
	o := stagingOrchestrator(state)
	o.ReadFile = func(string) ([]byte, error) { return nil, errors.New("boom") }
	unit := &packStaging{scope: "stacks/a"}
	err := o.materializeStaging(context.Background(), ".", unit)
	if err == nil || !strings.Contains(err.Error(), "read the tracked file") {
		t.Fatalf("expected the read finding, got %v", err)
	}
	if len(state.removed) != 1 {
		t.Fatalf("the partial staging is released: %+v", state.removed)
	}
}

func TestMaterializeStagingMkdirError(t *testing.T) {
	state := boundStagingState()
	state.mkdirErr = errors.New("boom")
	o := stagingOrchestrator(state)
	unit := &packStaging{scope: "stacks/a"}
	err := o.materializeStaging(context.Background(), ".", unit)
	if err == nil || !strings.Contains(err.Error(), "create the staging directory") {
		t.Fatalf("expected the mkdir finding, got %v", err)
	}
	if len(state.removed) != 1 {
		t.Fatalf("the partial staging is released: %+v", state.removed)
	}
}

func TestMaterializeStagingWriteError(t *testing.T) {
	state := boundStagingState()
	state.writeErr = errors.New("boom")
	o := stagingOrchestrator(state)
	unit := &packStaging{scope: "stacks/a"}
	err := o.materializeStaging(context.Background(), ".", unit)
	if err == nil || !strings.Contains(err.Error(), "stage the tracked file") {
		t.Fatalf("expected the write finding, got %v", err)
	}
	if len(state.removed) != 1 {
		t.Fatalf("the partial staging is released: %+v", state.removed)
	}
}

func TestUnstageStaging(t *testing.T) {
	state := boundStagingState()
	o := stagingOrchestrator(state)
	// An unmaterialized unit releases nothing.
	if err := o.unstageStaging(&packStaging{scope: "repository"}); err != nil {
		t.Fatalf("unstageStaging of an unmaterialized unit: %v", err)
	}
	if len(state.removed) != 0 {
		t.Fatalf("nothing was materialized: %+v", state.removed)
	}
	// A materialized unit is released and cleared.
	unit := &packStaging{scope: "stacks/a", dir: "staging-1"}
	if err := o.unstageStaging(unit); err != nil {
		t.Fatalf("unstageStaging: %v", err)
	}
	if unit.dir != "" || len(state.removed) != 1 || state.removed[0] != "staging-1" {
		t.Fatalf("the unit is released: %+v, %+v", unit, state.removed)
	}
	// The cleanup is fail-closed: a removal failure is an error and the unit
	// stays bound.
	state.removeErr = errors.New("boom")
	unit = &packStaging{scope: "stacks/a", dir: "staging-2"}
	err := o.unstageStaging(unit)
	if err == nil || !strings.Contains(err.Error(), "release the clean staging") {
		t.Fatalf("expected the release finding, got %v", err)
	}
	if unit.dir != "staging-2" {
		t.Fatalf("the failed release keeps the unit bound: %+v", unit)
	}
}
