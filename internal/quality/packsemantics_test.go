package quality

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// testPackDescriptorV2 returns the pack descriptor of the opentofu pack major
// version 2: the unchanged static layer plus the value-evaluated behavioral
// gate.
func testPackDescriptorV2() PackDescriptor {
	descriptor := testPackDescriptor()
	descriptor.Version = 2
	descriptor.Gates = []PackGate{
		{Name: "opentofu-fmt-check", Command: "tofu", Args: []string{"fmt", "-check", "-recursive"}, Scope: PackScopeRepository},
		{Name: "opentofu-init", Command: "tofu", Args: []string{"init", "-backend=false", "-input=false", "-no-color"}, Scope: PackScopePerRoot},
		{Name: "opentofu-validate", Command: "tofu", Args: []string{"validate", "-no-color"}, Scope: PackScopePerRoot},
		{Name: "opentofu-test", Command: "tofu", Args: []string{"test", "-no-color"}, Scope: PackScopePerRoot},
	}
	return descriptor
}

// testResolvedPackV2 returns the resolved form of the version-2 test
// descriptor.
func testResolvedPackV2() ResolvedPack {
	return ResolvedPack{Reference: "opentofu@2", Registry: territoryHomeModule, Descriptor: testPackDescriptorV2()}
}

func TestGateSemanticsFor(t *testing.T) {
	// A capability without engine-bound semantics executes its descriptor as
	// plain tool gates.
	plain := testResolvedPack()
	plain.Descriptor.Capability = "demo"
	semantics, err := gateSemanticsFor(plain)
	if err != nil {
		t.Fatalf("gateSemanticsFor: %v", err)
	}
	if semantics.evaluationSafetyGuard || semantics.behavioralGate != "" {
		t.Fatalf("an unregistered capability carries no engine semantics: %+v", semantics)
	}

	// The supported majors resolve their bound semantics.
	semantics, err = gateSemanticsFor(testResolvedPack())
	if err != nil {
		t.Fatalf("gateSemanticsFor v1: %v", err)
	}
	if semantics.evaluationSafetyGuard || semantics.behavioralGate != "" {
		t.Fatalf("the static-layer major carries no machinery: %+v", semantics)
	}
	semantics, err = gateSemanticsFor(testResolvedPackV2())
	if err != nil {
		t.Fatalf("gateSemanticsFor v2: %v", err)
	}
	if !semantics.evaluationSafetyGuard || semantics.behavioralGate != "opentofu-test" {
		t.Fatalf("the value-evaluation major binds its machinery: %+v", semantics)
	}
}

func TestGateSemanticsForUnsupportedMajor(t *testing.T) {
	pack := testResolvedPackV2()
	pack.Reference = "opentofu@3"
	pack.Descriptor.Version = 3
	_, err := gateSemanticsFor(pack)
	if err == nil {
		t.Fatal("expected the unsupported-major finding")
	}
	if !strings.Contains(err.Error(), "does not support") || !strings.Contains(err.Error(), "1, 2") {
		t.Fatalf("the finding must name the supported majors: %q", err)
	}
}

func TestGateSemanticsForMissingBehavioralGate(t *testing.T) {
	pack := testResolvedPackV2()
	pack.Descriptor.Gates = pack.Descriptor.Gates[:3]
	_, err := gateSemanticsFor(pack)
	if err == nil {
		t.Fatal("expected the missing-behavioral-gate finding")
	}
	if !strings.Contains(err.Error(), "does not carry the behavioral gate") {
		t.Fatalf("error = %q", err)
	}
}

func TestExecuteBehavioralProofDeferred(t *testing.T) {
	// An encryption-carrying root never executes offline: the deterministic
	// deferral record is the gate output, and no process runs.
	fs := newVirtualFS()
	fs.addFile("versions.tf", `terraform {
  encryption {
    key_provider "gcp_kms" "main" {}
  }
}
`)
	e := fakePackEngine(fs)
	e.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		t.Fatal("an encryption-carrying root must never execute the behavioral gate offline")
		return nil, nil
	}
	var stdout strings.Builder
	e.Stdout = &stdout
	gate := PackGate{Name: "opentofu-test", Command: "tofu", Args: []string{"test", "-no-color"}, Scope: PackScopePerRoot}
	if err := e.executeBehavioralProof(context.Background(), ".", "stacks/dep-control", testResolvedPackV2(), gate, "tofu"); err != nil {
		t.Fatalf("executeBehavioralProof: %v", err)
	}
	line := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(line, "opentofu-test (stacks/dep-control): DEFERRED:") {
		t.Fatalf("the deferral record = %q", line)
	}
	if !strings.Contains(line, "governed execution window") {
		t.Fatalf("the deferral record must bind the governed execution window: %q", line)
	}
}

func TestExecuteBehavioralProofExecutes(t *testing.T) {
	// An offline-capable root executes the behavioral gate against the clean
	// staging with the pack's enforced environment.
	fs := newVirtualFS()
	fs.addFile("main.tf", "variable \"x\" {}\n")
	e := fakePackEngine(fs)
	var gotDir, gotExecutable string
	var gotArgs, gotEnv []string
	e.ExecuteOutput = func(_ context.Context, dir, executable string, args []string, env []string) ([]byte, error) {
		gotDir, gotExecutable, gotArgs, gotEnv = dir, executable, args, env
		return []byte("1 passed, 0 failed"), nil
	}
	gate := PackGate{Name: "opentofu-test", Command: "tofu", Args: []string{"test", "-no-color"}, Scope: PackScopePerRoot}
	if err := e.executeBehavioralProof(context.Background(), ".", "stacks/plain", testResolvedPackV2(), gate, "tofu"); err != nil {
		t.Fatalf("executeBehavioralProof: %v", err)
	}
	if gotDir != "." || gotExecutable != "tofu" || strings.Join(gotArgs, " ") != "test -no-color" {
		t.Fatalf("the behavioral gate execution = %q %q %+v", gotDir, gotExecutable, gotArgs)
	}
	if strings.Join(gotEnv, "|") != "OPENTOFU_ENFORCE_GPG_VALIDATION=true|TF_IN_AUTOMATION=true" {
		t.Fatalf("the pack environment must reach the behavioral gate: %+v", gotEnv)
	}
}

func TestExecuteBehavioralProofFailure(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("main.tf", "variable \"x\" {}\n")
	e := fakePackEngine(fs)
	e.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return []byte("1 failed"), errors.New("exit status 1")
	}
	gate := PackGate{Name: "opentofu-test", Command: "tofu", Args: []string{"test", "-no-color"}, Scope: PackScopePerRoot}
	err := e.executeBehavioralProof(context.Background(), ".", "stacks/plain", testResolvedPackV2(), gate, "tofu")
	if err == nil {
		t.Fatal("expected the behavioral proof failure")
	}
	if !strings.Contains(err.Error(), "the behavioral proof of stacks/plain failed") || !strings.Contains(err.Error(), "1 failed") {
		t.Fatalf("the failure must carry the evidence: %q", err)
	}
}

func TestExecuteBehavioralProofModelError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.ReadDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("boom") }
	gate := PackGate{Name: "opentofu-test", Command: "tofu", Args: []string{"test", "-no-color"}, Scope: PackScopePerRoot}
	if err := e.executeBehavioralProof(context.Background(), ".", "stacks/plain", testResolvedPackV2(), gate, "tofu"); err == nil ||
		!strings.Contains(err.Error(), "read the root directory") {
		t.Fatalf("expected the model finding, got %v", err)
	}
}
