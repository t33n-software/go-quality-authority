package quality

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// recordedCall captures one executed process invocation.
type recordedCall struct {
	Dir        string
	Executable string
	Args       []string
	Env        []string
}

func testConfig() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Toolchain:     Toolchain{Language: "go", Version: "1.26.6"},
		Gates:         []Gate{{Name: "full-local-build", Command: "go"}},
	}
}

func fakeOrchestrator(fs *virtualFS) (Orchestrator, *[]recordedCall) {
	calls := &[]recordedCall{}
	var stdout, stderr strings.Builder
	o := Orchestrator{
		Config:   testConfig(),
		Discover: discovererFor(fs),
		Coverage: CoverageRunner{
			Run:    func(context.Context, string, string, ...string) ([]byte, error) { return []byte("ok 100.0%"), nil },
			Stdout: &stdout,
			Stderr: &stderr,
		},
		Execute: func(ctx context.Context, dir, executable string, args []string, env []string) error {
			*calls = append(*calls, recordedCall{Dir: dir, Executable: executable, Args: args, Env: env})
			return nil
		},
		ExecuteOutput: func(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error) {
			*calls = append(*calls, recordedCall{Dir: dir, Executable: executable, Args: args, Env: env})
			return []byte(""), nil
		},
		GoVersion:   func(context.Context, string) (string, error) { return "go1.26.6", nil },
		Stdout:      &stdout,
		Stderr:      &stderr,
		HasToolsMod: func(string) bool { return true },
		GoFiles:     func(string) ([]string, error) { return []string{"main.go"}, nil },
		Packs:       fakePackEngine(fs),
	}
	return o, calls
}

func TestOrchestratorPlanEmptyRoot(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	if _, err := o.Plan(context.Background(), " "); err == nil {
		t.Fatal("expected an error for an empty root")
	}
}

func TestOrchestratorPlanNilContext(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	// A nil context is normalized to the background context.
	if _, err := o.Plan(testNilContext(), "."); err != nil {
		t.Fatalf("Plan with nil context: %v", err)
	}
}

func TestOrchestratorPlanBinaryDiscoveryError(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.Discover = Discoverer{ReadDir: func(string) ([]os.DirEntry, error) { return nil, errors.New("boom") }}
	if _, err := o.Plan(context.Background(), "."); err == nil {
		t.Fatal("expected the binary discovery error")
	}
}

func TestOrchestratorPlanFuzzDiscoveryError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	o.Discover = Discoverer{
		ReadDir:  fs.readDir,
		ReadFile: fs.readFile,
		Walk:     func(string, iofs.WalkDirFunc) error { return errors.New("boom") },
	}
	if _, err := o.Plan(context.Background(), "."); err == nil {
		t.Fatal("expected the fuzz discovery error")
	}
}

func TestOrchestratorPlanGoFilesError(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.GoFiles = func(string) ([]string, error) { return nil, errors.New("boom") }
	if _, err := o.Plan(context.Background(), "."); err == nil {
		t.Fatal("expected the Go-files error")
	}
}

func TestOrchestratorPlanContent(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/quality-gate/main.go", "package main\n")
	fs.addFile("internal/quality/config_test.go", "package quality\n\nfunc FuzzParse(f *testing.F) {}\n")
	o, _ := fakeOrchestrator(fs)
	steps, err := o.Plan(context.Background(), ".")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.Name)
	}
	joined := strings.Join(names, "|")
	for _, want := range []string{
		"verify controlled toolchain",
		"download module dependencies",
		"check Go formatting",
		"run lint",
		"run unit, contract, and integration tests",
		"run race detector",
		"run vulnerability analysis",
		"validate Lefthook configuration",
		"build quality-gate",
		"smoke test quality-gate",
		"fuzz FuzzParse",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("plan is missing %q; got %q", want, joined)
		}
	}
}

func TestOrchestratorPlanWithoutToolsMod(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.HasToolsMod = func(string) bool { return false }
	steps, err := o.Plan(context.Background(), ".")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	toolsSteps := map[string]bool{
		"download tool dependencies":      true,
		"verify tool dependencies":        true,
		"verify tool metadata":            true,
		"run lint":                        true,
		"run vulnerability analysis":      true,
		"validate Lefthook configuration": true,
	}
	for _, step := range steps {
		if toolsSteps[step.Name] {
			t.Fatalf("unexpected tools step without a tools module: %q", step.Name)
		}
	}
}

func TestOrchestratorRunSuccess(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, calls := fakeOrchestrator(fs)
	if err := o.Run(context.Background(), "."); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(*calls) == 0 {
		t.Fatal("expected the plan steps to be executed")
	}
}

func TestOrchestratorRunPlanError(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.GoFiles = func(string) ([]string, error) { return nil, errors.New("boom") }
	if err := o.Run(context.Background(), "."); err == nil {
		t.Fatal("expected the plan error")
	}
}

func TestOrchestratorRunStepError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	o.Execute = func(context.Context, string, string, []string, []string) error { return errors.New("boom") }
	if err := o.Run(context.Background(), "."); err == nil {
		t.Fatal("expected the step error")
	}
}

func TestOrchestratorRunCoverageError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	var stderr strings.Builder
	o.Coverage = CoverageRunner{
		Run: func(context.Context, string, string, ...string) ([]byte, error) {
			return []byte("FAIL\texample.com/below\t0.2s\tcoverage: 87.2% of statements"), nil
		},
		Stdout: io.Discard,
		Stderr: &stderr,
	}
	if err := o.Run(context.Background(), "."); err == nil {
		t.Fatal("expected the coverage error")
	}
}

func TestOrchestratorVerifyToolchain(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	if err := o.verifyToolchain(context.Background(), "."); err != nil {
		t.Fatalf("verifyToolchain: %v", err)
	}
	o.Config.Toolchain.Language = "rust"
	if err := o.verifyToolchain(context.Background(), "."); err == nil {
		t.Fatal("expected the non-Go toolchain rejection")
	}
	o.Config.Toolchain.Language = "go"
	o.Config.Toolchain.Version = "1.25.0"
	if err := o.verifyToolchain(context.Background(), "."); err == nil {
		t.Fatal("expected a toolchain mismatch error")
	}
	o.GoVersion = func(context.Context, string) (string, error) { return "", errors.New("boom") }
	o.Config.Toolchain.Version = "1.26.6"
	if err := o.verifyToolchain(context.Background(), "."); err == nil {
		t.Fatal("expected the toolchain read error")
	}
}

func TestOrchestratorPlanResolvesDeclaredPacks(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	pack := testResolvedPack()
	provisionPack(t, &o, fs, pack)
	steps, err := o.Plan(context.Background(), ".")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.Name)
	}
	joined := strings.Join(names, "|")
	for _, want := range []string{"opentofu-version", "opentofu-fmt-check"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("plan is missing the pack step %q; got %q", want, joined)
		}
	}
	// The pack gates compose after the core analysis and before the project
	// binaries.
	analysis := strings.Index(joined, "run static analysis")
	packGate := strings.Index(joined, "opentofu-fmt-check")
	project := strings.Index(joined, "build tool")
	if analysis < 0 || packGate < 0 || project < 0 || !(analysis < packGate && packGate < project) {
		t.Fatalf("the composition order is core -> pack -> project; got %q", joined)
	}
}

func TestOrchestratorPlanUnknownPackFailsClosed(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	o.Config.Extends = []string{"opentofu@1"}
	// The fake engine resolves nothing: the reference is unknown.
	o.Packs.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return nil, errors.New("module not pinned")
	}
	if _, err := o.Plan(context.Background(), "."); err == nil {
		t.Fatal("expected the unknown-pack fail-closed error")
	} else if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("Plan error = %q, want the unknown-reference finding", err)
	}
}

func TestOrchestratorPlanPackNotProvisioned(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	o.Config.Extends = []string{"opentofu@1"}
	bindWorkingTreeRegistry(fs)
	// The pack resolves, but the tool is absent from the pack tool cache.
	if _, err := o.Plan(context.Background(), "."); err == nil {
		t.Fatal("expected the not-provisioned fail-closed error")
	} else if !strings.Contains(err.Error(), "not provisioned") {
		t.Fatalf("Plan error = %q, want the not-provisioned finding", err)
	}
}

func TestOrchestratorBinarySteps(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	steps := o.binarySteps([]Binary{{Package: "./cmd/a"}, {Package: "./cmd/b", Smoke: []string{"--help"}}})
	if len(steps) != 4 {
		t.Fatalf("steps = %d", len(steps))
	}
	// default smoke applies to the binary without an override
	if !reflect.DeepEqual(steps[1].Args, DefaultSmokeArguments) {
		t.Fatalf("default smoke = %+v", steps[1].Args)
	}
	if !reflect.DeepEqual(steps[3].Args, []string{"--help"}) {
		t.Fatalf("override smoke = %+v", steps[3].Args)
	}
}

func TestOrchestratorResolveBinariesOverride(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.Config.Project.Binaries = []Binary{{Package: "./cmd/a", Smoke: []string{"--custom"}}}
	merged := o.resolveBinaries([]Binary{{Package: "./cmd/a"}, {Package: "./cmd/b"}})
	if len(merged) != 2 {
		t.Fatalf("merged = %+v", merged)
	}
	for _, binary := range merged {
		if binary.Package == "./cmd/a" && !reflect.DeepEqual(binary.Smoke, []string{"--custom"}) {
			t.Fatalf("override not applied: %+v", binary)
		}
	}
}

func TestOrchestratorFuzzSteps(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	steps := o.fuzzSteps([]FuzzTarget{{Package: "./internal/a", Target: "FuzzA"}, {Package: "./internal/b", Target: "FuzzB", Time: "30s"}})
	if len(steps) != 2 {
		t.Fatalf("steps = %d", len(steps))
	}
	if !strings.Contains(strings.Join(steps[0].Args, " "), "-fuzztime=50000x") {
		t.Fatalf("default fuzz time = %+v", steps[0].Args)
	}
	if !strings.Contains(strings.Join(steps[1].Args, " "), "-fuzztime=30s") {
		t.Fatalf("override fuzz time = %+v", steps[1].Args)
	}
}

func TestOrchestratorResolveFuzzTargetsOverride(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.Config.Project.Fuzz = []FuzzTarget{{Package: "./internal/a", Target: "FuzzA", Time: "10s"}}
	merged := o.resolveFuzzTargets([]FuzzTarget{{Package: "./internal/a", Target: "FuzzA"}})
	if len(merged) != 1 || merged[0].Time != "10s" {
		t.Fatalf("merged = %+v", merged)
	}
}

func TestOrchestratorResolveFuzzTargetsSortsByTarget(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	merged := o.resolveFuzzTargets([]FuzzTarget{
		{Package: "./internal/a", Target: "FuzzB"},
		{Package: "./internal/a", Target: "FuzzA"},
	})
	if len(merged) != 2 || merged[0].Target != "FuzzA" || merged[1].Target != "FuzzB" {
		t.Fatalf("merged not sorted by target: %+v", merged)
	}
}

func TestBinaryArtifact(t *testing.T) {
	if got := binaryArtifact("windows", "tool"); !strings.HasSuffix(got, "tool.exe") {
		t.Fatalf("windows artifact = %q", got)
	}
	if got := binaryArtifact("linux", "tool"); strings.HasSuffix(got, ".exe") || !strings.HasSuffix(got, "tool") {
		t.Fatalf("linux artifact = %q", got)
	}
}

func TestModuleVerificationSteps(t *testing.T) {
	if len(moduleVerificationSteps(false)) != 3 {
		t.Fatal("expected three module steps without tools")
	}
	if len(moduleVerificationSteps(true)) != 6 {
		t.Fatal("expected six module steps with tools")
	}
}

func TestCanonicalAnalysisSteps(t *testing.T) {
	without := canonicalAnalysisSteps(false)
	if len(without) != 4 {
		t.Fatalf("expected four analysis steps without tools, got %d", len(without))
	}
	with := canonicalAnalysisSteps(true)
	if len(with) != 7 {
		t.Fatalf("expected seven analysis steps with tools, got %d", len(with))
	}
}

func TestGoSourceFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir+string(os.PathSeparator)+"cmd", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+string(os.PathSeparator)+"cmd"+string(os.PathSeparator)+"main.go", []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := GoSourceFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %+v", files)
	}
}

func TestGoSourceFilesError(t *testing.T) {
	if _, err := GoSourceFiles(filepath.Join("does", "not", "exist")); err == nil {
		t.Fatal("expected the walk error")
	}
}

func TestNewOrchestratorDefaults(t *testing.T) {
	o := NewOrchestrator(testConfig(), nil, nil)
	if o.Execute == nil || o.GoVersion == nil || o.GoFiles == nil || o.HasToolsMod == nil {
		t.Fatal("expected the production seams to be bound")
	}
	if o.Stdout == nil || o.Stderr == nil {
		t.Fatal("expected the default writers to be bound")
	}
}

func TestRunProcessOutput(t *testing.T) {
	output, err := runProcessOutput(context.Background(), ".", "go", []string{"version"}, nil)
	if err != nil {
		t.Fatalf("runProcessOutput: %v", err)
	}
	if !strings.Contains(string(output), "go version") {
		t.Fatalf("output = %q", output)
	}
	if err := runProcess(context.Background(), ".", "go", []string{"version"}, nil); err != nil {
		t.Fatalf("runProcess: %v", err)
	}
}

func TestRunProcessOutputWithEnvironment(t *testing.T) {
	// A non-empty environment extends the process environment of the step;
	// GOFLAGS is a recognized Go variable, so `go env` proves the propagation.
	output, err := runProcessOutput(context.Background(), ".", "go", []string{"env", "GOFLAGS"}, []string{"GOFLAGS=-mod=readonly"})
	if err != nil {
		t.Fatalf("runProcessOutput with env: %v", err)
	}
	if !strings.Contains(string(output), "-mod=readonly") {
		t.Fatalf("the step environment was not applied: %q", output)
	}
}

func TestOrchestratorRunNilContext(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	// A nil context is normalized to the background context.
	if err := o.Run(testNilContext(), "."); err != nil {
		t.Fatalf("Run with nil context: %v", err)
	}
}

func TestOrchestratorRunStepWithDirectory(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, calls := fakeOrchestrator(fs)
	o.GoFiles = func(string) ([]string, error) { return []string{"main.go"}, nil }
	// Inject a step with an explicit working directory through the plan.
	steps, err := o.Plan(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	withDir := append(steps, Step{Name: "custom", Dir: "tools", Executable: "go", Args: []string{"version"}})
	for _, step := range withDir {
		if err := o.runStep(context.Background(), ".", step); err != nil {
			t.Fatalf("runStep %q: %v", step.Name, err)
		}
	}
	found := false
	for _, call := range *calls {
		if call.Dir == filepath.Join(".", "tools") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the step working directory to be joined")
	}
}

func TestNewOrchestratorProductionSeams(t *testing.T) {
	o := NewOrchestrator(testConfig(), io.Discard, io.Discard)
	if err := o.Execute(context.Background(), ".", "go", []string{"version"}, nil); err != nil {
		t.Fatalf("production Execute seam: %v", err)
	}
	if _, err := o.ExecuteOutput(context.Background(), ".", "go", []string{"version"}, nil); err != nil {
		t.Fatalf("production ExecuteOutput seam: %v", err)
	}
	if _, err := o.GoVersion(context.Background(), "."); err != nil {
		t.Fatalf("production GoVersion seam: %v", err)
	}
	// The tools-module probe runs against a real tree.
	if o.HasToolsMod(t.TempDir()) {
		t.Fatal("expected no tools module in an empty tree")
	}
	// The pack engine is bound with its production seams.
	if o.Packs.ExecuteOutput == nil || o.Packs.ReadFile == nil || o.Packs.Fetch == nil || o.Packs.UserCacheDir == nil {
		t.Fatal("expected the pack engine production seams to be bound")
	}
}

func TestGoSourceFilesWalkError(t *testing.T) {
	_, err := goSourceFiles(".", func(root string, fn iofs.WalkDirFunc) error {
		return fn("internal/quality", fakeEntry{name: "quality", isDir: true}, errors.New("walk boom"))
	})
	if err == nil {
		t.Fatal("expected the walk error to propagate")
	}
}

func TestGoSourceFilesSkipsIgnoredDirectories(t *testing.T) {
	files, err := goSourceFiles(".", func(root string, fn iofs.WalkDirFunc) error {
		for _, path := range []string{"vendor", "main.go"} {
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
	if len(files) != 1 || files[0] != "main.go" {
		t.Fatalf("files = %+v", files)
	}
}

func TestOrchestratorRunStepAssertion(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, _ := fakeOrchestrator(fs)
	step := Step{Name: "opentofu-version", Executable: "tofu", Args: []string{"version"}, Expect: "OpenTofu v1.12.5"}
	// The assertion passes when the output carries the expectation.
	o.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return []byte("OpenTofu v1.12.5"), nil
	}
	if err := o.runStep(context.Background(), ".", step); err != nil {
		t.Fatalf("runStep assertion: %v", err)
	}
	// The assertion fails closed when the expectation is missing.
	o.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return []byte("other"), nil
	}
	if err := o.runStep(context.Background(), ".", step); err == nil {
		t.Fatal("expected the assertion mismatch finding")
	} else if !strings.Contains(err.Error(), "requires the output to carry") {
		t.Fatalf("error = %q", err)
	}
	// The assertion fails closed on the execution error.
	o.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return nil, errors.New("boom")
	}
	if err := o.runStep(context.Background(), ".", step); err == nil {
		t.Fatal("expected the assertion execution finding")
	}
}

func TestOrchestratorRunStepEnvPropagated(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	o, calls := fakeOrchestrator(fs)
	step := Step{Name: "opentofu-fmt-check", Executable: "tofu", Args: []string{"fmt"}, Env: []string{"TF_IN_AUTOMATION=true"}}
	if err := o.runStep(context.Background(), ".", step); err != nil {
		t.Fatalf("runStep: %v", err)
	}
	found := false
	for _, call := range *calls {
		if call.Executable == "tofu" && len(call.Env) == 1 && call.Env[0] == "TF_IN_AUTOMATION=true" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the pack environment to reach the process")
	}
}

func TestOrchestratorProvisionNoDeclarations(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	var stdout strings.Builder
	o.Stdout = &stdout
	if err := o.Provision(context.Background(), "."); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !strings.Contains(stdout.String(), "No capability packs declared") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestOrchestratorProvisionNilContext(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	var stdout strings.Builder
	o.Stdout = &stdout
	// A nil context is normalized to the background context.
	if err := o.Provision(testNilContext(), "."); err != nil {
		t.Fatalf("Provision with nil context: %v", err)
	}
}

func TestOrchestratorProvisionResolutionError(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.Config.Extends = []string{"opentofu@1"}
	o.Packs.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return nil, errors.New("module not pinned")
	}
	if err := o.Provision(context.Background(), "."); err == nil {
		t.Fatal("expected the resolution finding")
	}
}

func TestOrchestratorProvisionDelegation(t *testing.T) {
	fs := newVirtualFS()
	o, _ := fakeOrchestrator(fs)
	o.Config.Extends = []string{"opentofu@1"}
	// The working-tree registry carries the pack with the digest of the
	// fixture archive and no signature reference, so the recipe runs
	// end-to-end against the fake seams.
	archive := buildZip(t, map[string]string{"tofu": "tool-binary"})
	sum := sha256.Sum256(archive)
	document := strings.Replace(validPackJSON(), `"sha256":"dade9650e6b74fc7a8b986bd8717497d32f9e09cf82e479afef4977fa3085536"`, `"sha256":"`+hex.EncodeToString(sum[:])+`"`, 1)
	document = strings.Replace(document, `,"signature":"https://example.com/tofu.zip.sig"`, ``, 1)
	fs.addFile("go.mod", "module "+territoryHomeModule+"\n")
	fs.addFile("capabilities/infrastructure/opentofu/v1/pack.json", document)
	o.Packs.Fetch = func(_ context.Context, url string, _ int64) ([]byte, error) {
		if url == "https://example.com/tofu.zip" {
			return archive, nil
		}
		return nil, errors.New("unexpected download")
	}
	var stdout strings.Builder
	o.Packs.Stdout = &stdout
	if err := o.Provision(context.Background(), "."); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !strings.Contains(stdout.String(), "provisioned opentofu@1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
