package quality

import (
	"context"
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
}

func testConfig() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Toolchain:     Toolchain{GoVersion: "1.26.6"},
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
		Execute: func(ctx context.Context, dir, executable string, args ...string) error {
			*calls = append(*calls, recordedCall{Dir: dir, Executable: executable, Args: args})
			return nil
		},
		GoVersion:   func(context.Context, string) (string, error) { return "go1.26.6", nil },
		Stdout:      &stdout,
		Stderr:      &stderr,
		HasToolsMod: func(string) bool { return true },
		GoFiles:     func(string) ([]string, error) { return []string{"main.go"}, nil },
	}
	return o, calls
}

func TestOrchestratorPlanEmptyRoot(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	if _, err := o.Plan(" "); err == nil {
		t.Fatal("expected an error for an empty root")
	}
}

func TestOrchestratorPlanBinaryDiscoveryError(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.Discover = Discoverer{ReadDir: func(string) ([]os.DirEntry, error) { return nil, errors.New("boom") }}
	if _, err := o.Plan("."); err == nil {
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
	if _, err := o.Plan("."); err == nil {
		t.Fatal("expected the fuzz discovery error")
	}
}

func TestOrchestratorPlanGoFilesError(t *testing.T) {
	o, _ := fakeOrchestrator(newVirtualFS())
	o.GoFiles = func(string) ([]string, error) { return nil, errors.New("boom") }
	if _, err := o.Plan("."); err == nil {
		t.Fatal("expected the Go-files error")
	}
}

func TestOrchestratorPlanContent(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/quality-gate/main.go", "package main\n")
	fs.addFile("internal/quality/config_test.go", "package quality\n\nfunc FuzzParse(f *testing.F) {}\n")
	o, _ := fakeOrchestrator(fs)
	steps, err := o.Plan(".")
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
	steps, err := o.Plan(".")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	toolsSteps := map[string]bool{
		"download tool dependencies":  true,
		"verify tool dependencies":    true,
		"verify tool metadata":        true,
		"run lint":                    true,
		"run vulnerability analysis":  true,
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
	o.Execute = func(context.Context, string, string, ...string) error { return errors.New("boom") }
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
	o.Config.Toolchain.GoVersion = "go1.26.6"
	if err := o.verifyToolchain(context.Background(), "."); err != nil {
		t.Fatalf("verifyToolchain with go prefix: %v", err)
	}
	o.Config.Toolchain.GoVersion = "1.25.0"
	if err := o.verifyToolchain(context.Background(), "."); err == nil {
		t.Fatal("expected a toolchain mismatch error")
	}
	o.GoVersion = func(context.Context, string) (string, error) { return "", errors.New("boom") }
	o.Config.Toolchain.GoVersion = "1.26.6"
	if err := o.verifyToolchain(context.Background(), "."); err == nil {
		t.Fatal("expected the toolchain read error")
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
	output, err := runProcessOutput(context.Background(), ".", "go", "version")
	if err != nil {
		t.Fatalf("runProcessOutput: %v", err)
	}
	if !strings.Contains(string(output), "go version") {
		t.Fatalf("output = %q", output)
	}
	if err := runProcess(context.Background(), ".", "go", "version"); err != nil {
		t.Fatalf("runProcess: %v", err)
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
	steps, err := o.Plan(".")
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
	if err := o.Execute(context.Background(), ".", "go", "version"); err != nil {
		t.Fatalf("production Execute seam: %v", err)
	}
	if _, err := o.GoVersion(context.Background(), "."); err != nil {
		t.Fatalf("production GoVersion seam: %v", err)
	}
	// The tools-module probe runs against a real tree.
	if o.HasToolsMod(t.TempDir()) {
		t.Fatal("expected no tools module in an empty tree")
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
