package quality

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Step is one quality-gate command in the canonical plan. A step with a
// non-empty Expect is a fail-closed assertion: its combined output must carry
// the expected proof text. Env carries the enforced environment of a pack
// step; a nil Env inherits the process environment unchanged.
type Step struct {
	Name       string
	Dir        string
	Executable string
	Args       []string
	Env        []string
	Expect     string
	Timeout    time.Duration
}

// Orchestrator runs the canonical quality gate set for a tenant repository.
// It reads the schema-validated configuration seam, asserts the controlled
// toolchain, executes the canonical gates, resolves and provisions the
// declared capability packs, and applies convention discovery for command
// binaries and fuzz targets. It never mutates go.mod or go.sum.
type Orchestrator struct {
	Config   Config
	Discover Discoverer
	Coverage CoverageRunner
	// Execute runs a plan step without capturing its output.
	Execute func(ctx context.Context, dir, executable string, args []string, env []string) error
	// ExecuteOutput runs a plan step and returns its combined output; the
	// pack assertions consume it.
	ExecuteOutput func(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error)
	GoVersion     func(ctx context.Context, dir string) (string, error)
	Stdout        io.Writer
	Stderr        io.Writer
	// HasToolsMod reports whether the tenant carries a tools module.
	HasToolsMod func(root string) bool
	// GoFiles returns the repository's Go source files for the format gate.
	GoFiles func(root string) ([]string, error)
	// Packs is the capability-pack machinery: resolution, provisioning, and
	// the pack gate plan.
	Packs PackEngine
}

// NewOrchestrator binds the production seams of an Orchestrator.
func NewOrchestrator(config Config, stdout, stderr io.Writer) Orchestrator {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return Orchestrator{
		Config:   config,
		Discover: NewDiscoverer(),
		Coverage: NewCoverageRunner(stdout, stderr),
		Execute: func(ctx context.Context, dir, executable string, args []string, env []string) error {
			return runProcess(ctx, dir, executable, args, env)
		},
		ExecuteOutput: func(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error) {
			return runProcessOutput(ctx, dir, executable, args, env)
		},
		GoVersion: func(ctx context.Context, dir string) (string, error) {
			output, err := runProcessOutput(ctx, dir, "go", []string{"env", "GOVERSION"}, nil)
			return strings.TrimSpace(string(output)), err
		},
		Stdout: stdout,
		Stderr: stderr,
		HasToolsMod: func(root string) bool {
			_, err := os.Stat(filepath.Join(root, "tools", "go.mod"))
			return err == nil
		},
		GoFiles: GoSourceFiles,
		Packs:   NewPackEngine(stdout, stderr),
	}
}

// Plan builds the canonical quality-gate plan for a tenant repository. The
// plan is deterministic: identical configuration, registry stand, and
// discovery produce an identical step list. The composition order is fixed:
// the core gates, then the pack gates, then the project gates.
func (o Orchestrator) Plan(ctx context.Context, root string) ([]Step, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("a repository root is required for the quality gate")
	}
	// A declared pack is resolved against the registry union at the pinned
	// stand; an unknown reference is a fail-closed finding, never a silent
	// skip.
	var packs []ResolvedPack
	if len(o.Config.Extends) > 0 {
		resolved, err := o.Packs.Resolve(ctx, root, o.Config.Extends)
		if err != nil {
			return nil, err
		}
		packs = resolved
	}
	binaries, err := o.Discover.DiscoverBinaries(root)
	if err != nil {
		return nil, fmt.Errorf("discover command binaries: %w", err)
	}
	fuzzTargets, err := o.Discover.DiscoverFuzzTargets(root)
	if err != nil {
		return nil, fmt.Errorf("discover fuzz targets: %w", err)
	}
	goFiles, err := o.GoFiles(root)
	if err != nil {
		return nil, fmt.Errorf("list Go sources: %w", err)
	}
	packSteps, err := o.Packs.Steps(root, packs)
	if err != nil {
		return nil, err
	}

	steps := make([]Step, 0, 16)
	steps = append(steps, Step{
		Name: "verify controlled toolchain", Executable: "go", Args: []string{"env", "GOVERSION"},
	})
	steps = append(steps, moduleVerificationSteps(o.HasToolsMod(root))...)
	steps = append(steps, Step{
		Name: "check Go formatting", Executable: "gofmt", Args: append([]string{"-l"}, goFiles...),
	})
	steps = append(steps, canonicalAnalysisSteps(o.HasToolsMod(root))...)
	steps = append(steps, packSteps...)
	steps = append(steps, o.binarySteps(binaries)...)
	steps = append(steps, o.fuzzSteps(fuzzTargets)...)
	return steps, nil
}

// Provision resolves the declared capability packs and executes their
// recipes. A tenant without declarations provisions nothing.
func (o Orchestrator) Provision(ctx context.Context, root string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(o.Config.Extends) == 0 {
		fmt.Fprintln(o.Stdout, "No capability packs declared.")
		return nil
	}
	packs, err := o.Packs.Resolve(ctx, root, o.Config.Extends)
	if err != nil {
		return err
	}
	return o.Packs.Provision(ctx, packs)
}

// Run builds and executes the plan, failing closed on the first gate error.
func (o Orchestrator) Run(ctx context.Context, root string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	steps, err := o.Plan(ctx, root)
	if err != nil {
		return err
	}
	for _, step := range steps {
		if err := o.runStep(ctx, root, step); err != nil {
			return err
		}
	}
	// The coverage gate runs in-process: this home owns both the orchestrator
	// and the coverage measurement, so the evidence base is one toolchain.
	if err := o.Coverage.Check(ctx, root); err != nil {
		return err
	}
	fmt.Fprintln(o.Stdout, "Quality gate passed.")
	return nil
}

// runStep executes one plan step with its timeout and working directory.
func (o Orchestrator) runStep(ctx context.Context, root string, step Step) error {
	fmt.Fprintln(o.Stdout, "==>", step.Name)
	dir := root
	if step.Dir != "" {
		dir = filepath.Join(root, step.Dir)
	}
	timeout := step.Timeout
	if timeout <= 0 {
		timeout, _ = GateTimeout("")
	}
	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if step.Name == "verify controlled toolchain" {
		return o.verifyToolchain(stepCtx, dir)
	}
	if step.Expect != "" {
		output, err := o.ExecuteOutput(stepCtx, dir, step.Executable, step.Args, step.Env)
		if err != nil {
			return fmt.Errorf("%s: %w", step.Name, err)
		}
		if !strings.Contains(string(output), step.Expect) {
			return fmt.Errorf("%s: the assertion requires the output to carry %q", step.Name, step.Expect)
		}
		return nil
	}
	if err := o.Execute(stepCtx, dir, step.Executable, step.Args, step.Env); err != nil {
		return fmt.Errorf("%s: %w", step.Name, err)
	}
	return nil
}

// verifyToolchain asserts that the running toolchain matches the pinned
// language-keyed configuration identity.
func (o Orchestrator) verifyToolchain(ctx context.Context, dir string) error {
	if o.Config.Toolchain.Language != "go" {
		return fmt.Errorf("the Go territory orchestrator cannot assert the %q toolchain", o.Config.Toolchain.Language)
	}
	version, err := o.GoVersion(ctx, dir)
	if err != nil {
		return fmt.Errorf("read the controlled toolchain: %w", err)
	}
	if strings.TrimPrefix(version, "go") != o.Config.Toolchain.Version {
		return fmt.Errorf("controlled toolchain mismatch: running %s, pinned go%s", version, o.Config.Toolchain.Version)
	}
	return nil
}

// binarySteps builds and smoke-tests every discovered or configured binary.
func (o Orchestrator) binarySteps(binaries []Binary) []Step {
	resolved := o.resolveBinaries(binaries)
	steps := make([]Step, 0, len(resolved)*2)
	for _, binary := range resolved {
		name := filepath.Base(binary.Package)
		artifact := binaryArtifact(runtime.GOOS, name)
		steps = append(steps, Step{
			Name:       "build " + name,
			Executable: "go",
			Args:       []string{"build", "-mod=readonly", "-trimpath", "-o", artifact, binary.Package},
		})
		smoke := binary.Smoke
		if len(smoke) == 0 {
			smoke = DefaultSmokeArguments
		}
		steps = append(steps, Step{
			Name:       "smoke test " + name,
			Executable: artifact,
			Args:       smoke,
		})
	}
	return steps
}

// resolveBinaries merges discovered binaries with the configured overrides.
func (o Orchestrator) resolveBinaries(discovered []Binary) []Binary {
	merged := make([]Binary, 0, len(discovered)+len(o.Config.Project.Binaries))
	byPackage := make(map[string]Binary, len(discovered)+len(o.Config.Project.Binaries))
	for _, binary := range discovered {
		byPackage[binary.Package] = binary
	}
	for _, override := range o.Config.Project.Binaries {
		byPackage[override.Package] = override
	}
	for _, binary := range byPackage {
		merged = append(merged, binary)
	}
	// The plan is deterministic: the merged set is sorted by package path.
	sort.Slice(merged, func(i, j int) bool { return merged[i].Package < merged[j].Package })
	return merged
}

// binaryArtifact returns the OS-aware build artifact path for a binary: on
// Windows the executable carries the .exe extension. The platform is a
// parameter so both branches stay whitebox-testable.
func binaryArtifact(goos, name string) string {
	if goos == "windows" {
		name += ".exe"
	}
	return filepath.Join(".build", "bin", name)
}

// fuzzSteps runs every discovered or configured fuzz target.
func (o Orchestrator) fuzzSteps(targets []FuzzTarget) []Step {
	resolved := o.resolveFuzzTargets(targets)
	steps := make([]Step, 0, len(resolved))
	for _, target := range resolved {
		budget := target.Time
		if budget == "" {
			budget = DefaultFuzzTime
		}
		steps = append(steps, Step{
			Name:       "fuzz " + target.Target,
			Executable: "go",
			Args:       []string{"test", "-mod=readonly", target.Package, "-run=^$", "-fuzz=" + target.Target, "-fuzztime=" + budget, "-parallel=1"},
		})
	}
	return steps
}

// resolveFuzzTargets merges discovered fuzz targets with the configured
// overrides.
func (o Orchestrator) resolveFuzzTargets(discovered []FuzzTarget) []FuzzTarget {
	merged := make([]FuzzTarget, 0, len(discovered)+len(o.Config.Project.Fuzz))
	byKey := make(map[string]FuzzTarget, len(discovered)+len(o.Config.Project.Fuzz))
	for _, target := range discovered {
		byKey[target.Package+"|"+target.Target] = target
	}
	for _, override := range o.Config.Project.Fuzz {
		byKey[override.Package+"|"+override.Target] = override
	}
	for _, target := range byKey {
		merged = append(merged, target)
	}
	// The plan is deterministic: the merged set is sorted by package and target.
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Package != merged[j].Package {
			return merged[i].Package < merged[j].Package
		}
		return merged[i].Target < merged[j].Target
	})
	return merged
}

// moduleVerificationSteps verifies the module graph and the tools module.
func moduleVerificationSteps(hasTools bool) []Step {
	steps := []Step{
		{Name: "download module dependencies", Executable: "go", Args: []string{"mod", "download"}},
		{Name: "verify module dependencies", Executable: "go", Args: []string{"mod", "verify"}},
		{Name: "verify module metadata", Executable: "go", Args: []string{"mod", "tidy", "-diff"}},
	}
	if hasTools {
		steps = append(steps,
			Step{Name: "download tool dependencies", Executable: "go", Args: []string{"-C", "tools", "mod", "download"}},
			Step{Name: "verify tool dependencies", Executable: "go", Args: []string{"-C", "tools", "mod", "verify"}},
			Step{Name: "verify tool metadata", Executable: "go", Args: []string{"-C", "tools", "mod", "tidy", "-diff"}},
		)
	}
	return steps
}

// canonicalAnalysisSteps is the fleet-identical analysis set.
func canonicalAnalysisSteps(hasTools bool) []Step {
	steps := []Step{
		{Name: "typecheck packages and tests", Executable: "go", Args: []string{"test", "-mod=readonly", "-run=^$", "./..."}},
		{Name: "run unit, contract, and integration tests", Executable: "go", Args: []string{"test", "-mod=readonly", "./..."}},
		{Name: "run race detector", Executable: "go", Args: []string{"test", "-mod=readonly", "-race", "./..."}},
		{Name: "run static analysis", Executable: "go", Args: []string{"vet", "./..."}},
	}
	if hasTools {
		steps = append(steps,
			Step{Name: "run lint", Executable: "go", Args: []string{"tool", "-modfile", "tools/go.mod", "staticcheck", "./..."}},
			Step{Name: "run vulnerability analysis", Executable: "go", Args: []string{"tool", "-modfile", "tools/go.mod", "govulncheck", "./..."}},
			Step{Name: "validate Lefthook configuration", Executable: "go", Args: []string{"tool", "-modfile", "tools/go.mod", "lefthook", "validate"}},
		)
	}
	return steps
}

// GoSourceFiles returns the repository's Go source files in deterministic
// order for the format gate.
func GoSourceFiles(root string) ([]string, error) {
	return goSourceFiles(root, filepath.WalkDir)
}

// goSourceFiles walks the tree over an injected seam so the error path is
// whitebox-testable.
func goSourceFiles(root string, walk func(string, fs.WalkDirFunc) error) ([]string, error) {
	files := make([]string, 0)
	err := walk(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if ignoredDiscoveryDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// runProcess executes a command, streaming its output to the process stderr.
func runProcess(ctx context.Context, dir, executable string, args []string, env []string) error {
	_, err := runProcessOutput(ctx, dir, executable, args, env)
	return err
}

// runProcessOutput executes a command and returns its combined output. A
// non-empty env extends the process environment (the pack's enforced
// environment); a nil env inherits it unchanged.
func runProcessOutput(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = dir
	if len(env) > 0 {
		command.Env = append(os.Environ(), env...)
	}
	return command.CombinedOutput()
}
