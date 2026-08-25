package quality

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeFileInfo is a minimal os.FileInfo for the pack tool cache presence
// checks.
type fakeFileInfo struct{ name string }

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// stat extends the virtual filesystem with the presence probe the pack tool
// cache checks use.
func (fs *virtualFS) stat(path string) (os.FileInfo, error) {
	clean := filepath.Clean(path)
	if _, found := fs.files[clean]; found {
		return fakeFileInfo{name: filepath.Base(clean)}, nil
	}
	if _, found := fs.dirs[clean]; found {
		return fakeFileInfo{name: filepath.Base(clean)}, nil
	}
	return nil, os.ErrNotExist
}

// fakePackEngine binds the pack engine to the virtual filesystem and to
// inert process and network seams; tests override the seams they exercise.
func fakePackEngine(fs *virtualFS) PackEngine {
	return PackEngine{
		ExecuteOutput: func(context.Context, string, string, []string, []string) ([]byte, error) {
			return nil, errors.New("the fake pack engine executes no process")
		},
		ReadFile:  fs.readFile,
		ReadDir:   fs.readDir,
		Stat:      fs.stat,
		Walk:      fs.walk,
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		Chmod:     func(string, os.FileMode) error { return nil },
		TempDir:   func(string) (string, error) { return "staging", nil },
		RemoveAll: func(string) error { return nil },
		Fetch: func(context.Context, string, int64) ([]byte, error) {
			return nil, errors.New("the fake pack engine downloads nothing")
		},
		UserCacheDir: func() (string, error) { return "cache", nil },
		HasToolsMod:  func(string) bool { return true },
		GOOS:         "linux",
		GOARCH:       "amd64",
		Stdout:       io.Discard,
		Stderr:       io.Discard,
	}
}

// testPackDescriptor returns a valid opentofu pack descriptor; the artifact
// digest is a placeholder that the provisioning tests replace with the real
// digest of their fixture archive.
func testPackDescriptor() PackDescriptor {
	return PackDescriptor{
		Schema:     PackSchemaID,
		Capability: "opentofu",
		Area:       "infrastructure",
		Version:    1,
		Summary:    "OpenTofu infrastructure gates.",
		Provisioning: PackProvisioning{
			Kind:        PackProvisioningRecipe,
			Tool:        "tofu",
			Version:     "1.12.5",
			Environment: map[string]string{"TF_IN_AUTOMATION": "true", "OPENTOFU_ENFORCE_GPG_VALIDATION": "true"},
			Artifacts: map[string]PackArtifact{
				"linux-amd64": {
					URL:       "https://github.com/opentofu/opentofu/releases/download/v1.12.5/tofu_1.12.5_linux_amd64.zip",
					SHA256:    strings.Repeat("a", 64),
					Signature: "https://github.com/opentofu/opentofu/releases/download/v1.12.5/tofu_1.12.5_linux_amd64.zip.sig",
				},
			},
		},
		Discovery: PackDiscovery{
			Roots:       PackRoots{FileGlob: "**/*.tf"},
			ExcludeDirs: []string{".terraform"},
		},
		Assertions: []PackAssertion{
			{Name: "opentofu-version", Command: "tofu", Args: []string{"version"}, Expect: "OpenTofu v1.12.5"},
		},
		Gates: []PackGate{
			{Name: "opentofu-fmt-check", Command: "tofu", Args: []string{"fmt", "-check", "-recursive"}, Scope: PackScopeRepository},
			{Name: "opentofu-validate", Command: "tofu", Args: []string{"validate", "-no-color"}, Scope: PackScopePerRoot, Timeout: "5m"},
		},
	}
}

// testResolvedPack returns the resolved form of the test descriptor.
func testResolvedPack() ResolvedPack {
	return ResolvedPack{Reference: "opentofu@1", Registry: territoryHomeModule, Descriptor: testPackDescriptor()}
}

// bindWorkingTreeRegistry makes the tenant the territory home and carries the
// pack in its working-tree registry.
func bindWorkingTreeRegistry(fs *virtualFS) {
	fs.addFile("go.mod", "module "+territoryHomeModule+"\n")
	fs.addFile("capabilities/infrastructure/opentofu/v1/pack.json", validPackJSON())
}

// provisionPack marks the pack's tool as present in the pack tool cache of
// the fake engine.
func provisionPack(t *testing.T, o *Orchestrator, fs *virtualFS, pack ResolvedPack) {
	t.Helper()
	o.Config.Extends = []string{pack.Reference}
	bindWorkingTreeRegistry(fs)
	toolPath, err := o.Packs.ToolPath(pack)
	if err != nil {
		t.Fatalf("ToolPath: %v", err)
	}
	o.Packs.Stat = func(path string) (os.FileInfo, error) {
		if path == toolPath {
			return fakeFileInfo{name: filepath.Base(path)}, nil
		}
		return nil, os.ErrNotExist
	}
}

// moduleChannel returns an ExecuteOutput seam that resolves the given modules
// to the given directories through the tooling channel.
func moduleChannel(modules map[string]string) func(context.Context, string, string, []string, []string) ([]byte, error) {
	return func(_ context.Context, _ string, _ string, args []string, _ []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if module, found := strings.CutPrefix(joined, "mod download "); found {
			if _, ok := modules[module]; ok {
				return nil, nil
			}
			return nil, fmt.Errorf("module %s is not pinned", module)
		}
		if module, found := strings.CutPrefix(joined, "list -m -f {{.Dir}} "); found {
			if dir, ok := modules[module]; ok {
				return []byte(dir + "\n"), nil
			}
			return nil, fmt.Errorf("module %s is not pinned", module)
		}
		return nil, errors.New("unexpected process invocation")
	}
}

func TestPackEngineResolveEmpty(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		t.Fatal("a tenant without declarations must not touch the registry channel")
		return nil, nil
	}
	packs, err := e.Resolve(context.Background(), ".", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(packs) != 0 {
		t.Fatalf("packs = %+v", packs)
	}
}

func TestPackEngineResolveEmptyRoot(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	if _, err := e.Resolve(context.Background(), " ", []string{"opentofu@1"}); err == nil {
		t.Fatal("expected the empty-root error")
	}
}

func TestPackEngineResolveWorkingTree(t *testing.T) {
	fs := newVirtualFS()
	bindWorkingTreeRegistry(fs)
	e := fakePackEngine(fs)
	packs, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("packs = %+v", packs)
	}
	if packs[0].Registry != territoryHomeModule {
		t.Fatalf("registry = %q, want the working tree of the territory home", packs[0].Registry)
	}
	if packs[0].Descriptor.Capability != "opentofu" || packs[0].Descriptor.Version != 1 {
		t.Fatalf("descriptor = %+v", packs[0].Descriptor)
	}
}

func TestPackEngineResolveThroughToolingChannel(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSON())
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannel(map[string]string{
		sharedKernelModule:  "scg",
		territoryHomeModule: "gqa",
	})
	packs, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(packs) != 1 || packs[0].Registry != sharedKernelModule {
		t.Fatalf("packs = %+v", packs)
	}
}

func TestPackEngineResolveUnknown(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannel(map[string]string{
		sharedKernelModule:  "scg",
		territoryHomeModule: "gqa",
	})
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the unknown-reference finding")
	}
	if !strings.Contains(err.Error(), "unknown") || !strings.Contains(err.Error(), sharedKernelModule) {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineResolveUnavailableSharedKernel(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	e := fakePackEngine(fs)
	// The shared kernel is not pinned; the territory registry resolves empty.
	e.ExecuteOutput = moduleChannel(map[string]string{territoryHomeModule: "gqa"})
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the unknown-reference finding")
	}
	if !strings.Contains(err.Error(), "unavailable") || !strings.Contains(err.Error(), sharedKernelModule) {
		t.Fatalf("error = %q, want the unavailable shared kernel named", err)
	}
}

func TestPackEngineResolveAmbiguous(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSON())
	fs.addFile("gqa/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSON())
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannel(map[string]string{
		sharedKernelModule:  "scg",
		territoryHomeModule: "gqa",
	})
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the ambiguity finding")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineResolveNoToolsModule(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	e := fakePackEngine(fs)
	e.HasToolsMod = func(string) bool { return false }
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the tools-module finding")
	}
	if !strings.Contains(err.Error(), "tools/go.mod") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineResolveInvalidDescriptor(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module "+territoryHomeModule+"\n")
	fs.addFile("capabilities/infrastructure/opentofu/v1/pack.json", "{")
	e := fakePackEngine(fs)
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the invalid-descriptor finding")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineResolveIdentityMismatch(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module "+territoryHomeModule+"\n")
	// The descriptor carries area infrastructure but lives under wrongarea.
	fs.addFile("capabilities/wrongarea/opentofu/v1/pack.json", validPackJSON())
	e := fakePackEngine(fs)
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the identity-mismatch finding")
	}
	if !strings.Contains(err.Error(), "does not match its registry location") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineResolveRegistryReadError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module "+territoryHomeModule+"\n")
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannel(map[string]string{sharedKernelModule: "scg"})
	e.ReadDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("boom") }
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the registry read error")
	}
	if !strings.Contains(err.Error(), "read the registry") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineResolveDescriptorReadError(t *testing.T) {
	fs := newVirtualFS()
	bindWorkingTreeRegistry(fs)
	e := fakePackEngine(fs)
	e.ReadFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "pack.json") {
			return nil, errors.New("boom")
		}
		return fs.readFile(path)
	}
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the descriptor read error")
	}
	if !strings.Contains(err.Error(), "read the pack descriptor") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineResolveModuleIdentityError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	e := fakePackEngine(fs)
	e.ReadFile = func(string) ([]byte, error) { return nil, errors.New("boom") }
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the module identity error")
	}
	if !strings.Contains(err.Error(), "module declaration") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineResolveWithoutGoMod(t *testing.T) {
	// A repository without a go.mod is not a home; both registries resolve
	// through the tooling channel.
	fs := newVirtualFS()
	fs.addFile("scg/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSON())
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannel(map[string]string{
		sharedKernelModule:  "scg",
		territoryHomeModule: "gqa",
	})
	packs, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(packs) != 1 || packs[0].Registry != sharedKernelModule {
		t.Fatalf("packs = %+v", packs)
	}
}

func TestPackEngineResolveModuleDir(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.ExecuteOutput = func(_ context.Context, _ string, _ string, args []string, _ []string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "mod download example.com/m":
			return nil, nil
		case "list -m -f {{.Dir}} example.com/m":
			return []byte("dir\n"), nil
		default:
			return nil, errors.New("unexpected")
		}
	}
	dir, err := e.resolveModuleDir(context.Background(), ".", "example.com/m")
	if err != nil {
		t.Fatalf("resolveModuleDir: %v", err)
	}
	if dir != "dir" {
		t.Fatalf("dir = %q", dir)
	}
	e.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return nil, errors.New("boom")
	}
	if _, err := e.resolveModuleDir(context.Background(), ".", "example.com/m"); err == nil {
		t.Fatal("expected the download error")
	}
	e.ExecuteOutput = func(_ context.Context, _ string, _ string, args []string, _ []string) ([]byte, error) {
		if strings.Join(args, " ") == "mod download example.com/m" {
			return nil, nil
		}
		return nil, errors.New("boom")
	}
	if _, err := e.resolveModuleDir(context.Background(), ".", "example.com/m"); err == nil {
		t.Fatal("expected the list error")
	}
	e.ExecuteOutput = func(_ context.Context, _ string, _ string, args []string, _ []string) ([]byte, error) {
		if strings.Join(args, " ") == "mod download example.com/m" {
			return nil, nil
		}
		return []byte("\n"), nil
	}
	if _, err := e.resolveModuleDir(context.Background(), ".", "example.com/m"); err == nil {
		t.Fatal("expected the empty-directory error")
	}
}

func TestSplitPackReference(t *testing.T) {
	capability, major := splitPackReference("opentofu@1")
	if capability != "opentofu" || major != 1 {
		t.Fatalf("capability = %q, major = %d", capability, major)
	}
}

func TestPackEngineDiscoverRoots(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("main.tf", "resource {}\n")
	fs.addFile("stacks/a/main.tf", "resource {}\n")
	fs.addFile("stacks/b/sub/x.tf", "resource {}\n")
	fs.addFile(".terraform/ignored.tf", "resource {}\n")
	fs.addFile("docs/readme.md", "# docs\n")
	e := fakePackEngine(fs)
	roots, err := e.DiscoverRoots(".", PackDiscovery{
		Roots:       PackRoots{FileGlob: "**/*.tf"},
		ExcludeDirs: []string{".terraform"},
	})
	if err != nil {
		t.Fatalf("DiscoverRoots: %v", err)
	}
	want := []string{".", "stacks/a", "stacks/b/sub"}
	if strings.Join(roots, ",") != strings.Join(want, ",") {
		t.Fatalf("roots = %+v, want %+v", roots, want)
	}
}

func TestPackEngineDiscoverRootsMalformedGlob(t *testing.T) {
	fs := newVirtualFS()
	// A matching candidate forces the glob evaluation against the malformed
	// pattern.
	fs.addFile("main.tf", "resource {}\n")
	e := fakePackEngine(fs)
	_, err := e.DiscoverRoots(".", PackDiscovery{Roots: PackRoots{FileGlob: "**/*.t[f"}})
	if err == nil {
		t.Fatal("expected the malformed-glob error")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineDiscoverRootsWalkError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.Walk = func(string, fs.WalkDirFunc) error { return errors.New("boom") }
	if _, err := e.DiscoverRoots(".", PackDiscovery{Roots: PackRoots{FileGlob: "**/*.tf"}}); err == nil {
		t.Fatal("expected the walk error")
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"**/*.tf", "main.tf", true},
		{"**/*.tf", "a/main.tf", true},
		{"**/*.tf", "a/b/main.tf", true},
		{"**/*.tf", "main.go", false},
		{"**/*.tf", "a/b/readme.md", false},
		{"*.tf", "main.tf", true},
		{"*.tf", "a/main.tf", false},
		{"stacks/*.tf", "stacks/main.tf", true},
		{"stacks/*.tf", "other/main.tf", false},
		{"**", "a/b/c", true},
		{"a/**/z.tf", "a/z.tf", true},
		{"a/**/z.tf", "a/b/z.tf", true},
		{"a/**/z.tf", "a/b/c/z.tf", true},
		{"a/**/z.tf", "a/b/c/x.tf", false},
		// A ** that is not a full path segment is a plain segment wildcard
		// (the documented globstar semantics): a** is equivalent to a*.
		{"a**/*.tf", "ab/main.tf", true},
		{"a**/*.tf", "ab/main.go", false},
	}
	for _, testCase := range cases {
		got, err := matchGlob(testCase.pattern, testCase.name)
		if err != nil {
			t.Fatalf("matchGlob(%q, %q): %v", testCase.pattern, testCase.name, err)
		}
		if got != testCase.want {
			t.Fatalf("matchGlob(%q, %q) = %v, want %v", testCase.pattern, testCase.name, got, testCase.want)
		}
	}
}

func TestMatchGlobMalformed(t *testing.T) {
	if _, err := matchGlob("**/*.t[f", "main.tf"); err == nil {
		t.Fatal("expected the malformed pattern to fail")
	}
}

func TestPackEngineToolPath(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	path, err := e.ToolPath(testResolvedPack())
	if err != nil {
		t.Fatalf("ToolPath: %v", err)
	}
	joined := filepath.ToSlash(path)
	if !strings.HasSuffix(joined, "go-quality-authority/packs/opentofu/v1/linux-amd64/tofu") {
		t.Fatalf("ToolPath = %q", joined)
	}
	e.GOOS = "windows"
	path, err = e.ToolPath(testResolvedPack())
	if err != nil {
		t.Fatalf("ToolPath windows: %v", err)
	}
	if !strings.HasSuffix(filepath.ToSlash(path), "windows-amd64/tofu.exe") {
		t.Fatalf("ToolPath windows = %q", path)
	}
	e.UserCacheDir = func() (string, error) { return "", errors.New("boom") }
	if _, err := e.ToolPath(testResolvedPack()); err == nil {
		t.Fatal("expected the cache-location error")
	}
}

func TestPackEngineSteps(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("stacks/a/main.tf", "resource {}\n")
	fs.addFile("stacks/b/main.tf", "resource {}\n")
	e := fakePackEngine(fs)
	pack := testResolvedPack()
	toolPath, err := e.ToolPath(pack)
	if err != nil {
		t.Fatalf("ToolPath: %v", err)
	}
	e.Stat = func(path string) (os.FileInfo, error) {
		if path == toolPath {
			return fakeFileInfo{name: filepath.Base(path)}, nil
		}
		return nil, os.ErrNotExist
	}
	steps, err := e.Steps(".", []ResolvedPack{pack})
	if err != nil {
		t.Fatalf("Steps: %v", err)
	}
	if len(steps) != 4 {
		t.Fatalf("steps = %+v", steps)
	}
	// The assertion precedes the gates; the per-root gate expands per root.
	if steps[0].Name != "opentofu-version" || steps[0].Expect != "OpenTofu v1.12.5" {
		t.Fatalf("assertion step = %+v", steps[0])
	}
	if steps[0].Executable != toolPath {
		t.Fatalf("the assertion must run the provisioned tool: %+v", steps[0])
	}
	wantEnv := []string{"OPENTOFU_ENFORCE_GPG_VALIDATION=true", "TF_IN_AUTOMATION=true"}
	if strings.Join(steps[0].Env, "|") != strings.Join(wantEnv, "|") {
		t.Fatalf("assertion env = %+v", steps[0].Env)
	}
	if steps[1].Name != "opentofu-fmt-check" || steps[1].Dir != "" {
		t.Fatalf("repository gate = %+v", steps[1])
	}
	if steps[2].Name != "opentofu-validate (stacks/a)" || steps[2].Dir != "stacks/a" {
		t.Fatalf("per-root gate = %+v", steps[2])
	}
	if steps[3].Name != "opentofu-validate (stacks/b)" || steps[3].Dir != "stacks/b" {
		t.Fatalf("per-root gate = %+v", steps[3])
	}
	if steps[3].Timeout <= 0 {
		t.Fatalf("the gate timeout must resolve: %+v", steps[3])
	}
}

func TestPackEngineStepsNotProvisioned(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	_, err := e.Steps(".", []ResolvedPack{testResolvedPack()})
	if err == nil {
		t.Fatal("expected the not-provisioned finding")
	}
	if !strings.Contains(err.Error(), "not provisioned") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineStepsToolPathError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.UserCacheDir = func() (string, error) { return "", errors.New("boom") }
	if _, err := e.Steps(".", []ResolvedPack{testResolvedPack()}); err == nil {
		t.Fatal("expected the tool-path error")
	}
}

func TestPackEngineStepsAssertionCommandMismatch(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	pack := testResolvedPack()
	pack.Descriptor.Assertions[0].Command = "other"
	provisionTool(t, &e, pack)
	_, err := e.Steps(".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the assertion command finding")
	}
	if !strings.Contains(err.Error(), "must be the provisioned tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineStepsGateCommandMismatch(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	pack := testResolvedPack()
	pack.Descriptor.Gates[0].Command = "other"
	provisionTool(t, &e, pack)
	_, err := e.Steps(".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the gate command finding")
	}
	if !strings.Contains(err.Error(), "must be the provisioned tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineStepsGateTimeoutInvalid(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	pack := testResolvedPack()
	pack.Descriptor.Gates[1].Timeout = "abc"
	provisionTool(t, &e, pack)
	_, err := e.Steps(".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the gate timeout finding")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineStepsDiscoverRootsError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	pack := testResolvedPack()
	provisionTool(t, &e, pack)
	e.Walk = func(string, fs.WalkDirFunc) error { return errors.New("boom") }
	if _, err := e.Steps(".", []ResolvedPack{pack}); err == nil {
		t.Fatal("expected the discovery error")
	}
}

func TestPackEngineStepsEmpty(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	steps, err := e.Steps(".", nil)
	if err != nil {
		t.Fatalf("Steps: %v", err)
	}
	if len(steps) != 0 {
		t.Fatalf("steps = %+v", steps)
	}
}

// provisionTool marks the pack's tool as present in the pack tool cache of
// the engine.
func provisionTool(t *testing.T, e *PackEngine, pack ResolvedPack) {
	t.Helper()
	toolPath, err := e.ToolPath(pack)
	if err != nil {
		t.Fatalf("ToolPath: %v", err)
	}
	e.Stat = func(path string) (os.FileInfo, error) {
		if path == toolPath {
			return fakeFileInfo{name: filepath.Base(path)}, nil
		}
		return nil, os.ErrNotExist
	}
}

func TestPackEnvironment(t *testing.T) {
	env := packEnvironment(map[string]string{"B": "2", "A": "1"})
	if strings.Join(env, ",") != "A=1,B=2" {
		t.Fatalf("env = %+v", env)
	}
}

func TestNewPackEngineBindsProductionSeams(t *testing.T) {
	e := NewPackEngine(nil, nil)
	if e.ExecuteOutput == nil || e.ReadFile == nil || e.ReadDir == nil || e.Stat == nil || e.Walk == nil ||
		e.MkdirAll == nil || e.WriteFile == nil || e.Chmod == nil || e.TempDir == nil || e.RemoveAll == nil ||
		e.Fetch == nil || e.UserCacheDir == nil || e.HasToolsMod == nil {
		t.Fatal("expected every production seam to be bound")
	}
	if e.GOOS == "" || e.GOARCH == "" {
		t.Fatal("expected the runner platform to be bound")
	}
	// The real filesystem seams operate against a real tree.
	dir := t.TempDir()
	if err := e.MkdirAll(filepath.Join(dir, "cmd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.WriteFile(filepath.Join(dir, "cmd", "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReadFile(filepath.Join(dir, "cmd", "x.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReadDir(filepath.Join(dir, "cmd")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Stat(filepath.Join(dir, "cmd", "x.txt")); err != nil {
		t.Fatal(err)
	}
	if err := e.Chmod(filepath.Join(dir, "cmd", "x.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	staging, err := e.TempDir("pack-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RemoveAll(staging); err != nil {
		t.Fatal(err)
	}
	if _, err := e.UserCacheDir(); err != nil {
		t.Fatal(err)
	}
	if e.HasToolsMod(dir) {
		t.Fatal("expected no tools module in an empty tree")
	}
	// The production process seam executes against the real toolchain.
	if _, err := e.ExecuteOutput(context.Background(), ".", "go", []string{"version"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPackEngineResolveSharedKernelWorkingTree(t *testing.T) {
	// The tenant is the shared kernel itself: its registry is the working tree.
	fs := newVirtualFS()
	fs.addFile("go.mod", "module "+sharedKernelModule+"\n")
	fs.addFile("capabilities/infrastructure/opentofu/v1/pack.json", validPackJSON())
	e := fakePackEngine(fs)
	packs, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(packs) != 1 || packs[0].Registry != sharedKernelModule {
		t.Fatalf("packs = %+v", packs)
	}
}

func TestPackEngineModuleIdentityNoModuleLine(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "go 1.26\n")
	e := fakePackEngine(fs)
	module, err := e.moduleIdentity(".")
	if err != nil {
		t.Fatalf("moduleIdentity: %v", err)
	}
	if module != "" {
		t.Fatalf("module = %q, want no home", module)
	}
}

func TestPackEngineResolveSkipsNonDirArea(t *testing.T) {
	fs := newVirtualFS()
	bindWorkingTreeRegistry(fs)
	// A file directly in the capabilities tree is not an area and is skipped.
	fs.addFile("capabilities/README.md", "# capabilities\n")
	e := fakePackEngine(fs)
	packs, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("packs = %+v", packs)
	}
}

func TestPackEngineResolveAreaWithoutPack(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module "+territoryHomeModule+"\n")
	// The area exists, but it carries only another capability.
	fs.addFile("capabilities/infrastructure/other/v1/pack.json", validPackJSON())
	e := fakePackEngine(fs)
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil {
		t.Fatal("expected the unknown-reference finding")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineDiscoverRootsWalkCallbackError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	// The walk surfaces the error through the callback, not the walk call.
	e.Walk = func(_ string, fn fs.WalkDirFunc) error {
		return fn("main.tf", fakeEntry{name: "main.tf"}, errors.New("walk boom"))
	}
	if _, err := e.DiscoverRoots(".", PackDiscovery{Roots: PackRoots{FileGlob: "**/*.tf"}}); err == nil {
		t.Fatal("expected the callback walk error")
	}
}

func TestPackEngineDiscoverRootsRelError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	// A file outside an absolute root cannot be related to it; the base comes
	// from the runtime, never from a hardcoded OS-specific path form.
	// Convention: docs/conventions/testing/portable-test-construction.md
	e.Walk = func(_ string, fn fs.WalkDirFunc) error {
		return fn("relative/main.tf", fakeEntry{name: "main.tf"}, nil)
	}
	if _, err := e.DiscoverRoots(t.TempDir(), PackDiscovery{Roots: PackRoots{FileGlob: "**/*.tf"}}); err == nil {
		t.Fatal("expected the rel error")
	}
}
