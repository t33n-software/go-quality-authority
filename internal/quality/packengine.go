package quality

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// The registry module identities: the territory home (this home) carries the
// language-bound packs, and the supply-chain-governance shared kernel carries
// the language-neutral packs and both schemas. A pack exists exactly once
// across the fleet; the orchestrator resolves a declared reference against the
// union of both registries.
const (
	territoryHomeModule = "github.com/t33n-software/go-quality-authority"
	sharedKernelModule  = "github.com/t33n-software/supply-chain-governance"
)

// ResolvedPack is a descriptor proven against a registry at the pinned stand.
type ResolvedPack struct {
	// Reference is the declared <capability>@<major> reference.
	Reference string
	// Registry is the owning module path or the working tree of a home.
	Registry   string
	Descriptor PackDescriptor
}

// PackEngine resolves, provisions, and plans capability packs. Every
// filesystem, process, and network surface is an injected seam, so the
// machinery is whitebox-testable without a warm cache, a network, or a real
// tree, and runs identically on a cold CI runner and on a warm workstation.
type PackEngine struct {
	// ExecuteOutput runs a process and returns its combined output.
	ExecuteOutput func(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error)
	// ReadFile, ReadDir, Stat, and Walk are the read seams of the filesystem.
	ReadFile func(string) ([]byte, error)
	ReadDir  func(string) ([]os.DirEntry, error)
	Stat     func(string) (os.FileInfo, error)
	Walk     func(string, fs.WalkDirFunc) error
	// MkdirAll, WriteFile, Chmod, TempDir, and RemoveAll are the write seams
	// of the provisioning recipe.
	MkdirAll  func(string, os.FileMode) error
	WriteFile func(string, []byte, os.FileMode) error
	Chmod     func(string, os.FileMode) error
	TempDir   func(pattern string) (string, error)
	RemoveAll func(string) error
	// Fetch downloads a bound artifact through the integrity channel.
	Fetch func(ctx context.Context, url string, maxBytes int64) ([]byte, error)
	// UserCacheDir locates the pack tool cache.
	UserCacheDir func() (string, error)
	// HasToolsMod reports whether the tenant carries a tools module.
	HasToolsMod func(root string) bool
	// MaxToolBytes is the decompression bound of a pack tool; zero binds the
	// canonical default. The bound is engine configuration so the fail-closed
	// overflow path is provable.
	MaxToolBytes int64
	// GOOS and GOARCH identify the runner platform.
	GOOS, GOARCH   string
	Stdout, Stderr io.Writer
}

// maxToolBytes resolves the decompression bound of a pack tool against the
// canonical default.
func (e PackEngine) maxToolBytes() int64 {
	if e.MaxToolBytes > 0 {
		return e.MaxToolBytes
	}
	return maxPackToolBytes
}

// NewPackEngine binds the production seams of a PackEngine.
func NewPackEngine(stdout, stderr io.Writer) PackEngine {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return PackEngine{
		ExecuteOutput: func(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error) {
			return runProcessOutput(ctx, dir, executable, args, env)
		},
		ReadFile:  os.ReadFile,
		ReadDir:   os.ReadDir,
		Stat:      os.Stat,
		Walk:      filepath.WalkDir,
		MkdirAll:  os.MkdirAll,
		WriteFile: os.WriteFile,
		Chmod:     os.Chmod,
		TempDir: func(pattern string) (string, error) {
			return os.MkdirTemp("", pattern)
		},
		RemoveAll:    os.RemoveAll,
		Fetch:        fetchURL,
		UserCacheDir: os.UserCacheDir,
		HasToolsMod: func(root string) bool {
			_, err := os.Stat(filepath.Join(root, "tools", "go.mod"))
			return err == nil
		},
		GOOS:   runtime.GOOS,
		GOARCH: runtime.GOARCH,
		Stdout: stdout,
		Stderr: stderr,
	}
}

// Resolve resolves every declared pack reference against the union of the
// territory registry and the shared-kernel registry at the pinned stand. The
// resolution has exactly three outcomes, never two: a declared and known
// reference is provisioned and executed, a declared but unknown reference is a
// fail-closed finding, and a tenant without declarations resolves nothing.
func (e PackEngine) Resolve(ctx context.Context, root string, references []string) ([]ResolvedPack, error) {
	if len(references) == 0 {
		return nil, nil
	}
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("a repository root is required for pack resolution")
	}
	search, err := e.registryTrees(ctx, root)
	if err != nil {
		return nil, err
	}
	resolved := make([]ResolvedPack, 0, len(references))
	for _, reference := range references {
		capability, major := splitPackReference(reference)
		pack, err := e.resolveOne(reference, capability, major, search)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, pack)
	}
	return resolved, nil
}

// registryTree is one resolved registry tree: the capabilities/ directory of
// an owning module or of a home's working tree.
type registryTree struct {
	owner string
	dir   string
}

// registrySearch carries the resolvable registry trees plus the owners whose
// registry could not be resolved, so an unknown-reference finding names both
// the searched and the unavailable registries.
type registrySearch struct {
	trees       []registryTree
	unavailable []string
}

// registryTrees locates the registry trees. A home resolves its own registry
// from the working tree; every other registry is resolved through the
// tenant's integrity-pinned tooling module. A registry that cannot be
// resolved is recorded as unavailable; only a reference found nowhere fails
// closed.
func (e PackEngine) registryTrees(ctx context.Context, root string) (registrySearch, error) {
	module, err := e.moduleIdentity(root)
	if err != nil {
		return registrySearch{}, err
	}
	search := registrySearch{}
	territoryViaTree := module == territoryHomeModule
	sharedViaTree := module == sharedKernelModule
	if territoryViaTree {
		search.trees = append(search.trees, registryTree{owner: territoryHomeModule, dir: filepath.Join(root, "capabilities")})
	}
	if sharedViaTree {
		search.trees = append(search.trees, registryTree{owner: sharedKernelModule, dir: filepath.Join(root, "capabilities")})
	}
	if !territoryViaTree || !sharedViaTree {
		if !e.HasToolsMod(root) {
			return search, errors.New("capability packs require the tenant's integrity-pinned tooling module (tools/go.mod): no tools module is present")
		}
	}
	if !territoryViaTree {
		dir, err := e.resolveModuleCapabilities(ctx, root, territoryHomeModule)
		if err != nil {
			search.unavailable = append(search.unavailable, territoryHomeModule+": "+err.Error())
		} else {
			search.trees = append(search.trees, registryTree{owner: territoryHomeModule, dir: dir})
		}
	}
	if !sharedViaTree {
		dir, err := e.resolveModuleCapabilities(ctx, root, sharedKernelModule)
		if err != nil {
			search.unavailable = append(search.unavailable, sharedKernelModule+": "+err.Error())
		} else {
			search.trees = append(search.trees, registryTree{owner: sharedKernelModule, dir: dir})
		}
	}
	return search, nil
}

// moduleIdentity reads the tenant's own module declaration; a repository
// without a go.mod or without a module line is not a home.
func (e PackEngine) moduleIdentity(root string) (string, error) {
	contents, err := e.ReadFile(filepath.Join(root, "go.mod"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read the repository module declaration: %w", err)
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(contents), "\r\n", "\n"), "\n") {
		if module, found := strings.CutPrefix(strings.TrimSpace(line), "module "); found {
			return strings.TrimSpace(module), nil
		}
	}
	return "", nil
}

// resolveModuleCapabilities resolves a registry module's capabilities
// directory through the tenant's tooling channel.
func (e PackEngine) resolveModuleCapabilities(ctx context.Context, root, module string) (string, error) {
	dir, err := e.resolveModuleDir(ctx, root, module)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "capabilities"), nil
}

// resolveModuleDir resolves a module's cache directory through the tenant's
// integrity-pinned tooling module. The resolution never trusts a warm module
// cache: it downloads the module through the pinned channel (tools/go.sum)
// before querying its directory, so the machinery runs identically in
// cold-cache environments such as CI lanes.
func (e PackEngine) resolveModuleDir(ctx context.Context, root, module string) (string, error) {
	toolsDir := filepath.Join(root, "tools")
	if output, err := e.ExecuteOutput(ctx, toolsDir, "go", []string{"mod", "download", module}, nil); err != nil {
		return "", fmt.Errorf("go mod download %s: %w (%s)", module, err, strings.TrimSpace(string(output)))
	}
	output, err := e.ExecuteOutput(ctx, toolsDir, "go", []string{"list", "-m", "-f", "{{.Dir}}", module}, nil)
	if err != nil {
		return "", fmt.Errorf("go list -m %s: %w (%s)", module, err, strings.TrimSpace(string(output)))
	}
	resolved := strings.TrimSpace(string(output))
	if resolved == "" {
		return "", fmt.Errorf("go list -m %s returned no directory", module)
	}
	return resolved, nil
}

// resolveOne resolves one reference against every registry tree: exactly one
// match resolves, no match is a fail-closed unknown finding, and more than one
// match is a fail-closed ambiguity finding (a pack exists exactly once).
func (e PackEngine) resolveOne(reference, capability string, major int, search registrySearch) (ResolvedPack, error) {
	var matches []ResolvedPack
	for _, tree := range search.trees {
		pack, found, err := e.lookupPack(tree, capability, major)
		if err != nil {
			return ResolvedPack{}, err
		}
		if found {
			matches = append(matches, pack)
		}
	}
	switch len(matches) {
	case 0:
		return ResolvedPack{}, fmt.Errorf("capability pack reference %q is unknown to the registries at the pinned stand%s", reference, search.describe())
	case 1:
		return matches[0], nil
	default:
		return ResolvedPack{}, fmt.Errorf("capability pack reference %q is ambiguous: it is carried by %d registries, but a pack exists exactly once", reference, len(matches))
	}
}

// describe renders the searched and unavailable registries for the
// unknown-reference finding.
func (s registrySearch) describe() string {
	searched := make([]string, 0, len(s.trees))
	for _, tree := range s.trees {
		searched = append(searched, tree.owner)
	}
	text := " (searched: " + strings.Join(searched, ", ") + ")"
	if len(s.unavailable) > 0 {
		text += " (unavailable: " + strings.Join(s.unavailable, "; ") + ")"
	}
	return text
}

// lookupPack finds the descriptor of one capability at one major version in
// one registry tree and proves its identity against the registry location.
func (e PackEngine) lookupPack(tree registryTree, capability string, major int) (ResolvedPack, bool, error) {
	areas, err := e.ReadDir(tree.dir)
	if errors.Is(err, os.ErrNotExist) {
		return ResolvedPack{}, false, nil
	}
	if err != nil {
		return ResolvedPack{}, false, fmt.Errorf("read the registry %s: %w", tree.owner, err)
	}
	for _, area := range areas {
		if !area.IsDir() {
			continue
		}
		candidate := filepath.Join(tree.dir, area.Name(), capability, "v"+strconv.Itoa(major), "pack.json")
		contents, err := e.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ResolvedPack{}, false, fmt.Errorf("read the pack descriptor %s: %w", candidate, err)
		}
		descriptor, err := DecodePackDescriptor(contents)
		if err != nil {
			return ResolvedPack{}, false, fmt.Errorf("the pack descriptor %s is invalid: %w", candidate, err)
		}
		if descriptor.Capability != capability || descriptor.Version != major || descriptor.Area != area.Name() {
			return ResolvedPack{}, false, fmt.Errorf(
				"the pack descriptor %s identity %s/%s v%d does not match its registry location %s/%s v%d",
				candidate, descriptor.Area, descriptor.Capability, descriptor.Version, area.Name(), capability, major)
		}
		return ResolvedPack{
			Reference:  capability + "@" + strconv.Itoa(major),
			Registry:   tree.owner,
			Descriptor: descriptor,
		}, true, nil
	}
	return ResolvedPack{}, false, nil
}

// splitPackReference splits a validated <capability>@<major> reference. The
// grammar is proven by the configuration decoder, so the split never fails.
func splitPackReference(reference string) (string, int) {
	capability, rawMajor, _ := strings.Cut(reference, "@")
	major, _ := strconv.Atoi(rawMajor)
	return capability, major
}

// DiscoverRoots returns the sorted repository-relative per-root set of a
// pack: the parent directories of every file matching the discovery glob,
// with the excluded directory names skipped during the walk.
func (e PackEngine) DiscoverRoots(root string, discovery PackDiscovery) ([]string, error) {
	excluded := make(map[string]struct{}, len(discovery.ExcludeDirs))
	for _, name := range discovery.ExcludeDirs {
		excluded[name] = struct{}{}
	}
	roots := make(map[string]struct{})
	err := e.Walk(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if _, skip := excluded[entry.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		match, err := matchGlob(discovery.Roots.FileGlob, filepath.ToSlash(rel))
		if err != nil {
			return fmt.Errorf("the pack discovery glob %q is malformed: %w", discovery.Roots.FileGlob, err)
		}
		if match {
			roots[filepath.ToSlash(filepath.Dir(rel))] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	list := make([]string, 0, len(roots))
	for rootDir := range roots {
		list = append(list, rootDir)
	}
	sort.Strings(list)
	return list, nil
}

// matchGlob reports whether a repository-relative slash path matches the
// pack's discovery glob. The Go standard library carries no recursive
// wildcard: path.Match treats * as non-separator-crossing, so the recursive
// ** segment is handled here as the only grammar extension, and every other
// segment delegates to the standard library (correct by construction). A
// malformed pattern fails closed through the standard library's
// ErrBadPattern. The fleet's pack descriptors bind simple extension globs
// such as **/*.tf.
func matchGlob(pattern, name string) (bool, error) {
	return matchGlobSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

// matchGlobSegments matches path segments, treating a full ** segment as the
// recursive wildcard (zero or more segments) and delegating every other
// segment to path.Match.
func matchGlobSegments(pattern, name []string) (bool, error) {
	if len(pattern) == 0 {
		return len(name) == 0, nil
	}
	if pattern[0] == "**" {
		for skip := 0; skip <= len(name); skip++ {
			match, err := matchGlobSegments(pattern[1:], name[skip:])
			if err != nil {
				return false, err
			}
			if match {
				return true, nil
			}
		}
		return false, nil
	}
	if len(name) == 0 {
		return false, nil
	}
	match, err := path.Match(pattern[0], name[0])
	if err != nil || !match {
		return false, err
	}
	return matchGlobSegments(pattern[1:], name[1:])
}

// ToolPath returns the deterministic pack tool cache path of a resolved pack
// for the runner platform.
func (e PackEngine) ToolPath(pack ResolvedPack) (string, error) {
	cacheRoot, err := e.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate the pack tool cache: %w", err)
	}
	return filepath.Join(e.toolDirAt(cacheRoot, pack), e.toolExecutable(pack)), nil
}

// toolDirAt returns the deterministic pack tool cache directory of a resolved
// pack for the runner platform below the located cache root.
func (e PackEngine) toolDirAt(cacheRoot string, pack ResolvedPack) string {
	return filepath.Join(cacheRoot, "go-quality-authority", "packs",
		pack.Descriptor.Capability, "v"+strconv.Itoa(pack.Descriptor.Version), e.GOOS+"-"+e.GOARCH)
}

// toolExecutable returns the platform-aware executable name of the pack's
// tool.
func (e PackEngine) toolExecutable(pack ResolvedPack) string {
	tool := pack.Descriptor.Provisioning.Tool
	if e.GOOS == "windows" {
		tool += ".exe"
	}
	return tool
}

// Steps builds the deterministic pack gate plan: for every resolved pack in
// declaration order, the pack's assertions precede its gates; a repository
// gate runs once at the root, and a per-root gate runs once per discovered
// root. Every pack command must reference the provisioned tool, and a pack
// whose tool is not provisioned fails closed.
func (e PackEngine) Steps(root string, packs []ResolvedPack) ([]Step, error) {
	steps := make([]Step, 0)
	for _, pack := range packs {
		toolPath, err := e.ToolPath(pack)
		if err != nil {
			return nil, err
		}
		if _, err := e.Stat(toolPath); err != nil {
			return nil, fmt.Errorf("capability pack %q is not provisioned (%s); run `quality-gate provision`", pack.Reference, toolPath)
		}
		env := packEnvironment(pack.Descriptor.Provisioning.Environment)
		for _, assertion := range pack.Descriptor.Assertions {
			if assertion.Command != pack.Descriptor.Provisioning.Tool {
				return nil, fmt.Errorf("capability pack %q assertion %q command %q must be the provisioned tool %q",
					pack.Reference, assertion.Name, assertion.Command, pack.Descriptor.Provisioning.Tool)
			}
			steps = append(steps, Step{
				Name:       assertion.Name,
				Executable: toolPath,
				Args:       assertion.Args,
				Env:        env,
				Expect:     assertion.Expect,
			})
		}
		needsRoots := false
		for _, gate := range pack.Descriptor.Gates {
			if gate.Scope == PackScopePerRoot {
				needsRoots = true
			}
		}
		var roots []string
		if needsRoots {
			roots, err = e.DiscoverRoots(root, pack.Descriptor.Discovery)
			if err != nil {
				return nil, err
			}
		}
		for _, gate := range pack.Descriptor.Gates {
			if gate.Command != pack.Descriptor.Provisioning.Tool {
				return nil, fmt.Errorf("capability pack %q gate %q command %q must be the provisioned tool %q",
					pack.Reference, gate.Name, gate.Command, pack.Descriptor.Provisioning.Tool)
			}
			timeout, err := GateTimeout(gate.Timeout)
			if err != nil {
				return nil, fmt.Errorf("capability pack %q gate %q: %w", pack.Reference, gate.Name, err)
			}
			if gate.Scope == PackScopeRepository {
				steps = append(steps, Step{
					Name:       gate.Name,
					Executable: toolPath,
					Args:       gate.Args,
					Env:        env,
					Timeout:    timeout,
				})
				continue
			}
			for _, discovered := range roots {
				steps = append(steps, Step{
					Name:       gate.Name + " (" + discovered + ")",
					Dir:        discovered,
					Executable: toolPath,
					Args:       gate.Args,
					Env:        env,
					Timeout:    timeout,
				})
			}
		}
	}
	return steps, nil
}

// packEnvironment flattens the pack's enforced environment into a
// deterministic KEY=value list.
func packEnvironment(environment map[string]string) []string {
	env := make([]string, 0, len(environment))
	for name, value := range environment {
		env = append(env, name+"="+value)
	}
	sort.Strings(env)
	return env
}
