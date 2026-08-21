package quality

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DefaultSmokeArguments is the convention smoke invocation for a discovered
// command binary; a tenant overrides it per binary through the project block.
var DefaultSmokeArguments = []string{"--version"}

// DefaultFuzzTime is the convention execution budget for a discovered fuzz
// target; a tenant overrides it per target through the project block.
const DefaultFuzzTime = "50000x"

// fuzzFuncPattern matches a Fuzz function declaration at the start of a line.
var fuzzFuncPattern = regexp.MustCompile(`(?m)^func\s+(Fuzz[A-Za-z0-9_]*)\s*\(`)

// Discoverer finds convention-placed command binaries and fuzz targets. The
// filesystem seams are injected so the discovery rules are whitebox-testable
// without a real tree.
type Discoverer struct {
	ReadDir  func(string) ([]os.DirEntry, error)
	ReadFile func(string) ([]byte, error)
	Walk     func(string, fs.WalkDirFunc) error
}

// NewDiscoverer returns a Discoverer bound to the real filesystem.
func NewDiscoverer() Discoverer {
	return Discoverer{
		ReadDir:  os.ReadDir,
		ReadFile: os.ReadFile,
		Walk:     filepath.WalkDir,
	}
}

// DiscoverBinaries returns every ./cmd/<name> package that declares a main
// package, as a smoke-testable binary. A repository without a cmd directory
// has no binaries; that is a valid empty result, never an error.
func (d Discoverer) DiscoverBinaries(root string) ([]Binary, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("a repository root is required for binary discovery")
	}
	entries, err := d.ReadDir(filepath.Join(root, "cmd"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	binaries := make([]Binary, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		hasMain, err := d.dirDeclaresMain(filepath.Join(root, "cmd", entry.Name()))
		if err != nil {
			return nil, err
		}
		if hasMain {
			binaries = append(binaries, Binary{Package: "./cmd/" + entry.Name()})
		}
	}
	sort.Slice(binaries, func(i, j int) bool { return binaries[i].Package < binaries[j].Package })
	return binaries, nil
}

// dirDeclaresMain reports whether a directory holds at least one .go file that
// declares package main.
func (d Discoverer) dirDeclaresMain(dir string) (bool, error) {
	entries, err := d.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		contents, err := d.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return false, err
		}
		if declaresMainPackage(contents) {
			return true, nil
		}
	}
	return false, nil
}

// declaresMainPackage reports whether Go source declares package main.
func declaresMainPackage(contents []byte) bool {
	for _, line := range strings.Split(strings.ReplaceAll(string(contents), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "package main" {
			return true
		}
	}
	return false
}

// DiscoverFuzzTargets returns every Fuzz function declared in a *_test.go file
// with its repository-relative package path. Test-only and cache trees are
// excluded by convention.
func (d Discoverer) DiscoverFuzzTargets(root string) ([]FuzzTarget, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("a repository root is required for fuzz discovery")
	}
	targets := make([]FuzzTarget, 0)
	err := d.Walk(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if ignoredDiscoveryDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		contents, err := d.ReadFile(path)
		if err != nil {
			return err
		}
		pkg := "./" + filepath.ToSlash(relPath(root, path))
		for _, match := range fuzzFuncPattern.FindAllStringSubmatch(string(contents), -1) {
			targets = append(targets, FuzzTarget{Package: pkg, Target: match[1]})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Package != targets[j].Package {
			return targets[i].Package < targets[j].Package
		}
		return targets[i].Target < targets[j].Target
	})
	return targets, nil
}

// relPath returns the repository-relative directory of a file path.
func relPath(root, path string) string {
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return filepath.Dir(path)
	}
	return rel
}

// ignoredDiscoveryDirectory excludes trees that never carry production fuzz
// targets.
func ignoredDiscoveryDirectory(name string) bool {
	switch name {
	case ".build", ".git", ".cache", "coverage", "dist", "vendor":
		return true
	default:
		return false
	}
}
