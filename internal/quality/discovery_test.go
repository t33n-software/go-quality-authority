package quality

import (
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

// fakeEntry is a minimal os.DirEntry for the discovery seams.
type fakeEntry struct {
	name  string
	isDir bool
}

func (e fakeEntry) Name() string               { return e.name }
func (e fakeEntry) IsDir() bool                { return e.isDir }
func (e fakeEntry) Type() os.FileMode          { return 0 }
func (e fakeEntry) Info() (os.FileInfo, error) { return nil, nil }

// treeWalker walks a virtual tree expressed as path->content for files and a
// set of directory paths.
type virtualFS struct {
	files map[string]string
	dirs  map[string][]os.DirEntry
}

func newVirtualFS() *virtualFS {
	// The root directory always exists so a walk over "." succeeds even when the
	// tree carries no files yet.
	return &virtualFS{files: map[string]string{}, dirs: map[string][]os.DirEntry{".": {}}}
}

func (fs *virtualFS) addFile(path, contents string) {
	clean := filepath.Clean(path)
	fs.files[clean] = contents
	dir := filepath.Dir(clean)
	name := filepath.Base(clean)
	fs.dirs[dir] = append(fs.dirs[dir], fakeEntry{name: name, isDir: false})
	fs.ensureDirs(dir)
}

func (fs *virtualFS) ensureDirs(dir string) {
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		name := filepath.Base(dir)
		found := false
		for _, entry := range fs.dirs[parent] {
			if entry.Name() == name && entry.IsDir() {
				found = true
				break
			}
		}
		if !found {
			fs.dirs[parent] = append(fs.dirs[parent], fakeEntry{name: name, isDir: true})
		}
		dir = parent
	}
}

func (fs *virtualFS) readDir(dir string) ([]os.DirEntry, error) {
	entries, found := fs.dirs[filepath.Clean(dir)]
	if !found {
		return nil, os.ErrNotExist
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func (fs *virtualFS) readFile(path string) ([]byte, error) {
	contents, found := fs.files[filepath.Clean(path)]
	if !found {
		return nil, os.ErrNotExist
	}
	return []byte(contents), nil
}

func (fs *virtualFS) walk(root string, fn iofs.WalkDirFunc) error {
	root = filepath.Clean(root)
	if _, found := fs.dirs[root]; !found {
		return os.ErrNotExist
	}
	underRoot := func(path string) bool {
		if root == "." {
			return true
		}
		return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
	}
	// deterministic pre-order walk over the recorded directories and files
	var paths []string
	for dir := range fs.dirs {
		if underRoot(dir) {
			paths = append(paths, dir)
		}
	}
	for file := range fs.files {
		if underRoot(file) {
			paths = append(paths, file)
		}
	}
	sort.Strings(paths)
	var skipPrefixes []string
	for _, path := range paths {
		skipped := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(path, prefix) {
				skipped = true
				break
			}
		}
		if skipped {
			continue
		}
		entry, _ := fs.entryFor(path)
		err := fn(path, entry, nil)
		if errors.Is(err, filepath.SkipDir) {
			skipPrefixes = append(skipPrefixes, path+string(filepath.Separator))
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (fs *virtualFS) entryFor(path string) (os.DirEntry, bool) {
	if _, isFile := fs.files[path]; isFile {
		return fakeEntry{name: filepath.Base(path), isDir: false}, false
	}
	return fakeEntry{name: filepath.Base(path), isDir: true}, true
}

func discovererFor(fs *virtualFS) Discoverer {
	return Discoverer{ReadDir: fs.readDir, ReadFile: fs.readFile, Walk: fs.walk}
}

func TestDiscoverBinaries(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/quality-gate/main.go", "package main\n")
	fs.addFile("cmd/check-coverage/main.go", "package main\r\n")
	fs.addFile("cmd/tools/doc.go", "package tools\n")
	fs.addFile("internal/quality/config.go", "package quality\n")
	binaries, err := discovererFor(fs).DiscoverBinaries(".")
	if err != nil {
		t.Fatalf("DiscoverBinaries: %v", err)
	}
	if len(binaries) != 2 {
		t.Fatalf("binaries = %+v", binaries)
	}
	if binaries[0].Package != "./cmd/check-coverage" || binaries[1].Package != "./cmd/quality-gate" {
		t.Fatalf("binaries not sorted: %+v", binaries)
	}
}

func TestDiscoverBinariesEmptyRoot(t *testing.T) {
	if _, err := NewDiscoverer().DiscoverBinaries(" "); err == nil {
		t.Fatal("expected an error for an empty root")
	}
}

func TestDiscoverBinariesNoCmdDir(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/x\n")
	binaries, err := discovererFor(fs).DiscoverBinaries(".")
	if err != nil {
		t.Fatalf("DiscoverBinaries without cmd: %v", err)
	}
	if len(binaries) != 0 {
		t.Fatalf("expected no binaries, got %+v", binaries)
	}
}

func TestDiscoverBinariesReadDirError(t *testing.T) {
	d := Discoverer{ReadDir: func(string) ([]os.DirEntry, error) { return nil, errors.New("boom") }}
	if _, err := d.DiscoverBinaries("."); err == nil {
		t.Fatal("expected the read-dir error")
	}
}

func TestDiscoverBinariesDirReadError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	d := Discoverer{
		ReadDir: func(dir string) ([]os.DirEntry, error) {
			if strings.HasSuffix(dir, "tool") {
				return nil, errors.New("boom")
			}
			return fs.readDir(dir)
		},
		ReadFile: fs.readFile,
	}
	if _, err := d.DiscoverBinaries("."); err == nil {
		t.Fatal("expected the nested read-dir error")
	}
}

func TestDiscoverBinariesFileReadError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	d := Discoverer{
		ReadDir:  fs.readDir,
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("boom") },
	}
	if _, err := d.DiscoverBinaries("."); err == nil {
		t.Fatal("expected the file read error")
	}
}

func TestDeclaresMainPackage(t *testing.T) {
	if !declaresMainPackage([]byte("package main\n")) {
		t.Fatal("expected package main to be detected")
	}
	if declaresMainPackage([]byte("package tools\n")) {
		t.Fatal("expected a non-main package to be rejected")
	}
	if !declaresMainPackage([]byte("// comment\npackage main\r\n")) {
		t.Fatal("expected CRLF tolerance")
	}
}

func TestDiscoverFuzzTargets(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("internal/quality/config_test.go", "package quality\n\nfunc FuzzParse(f *testing.F) {}\n")
	fs.addFile("internal/quality/config.go", "package quality\n")
	fs.addFile("internal/domain/branch/branch_test.go", "package branch\n\nfunc FuzzParse(f *testing.F) {}\nfunc FuzzValues(f *testing.F) {}\n")
	fs.addFile("vendor/x/x_test.go", "package x\n\nfunc FuzzNo(f *testing.F) {}\n")
	targets, err := discovererFor(fs).DiscoverFuzzTargets(".")
	if err != nil {
		t.Fatalf("DiscoverFuzzTargets: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("targets = %+v", targets)
	}
	if targets[0].Package != "./internal/domain/branch" || targets[0].Target != "FuzzParse" {
		t.Fatalf("unexpected first target: %+v", targets[0])
	}
	if targets[2].Package != "./internal/quality" || targets[2].Target != "FuzzParse" {
		t.Fatalf("unexpected last target: %+v", targets[2])
	}
}

func TestDiscoverFuzzTargetsEmptyRoot(t *testing.T) {
	if _, err := NewDiscoverer().DiscoverFuzzTargets(" "); err == nil {
		t.Fatal("expected an error for an empty root")
	}
}

func TestDiscoverFuzzTargetsWalkError(t *testing.T) {
	d := Discoverer{Walk: func(string, iofs.WalkDirFunc) error { return errors.New("boom") }}
	if _, err := d.DiscoverFuzzTargets("."); err == nil {
		t.Fatal("expected the walk error")
	}
}

func TestDiscoverFuzzTargetsReadError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("internal/quality/config_test.go", "package quality\n\nfunc FuzzParse(f *testing.F) {}\n")
	d := Discoverer{
		Walk:     fs.walk,
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("boom") },
	}
	if _, err := d.DiscoverFuzzTargets("."); err == nil {
		t.Fatal("expected the read error")
	}
}

func TestDiscoverFuzzTargetsWalkErrorPropagated(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("internal/quality/config_test.go", "package quality\n")
	d := Discoverer{
		Walk: func(root string, fn iofs.WalkDirFunc) error {
			return fn(filepath.Join(root, "internal"), fakeEntry{name: "internal", isDir: true}, errors.New("walk boom"))
		},
		ReadFile: fs.readFile,
	}
	if _, err := d.DiscoverFuzzTargets("."); err == nil {
		t.Fatal("expected the propagated walk error")
	}
}

func TestIgnoredDiscoveryDirectory(t *testing.T) {
	for _, name := range []string{".build", ".git", ".cache", "coverage", "dist", "vendor"} {
		if !ignoredDiscoveryDirectory(name) {
			t.Fatalf("expected %q to be ignored", name)
		}
	}
	if ignoredDiscoveryDirectory("internal") {
		t.Fatal("expected internal to be included")
	}
}

func TestRelPathFallsBackOnError(t *testing.T) {
	// Force the fallback branch portably: an absolute base and a relative
	// target cannot be related by filepath.Rel on any supported platform, so
	// the error branch is taken on every operating system. The base must come
	// from the runtime (t.TempDir()), never from a hardcoded OS-specific path
	// form — a Windows drive-letter base is not absolute on Linux and would
	// silently stop exercising the fallback there. Convention:
	// docs/conventions/testing/portable-test-construction.md
	got := filepath.ToSlash(relPath(t.TempDir(), "internal/quality/config_test.go"))
	if got != "internal/quality" {
		t.Fatalf("relPath fallback = %q", got)
	}
}

func TestDiscoverBinariesSkipsFiles(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	fs.addFile("cmd/README.md", "# cmd\n")
	binaries, err := discovererFor(fs).DiscoverBinaries(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(binaries) != 1 || binaries[0].Package != "./cmd/tool" {
		t.Fatalf("binaries = %+v", binaries)
	}
}

func TestDirDeclaresMainSkipsNonGoAndSubdirs(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("cmd/tool/main.go", "package main\n")
	fs.addFile("cmd/tool/README.md", "# tool\n")
	fs.addFile("cmd/tool/internal/x.go", "package internal\n")
	binaries, err := discovererFor(fs).DiscoverBinaries(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(binaries) != 1 || binaries[0].Package != "./cmd/tool" {
		t.Fatalf("binaries = %+v", binaries)
	}
}

func TestNewDiscovererBindsRealFilesystem(t *testing.T) {
	d := NewDiscoverer()
	if d.ReadDir == nil || d.ReadFile == nil || d.Walk == nil {
		t.Fatal("expected the real filesystem seams to be bound")
	}
	// The real seams operate against a real temporary tree.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "cmd", "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmd", "tool", "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binaries, err := d.DiscoverBinaries(dir)
	if err != nil {
		t.Fatalf("DiscoverBinaries on a real tree: %v", err)
	}
	if len(binaries) != 1 || binaries[0].Package != "./cmd/tool" {
		t.Fatalf("binaries = %+v", binaries)
	}
}

func TestVirtualFSSortingStability(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("b/b_test.go", "package b\n\nfunc FuzzB(f *testing.F) {}\n")
	fs.addFile("a/a_test.go", "package a\n\nfunc FuzzA(f *testing.F) {}\n")
	targets, err := discovererFor(fs).DiscoverFuzzTargets(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].Package != "./a" || targets[1].Package != "./b" {
		t.Fatalf("targets not sorted: %+v", targets)
	}
}

var _ = fstest.MapFS{} // keep testing/fstest referenced for seam documentation
