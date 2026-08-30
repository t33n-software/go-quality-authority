// Package packaging binds the canonical artifacts of the go-quality-authority
// home — the config schema, the conformance vectors, and the tool catalog — to
// the quality core through contract tests.
package packaging

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/t33n-software/go-quality-authority/internal/quality"
)

// repoRoot resolves the repository root from the packaging test package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

// readArtifact reads a canonical artifact relative to the repository root.
func readArtifact(t *testing.T, relative string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return contents
}

// listVectors returns the sorted vector file names in a conformance lane.
func listVectors(t *testing.T, lane string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), "conformance", lane))
	if err != nil {
		t.Fatalf("list %s vectors: %v", lane, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("the %s lane carries no vectors", lane)
	}
	return names
}

func TestConfigSeamIsReferencedByCanonicalIdentity(t *testing.T) {
	// The seam definition lives exactly once in the supply-chain-governance
	// shared kernel from version 4; this home references it by identity and
	// never carries a schema copy.
	if quality.SchemaID != "quality-gate-config/v4" {
		t.Fatalf("SchemaID = %q, want the centralized v4 identity", quality.SchemaID)
	}
	if quality.SchemaVersion != 4 {
		t.Fatalf("SchemaVersion = %d, want 4", quality.SchemaVersion)
	}
	readme := string(readArtifact(t, "README.md"))
	if !strings.Contains(readme, "supply-chain-governance") || !strings.Contains(readme, "quality-gate-config/v4") {
		t.Fatal("the README must reference the centralized seam definition in the shared kernel")
	}
	if _, err := os.Stat(filepath.Join(repoRoot(t), "schemas", "quality-gate-config")); !os.IsNotExist(err) {
		t.Fatal("the local schema copy must not exist; the seam is owned by the shared kernel")
	}
}

func TestPositiveConformanceVectors(t *testing.T) {
	for _, name := range listVectors(t, "positive") {
		t.Run(name, func(t *testing.T) {
			contents := readArtifact(t, "conformance/positive/"+name)
			if _, err := quality.DecodeConfig(contents); err != nil {
				t.Fatalf("positive vector %s must decode: %v", name, err)
			}
		})
	}
}

func TestNegativeConformanceVectors(t *testing.T) {
	for _, name := range listVectors(t, "negative") {
		t.Run(name, func(t *testing.T) {
			contents := readArtifact(t, "conformance/negative/"+name)
			if _, err := quality.DecodeConfig(contents); err == nil {
				t.Fatalf("negative vector %s must be rejected", name)
			}
		})
	}
}

// gitRunsClean proves a git predicate at the repository root by exit status.
func gitRunsClean(t *testing.T, args ...string) bool {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot(t)
	return cmd.Run() == nil
}

// gitOutput reads a git query result at the repository root.
func gitOutput(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

func TestSelfPinTracksTheMergedLineDecoder(t *testing.T) {
	// The tools module pins this home's own module so the lane-build proof
	// exercises the same pinned channel the tenants consume. The pin is a
	// release-gate input: the lifecycle publish lane invokes the pinned
	// quality-gate against this repository's configuration seam, so the pinned
	// stand must always speak the current seam. Two fail-closed invariants
	// bind that currency: the pin binds a commit on the merged develop line
	// (never a pull-request-only commit), and the pin never predates the
	// newest change to the configuration decoder surface on that line. A
	// decoder change merges first and the repin follows on the merged line;
	// every pull request in between fails this guard.
	contents := string(readArtifact(t, "tools/go.mod"))
	match := regexp.MustCompile(`(?m)\bgithub\.com/t33n-software/go-quality-authority\s+(v\S+)`).FindStringSubmatch(contents)
	if match == nil {
		t.Fatal("the tools module must pin this home's own module for the lane-build proof")
	}
	version := match[1]
	pin := version
	if pseudo := regexp.MustCompile(`^v0\.0\.0-\d{14}-([0-9a-f]{12})$`).FindStringSubmatch(version); pseudo != nil {
		pin = pseudo[1]
	} else {
		pin = gitOutput(t, "rev-parse", version+"^{commit}")
	}
	if !gitRunsClean(t, "merge-base", "--is-ancestor", pin, "origin/develop") {
		t.Fatalf("the self pin %q is not reachable from origin/develop; the tool pin must bind a commit on the merged develop line, never a pull-request-only commit that the cross-repo resolver cannot find", version)
	}
	decoder := gitOutput(t, "log", "-1", "--format=%H", "origin/develop", "--", "internal/quality/config.go")
	if decoder == "" {
		t.Fatal("the configuration decoder surface must exist on the merged develop line")
	}
	if !gitRunsClean(t, "merge-base", "--is-ancestor", decoder, pin) {
		t.Fatalf("the self pin %q predates the current configuration decoder stand %s; the pinned quality-gate must speak the current config seam — repin the self tools on the merged line", version, decoder)
	}
}

func TestToolCatalog(t *testing.T) {
	contents := readArtifact(t, "catalog/tools.json")
	var catalog struct {
		SchemaVersion int `json:"schemaVersion"`
		Tools         []struct {
			Name    string `json:"name"`
			Module  string `json:"module"`
			Package string `json:"package"`
			Purpose string `json:"purpose"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(contents, &catalog); err != nil {
		t.Fatalf("the tool catalog is not valid JSON: %v", err)
	}
	if catalog.SchemaVersion != 1 {
		t.Fatalf("catalog schemaVersion = %d, want 1", catalog.SchemaVersion)
	}
	canonical := []string{"staticcheck", "govulncheck", "lefthook", "quality-gate", "check-coverage", "git-governance", "license"}
	seen := make(map[string]bool, len(catalog.Tools))
	for _, tool := range catalog.Tools {
		if tool.Name == "" || tool.Module == "" || tool.Package == "" || tool.Purpose == "" {
			t.Fatalf("every tool entry must be complete: %+v", tool)
		}
		if seen[tool.Name] {
			t.Fatalf("duplicate tool %q", tool.Name)
		}
		seen[tool.Name] = true
	}
	for _, name := range canonical {
		if !seen[name] {
			t.Fatalf("the canonical tool %q is missing from the catalog", name)
		}
	}
}
