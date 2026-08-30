// Package packaging binds the canonical artifacts of the go-quality-authority
// home — the config schema, the conformance vectors, and the tool catalog — to
// the quality core through contract tests.
package packaging

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	canonical := []string{"staticcheck", "govulncheck", "lefthook", "quality-gate", "check-coverage", "git-governance"}
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
