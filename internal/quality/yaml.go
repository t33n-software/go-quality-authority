package quality

import (
	"fmt"
	"io/fs"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// YAMLFiles returns the repository's YAML documents (every .yml and .yaml
// file outside the VCS, vendor, cache, and build trees) in deterministic
// order for the wellformedness gate. The discovery is by convention: no
// declaration and no configuration extension exists.
func YAMLFiles(root string) ([]string, error) {
	return yamlFiles(root, filepath.WalkDir)
}

// yamlFiles walks the tree over an injected seam so the error path is
// whitebox-testable.
func yamlFiles(root string, walk func(string, fs.WalkDirFunc) error) ([]string, error) {
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
		switch filepath.Ext(path) {
		case ".yml", ".yaml":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// verifyYAMLWellformedness is the fail-closed wellformedness proof of the
// convention-discovered YAML documents: every document is parsed with the
// admitted fleet-standard YAML library, and a malformed document fails the
// gate with its parse error. A repository without YAML documents is
// vacuously green. The parser is never re-implemented.
func (o Orchestrator) verifyYAMLWellformedness(files []string) error {
	for _, file := range files {
		contents, err := o.ReadFile(file)
		if err != nil {
			return fmt.Errorf("verify YAML wellformedness: read %s: %w", file, err)
		}
		var document any
		if err := yaml.Unmarshal(contents, &document); err != nil {
			return fmt.Errorf("verify YAML wellformedness: %s: %w", file, err)
		}
	}
	return nil
}
