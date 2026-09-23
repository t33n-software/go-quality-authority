package quality

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// packStaging is one clean-staging execution unit of the pack gate plan:
// exactly the repository's tracked files — the VCS index oracle, which never
// carries execution residue such as .terraform/, *.tfstate, or *.tfvars —
// copied structure-preserving into an isolated directory. One unit is shared
// by exactly one pack's gate sequence of one root, or by one pack's
// repository-scope gates, so every pack gate proves the committed form of its
// root — identically on a fresh CI checkout and on a local working directory,
// and identically before and after any execution.
type packStaging struct {
	// scope is the audit identity of the unit: "repository" for the
	// repository-scope gates of a pack, or the repository-relative root path.
	scope string
	// dir is the materialized staging directory; empty until materialized.
	dir string
}

// materializeStaging lazily materializes the unit. A partially materialized
// staging is never left behind: a copy failure releases the directory before
// the failure surfaces.
func (o Orchestrator) materializeStaging(ctx context.Context, root string, unit *packStaging) error {
	if unit.dir != "" {
		return nil
	}
	dir, err := o.TempDir("quality-gate-staging-")
	if err != nil {
		return fmt.Errorf("create the clean staging of %s: %w", unit.scope, err)
	}
	if err := o.copyTrackedFiles(ctx, root, dir); err != nil {
		return errors.Join(
			fmt.Errorf("materialize the clean staging of %s: %w", unit.scope, err),
			o.RemoveAll(dir),
		)
	}
	unit.dir = dir
	return nil
}

// copyTrackedFiles copies exactly the repository's tracked files into the
// staging directory. The tracked set is the VCS index (`git ls-files -z`,
// NUL-separated against quoting), so the staging carries the committed form
// and never an execution residue; the content is the working tree — the
// commit candidate locally and the commit in CI. Every failure is
// fail-closed.
func (o Orchestrator) copyTrackedFiles(ctx context.Context, root, staging string) error {
	output, err := o.ExecuteOutput(ctx, root, "git", []string{"ls-files", "-z"}, nil)
	if err != nil {
		return fmt.Errorf("enumerate the tracked files: %w (%s)", err, failureOutputTail(output))
	}
	for _, name := range strings.Split(string(output), "\x00") {
		if name == "" {
			continue
		}
		contents, err := o.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return fmt.Errorf("read the tracked file %q: %w", name, err)
		}
		target := filepath.Join(staging, filepath.FromSlash(name))
		if err := o.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create the staging directory of %q: %w", name, err)
		}
		if err := o.WriteFile(target, contents, 0o644); err != nil {
			return fmt.Errorf("stage the tracked file %q: %w", name, err)
		}
	}
	return nil
}

// unstageStaging releases the materialized staging of a unit. The cleanup is
// fail-closed: a removal failure is an error, never a silent residue.
func (o Orchestrator) unstageStaging(unit *packStaging) error {
	if unit.dir == "" {
		return nil
	}
	if err := o.RemoveAll(unit.dir); err != nil {
		return fmt.Errorf("release the clean staging of %s: %w", unit.scope, err)
	}
	unit.dir = ""
	return nil
}
