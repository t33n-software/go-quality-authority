package quality

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// governedBaselineKeys is the engine's governed baseline environment for pack
// gate executions: the minimal, explicit, platform-keyed ambient variable set
// a process needs to function deterministically. Everything else a pack gate
// sees is the pack's declared environment — the operator process's
// uncontrolled inheritance (its session, credential, or proxy state) never
// reaches a pack gate, because a gate whose outcome can change with the
// ambient machine state is not a proof.
var governedBaselineKeys = map[string][]string{
	"windows": {"PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"},
	"other":   {"PATH", "HOME", "TMPDIR"},
}

// governedBaselineEnvironment resolves the governed baseline of the runner
// platform through the injected lookup seam: exactly the bound keys that are
// present, in deterministic order.
func governedBaselineEnvironment(lookup func(string) (string, bool), goos string) []string {
	keys := governedBaselineKeys["other"]
	if goos == "windows" {
		keys = governedBaselineKeys["windows"]
	}
	baseline := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, bound := lookup(key); bound {
			baseline = append(baseline, key+"="+value)
		}
	}
	sort.Strings(baseline)
	return baseline
}

// packCacheBinding binds the governed artifact-cache surface of a
// cache-capable provisioned tool: the environment key and the cache directory
// below the engine's governed cache root.
type packCacheBinding struct {
	envKey string
	dir    string
}

// packCacheBindings is the engine's registry of cache-capable provisioned
// tools, keyed by capability — canonically the OpenTofu plugin cache with its
// lock-aware form, so a per-root gate sequence downloads each bound provider
// artifact once, never once per root.
var packCacheBindings = map[string]packCacheBinding{
	"opentofu": {envKey: "TF_PLUGIN_CACHE_DIR", dir: filepath.Join("opentofu", "plugin-cache")},
}

// mergeEnvironment overlays the pack's declared environment on the governed
// baseline; a declared key wins every collision.
func (e PackEngine) mergeEnvironment(declared map[string]string) map[string]string {
	merged := make(map[string]string, len(declared)+1)
	for _, entry := range governedBaselineEnvironment(e.Getenv, e.GOOS) {
		key, value, _ := strings.Cut(entry, "=")
		merged[key] = value
	}
	for key, value := range declared {
		merged[key] = value
	}
	return merged
}

// controlledEnvironment resolves the exact process environment of a pack gate
// execution: the pack's declared environment over the engine's governed
// baseline, plus the governed artifact-cache binding of a cache-capable tool
// (a descriptor-declared cache binding wins). The operator process's
// uncontrolled inheritance never reaches a pack gate.
func (e PackEngine) controlledEnvironment(declared map[string]string, capability string) ([]string, error) {
	merged := e.mergeEnvironment(declared)
	if binding, bound := packCacheBindings[capability]; bound {
		if _, declaredCache := declared[binding.envKey]; !declaredCache {
			cacheRoot, err := e.UserCacheDir()
			if err != nil {
				return nil, fmt.Errorf("locate the governed artifact cache of capability %q: %w", capability, err)
			}
			dir := filepath.Join(cacheRoot, "go-quality-authority", "cache", binding.dir)
			if err := e.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("create the governed artifact cache of capability %q: %w", capability, err)
			}
			merged[binding.envKey] = dir
		}
	}
	return packEnvironment(merged), nil
}
