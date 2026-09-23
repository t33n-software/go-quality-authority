package quality

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGovernedBaselineEnvironment(t *testing.T) {
	lookup := func(key string) (string, bool) {
		switch key {
		case "PATH":
			return "/bin", true
		case "HOME":
			return "/home/runner", true
		case "SYSTEMROOT":
			return `C:\Windows`, true
		}
		return "", false
	}
	// The POSIX form binds exactly the present bound keys, sorted.
	posix := governedBaselineEnvironment(lookup, "linux")
	if strings.Join(posix, "|") != "HOME=/home/runner|PATH=/bin" {
		t.Fatalf("the posix baseline = %+v", posix)
	}
	// The windows form binds its platform set.
	windows := governedBaselineEnvironment(lookup, "windows")
	if strings.Join(windows, "|") != `PATH=/bin|SYSTEMROOT=C:\Windows` {
		t.Fatalf("the windows baseline = %+v", windows)
	}
	// Nothing present binds nothing.
	if got := governedBaselineEnvironment(func(string) (string, bool) { return "", false }, "linux"); len(got) != 0 {
		t.Fatalf("the empty baseline = %+v", got)
	}
}

func TestMergeEnvironment(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.Getenv = func(key string) (string, bool) {
		if key == "PATH" {
			return "/bin", true
		}
		return "", false
	}
	// The declared environment overlays the governed baseline and wins every
	// collision.
	merged := e.mergeEnvironment(map[string]string{"TF_IN_AUTOMATION": "true", "PATH": "/custom"})
	if merged["PATH"] != "/custom" || merged["TF_IN_AUTOMATION"] != "true" {
		t.Fatalf("merged = %+v", merged)
	}
}

func TestControlledEnvironment(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.Getenv = func(key string) (string, bool) {
		if key == "PATH" {
			return "/bin", true
		}
		return "", false
	}
	// A cache-capable capability binds the governed artifact cache below the
	// engine's governed cache root.
	env, err := e.controlledEnvironment(map[string]string{"TF_IN_AUTOMATION": "true"}, "opentofu")
	if err != nil {
		t.Fatalf("controlledEnvironment: %v", err)
	}
	cache := filepath.Join("cache", "go-quality-authority", "cache", "opentofu", "plugin-cache")
	want := []string{"PATH=/bin", "TF_IN_AUTOMATION=true", "TF_PLUGIN_CACHE_DIR=" + cache}
	if strings.Join(env, "|") != strings.Join(want, "|") {
		t.Fatalf("env = %+v, want %+v", env, want)
	}
}

func TestControlledEnvironmentWithoutCacheBinding(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.UserCacheDir = func() (string, error) {
		t.Fatal("a capability without a cache binding never locates the cache")
		return "", nil
	}
	// A capability without a cache binding carries exactly the declared
	// environment over the baseline.
	env, err := e.controlledEnvironment(map[string]string{"A": "1"}, "demo")
	if err != nil {
		t.Fatalf("controlledEnvironment: %v", err)
	}
	if strings.Join(env, "|") != "A=1" {
		t.Fatalf("env = %+v", env)
	}
}

func TestControlledEnvironmentDeclaredCacheWins(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.MkdirAll = func(string, os.FileMode) error {
		t.Fatal("a descriptor-declared cache binding never creates the governed cache")
		return nil
	}
	// A descriptor-declared cache binding wins; the engine creates nothing.
	env, err := e.controlledEnvironment(map[string]string{"TF_PLUGIN_CACHE_DIR": "/declared"}, "opentofu")
	if err != nil {
		t.Fatalf("controlledEnvironment: %v", err)
	}
	if strings.Join(env, "|") != "TF_PLUGIN_CACHE_DIR=/declared" {
		t.Fatalf("env = %+v", env)
	}
}

func TestControlledEnvironmentCacheLocationError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.UserCacheDir = func() (string, error) { return "", errors.New("boom") }
	_, err := e.controlledEnvironment(map[string]string{}, "opentofu")
	if err == nil || !strings.Contains(err.Error(), "locate the governed artifact cache") {
		t.Fatalf("expected the cache-location finding: %v", err)
	}
}

func TestControlledEnvironmentCacheCreateError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.MkdirAll = func(string, os.FileMode) error { return errors.New("boom") }
	_, err := e.controlledEnvironment(map[string]string{}, "opentofu")
	if err == nil || !strings.Contains(err.Error(), "create the governed artifact cache") {
		t.Fatalf("expected the cache-create finding: %v", err)
	}
}
