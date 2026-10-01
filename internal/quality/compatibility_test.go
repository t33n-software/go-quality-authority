package quality

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// validPackJSONWithMinEngine renders the valid pack document with the engine
// machinery binding.
func validPackJSONWithMinEngine(version string) string {
	return strings.Replace(validPackJSON(), `"summary":"OpenTofu infrastructure gates."`, `"summary":"OpenTofu infrastructure gates.","minEngineVersion":"`+version+`"`, 1)
}

// validPackJSONWithMinEngineAt renders the valid pack document with the
// engine machinery binding at the given pack major.
func validPackJSONWithMinEngineAt(version string, major int) string {
	document := validPackJSONWithMinEngine(version)
	return strings.Replace(document, `"version":1`, fmt.Sprintf(`"version":%d`, major), 1)
}

// moduleChannelWithVersions extends the tooling-channel fixture with the
// version query of the engine-currency enforcement.
func moduleChannelWithVersions(modules, versions map[string]string) func(context.Context, string, string, []string, []string) ([]byte, error) {
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
		if module, found := strings.CutPrefix(joined, "list -m -f {{.Version}} "); found {
			if version, ok := versions[module]; ok {
				return []byte(version + "\n"), nil
			}
			return nil, fmt.Errorf("module %s carries no version fixture", module)
		}
		return nil, errors.New("unexpected process invocation")
	}
}

func TestClassifyEngineVersion(t *testing.T) {
	// The development identity: the working tree, the dev and (devel) forms,
	// and the merged-line pseudo-version form.
	for _, raw := range []string{"", "dev", "(devel)", "v0.0.0-20260916122150-8b132b217c3e"} {
		identity, err := classifyEngineVersion(raw)
		if err != nil {
			t.Fatalf("classifyEngineVersion(%q): %v", raw, err)
		}
		if identity.release {
			t.Fatalf("%q must be the development identity", raw)
		}
	}
	// The release identity, with and without the v prefix.
	for _, raw := range []string{"1.2.3", "v1.2.3"} {
		identity, err := classifyEngineVersion(raw)
		if err != nil {
			t.Fatalf("classifyEngineVersion(%q): %v", raw, err)
		}
		if !identity.release || identity.parts != [3]int{1, 2, 3} {
			t.Fatalf("%q must be the release identity 1.2.3: %+v", raw, identity)
		}
	}
	// Malformed forms fail closed.
	for _, raw := range []string{"1.2", "1.2.3.4", "garbage", "1.2.x"} {
		if _, err := classifyEngineVersion(raw); err == nil {
			t.Fatalf("expected the malformed-version finding for %q", raw)
		}
	}
}

func TestEngineVersionIdentityPredates(t *testing.T) {
	// The development identity postdates every release.
	development := engineVersionIdentity{raw: "dev"}
	if development.predates([3]int{99, 0, 0}) {
		t.Fatal("the development identity never predates a floor")
	}
	release := func(major, minor, patch int) engineVersionIdentity {
		return engineVersionIdentity{release: true, parts: [3]int{major, minor, patch}}
	}
	floor := [3]int{1, 2, 3}
	if release(1, 2, 3).predates(floor) {
		t.Fatal("an equal release does not predate the floor")
	}
	if !release(1, 2, 2).predates(floor) {
		t.Fatal("an older patch predates the floor")
	}
	if !release(1, 1, 9).predates(floor) {
		t.Fatal("an older minor predates the floor")
	}
	if !release(0, 9, 9).predates(floor) {
		t.Fatal("an older major predates the floor")
	}
	if release(2, 0, 0).predates(floor) {
		t.Fatal("a newer release does not predate the floor")
	}
}

func TestParseReleaseFloor(t *testing.T) {
	floor, err := parseReleaseFloor("1.3.0")
	if err != nil || floor != [3]int{1, 3, 0} {
		t.Fatalf("parseReleaseFloor: %+v, %v", floor, err)
	}
	if _, err := parseReleaseFloor("1.3"); err == nil {
		t.Fatal("expected the two-part rejection")
	}
	if _, err := parseReleaseFloor("1.3.x"); err == nil {
		t.Fatal("expected the non-numeric rejection")
	}
}

func TestCompatibilityProven(t *testing.T) {
	if !compatibilityProven("opentofu", 1) || !compatibilityProven("opentofu", 2) {
		t.Fatal("the register carries the proven opentofu majors")
	}
	if compatibilityProven("opentofu", 3) {
		t.Fatal("an unregistered major is unproven")
	}
	if compatibilityProven("unknown", 1) {
		t.Fatal("an unknown capability is unproven")
	}
}

func TestProveEngineCurrency(t *testing.T) {
	pack := testResolvedPack()
	pack.Descriptor.MinEngineVersion = "1.0.0"
	// A satisfying release passes.
	if err := fakePackEngine(newVirtualFS()).proveEngineCurrency(pack, engineVersionIdentity{raw: "v1.0.0", release: true, parts: [3]int{1, 0, 0}}); err != nil {
		t.Fatalf("proveEngineCurrency: %v", err)
	}
	// A predating release fails closed, naming the required level.
	err := fakePackEngine(newVirtualFS()).proveEngineCurrency(pack, engineVersionIdentity{raw: "v0.9.0", release: true, parts: [3]int{0, 9, 0}})
	if err == nil || !strings.Contains(err.Error(), "requires engine machinery 1.0.0 or newer") {
		t.Fatalf("expected the required-level finding: %v", err)
	}
	// The development identity satisfies the floor.
	if err := fakePackEngine(newVirtualFS()).proveEngineCurrency(pack, engineVersionIdentity{raw: "dev"}); err != nil {
		t.Fatalf("the development identity satisfies the floor: %v", err)
	}
	// An unproven combination fails closed, naming it.
	unproven := testResolvedPack()
	unproven.Reference = "opentofu@3"
	unproven.Descriptor.Version = 3
	unproven.Descriptor.MinEngineVersion = "1.0.0"
	err = fakePackEngine(newVirtualFS()).proveEngineCurrency(unproven, engineVersionIdentity{raw: "dev"})
	if err == nil || !strings.Contains(err.Error(), "no compatibility proof entry") || !strings.Contains(err.Error(), "opentofu@3") {
		t.Fatalf("expected the unproven-combination finding: %v", err)
	}
	// A malformed floor fails closed.
	malformed := testResolvedPack()
	malformed.Descriptor.MinEngineVersion = "1.0"
	if err := fakePackEngine(newVirtualFS()).proveEngineCurrency(malformed, engineVersionIdentity{raw: "dev"}); err == nil || !strings.Contains(err.Error(), "minEngineVersion") {
		t.Fatalf("expected the malformed-floor finding: %v", err)
	}
}

func TestEngineIdentity(t *testing.T) {
	// The home's working tree is the development identity — no version query.
	e := fakePackEngine(newVirtualFS())
	e.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		t.Fatal("the home working tree never queries the tooling channel")
		return nil, nil
	}
	identity, err := e.engineIdentity(context.Background(), ".", territoryHomeModule)
	if err != nil || identity.release {
		t.Fatalf("the home identity = %+v, %v", identity, err)
	}
	// A tenant binds the pinned engine module version through the tooling
	// channel.
	e = fakePackEngine(newVirtualFS())
	e.ExecuteOutput = moduleChannelWithVersions(
		map[string]string{territoryHomeModule: "gqa"},
		map[string]string{territoryHomeModule: "v0.0.0-20260916122150-8b132b217c3e"},
	)
	identity, err = e.engineIdentity(context.Background(), ".", "example.com/tenant")
	if err != nil || identity.release {
		t.Fatalf("the tenant identity = %+v, %v", identity, err)
	}
	// The channel failure propagates.
	e.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return nil, errors.New("boom")
	}
	if _, err := e.engineIdentity(context.Background(), ".", "example.com/tenant"); err == nil {
		t.Fatal("expected the channel failure")
	}
	// A malformed pinned version fails closed.
	e.ExecuteOutput = moduleChannelWithVersions(map[string]string{territoryHomeModule: "gqa"}, map[string]string{territoryHomeModule: "garbage"})
	if _, err := e.engineIdentity(context.Background(), ".", "example.com/tenant"); err == nil {
		t.Fatal("expected the malformed-version finding")
	}
}

func TestResolveModuleVersion(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.ExecuteOutput = moduleChannelWithVersions(map[string]string{"example.com/m": "dir"}, map[string]string{"example.com/m": "v1.2.3"})
	version, err := e.resolveModuleVersion(context.Background(), ".", "example.com/m")
	if err != nil || version != "v1.2.3" {
		t.Fatalf("resolveModuleVersion = %q, %v", version, err)
	}
	// The download failure propagates.
	e.ExecuteOutput = func(context.Context, string, string, []string, []string) ([]byte, error) {
		return nil, errors.New("boom")
	}
	if _, err := e.resolveModuleVersion(context.Background(), ".", "example.com/m"); err == nil {
		t.Fatal("expected the download failure")
	}
	// The list failure propagates.
	e.ExecuteOutput = func(_ context.Context, _ string, _ string, args []string, _ []string) ([]byte, error) {
		if strings.Join(args, " ") == "mod download example.com/m" {
			return nil, nil
		}
		return nil, errors.New("boom")
	}
	if _, err := e.resolveModuleVersion(context.Background(), ".", "example.com/m"); err == nil {
		t.Fatal("expected the list failure")
	}
	// An empty version fails closed.
	e.ExecuteOutput = func(_ context.Context, _ string, _ string, args []string, _ []string) ([]byte, error) {
		if strings.Join(args, " ") == "mod download example.com/m" {
			return nil, nil
		}
		return []byte("\n"), nil
	}
	if _, err := e.resolveModuleVersion(context.Background(), ".", "example.com/m"); err == nil || !strings.Contains(err.Error(), "no version") {
		t.Fatalf("expected the empty-version finding: %v", err)
	}
}

func TestPackEngineResolveCurrencyFloor(t *testing.T) {
	// A tenant whose pinned engine predates the declared machinery floor fails
	// closed at resolution, naming the required level.
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSONWithMinEngine("2.0.0"))
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannelWithVersions(
		map[string]string{sharedKernelModule: "scg", territoryHomeModule: "gqa"},
		map[string]string{territoryHomeModule: "v1.0.0"},
	)
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil || !strings.Contains(err.Error(), "requires engine machinery 2.0.0 or newer") {
		t.Fatalf("expected the required-level finding: %v", err)
	}
}

func TestPackEngineResolveCurrencySatisfied(t *testing.T) {
	// A current release pin satisfies the floor and carries the proof entry.
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSONWithMinEngine("1.0.0"))
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannelWithVersions(
		map[string]string{sharedKernelModule: "scg", territoryHomeModule: "gqa"},
		map[string]string{territoryHomeModule: "v1.0.0"},
	)
	packs, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err != nil || len(packs) != 1 {
		t.Fatalf("Resolve: %+v, %v", packs, err)
	}
}

func TestPackEngineResolveCurrencyUnproven(t *testing.T) {
	// A pack major without a proof entry fails closed, naming the unproven
	// combination.
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/infrastructure/opentofu/v9/pack.json", validPackJSONWithMinEngineAt("1.0.0", 9))
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannelWithVersions(
		map[string]string{sharedKernelModule: "scg", territoryHomeModule: "gqa"},
		map[string]string{territoryHomeModule: "v1.0.0"},
	)
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@9"})
	if err == nil || !strings.Contains(err.Error(), "no compatibility proof entry") || !strings.Contains(err.Error(), "opentofu@9") {
		t.Fatalf("expected the unproven-combination finding: %v", err)
	}
}

func TestPackEngineResolveWithoutMinEngineVersionSkipsTheCurrencyChannel(t *testing.T) {
	// A descriptor without minEngineVersion resolves exactly as before: the
	// version channel is never queried.
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSON())
	e := fakePackEngine(fs)
	channel := moduleChannel(map[string]string{sharedKernelModule: "scg"})
	e.ExecuteOutput = func(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "{{.Version}}") {
			t.Fatal("a descriptor without minEngineVersion never queries the version channel")
		}
		return channel(ctx, dir, executable, args, env)
	}
	if _, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestPackEngineResolveCurrencyHomeWorkingTree(t *testing.T) {
	// The home's working tree is the development identity: the floor is
	// satisfied without a version query — the registry channel resolves the
	// shared kernel as usual, but the version surface is never touched.
	fs := newVirtualFS()
	fs.addFile("go.mod", "module "+territoryHomeModule+"\n")
	fs.addFile("capabilities/infrastructure/opentofu/v1/pack.json", validPackJSONWithMinEngine("1.0.0"))
	e := fakePackEngine(fs)
	channel := moduleChannelWithVersions(map[string]string{sharedKernelModule: "scg"}, nil)
	e.ExecuteOutput = func(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "{{.Version}}") {
			t.Fatal("the home working tree never queries the version channel")
		}
		return channel(ctx, dir, executable, args, env)
	}
	if _, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestPackEngineResolveCurrencyModuleIdentityError(t *testing.T) {
	// The module-identity failure inside the currency wiring fails closed.
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSONWithMinEngine("1.0.0"))
	e := fakePackEngine(fs)
	e.ExecuteOutput = moduleChannelWithVersions(
		map[string]string{sharedKernelModule: "scg", territoryHomeModule: "gqa"},
		map[string]string{territoryHomeModule: "v1.0.0"},
	)
	reads := 0
	base := e.ReadFile
	e.ReadFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "go.mod") {
			reads++
			if reads > 1 {
				return nil, errors.New("boom")
			}
		}
		return base(path)
	}
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil || !strings.Contains(err.Error(), "module declaration") {
		t.Fatalf("expected the module-identity finding: %v", err)
	}
}

func TestPackEngineResolveCurrencyIdentityError(t *testing.T) {
	// The version-channel failure of the engine-identity resolution fails
	// closed.
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/infrastructure/opentofu/v1/pack.json", validPackJSONWithMinEngine("1.0.0"))
	e := fakePackEngine(fs)
	channel := moduleChannelWithVersions(map[string]string{sharedKernelModule: "scg", territoryHomeModule: "gqa"}, nil)
	e.ExecuteOutput = func(ctx context.Context, dir, executable string, args []string, env []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "{{.Version}}") {
			return nil, errors.New("boom")
		}
		return channel(ctx, dir, executable, args, env)
	}
	_, err := e.Resolve(context.Background(), ".", []string{"opentofu@1"})
	if err == nil || !strings.Contains(err.Error(), "go list -m") {
		t.Fatalf("expected the version-channel finding: %v", err)
	}
}
