package quality

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// compatibilityProofRegister is the engine's release-proven compatibility
// register: the pack majors this engine version is proven against, keyed by
// capability. Every engine release extends it by executing the conformance
// vectors of every active pack major against the release candidate, and the
// signed release artifact carries the resulting register; a pack major that
// leaves the active set receives no further entries, so a tenant still bound
// to it fails closed on the next engine bump — the governed retirement
// signal, never a silent breakage.
var compatibilityProofRegister = map[string][]int{
	"opentofu": {1, 2},
}

// engineVersionIdentity is the running engine's version identity at
// resolution. The home's working tree and merged-line pseudo-version pins are
// the development identity — the newest machinery, which postdates every
// release. A release pin carries its three-part version.
type engineVersionIdentity struct {
	raw     string
	release bool
	parts   [3]int
}

// classifyEngineVersion binds the version identity of a raw module version:
// the development identity for the working tree, the `dev` and `(devel)`
// forms, and merged-line pseudo-versions; the release identity for the
// three-part release form.
func classifyEngineVersion(raw string) (engineVersionIdentity, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "dev" || trimmed == "(devel)" || strings.HasPrefix(trimmed, "v0.0.0-") {
		return engineVersionIdentity{raw: trimmed}, nil
	}
	parts, err := parseReleaseFloor(trimmed)
	if err != nil {
		return engineVersionIdentity{}, fmt.Errorf("the engine version %q is neither the three-part release form nor a merged-line development form", trimmed)
	}
	return engineVersionIdentity{raw: trimmed, release: true, parts: parts}, nil
}

// predates reports whether the identity predates the required release floor.
// The development identity postdates every release and never predates a
// floor.
func (i engineVersionIdentity) predates(floor [3]int) bool {
	if !i.release {
		return false
	}
	for index := range i.parts {
		if i.parts[index] != floor[index] {
			return i.parts[index] < floor[index]
		}
	}
	return false
}

// parseReleaseFloor parses a declared minimum engine version into its
// three-part form.
func parseReleaseFloor(raw string) ([3]int, error) {
	var floor [3]int
	parts := strings.Split(strings.TrimPrefix(raw, "v"), ".")
	if len(parts) != 3 {
		return floor, fmt.Errorf("minEngineVersion %q must be a pinned three-part engine version such as 1.3.0", raw)
	}
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return floor, fmt.Errorf("minEngineVersion %q must be numeric in every part: %w", raw, err)
		}
		floor[index] = value
	}
	return floor, nil
}

// compatibilityProven reports whether the engine's compatibility proof
// register carries a proof entry for the pack major.
func compatibilityProven(capability string, major int) bool {
	for _, proven := range compatibilityProofRegister[capability] {
		if proven == major {
			return true
		}
	}
	return false
}

// proveEngineCurrency enforces the engine-machinery currency of a bound pack
// at gate-plan resolution: a pack whose descriptor declares minEngineVersion
// refuses to run on an engine that predates the declared level or carries no
// compatibility proof entry for the pack major. The refusal is fail-closed
// and names the required level or the unproven combination — the pack's
// declared form never degrades into a local re-implementation on an older
// engine and never executes unproven on a newer one.
func (e PackEngine) proveEngineCurrency(pack ResolvedPack, identity engineVersionIdentity) error {
	floor, err := parseReleaseFloor(pack.Descriptor.MinEngineVersion)
	if err != nil {
		return fmt.Errorf("capability pack %q: %w", pack.Reference, err)
	}
	if identity.predates(floor) {
		return fmt.Errorf("capability pack %q requires engine machinery %s or newer, but the pinned engine is %s; flip the tenant's engine pin to a current stand", pack.Reference, pack.Descriptor.MinEngineVersion, identity.raw)
	}
	if !compatibilityProven(pack.Descriptor.Capability, pack.Descriptor.Version) {
		return fmt.Errorf("capability pack %q carries no compatibility proof entry for the pinned engine %s: the unproven combination never executes; the proof entry lands with an engine release that proves the pack's conformance vectors", pack.Reference, identity.raw)
	}
	return nil
}

// engineIdentity resolves the running engine's version identity: the home's
// working tree is the development identity (the newest machinery); a tenant's
// consumption binds the pinned engine module version through the tenant's
// integrity-pinned tooling channel.
func (e PackEngine) engineIdentity(ctx context.Context, root, module string) (engineVersionIdentity, error) {
	if module == territoryHomeModule {
		return engineVersionIdentity{raw: "the home working tree"}, nil
	}
	version, err := e.resolveModuleVersion(ctx, root, territoryHomeModule)
	if err != nil {
		return engineVersionIdentity{}, err
	}
	identity, err := classifyEngineVersion(version)
	if err != nil {
		return engineVersionIdentity{}, err
	}
	return identity, nil
}
