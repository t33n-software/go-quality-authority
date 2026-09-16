package quality

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// packGateSemantics binds the engine-level gate semantics of a known pack
// major: the machinery the descriptor's tool invocations alone cannot
// express. The support is engine machinery versioned with the orchestrator —
// never a per-pack option and never tenant configuration.
type packGateSemantics struct {
	// evaluationSafetyGuard injects the static evaluation-safety proof of
	// every custom condition of every root before the root's gate sequence.
	evaluationSafetyGuard bool
	// behavioralGate names the descriptor gate whose execution form the
	// engine replaces with the offline-capability classification: an
	// encryption-carrying root never executes offline, and the deterministic
	// deferral record is emitted — never a silent skip.
	behavioralGate string
}

// packGateSemanticsSupport is the engine-versioned registry of the supported
// pack-major gate semantics, keyed by capability and major version.
var packGateSemanticsSupport = map[string]map[int]packGateSemantics{
	"opentofu": {
		1: {},
		2: {evaluationSafetyGuard: true, behavioralGate: "opentofu-test"},
	},
}

// gateSemanticsFor resolves the engine-level gate semantics of a resolved
// pack. A capability without engine-bound semantics executes its descriptor
// as plain tool gates. A capability with versioned gate semantics fails
// closed at a major this engine does not support — a tenant flip to such a
// major is a fail-closed finding, never a silent skip. A pack whose
// descriptor does not carry the behavioral gate its semantics bind is a
// fail-closed contract breach.
func gateSemanticsFor(pack ResolvedPack) (packGateSemantics, error) {
	majors, registered := packGateSemanticsSupport[pack.Descriptor.Capability]
	if !registered {
		return packGateSemantics{}, nil
	}
	semantics, supported := majors[pack.Descriptor.Version]
	if !supported {
		supported := make([]string, 0, len(majors))
		for major := range majors {
			supported = append(supported, strconv.Itoa(major))
		}
		sort.Strings(supported)
		return packGateSemantics{}, fmt.Errorf(
			"capability pack %q binds gate semantics at a major this engine does not support (supported majors of %q: %s); the flip to an unsupported pack major is a fail-closed finding, never a silent skip",
			pack.Reference, pack.Descriptor.Capability, strings.Join(supported, ", "))
	}
	if semantics.behavioralGate != "" {
		found := false
		for _, gate := range pack.Descriptor.Gates {
			if gate.Name == semantics.behavioralGate {
				found = true
				break
			}
		}
		if !found {
			return packGateSemantics{}, fmt.Errorf(
				"capability pack %q does not carry the behavioral gate %q its engine-bound gate semantics require",
				pack.Reference, semantics.behavioralGate)
		}
	}
	return semantics, nil
}

// behavioralProofDeferredMarker is the deterministic, greppable marker of the
// deferral record line: the behavioral proof of an encryption-carrying root
// is bound to the governed execution window, and the record is its
// deterministic gate output — never a silent skip.
const behavioralProofDeferredMarker = "DEFERRED"

// executeBehavioralProof executes the pack's behavioral gate against the
// clean staging of one root when the root is offline-capable, and emits the
// deterministic deferral record for an encryption-carrying root: its
// initialization resolves encryption key material that the offline gate never
// carries, so its behavioral proof is bound to the governed execution window.
func (e PackEngine) executeBehavioralProof(ctx context.Context, dir, root string, pack ResolvedPack, gate PackGate, toolPath string) error {
	model, err := e.buildRootModel(dir)
	if err != nil {
		return err
	}
	if model.encrypted {
		fmt.Fprintf(e.Stdout, "%s (%s): %s: the root carries an encryption block; its initialization resolves encryption key material that the offline gate never carries, so its behavioral proof is bound to the governed execution window\n",
			gate.Name, root, behavioralProofDeferredMarker)
		return nil
	}
	output, err := e.ExecuteOutput(ctx, dir, toolPath, gate.Args, packEnvironment(pack.Descriptor.Provisioning.Environment))
	if err != nil {
		return fmt.Errorf("the behavioral proof of %s failed: %w (%s)", root, err, strings.TrimSpace(string(output)))
	}
	return nil
}
