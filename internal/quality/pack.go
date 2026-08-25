package quality

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// PackSchemaID is the canonical capability pack descriptor schema identifier.
// The schema is owned by the supply-chain-governance shared kernel
// (schemas/capability-pack/v1/capability-pack.schema.json); this home decodes
// the shared document strictly and never redefines or copies the schema.
const PackSchemaID = "capability-pack/v1"

// PackProvisioningRecipe is the only provisioning kind: a bound recipe of
// digest- and signature-verified artifact downloads.
const PackProvisioningRecipe = "recipe"

// Pack gate scopes: a repository gate runs once at the repository root; a
// per-root gate runs once per discovered root.
const (
	PackScopeRepository = "repository"
	PackScopePerRoot    = "per-root"
)

var (
	packIdentityPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	packToolPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	packVersionPattern     = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
	packPlatformPattern    = regexp.MustCompile(`^[a-z0-9]+-[a-z0-9]+$`)
	packEnvironmentPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	packDigestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// PackDescriptor is one versioned capability pack descriptor. The descriptor
// is data, never code: the orchestrator interprets it generically, so a new
// pack is a new descriptor with its vectors, never an orchestrator change.
type PackDescriptor struct {
	Schema       string           `json:"schema"`
	Capability   string           `json:"capability"`
	Area         string           `json:"area"`
	Version      int              `json:"version"`
	Summary      string           `json:"summary"`
	Provisioning PackProvisioning `json:"provisioning"`
	Discovery    PackDiscovery    `json:"discovery"`
	Assertions   []PackAssertion  `json:"assertions"`
	Gates        []PackGate       `json:"gates"`
}

// PackProvisioning binds the recipe by which a runner receives the pack's
// tool: the tool name, the fleet-governed version, the enforced environment,
// and the digest-bound artifacts keyed by platform (<goos>-<goarch>).
type PackProvisioning struct {
	Kind        string                  `json:"kind"`
	Tool        string                  `json:"tool"`
	Version     string                  `json:"version"`
	Environment map[string]string       `json:"environment"`
	Artifacts   map[string]PackArtifact `json:"artifacts"`
}

// PackArtifact binds one platform's release artifact by URL and digest; the
// signature reference is bound where the publisher signs the artifact.
type PackArtifact struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature,omitempty"`
}

// PackDiscovery binds how the pack finds its work: the file glob whose parent
// directories form the per-root set, plus the excluded directory names.
type PackDiscovery struct {
	Roots       PackRoots `json:"roots"`
	ExcludeDirs []string  `json:"excludeDirs"`
}

// PackRoots binds the file glob whose parent directories form the per-root
// set.
type PackRoots struct {
	FileGlob string `json:"fileGlob"`
}

// PackAssertion is a fail-closed environment proof executed before any pack
// gate: the command output must carry the expected proof text.
type PackAssertion struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Expect  string   `json:"expect"`
}

// PackGate is one pack gate step.
type PackGate struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Scope   string   `json:"scope"`
	Timeout string   `json:"timeout,omitempty"`
}

// forbiddenPackContentMarkers mirrors the credential boundary of the shared
// kernel's evidence graph: a pack descriptor must never carry secrets, tokens,
// private keys, authorization headers, or volatile log fragments. The marker
// list is the fleet's shared boundary; this home enforces it locally because
// the shared kernel's guard is not importable across the module boundary.
var forbiddenPackContentMarkers = []string{
	"-----begin",
	"private key",
	"authorization:",
	"bearer ",
	"ghp_",
	"gho_",
	"ghu_",
	"ghs_",
	"ghr_",
	"github_pat_",
	"access_token",
	"refresh_token",
	"client_secret",
}

// rejectForbiddenPackContent fails closed when a descriptor carries
// credential-like content.
func rejectForbiddenPackContent(data []byte) error {
	lowered := bytes.ToLower(data)
	for _, marker := range forbiddenPackContentMarkers {
		if bytes.Contains(lowered, []byte(marker)) {
			return fmt.Errorf("capability pack descriptor contains forbidden credential-like content marker %q", marker)
		}
	}
	return nil
}

// DecodePackDescriptor strictly decodes and validates one capability-pack/v1
// descriptor. Unknown fields, trailing documents, credential-like content, and
// invariant violations are rejected with a precise field error.
func DecodePackDescriptor(data []byte) (PackDescriptor, error) {
	var descriptor PackDescriptor
	if len(data) == 0 {
		return descriptor, errors.New("capability pack descriptor must not be empty")
	}
	if err := rejectForbiddenPackContent(data); err != nil {
		return descriptor, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return descriptor, fmt.Errorf("capability pack descriptor must contain valid JSON with known fields: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return descriptor, errors.New("capability pack descriptor must contain exactly one JSON document")
	}
	if err := descriptor.Validate(); err != nil {
		return descriptor, err
	}
	return descriptor, nil
}

// Validate enforces every capability-pack/v1 invariant.
func (d PackDescriptor) Validate() error {
	if d.Schema != PackSchemaID {
		return fmt.Errorf("schema must be %q, got %q", PackSchemaID, d.Schema)
	}
	if !packIdentityPattern.MatchString(d.Capability) {
		return fmt.Errorf("capability %q must be a lowercase kebab identifier", d.Capability)
	}
	if !packIdentityPattern.MatchString(d.Area) {
		return fmt.Errorf("area %q must be a lowercase kebab identifier", d.Area)
	}
	if d.Version < 1 {
		return fmt.Errorf("version must be a positive major version, got %d", d.Version)
	}
	if strings.TrimSpace(d.Summary) == "" {
		return errors.New("summary must not be empty")
	}
	if err := d.Provisioning.validate(); err != nil {
		return fmt.Errorf("provisioning: %w", err)
	}
	if err := d.Discovery.validate(); err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	for index, assertion := range d.Assertions {
		if err := assertion.validate(); err != nil {
			return fmt.Errorf("assertions[%d]: %w", index, err)
		}
	}
	if len(d.Gates) == 0 {
		return errors.New("gates must not be empty")
	}
	seen := make(map[string]struct{}, len(d.Gates))
	for index, gate := range d.Gates {
		if err := gate.validate(d.Capability); err != nil {
			return fmt.Errorf("gates[%d]: %w", index, err)
		}
		if _, found := seen[gate.Name]; found {
			return fmt.Errorf("gates[%d]: gate name %q is not unique", index, gate.Name)
		}
		seen[gate.Name] = struct{}{}
	}
	return nil
}

func (p PackProvisioning) validate() error {
	if p.Kind != PackProvisioningRecipe {
		return fmt.Errorf("kind must be %q, got %q", PackProvisioningRecipe, p.Kind)
	}
	if !packToolPattern.MatchString(p.Tool) {
		return fmt.Errorf("tool %q must be a lowercase executable name", p.Tool)
	}
	if !packVersionPattern.MatchString(p.Version) {
		return fmt.Errorf("version %q must be a pinned version such as 1.12.5", p.Version)
	}
	for name, value := range p.Environment {
		if !packEnvironmentPattern.MatchString(name) {
			return fmt.Errorf("environment key %q must be an upper snake case name", name)
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("environment %q must not contain NUL or line-control characters", name)
		}
	}
	if len(p.Artifacts) == 0 {
		return errors.New("artifacts must bind at least one platform")
	}
	for platform, artifact := range p.Artifacts {
		if !packPlatformPattern.MatchString(platform) {
			return fmt.Errorf("artifact key %q must use the <goos>-<goarch> form", platform)
		}
		if err := artifact.validate(platform); err != nil {
			return err
		}
	}
	return nil
}

func (a PackArtifact) validate(platform string) error {
	if !strings.HasPrefix(a.URL, "https://") {
		return fmt.Errorf("artifact %q url must use https", platform)
	}
	if strings.ContainsAny(a.URL, "\x00\r\n") {
		return fmt.Errorf("artifact %q url must not contain control characters", platform)
	}
	if !packDigestPattern.MatchString(a.SHA256) {
		return fmt.Errorf("artifact %q sha256 must be 64 lowercase hex characters", platform)
	}
	if a.Signature != "" && strings.ContainsAny(a.Signature, "\x00\r\n") {
		return fmt.Errorf("artifact %q signature reference must not contain control characters", platform)
	}
	return nil
}

func (d PackDiscovery) validate() error {
	if strings.TrimSpace(d.Roots.FileGlob) == "" || strings.ContainsAny(d.Roots.FileGlob, "\x00\r\n") {
		return errors.New("roots.fileGlob must be a non-empty glob")
	}
	seen := make(map[string]struct{}, len(d.ExcludeDirs))
	for index, directory := range d.ExcludeDirs {
		if strings.TrimSpace(directory) == "" || strings.ContainsAny(directory, "\x00\r\n") {
			return fmt.Errorf("excludeDirs[%d] must be a non-empty directory name", index)
		}
		if _, found := seen[directory]; found {
			return fmt.Errorf("excludeDirs[%d] %q is not unique", index, directory)
		}
		seen[directory] = struct{}{}
	}
	return nil
}

func (a PackAssertion) validate() error {
	if !packIdentityPattern.MatchString(a.Name) {
		return fmt.Errorf("assertion name %q must be a lowercase kebab identifier", a.Name)
	}
	if err := validatePackCommand(a.Command); err != nil {
		return err
	}
	for index, argument := range a.Args {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("args[%d] must not contain NUL or line-control characters", index)
		}
	}
	if a.Expect == "" {
		return errors.New("expect must not be empty")
	}
	return nil
}

func (g PackGate) validate(capability string) error {
	if !packIdentityPattern.MatchString(g.Name) {
		return fmt.Errorf("gate name %q must be a lowercase kebab identifier", g.Name)
	}
	if !strings.HasPrefix(g.Name, capability+"-") {
		return fmt.Errorf("gate name %q must be prefixed by the capability %q", g.Name, capability)
	}
	if err := validatePackCommand(g.Command); err != nil {
		return err
	}
	for index, argument := range g.Args {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("args[%d] must not contain NUL or line-control characters", index)
		}
	}
	if g.Scope != PackScopeRepository && g.Scope != PackScopePerRoot {
		return fmt.Errorf("scope %q must be %q or %q", g.Scope, PackScopeRepository, PackScopePerRoot)
	}
	if g.Timeout != "" {
		timeout, err := time.ParseDuration(g.Timeout)
		if err != nil || timeout <= 0 {
			return fmt.Errorf("timeout %q must be a positive Go duration", g.Timeout)
		}
	}
	return nil
}

func validatePackCommand(command string) error {
	if strings.TrimSpace(command) == "" || strings.ContainsAny(command, "\x00\r\n") {
		return errors.New("command must be a non-empty executable name or path without control characters")
	}
	return nil
}
