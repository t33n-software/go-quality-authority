// Package quality implements the Go territory home: the quality-gate
// orchestrator, the 100-percent statement-coverage gate, the canonical
// quality-gate configuration seam, and the canonical Go tool catalog.
//
// The configuration seam is a typed trust boundary between the fleet and a
// tenant. It is strictly decoded, versioned, and owned by this home; project
// specifics are data, never forked logic.
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

// SchemaVersion is the canonical quality-gate configuration schema version
// published by this home. Version 4 moves the seam definition into the
// supply-chain-governance shared kernel: the toolchain identity becomes
// language-keyed and tenants declare capability packs through extends.
const SchemaVersion = 4

// SchemaID is the canonical schema identity of the configuration seam. From
// version 4 the seam definition lives exactly once in the
// supply-chain-governance shared kernel; this home references it by identity
// and never carries a copy.
const SchemaID = "quality-gate-config/v4"

const (
	maxConfigBytes   = 1 << 20
	maxGateCount     = 32
	maxArgumentCount = 64
	maxBinaryCount   = 32
	maxFuzzCount     = 64
	maxSmokeCount    = 16
	maxExtendsCount  = 32

	defaultGateTimeout = 5 * time.Minute
)

var (
	gateNamePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	fuzzNamePattern      = regexp.MustCompile(`^Fuzz[A-Za-z0-9_]*$`)
	languagePattern      = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	versionPattern       = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
	packReferencePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*@[0-9]+$`)
	packagePattern       = regexp.MustCompile(`^\.?/[A-Za-z0-9_./-]+$`)
)

// Config is the canonical quality-gate configuration seam.
type Config struct {
	SchemaVersion int
	Toolchain     Toolchain
	Extends       []string
	Defaults      Scope
	Gates         []Gate
	Project       Project
}

// Toolchain binds the controlled toolchain identity as language-keyed tenant
// data: the same seam form serves every language territory without a schema
// fork.
type Toolchain struct {
	Language string
	Version  string
}

// Scope selects the branch families a gate set applies to.
type Scope struct {
	IncludeFamilies []string
	ExcludeFamilies []string
}

// Gate is one explicitly declared quality command.
type Gate struct {
	Name             string
	Command          string
	Args             []string
	Timeout          string
	WorkingDirectory string
	IncludeFamilies  []string
	ExcludeFamilies  []string
}

// Project carries the tenant's named exceptions to convention discovery.
type Project struct {
	Binaries []Binary
	Fuzz     []FuzzTarget
}

// Binary declares a smoke-tested command binary with explicit arguments.
type Binary struct {
	Package string
	Smoke   []string
}

// FuzzTarget declares a boundary fuzz target with its execution budget.
type FuzzTarget struct {
	Package string
	Target  string
	Time    string
}

// configDocument is the wire form of the configuration seam. Unknown fields
// are rejected at decode time.
type configDocument struct {
	SchemaVersion int           `json:"schemaVersion"`
	Toolchain     toolchainJSON `json:"toolchain"`
	Extends       []string      `json:"extends"`
	Defaults      scopeJSON     `json:"defaults"`
	Gates         []gateJSON    `json:"gates"`
	Project       projectJSON   `json:"project"`
}

type toolchainJSON struct {
	Language string `json:"language"`
	Version  string `json:"version"`
}

type scopeJSON struct {
	IncludeFamilies []string `json:"includeFamilies"`
	ExcludeFamilies []string `json:"excludeFamilies"`
}

type gateJSON struct {
	Name             string   `json:"name"`
	Command          string   `json:"command"`
	Args             []string `json:"args"`
	Timeout          string   `json:"timeout"`
	WorkingDirectory string   `json:"workingDirectory"`
	IncludeFamilies  []string `json:"includeFamilies"`
	ExcludeFamilies  []string `json:"excludeFamilies"`
}

type projectJSON struct {
	Binaries []binaryJSON `json:"binaries"`
	Fuzz     []fuzzJSON   `json:"fuzz"`
}

type binaryJSON struct {
	Package string   `json:"package"`
	Smoke   []string `json:"smoke"`
}

type fuzzJSON struct {
	Package string `json:"package"`
	Target  string `json:"target"`
	Time    string `json:"time"`
}

// DecodeConfig strictly decodes and validates the canonical configuration
// seam. Unknown fields, trailing documents, and invariant violations are
// rejected with a precise field error.
func DecodeConfig(contents []byte) (Config, error) {
	if len(contents) == 0 {
		return Config{}, errors.New("quality configuration must not be empty")
	}
	if len(contents) > maxConfigBytes {
		return Config{}, fmt.Errorf("quality configuration must not exceed %d bytes", maxConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var document configDocument
	if err := decoder.Decode(&document); err != nil {
		return Config{}, fmt.Errorf("quality configuration must contain valid JSON with known fields: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("quality configuration must contain exactly one JSON document")
	}
	return validateDocument(document)
}

func validateDocument(document configDocument) (Config, error) {
	if document.SchemaVersion != SchemaVersion {
		return Config{}, fmt.Errorf("schemaVersion must equal %d", SchemaVersion)
	}
	if !languagePattern.MatchString(document.Toolchain.Language) {
		return Config{}, fmt.Errorf("toolchain.language must be a lowercase language identifier such as go")
	}
	if !versionPattern.MatchString(document.Toolchain.Version) {
		return Config{}, fmt.Errorf("toolchain.version must be a pinned version such as 1.26.6")
	}
	if err := validateExtends(document.Extends); err != nil {
		return Config{}, err
	}
	if len(document.Gates) == 0 || len(document.Gates) > maxGateCount {
		return Config{}, fmt.Errorf("gates must contain between 1 and %d entries", maxGateCount)
	}
	if err := validateScope("defaults", document.Defaults); err != nil {
		return Config{}, err
	}

	config := Config{
		SchemaVersion: document.SchemaVersion,
		Toolchain: Toolchain{
			Language: document.Toolchain.Language,
			Version:  document.Toolchain.Version,
		},
		Extends: document.Extends,
		Defaults: Scope{
			IncludeFamilies: document.Defaults.IncludeFamilies,
			ExcludeFamilies: document.Defaults.ExcludeFamilies,
		},
		Gates: make([]Gate, 0, len(document.Gates)),
		Project: Project{
			Binaries: make([]Binary, 0, len(document.Project.Binaries)),
			Fuzz:     make([]FuzzTarget, 0, len(document.Project.Fuzz)),
		},
	}

	seen := make(map[string]struct{}, len(document.Gates))
	for _, gate := range document.Gates {
		if err := validateGate(gate, seen); err != nil {
			return Config{}, err
		}
		config.Gates = append(config.Gates, convertGate(gate))
	}
	if err := validateProject(document.Project); err != nil {
		return Config{}, err
	}
	for _, binary := range document.Project.Binaries {
		config.Project.Binaries = append(config.Project.Binaries, Binary(binary))
	}
	for _, target := range document.Project.Fuzz {
		config.Project.Fuzz = append(config.Project.Fuzz, FuzzTarget(target))
	}
	return config, nil
}

func validateGate(gate gateJSON, seen map[string]struct{}) error {
	if !gateNamePattern.MatchString(gate.Name) {
		return fmt.Errorf("gate names must use lowercase letters, digits, hyphens, or underscores: %q", gate.Name)
	}
	if _, found := seen[gate.Name]; found {
		return fmt.Errorf("gate names must be unique: %q", gate.Name)
	}
	seen[gate.Name] = struct{}{}
	if strings.TrimSpace(gate.Command) == "" || strings.ContainsAny(gate.Command, "\r\n") {
		return fmt.Errorf("gate %q command must be a non-empty executable name or path", gate.Name)
	}
	if len(gate.Args) > maxArgumentCount {
		return fmt.Errorf("gate %q may contain at most %d arguments", gate.Name, maxArgumentCount)
	}
	for _, argument := range gate.Args {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("gate %q arguments cannot contain NUL or line-control characters", gate.Name)
		}
	}
	if _, err := GateTimeout(gate.Timeout); err != nil {
		return fmt.Errorf("gate %q has an invalid timeout: %w", gate.Name, err)
	}
	if err := validateScope("gate "+gate.Name, scopeJSON{
		IncludeFamilies: gate.IncludeFamilies,
		ExcludeFamilies: gate.ExcludeFamilies,
	}); err != nil {
		return err
	}
	return nil
}

func convertGate(gate gateJSON) Gate {
	return Gate(gate)
}

// validateExtends checks the capability pack declaration form. The decoder
// validates the reference grammar only; resolving a pack against the registry
// is the orchestrator's provisioning responsibility.
func validateExtends(references []string) error {
	if len(references) > maxExtendsCount {
		return fmt.Errorf("extends must contain at most %d capability pack references", maxExtendsCount)
	}
	seen := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if !packReferencePattern.MatchString(reference) {
			return fmt.Errorf("extends entries must use the <capability>@<major> form such as opentofu@1: %q", reference)
		}
		if _, found := seen[reference]; found {
			return fmt.Errorf("extends entries must be unique: %q", reference)
		}
		seen[reference] = struct{}{}
	}
	return nil
}

func validateScope(label string, scope scopeJSON) error {
	included := make(map[string]struct{}, len(scope.IncludeFamilies))
	for _, family := range scope.IncludeFamilies {
		if strings.TrimSpace(family) == "" {
			return fmt.Errorf("%s includes an empty branch family", label)
		}
		if _, found := included[family]; found {
			return fmt.Errorf("%s cannot include the same branch family more than once: %q", label, family)
		}
		included[family] = struct{}{}
	}
	excluded := make(map[string]struct{}, len(scope.ExcludeFamilies))
	for _, family := range scope.ExcludeFamilies {
		if strings.TrimSpace(family) == "" {
			return fmt.Errorf("%s excludes an empty branch family", label)
		}
		if _, found := excluded[family]; found {
			return fmt.Errorf("%s cannot exclude the same branch family more than once: %q", label, family)
		}
		if _, found := included[family]; found {
			return fmt.Errorf("%s cannot both include and exclude %q", label, family)
		}
		excluded[family] = struct{}{}
	}
	return nil
}

func validateProject(project projectJSON) error {
	if len(project.Binaries) > maxBinaryCount {
		return fmt.Errorf("project.binaries must contain at most %d entries", maxBinaryCount)
	}
	if len(project.Fuzz) > maxFuzzCount {
		return fmt.Errorf("project.fuzz must contain at most %d entries", maxFuzzCount)
	}
	seenBinaries := make(map[string]struct{}, len(project.Binaries))
	for _, binary := range project.Binaries {
		if !packagePattern.MatchString(binary.Package) {
			return fmt.Errorf("project.binaries package must be a repository-relative package path: %q", binary.Package)
		}
		if _, found := seenBinaries[binary.Package]; found {
			return fmt.Errorf("project.binaries package must be unique: %q", binary.Package)
		}
		seenBinaries[binary.Package] = struct{}{}
		if len(binary.Smoke) > maxSmokeCount {
			return fmt.Errorf("project.binaries %q may contain at most %d smoke arguments", binary.Package, maxSmokeCount)
		}
		for _, argument := range binary.Smoke {
			if strings.ContainsAny(argument, "\x00\r\n") {
				return fmt.Errorf("project.binaries %q smoke arguments cannot contain NUL or line-control characters", binary.Package)
			}
		}
	}
	seenFuzz := make(map[string]struct{}, len(project.Fuzz))
	for _, target := range project.Fuzz {
		if !packagePattern.MatchString(target.Package) {
			return fmt.Errorf("project.fuzz package must be a repository-relative package path: %q", target.Package)
		}
		if !fuzzNamePattern.MatchString(target.Target) {
			return fmt.Errorf("project.fuzz target must be a Fuzz function name: %q", target.Target)
		}
		key := target.Package + "|" + target.Target
		if _, found := seenFuzz[key]; found {
			return fmt.Errorf("project.fuzz target must be unique: %q", key)
		}
		seenFuzz[key] = struct{}{}
		if _, err := FuzzTime(target.Time); err != nil {
			return fmt.Errorf("project.fuzz %q has an invalid time budget: %w", target.Target, err)
		}
	}
	return nil
}

// GateTimeout resolves a gate timeout against the canonical fallback.
func GateTimeout(raw string) (time.Duration, error) {
	if raw == "" {
		return defaultGateTimeout, nil
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout <= 0 {
		return 0, errors.New("timeout must be a positive Go duration")
	}
	return timeout, nil
}

// FuzzTime validates a fuzz execution budget such as 50000x or 30s.
func FuzzTime(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("fuzz time budget must not be empty")
	}
	if strings.HasSuffix(raw, "x") {
		count := strings.TrimSuffix(raw, "x")
		if count == "" {
			return "", errors.New("fuzz execution count must not be empty")
		}
		for _, r := range count {
			if r < '0' || r > '9' {
				return "", fmt.Errorf("fuzz execution count must be numeric: %q", raw)
			}
		}
		return raw, nil
	}
	if _, err := time.ParseDuration(raw); err != nil {
		return "", fmt.Errorf("fuzz time budget must be a positive Go duration or an execution count: %q", raw)
	}
	return raw, nil
}
