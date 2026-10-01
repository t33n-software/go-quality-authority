package quality

import (
	"strings"
	"testing"
	"time"
)

func validConfigJSON() string {
	return `{
  "schemaVersion": 4,
  "toolchain": { "language": "go", "version": "1.26.6" },
  "extends": ["opentofu@1"],
  "defaults": { "includeFamilies": ["feature", "fix"] },
  "gates": [
    {
      "name": "full-local-build",
      "command": "go",
      "args": ["tool", "-modfile", "tools/go.mod", "quality-gate"],
      "timeout": "15m"
    }
  ],
  "project": {
    "binaries": [{ "package": "./cmd/tool", "smoke": ["--version"] }],
    "fuzz": [{ "package": "./internal/boundary", "target": "FuzzParse", "time": "50000x" }]
  }
}`
}

func TestDecodeConfigValid(t *testing.T) {
	config, err := DecodeConfig([]byte(validConfigJSON()))
	if err != nil {
		t.Fatalf("DecodeConfig returned error: %v", err)
	}
	if config.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", config.SchemaVersion, SchemaVersion)
	}
	if config.Toolchain.Language != "go" || config.Toolchain.Version != "1.26.6" {
		t.Fatalf("Toolchain = %+v", config.Toolchain)
	}
	if len(config.Extends) != 1 || config.Extends[0] != "opentofu@1" {
		t.Fatalf("Extends = %+v", config.Extends)
	}
	if len(config.Gates) != 1 || config.Gates[0].Name != "full-local-build" {
		t.Fatalf("Gates = %+v", config.Gates)
	}
	if len(config.Project.Binaries) != 1 || config.Project.Binaries[0].Package != "./cmd/tool" {
		t.Fatalf("Binaries = %+v", config.Project.Binaries)
	}
	if len(config.Project.Fuzz) != 1 || config.Project.Fuzz[0].Target != "FuzzParse" {
		t.Fatalf("Fuzz = %+v", config.Project.Fuzz)
	}
}

func TestDecodeConfigRejectsEmpty(t *testing.T) {
	if _, err := DecodeConfig(nil); err == nil {
		t.Fatal("expected an error for empty contents")
	}
}

func TestDecodeConfigRejectsOversized(t *testing.T) {
	contents := make([]byte, maxConfigBytes+1)
	if _, err := DecodeConfig(contents); err == nil {
		t.Fatal("expected an error for oversized contents")
	}
}

func TestDecodeConfigRejectsInvalidJSON(t *testing.T) {
	if _, err := DecodeConfig([]byte("{")); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestDecodeConfigRejectsUnknownField(t *testing.T) {
	if _, err := DecodeConfig([]byte(`{"schemaVersion":4,"toolchain":{"language":"go","version":"1.26.6"},"gates":[{"name":"a","command":"go"}],"bogus":true}`)); err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}

func TestDecodeConfigRejectsTrailingDocument(t *testing.T) {
	contents := validConfigJSON() + "\n{}"
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for a trailing document")
	}
}

func TestDecodeConfigRejectsWrongSchemaVersion(t *testing.T) {
	// Both the previous v3 form and any future unsupported version are
	// rejected: the decoder accepts exactly the canonical version.
	for _, version := range []string{"3", "5"} {
		contents := strings.Replace(validConfigJSON(), `"schemaVersion": 4`, `"schemaVersion": `+version, 1)
		if _, err := DecodeConfig([]byte(contents)); err == nil {
			t.Fatalf("expected an error for schemaVersion %s", version)
		}
	}
}

func TestDecodeConfigRejectsThePreviousWireForm(t *testing.T) {
	// The v3 toolchain field is an unknown field under the v4 wire form.
	if _, err := DecodeConfig([]byte(`{"schemaVersion":4,"toolchain":{"goVersion":"1.26.6"},"gates":[{"name":"a","command":"go"}]}`)); err == nil {
		t.Fatal("expected an error for the v3 toolchain wire form")
	}
}

func TestDecodeConfigRejectsInvalidToolchainLanguage(t *testing.T) {
	contents := strings.Replace(validConfigJSON(), `"language": "go"`, `"language": "Go"`, 1)
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for an invalid toolchain language")
	}
}

func TestDecodeConfigRejectsInvalidToolchainVersion(t *testing.T) {
	contents := strings.Replace(validConfigJSON(), `"version": "1.26.6"`, `"version": "latest"`, 1)
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for an invalid toolchain version")
	}
}

func TestDecodeConfigValidatesExtends(t *testing.T) {
	t.Run("absent and empty declarations are valid", func(t *testing.T) {
		for _, contents := range []string{
			`{"schemaVersion":4,"toolchain":{"language":"go","version":"1.26.6"},"gates":[{"name":"a","command":"go"}]}`,
			`{"schemaVersion":4,"toolchain":{"language":"go","version":"1.26.6"},"extends":[],"gates":[{"name":"a","command":"go"}]}`,
		} {
			if _, err := DecodeConfig([]byte(contents)); err != nil {
				t.Fatalf("DecodeConfig rejected a valid declaration: %v", err)
			}
		}
	})

	tests := []struct {
		name    string
		extends string
		wantErr string
	}{
		{name: "missing major version", extends: `["opentofu"]`, wantErr: "<capability>@<major>"},
		{name: "unpinned major version", extends: `["opentofu@latest"]`, wantErr: "<capability>@<major>"},
		{name: "uppercase capability", extends: `["OpenTofu@1"]`, wantErr: "<capability>@<major>"},
		{name: "duplicate reference", extends: `["opentofu@1","opentofu@1"]`, wantErr: "unique"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contents := strings.Replace(validConfigJSON(), `"extends": ["opentofu@1"]`, `"extends": `+test.extends, 1)
			_, err := DecodeConfig([]byte(contents))
			if err == nil {
				t.Fatalf("expected an error containing %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
		})
	}

	t.Run("too many references", func(t *testing.T) {
		references := make([]string, 0, maxExtendsCount+1)
		for index := 0; index <= maxExtendsCount; index++ {
			references = append(references, `"capability-`+strings.Repeat("x", index+1)+`@1"`)
		}
		contents := strings.Replace(validConfigJSON(), `"extends": ["opentofu@1"]`, `"extends": [`+strings.Join(references, ",")+`]`, 1)
		if _, err := DecodeConfig([]byte(contents)); err == nil {
			t.Fatal("expected an error for too many extends references")
		}
	})
}

func TestDecodeConfigRejectsEmptyGates(t *testing.T) {
	contents := strings.Replace(validConfigJSON(), `"gates": [
    {
      "name": "full-local-build",
      "command": "go",
      "args": ["tool", "-modfile", "tools/go.mod", "quality-gate"],
      "timeout": "15m"
    }
  ]`, `"gates": []`, 1)
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for empty gates")
	}
}

func TestDecodeConfigGateValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "invalid gate name",
			mutate: func(s string) string {
				return strings.Replace(s, `"name": "full-local-build"`, `"name": "Full_Local_Build!"`, 1)
			},
			wantErr: "gate names",
		},
		{
			name: "duplicate gate name",
			mutate: func(s string) string {
				return strings.Replace(s, `"timeout": "15m"
    }
  ]`, `"timeout": "15m"
    },
    {
      "name": "full-local-build",
      "command": "go"
    }
  ]`, 1)
			},
			wantErr: "unique",
		},
		{
			name: "empty command",
			mutate: func(s string) string {
				return strings.Replace(s, `"command": "go"`, `"command": " "`, 1)
			},
			wantErr: "command",
		},
		{
			name: "invalid timeout",
			mutate: func(s string) string {
				return strings.Replace(s, `"timeout": "15m"`, `"timeout": "never"`, 1)
			},
			wantErr: "timeout",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeConfig([]byte(test.mutate(validConfigJSON()))); err == nil {
				t.Fatalf("expected an error containing %q", test.wantErr)
			} else if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestDecodeConfigRejectsDuplicateDefaultsFamily(t *testing.T) {
	contents := strings.Replace(validConfigJSON(), `"includeFamilies": ["feature", "fix"]`, `"includeFamilies": ["feature", "feature"]`, 1)
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for a duplicate defaults family")
	}
}

func TestDecodeConfigRejectsIncludeExcludeConflict(t *testing.T) {
	contents := strings.Replace(validConfigJSON(), `"includeFamilies": ["feature", "fix"]`, `"includeFamilies": ["feature"], "excludeFamilies": ["feature"]`, 1)
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for an include/exclude conflict")
	}
}

func TestDecodeConfigRejectsDuplicateProjectBinary(t *testing.T) {
	contents := strings.Replace(validConfigJSON(), `"binaries": [{ "package": "./cmd/tool", "smoke": ["--version"] }]`, `"binaries": [{ "package": "./cmd/tool" }, { "package": "./cmd/tool" }]`, 1)
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for a duplicate project binary")
	}
}

func TestDecodeConfigRejectsInvalidFuzzTarget(t *testing.T) {
	contents := strings.Replace(validConfigJSON(), `"target": "FuzzParse"`, `"target": "Parse"`, 1)
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for an invalid fuzz target")
	}
}

func TestDecodeConfigRejectsInvalidFuzzTime(t *testing.T) {
	contents := strings.Replace(validConfigJSON(), `"time": "50000x"`, `"time": "often"`, 1)
	if _, err := DecodeConfig([]byte(contents)); err == nil {
		t.Fatal("expected an error for an invalid fuzz time")
	}
}

func TestGateTimeout(t *testing.T) {
	fallback, err := GateTimeout("")
	if err != nil {
		t.Fatalf("GateTimeout empty: %v", err)
	}
	if fallback != defaultGateTimeout {
		t.Fatalf("fallback = %v, want %v", fallback, defaultGateTimeout)
	}
	parsed, err := GateTimeout("90s")
	if err != nil {
		t.Fatalf("GateTimeout 90s: %v", err)
	}
	if parsed != 90*time.Second {
		t.Fatalf("parsed = %v", parsed)
	}
	if _, err := GateTimeout("never"); err == nil {
		t.Fatal("expected an error for an invalid timeout")
	}
	if _, err := GateTimeout("-5s"); err == nil {
		t.Fatal("expected an error for a negative timeout")
	}
}

func TestFuzzTime(t *testing.T) {
	if _, err := FuzzTime(""); err == nil {
		t.Fatal("expected an error for an empty budget")
	}
	if _, err := FuzzTime("x"); err == nil {
		t.Fatal("expected an error for an empty execution count")
	}
	if _, err := FuzzTime("10x"); err != nil {
		t.Fatalf("FuzzTime 10x: %v", err)
	}
	if _, err := FuzzTime("5ax"); err == nil {
		t.Fatal("expected an error for a non-numeric execution count")
	}
	if _, err := FuzzTime("30s"); err != nil {
		t.Fatalf("FuzzTime 30s: %v", err)
	}
	if _, err := FuzzTime("often"); err == nil {
		t.Fatal("expected an error for an invalid budget")
	}
}

// configWithGates builds a minimal valid config carrying the given gates JSON
// fragment so branch tests can isolate a single gate invariant.
func configWithGates(t *testing.T, gates string) string {
	t.Helper()
	return `{
  "schemaVersion": 4,
  "toolchain": { "language": "go", "version": "1.26.6" },
  "gates": [` + gates + `]
}`
}

func TestDecodeConfigGateBranchLimits(t *testing.T) {
	manyArgs := make([]string, 0, maxArgumentCount+1)
	for i := 0; i <= maxArgumentCount; i++ {
		manyArgs = append(manyArgs, `"a"`)
	}
	tests := []struct {
		name  string
		gates string
	}{
		{
			name:  "too many arguments",
			gates: `{"name":"a","command":"go","args":[` + strings.Join(manyArgs, ",") + `]}`,
		},
		{
			name:  "argument with control character",
			gates: `{"name":"a","command":"go","args":["bad\u0000arg"]}`,
		},
		{
			name:  "gate scope include exclude conflict",
			gates: `{"name":"a","command":"go","includeFamilies":["feature"],"excludeFamilies":["feature"]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeConfig([]byte(configWithGates(t, test.gates))); err == nil {
				t.Fatal("expected a decode error")
			}
		})
	}
}

func TestDecodeConfigScopeBranches(t *testing.T) {
	tests := []struct {
		name    string
		scope   string
		wantErr string
	}{
		{name: "empty include family", scope: `"includeFamilies":[" "]`, wantErr: "empty branch family"},
		{name: "empty exclude family", scope: `"excludeFamilies":[" "]`, wantErr: "empty branch family"},
		{name: "duplicate exclude family", scope: `"excludeFamilies":["fix","fix"]`, wantErr: "more than once"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contents := `{
  "schemaVersion": 4,
  "toolchain": { "language": "go", "version": "1.26.6" },
  "defaults": { ` + test.scope + ` },
  "gates": [{"name":"a","command":"go"}]
}`
			if _, err := DecodeConfig([]byte(contents)); err == nil {
				t.Fatalf("expected an error containing %q", test.wantErr)
			} else if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestDecodeConfigProjectBranches(t *testing.T) {
	base := func(project string) string {
		return `{
  "schemaVersion": 4,
  "toolchain": { "language": "go", "version": "1.26.6" },
  "gates": [{"name":"a","command":"go"}],
  "project": ` + project + `
}`
	}
	manyBinaries := make([]string, 0, maxBinaryCount+1)
	for i := 0; i <= maxBinaryCount; i++ {
		manyBinaries = append(manyBinaries, `{"package":"./cmd/t`+strings.Repeat("x", 1)+`"}`)
	}
	manySmoke := make([]string, 0, maxSmokeCount+1)
	for i := 0; i <= maxSmokeCount; i++ {
		manySmoke = append(manySmoke, `"s"`)
	}
	manyFuzz := make([]string, 0, maxFuzzCount+1)
	for i := 0; i <= maxFuzzCount; i++ {
		manyFuzz = append(manyFuzz, `{"package":"./internal/a","target":"FuzzA","time":"1x"}`)
	}
	tests := []struct {
		name    string
		project string
	}{
		{name: "too many binaries", project: `{"binaries":[` + strings.Join(manyBinaries, ",") + `]}`},
		{name: "invalid binary package", project: `{"binaries":[{"package":"cmd/tool"}]}`},
		{name: "too many smoke arguments", project: `{"binaries":[{"package":"./cmd/t","smoke":[` + strings.Join(manySmoke, ",") + `]}]}`},
		{name: "smoke argument with control character", project: `{"binaries":[{"package":"./cmd/t","smoke":["bad\u0000"]}]}`},
		{name: "too many fuzz targets", project: `{"fuzz":[` + strings.Join(manyFuzz, ",") + `]}`},
		{name: "invalid fuzz package", project: `{"fuzz":[{"package":"internal/a","target":"FuzzA","time":"1x"}]}`},
		{name: "duplicate fuzz target", project: `{"fuzz":[{"package":"./internal/a","target":"FuzzA","time":"1x"},{"package":"./internal/a","target":"FuzzA","time":"1x"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeConfig([]byte(base(test.project))); err == nil {
				t.Fatal("expected a decode error")
			}
		})
	}
}
