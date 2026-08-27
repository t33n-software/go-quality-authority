package quality

import (
	"strings"
	"testing"
)

// validPackJSON is the compact, fully valid capability-pack/v1 document every
// rejection case mutates exactly once.
func validPackJSON() string {
	return `{"schema":"capability-pack/v1","capability":"opentofu","area":"infrastructure","version":1,"summary":"OpenTofu infrastructure gates.","provisioning":{"kind":"recipe","tool":"tofu","version":"1.12.5","environment":{"OPENTOFU_ENFORCE_GPG_VALIDATION":"true"},"artifacts":{"linux-amd64":{"url":"https://example.com/tofu.zip","sha256":"dade9650e6b74fc7a8b986bd8717497d32f9e09cf82e479afef4977fa3085536","signature":"https://example.com/tofu.zip.sig"}}},"discovery":{"roots":{"fileGlob":"**/*.tf"},"excludeDirs":[".terraform"]},"assertions":[{"name":"opentofu-version","command":"tofu","args":["version"],"expect":"OpenTofu v1.12.5"}],"gates":[{"name":"opentofu-fmt-check","command":"tofu","args":["fmt","-check"],"scope":"repository"},{"name":"opentofu-validate","command":"tofu","args":["validate"],"scope":"per-root","timeout":"5m"}]}`
}

func TestDecodePackDescriptor(t *testing.T) {
	descriptor, err := DecodePackDescriptor([]byte(validPackJSON()))
	if err != nil {
		t.Fatalf("DecodePackDescriptor: %v", err)
	}
	if descriptor.Schema != PackSchemaID {
		t.Fatalf("schema = %q", descriptor.Schema)
	}
	if descriptor.Capability != "opentofu" || descriptor.Area != "infrastructure" || descriptor.Version != 1 {
		t.Fatalf("identity = %+v", descriptor)
	}
	if descriptor.Summary != "OpenTofu infrastructure gates." {
		t.Fatalf("summary = %q", descriptor.Summary)
	}
	provisioning := descriptor.Provisioning
	if provisioning.Kind != PackProvisioningRecipe || provisioning.Tool != "tofu" || provisioning.Version != "1.12.5" {
		t.Fatalf("provisioning = %+v", provisioning)
	}
	if provisioning.Environment["OPENTOFU_ENFORCE_GPG_VALIDATION"] != "true" {
		t.Fatalf("environment = %+v", provisioning.Environment)
	}
	artifact, found := provisioning.Artifacts["linux-amd64"]
	if !found {
		t.Fatalf("artifacts = %+v", provisioning.Artifacts)
	}
	if artifact.URL != "https://example.com/tofu.zip" || artifact.Signature != "https://example.com/tofu.zip.sig" {
		t.Fatalf("artifact = %+v", artifact)
	}
	if descriptor.Discovery.Roots.FileGlob != "**/*.tf" || len(descriptor.Discovery.ExcludeDirs) != 1 {
		t.Fatalf("discovery = %+v", descriptor.Discovery)
	}
	if len(descriptor.Assertions) != 1 || descriptor.Assertions[0].Expect != "OpenTofu v1.12.5" {
		t.Fatalf("assertions = %+v", descriptor.Assertions)
	}
	if len(descriptor.Gates) != 2 {
		t.Fatalf("gates = %+v", descriptor.Gates)
	}
	if descriptor.Gates[0].Scope != PackScopeRepository || descriptor.Gates[1].Scope != PackScopePerRoot {
		t.Fatalf("gate scopes = %+v", descriptor.Gates)
	}
	if descriptor.Gates[1].Timeout != "5m" {
		t.Fatalf("gate timeout = %q", descriptor.Gates[1].Timeout)
	}
}

func TestDecodePackDescriptorWithoutSignature(t *testing.T) {
	// The signature reference is optional; a descriptor without it decodes.
	document := strings.Replace(validPackJSON(), `,"signature":"https://example.com/tofu.zip.sig"`, ``, 1)
	descriptor, err := DecodePackDescriptor([]byte(document))
	if err != nil {
		t.Fatalf("DecodePackDescriptor without signature: %v", err)
	}
	if descriptor.Provisioning.Artifacts["linux-amd64"].Signature != "" {
		t.Fatal("expected no signature reference")
	}
}

func TestDecodePackDescriptorBootstrapForm(t *testing.T) {
	// The engine-bound signature verifier bootstrap form: the install-proof
	// assertion without the gates and discovery surfaces.
	document := `{"schema":"capability-pack/v1","capability":"cosign","area":"security","version":1,"summary":"Signature verifier bootstrap.","provisioning":{"kind":"recipe","tool":"cosign","version":"3.0.6","environment":{},"artifacts":{"linux-amd64":{"url":"https://example.com/cosign-linux-amd64","sha256":"` + strings.Repeat("b", 64) + `"}}},"assertions":[{"name":"cosign-version","command":"cosign","args":["version"],"expect":"v3.0.6"}]}`
	descriptor, err := DecodePackDescriptor([]byte(document))
	if err != nil {
		t.Fatalf("DecodePackDescriptor: %v", err)
	}
	if descriptor.Gates != nil || descriptor.Discovery != nil {
		t.Fatalf("the bootstrap form carries no gates or discovery surface: %+v", descriptor)
	}
	if len(descriptor.Assertions) != 1 || descriptor.Assertions[0].Expect != "v3.0.6" {
		t.Fatalf("assertions = %+v", descriptor.Assertions)
	}
}

func TestDecodePackDescriptorRepositoryGateWithoutDiscovery(t *testing.T) {
	// A repository-scope gate needs no discovery surface.
	document := `{"schema":"capability-pack/v1","capability":"cosign","area":"security","version":1,"summary":"A repository-scope gate needs no discovery.","provisioning":{"kind":"recipe","tool":"cosign","version":"3.0.6","environment":{},"artifacts":{"linux-amd64":{"url":"https://example.com/cosign-linux-amd64","sha256":"` + strings.Repeat("b", 64) + `"}}},"assertions":[],"gates":[{"name":"cosign-verify","command":"cosign","args":["verify"],"scope":"repository"}]}`
	descriptor, err := DecodePackDescriptor([]byte(document))
	if err != nil {
		t.Fatalf("DecodePackDescriptor: %v", err)
	}
	if descriptor.Discovery != nil || len(descriptor.Gates) != 1 {
		t.Fatalf("descriptor = %+v", descriptor)
	}
}

func TestDecodePackDescriptorRejections(t *testing.T) {
	cases := []struct {
		name     string
		document string
		want     string
	}{
		{"empty", ``, "must not be empty"},
		{"not json", `not json`, "valid JSON with known fields"},
		{"trailing document", validPackJSON() + ` {}`, "exactly one JSON document"},
		{"unknown field", strings.Replace(validPackJSON(), `"summary"`, `"bogus":true,"summary"`, 1), "valid JSON with known fields"},
		{"wrong schema", strings.Replace(validPackJSON(), `"schema":"capability-pack/v1"`, `"schema":"capability-pack/v2"`, 1), `schema must be "capability-pack/v1"`},
		{"capability not kebab", strings.Replace(validPackJSON(), `"capability":"opentofu"`, `"capability":"OpenTofu"`, 1), "capability"},
		{"area not kebab", strings.Replace(validPackJSON(), `"area":"infrastructure"`, `"area":"Infra"`, 1), "area"},
		{"version zero", strings.Replace(validPackJSON(), `"version":1`, `"version":0`, 1), "version must be a positive major version"},
		{"empty summary", strings.Replace(validPackJSON(), `"summary":"OpenTofu infrastructure gates."`, `"summary":" "`, 1), "summary must not be empty"},
		{"wrong provisioning kind", strings.Replace(validPackJSON(), `"kind":"recipe"`, `"kind":"binary"`, 1), `kind must be "recipe"`},
		{"tool not lowercase", strings.Replace(validPackJSON(), `"tool":"tofu"`, `"tool":"Tofu"`, 1), "tool"},
		{"version not pinned", strings.Replace(validPackJSON(), `"version":"1.12.5"`, `"version":"latest"`, 1), "must be a pinned version"},
		{"environment key not upper snake", strings.Replace(validPackJSON(), `"OPENTOFU_ENFORCE_GPG_VALIDATION":"true"`, `"opentofu_enforce":"true"`, 1), "environment key"},
		{"environment value control", strings.Replace(validPackJSON(), `"OPENTOFU_ENFORCE_GPG_VALIDATION":"true"`, `"OPENTOFU_ENFORCE_GPG_VALIDATION":"tr\nue"`, 1), "must not contain NUL or line-control"},
		{"no artifacts", strings.Replace(validPackJSON(), `"artifacts":{"linux-amd64":{"url":"https://example.com/tofu.zip","sha256":"dade9650e6b74fc7a8b986bd8717497d32f9e09cf82e479afef4977fa3085536","signature":"https://example.com/tofu.zip.sig"}}`, `"artifacts":{}`, 1), "artifacts must bind at least one platform"},
		{"bad platform key", strings.Replace(validPackJSON(), `"linux-amd64":{`, `"linuxamd64":{`, 1), "must use the <goos>-<goarch> form"},
		{"artifact url not https", strings.Replace(validPackJSON(), `"url":"https://example.com/tofu.zip"`, `"url":"http://example.com/tofu.zip"`, 1), "url must use https"},
		{"artifact url control", strings.Replace(validPackJSON(), `"url":"https://example.com/tofu.zip"`, `"url":"https://example.com/tofu\n.zip"`, 1), "url must not contain control characters"},
		{"artifact digest malformed", strings.Replace(validPackJSON(), `"sha256":"dade9650e6b74fc7a8b986bd8717497d32f9e09cf82e479afef4977fa3085536"`, `"sha256":"abc"`, 1), "sha256 must be 64 lowercase hex"},
		{"signature control", strings.Replace(validPackJSON(), `"signature":"https://example.com/tofu.zip.sig"`, `"signature":"https://example.com/tofu\n.zip.sig"`, 1), "signature reference must not contain control characters"},
		{"file glob empty", strings.Replace(validPackJSON(), `"fileGlob":"**/*.tf"`, `"fileGlob":""`, 1), "roots.fileGlob must be a non-empty glob"},
		{"discovery present but empty", strings.Replace(validPackJSON(), `"discovery":{"roots":{"fileGlob":"**/*.tf"},"excludeDirs":[".terraform"]}`, `"discovery":{}`, 1), "roots.fileGlob"},
		{"per-root gate without discovery", strings.Replace(validPackJSON(), `"discovery":{"roots":{"fileGlob":"**/*.tf"},"excludeDirs":[".terraform"]},`, ``, 1), "per-root scope requires the discovery surface"},
		{"file glob control", strings.Replace(validPackJSON(), `"fileGlob":"**/*.tf"`, `"fileGlob":"**/*.t\nf"`, 1), "roots.fileGlob must be a non-empty glob"},
		{"exclude dir empty", strings.Replace(validPackJSON(), `"excludeDirs":[".terraform"]`, `"excludeDirs":[""]`, 1), "must be a non-empty directory name"},
		{"exclude dir control", strings.Replace(validPackJSON(), `"excludeDirs":[".terraform"]`, `"excludeDirs":[".terr\naform"]`, 1), "must be a non-empty directory name"},
		{"exclude dir duplicate", strings.Replace(validPackJSON(), `"excludeDirs":[".terraform"]`, `"excludeDirs":[".terraform",".terraform"]`, 1), "is not unique"},
		{"assertion name not kebab", strings.Replace(validPackJSON(), `"name":"opentofu-version"`, `"name":"Opentofu-version"`, 1), "assertion name"},
		{"assertion command empty", strings.Replace(validPackJSON(), `"command":"tofu","args":["version"]`, `"command":"","args":["version"]`, 1), "command must be a non-empty executable"},
		{"assertion args control", strings.Replace(validPackJSON(), `"args":["version"]`, `"args":["ver\nsion"]`, 1), "must not contain NUL or line-control"},
		{"assertion expect empty", strings.Replace(validPackJSON(), `"expect":"OpenTofu v1.12.5"`, `"expect":""`, 1), "expect must not be empty"},
		{"gates empty", strings.Replace(validPackJSON(), `"gates":[{"name":"opentofu-fmt-check","command":"tofu","args":["fmt","-check"],"scope":"repository"},{"name":"opentofu-validate","command":"tofu","args":["validate"],"scope":"per-root","timeout":"5m"}]`, `"gates":[]`, 1), "gates must not be empty"},
		{"gate name not kebab", strings.Replace(validPackJSON(), `"name":"opentofu-fmt-check"`, `"name":"Opentofu-fmt-check"`, 1), "gate name"},
		{"gate name without prefix", strings.Replace(validPackJSON(), `"name":"opentofu-fmt-check"`, `"name":"fmt-check"`, 1), "must be prefixed by the capability"},
		{"gate command empty", strings.Replace(validPackJSON(), `"command":"tofu","args":["fmt","-check"]`, `"command":"","args":["fmt","-check"]`, 1), "command must be a non-empty executable"},
		{"gate args control", strings.Replace(validPackJSON(), `"args":["fmt","-check"]`, `"args":["fmt","-che\nck"]`, 1), "must not contain NUL or line-control"},
		{"gate scope invalid", strings.Replace(validPackJSON(), `"scope":"repository"`, `"scope":"project"`, 1), "scope"},
		{"gate timeout invalid", strings.Replace(validPackJSON(), `"timeout":"5m"`, `"timeout":"abc"`, 1), "must be a positive Go duration"},
		{"gate timeout negative", strings.Replace(validPackJSON(), `"timeout":"5m"`, `"timeout":"-5m"`, 1), "must be a positive Go duration"},
		{"gate names duplicate", strings.Replace(validPackJSON(), `"name":"opentofu-validate"`, `"name":"opentofu-fmt-check"`, 1), "is not unique"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := DecodePackDescriptor([]byte(testCase.document))
			if err == nil {
				t.Fatalf("expected the rejection of %s", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %q, want it to contain %q", err, testCase.want)
			}
		})
	}
}

func TestDecodePackDescriptorForbiddenContent(t *testing.T) {
	document := strings.Replace(validPackJSON(), `"summary":"OpenTofu infrastructure gates."`, `"summary":"-----BEGIN PRIVATE KEY-----"`, 1)
	_, err := DecodePackDescriptor([]byte(document))
	if err == nil {
		t.Fatal("expected the forbidden-content rejection")
	}
	if !strings.Contains(err.Error(), "forbidden credential-like content") {
		t.Fatalf("error = %q", err)
	}
}

func TestRejectForbiddenPackContentMarkers(t *testing.T) {
	// Every marker of the mirrored credential boundary fires, case-insensitively.
	for _, marker := range forbiddenPackContentMarkers {
		probe := []byte("prefix " + strings.ToUpper(marker) + " suffix")
		if err := rejectForbiddenPackContent(probe); err == nil {
			t.Fatalf("expected the marker %q to be rejected", marker)
		}
	}
	if err := rejectForbiddenPackContent([]byte(validPackJSON())); err != nil {
		t.Fatalf("the valid descriptor must pass the guard: %v", err)
	}
}
