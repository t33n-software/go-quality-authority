package quality

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// provisionState carries the fake seam state of a provisioning test.
type provisionState struct {
	fetch           map[string][]byte
	fetchErr        map[string]error
	written         map[string][]byte
	execErr         error
	proofErr        error
	signErr         error
	execCalls       []string
	mkdirErr        error
	writeErr        error
	writeFailSuffix string
	chmodErr        error
	removeErr       error
	tempErr         error
	cacheErr        error
	cacheCalls      int
	cacheFailAfter  int
	chmodCalls      int
	chmodFailAfter  int
	chmodCalled     bool
	stdout          strings.Builder
	fs              *virtualFS
	modules         map[string]string
	verifierBanner  string
}

// provisionEngine binds the pack engine to the fake provisioning seams.
func provisionEngine(state *provisionState, goos string) PackEngine {
	return PackEngine{
		ExecuteOutput: func(_ context.Context, _ string, executable string, args []string, _ []string) ([]byte, error) {
			joined := strings.Join(args, " ")
			state.execCalls = append(state.execCalls, executable+" "+joined)
			if executable == "go" {
				// The integrity-pinned tooling channel of the tenant.
				if module, found := strings.CutPrefix(joined, "mod download "); found {
					if _, ok := state.modules[module]; ok {
						return nil, nil
					}
					return nil, fmt.Errorf("module %s is not pinned", module)
				}
				if module, found := strings.CutPrefix(joined, "list -m -f {{.Dir}} "); found {
					if dir, ok := state.modules[module]; ok {
						return []byte(dir + "\n"), nil
					}
					return nil, fmt.Errorf("module %s is not pinned", module)
				}
				return nil, errors.New("unexpected go invocation")
			}
			if state.execErr != nil {
				return nil, state.execErr
			}
			// The provisioned verifier binary: the version invocation is the
			// install proof; every other invocation is a signature proof.
			if strings.HasPrefix(joined, "version") {
				if state.proofErr != nil {
					return nil, state.proofErr
				}
				banner := state.verifierBanner
				if banner == "" {
					banner = "GitVersion:    v3.0.6"
				}
				return []byte(banner), nil
			}
			if state.signErr != nil {
				return nil, state.signErr
			}
			return []byte("verified"), nil
		},
		ReadFile: func(path string) ([]byte, error) {
			if state.fs != nil {
				return state.fs.readFile(path)
			}
			return nil, os.ErrNotExist
		},
		ReadDir: func(path string) ([]os.DirEntry, error) {
			if state.fs != nil {
				return state.fs.readDir(path)
			}
			return nil, os.ErrNotExist
		},
		Stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		Walk:     func(string, fs.WalkDirFunc) error { return nil },
		MkdirAll: func(string, os.FileMode) error { return state.mkdirErr },
		WriteFile: func(path string, data []byte, _ os.FileMode) error {
			if state.writeErr != nil {
				return state.writeErr
			}
			if state.writeFailSuffix != "" && strings.HasSuffix(path, state.writeFailSuffix) {
				return errors.New("boom")
			}
			state.written[path] = data
			return nil
		},
		Chmod: func(string, os.FileMode) error {
			state.chmodCalled = true
			state.chmodCalls++
			if state.chmodFailAfter > 0 && state.chmodCalls > state.chmodFailAfter {
				return errors.New("boom")
			}
			return state.chmodErr
		},
		TempDir: func(string) (string, error) {
			if state.tempErr != nil {
				return "", state.tempErr
			}
			return "staging", nil
		},
		RemoveAll: func(string) error { return state.removeErr },
		Fetch: func(_ context.Context, url string, _ int64) ([]byte, error) {
			if err, found := state.fetchErr[url]; found {
				return nil, err
			}
			data, found := state.fetch[url]
			if !found {
				return nil, fmt.Errorf("no fixture for %s", url)
			}
			return data, nil
		},
		UserCacheDir: func() (string, error) {
			state.cacheCalls++
			if state.cacheFailAfter > 0 && state.cacheCalls > state.cacheFailAfter {
				return "", errors.New("boom")
			}
			if state.cacheErr != nil {
				return "", state.cacheErr
			}
			return "cache", nil
		},
		HasToolsMod: func(string) bool { return true },
		GOOS:        goos,
		GOARCH:      "amd64",
		Stdout:      &state.stdout,
		Stderr:      io.Discard,
	}
}

// buildZip builds a real in-memory zip archive with the given entries.
func buildZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// provisionFixture builds a resolved pack whose artifact is a real zip
// archive carrying the tool, with the digest bound to the archive bytes.
func provisionFixture(t *testing.T, entries map[string]string) (ResolvedPack, []byte) {
	t.Helper()
	archive := buildZip(t, entries)
	sum := sha256.Sum256(archive)
	pack := testResolvedPack()
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.SHA256 = hex.EncodeToString(sum[:])
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	return pack, archive
}

// provisionReady returns a provision state with the artifact, signature, and
// certificate fixtures of every bound platform of the pack.
func provisionReady(pack ResolvedPack, archive []byte) *provisionState {
	fetch := map[string][]byte{}
	for _, artifact := range pack.Descriptor.Provisioning.Artifacts {
		fetch[artifact.URL] = archive
		if artifact.Signature != "" {
			fetch[artifact.Signature] = []byte("signature")
			fetch[strings.TrimSuffix(artifact.Signature, ".sig")+".pem"] = []byte("certificate")
		}
	}
	return &provisionState{
		fetch:    fetch,
		fetchErr: map[string]error{},
		written:  map[string][]byte{},
	}
}

// verifierBinary is the raw cosign binary fixture of the verifier bootstrap
// tests.
func verifierBinary() []byte { return []byte("cosign-binary") }

// verifierDescriptorJSON renders the cosign bootstrap descriptor with the
// digest of the raw binary fixture bound.
func verifierDescriptorJSON(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256(verifierBinary())
	digest := hex.EncodeToString(sum[:])
	return `{"schema":"capability-pack/v1","capability":"cosign","area":"security","version":1,"summary":"Signature verifier bootstrap.","provisioning":{"kind":"recipe","tool":"cosign","version":"3.0.6","environment":{},"artifacts":{"linux-amd64":{"url":"https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64","sha256":"` + digest + `"},"windows-amd64":{"url":"https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-windows-amd64.exe","sha256":"` + digest + `"}}},"assertions":[{"name":"cosign-version","command":"cosign","args":["version"],"expect":"v3.0.6"}]}`
}

// bindVerifier binds the signature verifier bootstrap into the provisioning
// seams: the shared-kernel registry carries the cosign pack in the fixture
// tree, the tooling channel resolves both registries, and the raw cosign
// binary fixture is bound by digest.
func bindVerifier(t *testing.T, state *provisionState) {
	t.Helper()
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("scg/capabilities/security/cosign/v1/pack.json", verifierDescriptorJSON(t))
	state.fs = fs
	state.modules = map[string]string{
		sharedKernelModule:  "scg",
		territoryHomeModule: "gqa",
	}
	state.fetch["https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64"] = verifierBinary()
	state.fetch["https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-windows-amd64.exe"] = verifierBinary()
}

func TestPackEngineProvision(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	if err := e.Provision(context.Background(), ".", []ResolvedPack{pack}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// The verifier is provisioned from its raw binary before the
	// signature-bound pack: its install proof precedes the pack's signature
	// proof.
	verifierTool := filepath.Join("cache", "go-quality-authority", "packs", "cosign", "v1", "linux-amd64", "cosign")
	if string(state.written[verifierTool]) != "cosign-binary" {
		t.Fatalf("the verifier was not installed from the raw binary: %+v", state.written)
	}
	toolPath := filepath.Join("cache", "go-quality-authority", "packs", "opentofu", "v1", "linux-amd64", "tofu")
	if string(state.written[toolPath]) != "tool-binary" {
		t.Fatalf("the tool was not installed: %+v", state.written)
	}
	if !state.chmodCalled {
		t.Fatal("expected the tools to be marked executable on a non-windows runner")
	}
	proofAt, signAt := -1, -1
	for index, call := range state.execCalls {
		if strings.HasSuffix(call, " version") {
			proofAt = index
		}
		if strings.Contains(call, " verify-blob ") {
			signAt = index
		}
	}
	if proofAt < 0 || signAt < 0 || proofAt > signAt {
		t.Fatalf("the verifier install proof must precede the signature proof: %+v", state.execCalls)
	}
	call := state.execCalls[signAt]
	for _, want := range []string{
		verifierTool, "verify-blob", "--certificate", "--signature",
		"--certificate-identity", "https://github.com/opentofu/opentofu/.github/workflows/release.yml@refs/heads/v1.12",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
	} {
		if !strings.Contains(call, want) {
			t.Fatalf("the cosign invocation is missing %q: %q", want, call)
		}
	}
	if !strings.Contains(state.stdout.String(), "provisioned cosign@1") {
		t.Fatalf("stdout = %q", state.stdout.String())
	}
	if !strings.Contains(state.stdout.String(), "provisioned opentofu@1") {
		t.Fatalf("stdout = %q", state.stdout.String())
	}
}

func TestPackEngineProvisionNoArtifactForPlatform(t *testing.T) {
	pack := testResolvedPack()
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	delete(pack.Descriptor.Provisioning.Artifacts, "linux-amd64")
	pack.Descriptor.Provisioning.Artifacts["darwin-arm64"] = artifact
	state := provisionReady(pack, nil)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the unbound-platform finding")
	}
	if !strings.Contains(err.Error(), "binds no artifact for the runner platform") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionDownloadError(t *testing.T) {
	pack, _ := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, nil)
	state.fetchErr[pack.Descriptor.Provisioning.Artifacts["linux-amd64"].URL] = errors.New("network down")
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the download finding")
	}
	if !strings.Contains(err.Error(), "download the artifact") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionDigestMismatch(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.SHA256 = strings.Repeat("b", 64)
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the digest finding")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionSignatureNoAnchor(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.URL = "https://example.com/tofu.zip"
	artifact.Signature = "https://example.com/tofu.zip.sig"
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the missing-anchor finding")
	}
	if !strings.Contains(err.Error(), "no bound trust anchor") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionSignatureNotSigForm(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = strings.TrimSuffix(artifact.Signature, ".sig") + ".asc"
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the signature-form finding")
	}
	if !strings.Contains(err.Error(), "cosign .sig form") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionSignatureDownloadError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	state.fetchErr[pack.Descriptor.Provisioning.Artifacts["linux-amd64"].Signature] = errors.New("network down")
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the signature download finding")
	}
	if !strings.Contains(err.Error(), "download the signature") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionCertificateDownloadError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	signature := pack.Descriptor.Provisioning.Artifacts["linux-amd64"].Signature
	state.fetchErr[strings.TrimSuffix(signature, ".sig")+".pem"] = errors.New("network down")
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the certificate download finding")
	}
	if !strings.Contains(err.Error(), "download the signature certificate") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierNotExecutable(t *testing.T) {
	// The verifier's install proof fails closed when the provisioned binary
	// is not executable — the engine provisions the verifier itself, so a
	// missing binary is a provisioning defect, never a lane assumption.
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.proofErr = exec.ErrNotFound
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the verifier install-proof finding")
	}
	if !strings.Contains(err.Error(), "install proof") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierProofMismatch(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.verifierBanner = "GitVersion:    v9.9.9"
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the verifier proof-mismatch finding")
	}
	if !strings.Contains(err.Error(), "requires the output to carry") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierUnknown(t *testing.T) {
	// A signature-bound pack fails closed when the registry at the pinned
	// stand does not carry the verifier pack.
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	state.fs = fs
	state.modules = map[string]string{sharedKernelModule: "scg", territoryHomeModule: "gqa"}
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the verifier-resolution finding")
	}
	if !strings.Contains(err.Error(), "provision the signature verifier") {
		t.Fatalf("error = %q", err)
	}
	toolPath := filepath.Join("cache", "go-quality-authority", "packs", "opentofu", "v1", "linux-amd64", "tofu")
	if _, found := state.written[toolPath]; found {
		t.Fatal("the signature-bound pack must not be provisioned without the verifier")
	}
}

func TestPackEngineProvisionVerifierWrongIdentity(t *testing.T) {
	// A cosign pack carried by the territory registry instead of the shared
	// kernel is not the engine-bound verifier identity.
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	fs := newVirtualFS()
	fs.addFile("go.mod", "module example.com/tenant\n")
	fs.addFile("gqa/capabilities/security/cosign/v1/pack.json", verifierDescriptorJSON(t))
	state.fs = fs
	state.modules = map[string]string{sharedKernelModule: "scg", territoryHomeModule: "gqa"}
	state.fetch["https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64"] = verifierBinary()
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the verifier-identity finding")
	}
	if !strings.Contains(err.Error(), "is not the engine-bound identity") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierAssertionCommandMismatch(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	document := strings.Replace(verifierDescriptorJSON(t), `"command":"cosign"`, `"command":"other"`, 1)
	state.fs.addFile("scg/capabilities/security/cosign/v1/pack.json", document)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the verifier assertion-command finding")
	}
	if !strings.Contains(err.Error(), "must be the provisioned tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierRawBinaryOverBound(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	e.MaxToolBytes = 4
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the over-bound finding")
	}
	if !strings.Contains(err.Error(), "exceeds the extraction bound") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionZipChmodError(t *testing.T) {
	// The zip-form install marks the extracted tool executable; the failure
	// is fail-closed.
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.chmodFailAfter = 1
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the chmod finding")
	}
	if !strings.Contains(err.Error(), "mark the tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierRegistryUnavailable(t *testing.T) {
	// The verifier bootstrap fails closed when the tenant carries no
	// integrity-pinned tooling module.
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	e.HasToolsMod = func(string) bool { return false }
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the registry finding")
	}
	if !strings.Contains(err.Error(), "provision the signature verifier") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierProofToolPathError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.cacheFailAfter = 1
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the proof tool-path finding")
	}
	if !strings.Contains(err.Error(), "prove the signature verifier") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierToolPathError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.cacheFailAfter = 2
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the verifier tool-path finding")
	}
	if !strings.Contains(err.Error(), "locate the pack tool cache") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionSignatureVerifierNotExecutable(t *testing.T) {
	// The signature proof fails closed when the provisioned verifier binary is
	// not executable.
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.signErr = exec.ErrNotFound
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the verifier-execution finding")
	}
	if !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionVerifierInstallWriteError(t *testing.T) {
	// The raw-binary install of the verifier fails closed on the write error.
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.writeFailSuffix = "cosign"
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the verifier install finding")
	}
	if !strings.Contains(err.Error(), "install the tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionCosignFailure(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.signErr = errors.New("signature mismatch")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the invalid-signature finding")
	}
	if !strings.Contains(err.Error(), "is invalid") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionDigestOnlyGuard(t *testing.T) {
	// A non-verifier pack without a signature binding fails closed: only the
	// engine-bound signature verifier is provisioned digest-only.
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the digest-only guard finding")
	}
	if !strings.Contains(err.Error(), "binds no signature proof") {
		t.Fatalf("error = %q", err)
	}
	if len(state.execCalls) != 0 {
		t.Fatalf("the guard must fire before any registry or proof invocation: %+v", state.execCalls)
	}
	toolPath := filepath.Join("cache", "go-quality-authority", "packs", "opentofu", "v1", "linux-amd64", "tofu")
	if _, found := state.written[toolPath]; found {
		t.Fatal("a digest-only non-verifier pack must never be installed")
	}
}

func TestPackEngineProvisionNotAZip(t *testing.T) {
	archive := []byte("not a zip archive")
	sum := sha256.Sum256(archive)
	pack := testResolvedPack()
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.SHA256 = hex.EncodeToString(sum[:])
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the archive-form finding")
	}
	if !strings.Contains(err.Error(), "not a zip archive") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionToolMissing(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"other": "x"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the missing-tool finding")
	}
	if !strings.Contains(err.Error(), "does not contain the tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionToolDuplicate(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "a", "bin/tofu": "b"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the duplicate-tool finding")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionChmodError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.chmodErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the chmod finding")
	}
	if !strings.Contains(err.Error(), "mark the tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionWindowsNoChmod(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu.exe": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	delete(pack.Descriptor.Provisioning.Artifacts, "linux-amd64")
	pack.Descriptor.Provisioning.Artifacts["windows-amd64"] = artifact
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "windows")
	if err := e.Provision(context.Background(), ".", []ResolvedPack{pack}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if state.chmodCalled {
		t.Fatal("a windows runner must not chmod the tool")
	}
	toolPath := filepath.Join("cache", "go-quality-authority", "packs", "opentofu", "v1", "windows-amd64", "tofu.exe")
	if string(state.written[toolPath]) != "tool-binary" {
		t.Fatalf("the tool was not installed: %+v", state.written)
	}
}

func TestPackEngineProvisionCacheError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.cacheErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	if err := e.Provision(context.Background(), ".", []ResolvedPack{pack}); err == nil {
		t.Fatal("expected the cache-location finding")
	}
}

func TestPackEngineProvisionCleanCacheError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.removeErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the cache-clean finding")
	}
	if !strings.Contains(err.Error(), "clean the pack tool cache") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionMkdirError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.mkdirErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the cache-create finding")
	}
	if !strings.Contains(err.Error(), "create the pack tool cache") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionWriteToolError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.writeFailSuffix = "tofu"
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the tool-write finding")
	}
	if !strings.Contains(err.Error(), "extract the tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionStagingTempError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.tempErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the staging finding")
	}
	if !strings.Contains(err.Error(), "stage the signature material") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionStagingWriteError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.writeFailSuffix = "artifact.bin"
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the staging write finding")
	}
	if !strings.Contains(err.Error(), "stage the artifact") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionStagingSignatureWriteError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.writeFailSuffix = ".sig"
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the signature staging finding")
	}
	if !strings.Contains(err.Error(), "stage the signature") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionStagingCertificateWriteError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	state.writeFailSuffix = ".pem"
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the certificate staging finding")
	}
	if !strings.Contains(err.Error(), "stage the signature certificate") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionSkipsNonRegularEntries(t *testing.T) {
	// A directory entry in the archive is not a tool candidate and is skipped.
	pack, archive := provisionFixture(t, map[string]string{"docs/": "", "tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	if err := e.Provision(context.Background(), ".", []ResolvedPack{pack}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	toolPath := filepath.Join("cache", "go-quality-authority", "packs", "opentofu", "v1", "linux-amd64", "tofu")
	if string(state.written[toolPath]) != "tool-binary" {
		t.Fatalf("the tool was not installed: %+v", state.written)
	}
}

// withUnsupportedMethod patches the compression method of the archive's first
// central-directory entry to an unsupported algorithm, so the entry fails to
// open. The digest of the patched archive is the bound value.
func withUnsupportedMethod(t *testing.T, archive []byte) []byte {
	t.Helper()
	index := bytes.Index(archive, []byte("PK\x01\x02"))
	if index < 0 {
		t.Fatal("no central directory in the fixture archive")
	}
	// The compression method sits ten bytes into the central directory entry.
	archive[index+10] = 99
	archive[index+11] = 0
	return archive
}

func TestPackEngineProvisionOpenUnsupportedMethod(t *testing.T) {
	archive := withUnsupportedMethod(t, buildZip(t, map[string]string{"tofu": "tool-binary"}))
	pack := testResolvedPack()
	sum := sha256.Sum256(archive)
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.SHA256 = hex.EncodeToString(sum[:])
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	bindVerifier(t, state)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), ".", []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the tool-entry open finding")
	}
	if !strings.Contains(err.Error(), "extract the tool") {
		t.Fatalf("error = %q", err)
	}
}

// errorReader fails every read.
type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

func TestPackEngineExtractToolReadError(t *testing.T) {
	e := provisionEngine(&provisionState{written: map[string][]byte{}}, "linux")
	if err := e.extractTool(errorReader{}, "tool"); err == nil {
		t.Fatal("expected the read error")
	}
}

func TestPackEngineExtractToolOverBound(t *testing.T) {
	e := provisionEngine(&provisionState{written: map[string][]byte{}}, "linux")
	e.MaxToolBytes = 4
	err := e.extractTool(strings.NewReader("tool-binary"), "tool")
	if err == nil {
		t.Fatal("expected the over-bound finding")
	}
	if !strings.Contains(err.Error(), "exceeds the extraction bound") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineMaxToolBytes(t *testing.T) {
	e := provisionEngine(&provisionState{}, "linux")
	if e.maxToolBytes() != maxPackToolBytes {
		t.Fatalf("default bound = %d", e.maxToolBytes())
	}
	e.MaxToolBytes = 4
	if e.maxToolBytes() != 4 {
		t.Fatalf("bound = %d", e.maxToolBytes())
	}
}

func TestPublisherAnchorFor(t *testing.T) {
	anchor, found := publisherAnchorFor("https://github.com/opentofu/opentofu/releases/download/v1.12.5/tofu.zip")
	if !found {
		t.Fatal("expected the opentofu anchor")
	}
	if anchor.issuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("issuer = %q", anchor.issuer)
	}
	if _, found := publisherAnchorFor("https://example.com/tofu.zip"); found {
		t.Fatal("expected no anchor for an unknown publisher")
	}
}

func TestReleaseFamily(t *testing.T) {
	cases := map[string]string{"1.12.5": "v1.12", "1.12": "v1.12", "1": "v1"}
	for version, want := range cases {
		if got := releaseFamily(version); got != want {
			t.Fatalf("releaseFamily(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestFetchURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("payload"))
		case "/status":
			w.WriteHeader(http.StatusNotFound)
		case "/large":
			_, _ = w.Write([]byte("more-than-two"))
		case "/truncated":
			// The declared length exceeds the body, so the read fails.
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("ab"))
		}
	}))
	defer server.Close()
	data, err := fetchURL(context.Background(), server.URL+"/ok", 16)
	if err != nil {
		t.Fatalf("fetchURL: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("data = %q", data)
	}
	if _, err := fetchURL(context.Background(), server.URL+"/status", 16); err == nil {
		t.Fatal("expected the status finding")
	}
	if _, err := fetchURL(context.Background(), server.URL+"/large", 2); err == nil {
		t.Fatal("expected the byte-bound finding")
	}
	if _, err := fetchURL(context.Background(), server.URL+"/truncated", 16); err == nil {
		t.Fatal("expected the truncated-body finding")
	}
	if _, err := fetchURL(context.Background(), "://malformed", 16); err == nil {
		t.Fatal("expected the request-construction finding")
	}
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if _, err := fetchURL(context.Background(), closed.URL+"/x", 16); err == nil {
		t.Fatal("expected the transport finding")
	}
}
