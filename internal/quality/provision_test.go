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
	execCalls       []string
	mkdirErr        error
	writeErr        error
	writeFailSuffix string
	chmodErr        error
	removeErr       error
	tempErr         error
	cacheErr        error
	chmodCalled     bool
	stdout          strings.Builder
}

// provisionEngine binds the pack engine to the fake provisioning seams.
func provisionEngine(state *provisionState, goos string) PackEngine {
	return PackEngine{
		ExecuteOutput: func(_ context.Context, _ string, executable string, args []string, _ []string) ([]byte, error) {
			state.execCalls = append(state.execCalls, executable+" "+strings.Join(args, " "))
			if state.execErr != nil {
				return nil, state.execErr
			}
			return []byte("verified"), nil
		},
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		ReadDir:  func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
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

func TestPackEngineProvision(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "linux")
	if err := e.Provision(context.Background(), []ResolvedPack{pack}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	toolPath := filepath.Join("cache", "go-quality-authority", "packs", "opentofu", "v1", "linux-amd64", "tofu")
	if string(state.written[toolPath]) != "tool-binary" {
		t.Fatalf("the tool was not installed: %+v", state.written)
	}
	if !state.chmodCalled {
		t.Fatal("expected the tool to be marked executable on a non-windows runner")
	}
	if len(state.execCalls) != 1 {
		t.Fatalf("expected exactly one cosign verification, got %+v", state.execCalls)
	}
	call := state.execCalls[0]
	for _, want := range []string{
		"cosign", "verify-blob", "--certificate", "--signature",
		"--certificate-identity", "https://github.com/opentofu/opentofu/.github/workflows/release.yml@refs/heads/v1.12",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
	} {
		if !strings.Contains(call, want) {
			t.Fatalf("the cosign invocation is missing %q: %q", want, call)
		}
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
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the certificate download finding")
	}
	if !strings.Contains(err.Error(), "download the signature certificate") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionCosignMissing(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	state.execErr = exec.ErrNotFound
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the cosign-availability finding")
	}
	if !strings.Contains(err.Error(), "cosign is not available") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionCosignFailure(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	state := provisionReady(pack, archive)
	state.execErr = errors.New("signature mismatch")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the invalid-signature finding")
	}
	if !strings.Contains(err.Error(), "is invalid") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionWithoutSignature(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "linux")
	if err := e.Provision(context.Background(), []ResolvedPack{pack}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(state.execCalls) != 0 {
		t.Fatalf("a descriptor without a signature must not invoke cosign: %+v", state.execCalls)
	}
	toolPath := filepath.Join("cache", "go-quality-authority", "packs", "opentofu", "v1", "linux-amd64", "tofu")
	if string(state.written[toolPath]) != "tool-binary" {
		t.Fatalf("the tool was not installed: %+v", state.written)
	}
}

func TestPackEngineProvisionNotAZip(t *testing.T) {
	archive := []byte("not a zip archive")
	sum := sha256.Sum256(archive)
	pack := testResolvedPack()
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.SHA256 = hex.EncodeToString(sum[:])
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the archive-form finding")
	}
	if !strings.Contains(err.Error(), "not a zip archive") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionToolMissing(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"other": "x"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the missing-tool finding")
	}
	if !strings.Contains(err.Error(), "does not contain the tool") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionToolDuplicate(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "a", "bin/tofu": "b"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the duplicate-tool finding")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionChmodError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	state.chmodErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	artifact.Signature = ""
	delete(pack.Descriptor.Provisioning.Artifacts, "linux-amd64")
	pack.Descriptor.Provisioning.Artifacts["windows-amd64"] = artifact
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "windows")
	if err := e.Provision(context.Background(), []ResolvedPack{pack}); err != nil {
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
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	state.cacheErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	if err := e.Provision(context.Background(), []ResolvedPack{pack}); err == nil {
		t.Fatal("expected the cache-location finding")
	}
}

func TestPackEngineProvisionCleanCacheError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	state.removeErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the cache-clean finding")
	}
	if !strings.Contains(err.Error(), "clean the pack tool cache") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionMkdirError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	state.mkdirErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
	if err == nil {
		t.Fatal("expected the cache-create finding")
	}
	if !strings.Contains(err.Error(), "create the pack tool cache") {
		t.Fatalf("error = %q", err)
	}
}

func TestPackEngineProvisionWriteToolError(t *testing.T) {
	pack, archive := provisionFixture(t, map[string]string{"tofu": "tool-binary"})
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	state.writeErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	state.tempErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	state.writeErr = errors.New("boom")
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	state.writeFailSuffix = ".sig"
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	state.writeFailSuffix = ".pem"
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
	artifact := pack.Descriptor.Provisioning.Artifacts["linux-amd64"]
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "linux")
	if err := e.Provision(context.Background(), []ResolvedPack{pack}); err != nil {
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
	artifact.Signature = ""
	pack.Descriptor.Provisioning.Artifacts["linux-amd64"] = artifact
	state := provisionReady(pack, archive)
	e := provisionEngine(state, "linux")
	err := e.Provision(context.Background(), []ResolvedPack{pack})
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
