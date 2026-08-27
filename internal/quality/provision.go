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
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
)

// The provisioning bounds: a download is bounded, and the decompression of
// the bound artifact is bounded, so a diverging or hostile artifact never
// exhausts the lane.
const (
	maxPackArtifactBytes  = int64(1) << 30 // 1 GiB download bound
	maxPackSignatureBytes = int64(1) << 20 // 1 MiB signature material bound
	maxPackToolBytes      = int64(1) << 31 // 2 GiB decompression bound
)

// Provision executes the recipe of every resolved pack in declaration order:
// the bound artifact for the runner platform is downloaded through the
// integrity channel, its sha256 digest is verified fail-closed, its cosign
// signature is verified where the descriptor binds one, and the tool is
// installed into the pack tool cache. Before the first signature-bound pack,
// the engine resolves and provisions the bound signature verifier from the
// registry — the machinery-internal bootstrap, never a tenant declaration, a
// payload step, or a runner assumption.
func (e PackEngine) Provision(ctx context.Context, root string, packs []ResolvedPack) error {
	verifierTool := ""
	for _, pack := range packs {
		if packBindsSignature(pack) && verifierTool == "" {
			tool, err := e.provisionVerifier(ctx, root)
			if err != nil {
				return err
			}
			verifierTool = tool
		}
		if err := e.provisionOne(ctx, pack, verifierTool); err != nil {
			return err
		}
	}
	return nil
}

// provisionVerifier resolves the engine-bound signature verifier against the
// registry at the tenant's pinned stand, provisions it digest-only under the
// single documented bootstrap exception, and runs its assertions as the
// install proof. Only the cosign pack of the shared kernel's security area is
// the verifier identity; every other resolution fails closed.
func (e PackEngine) provisionVerifier(ctx context.Context, root string) (string, error) {
	search, err := e.registryTrees(ctx, root)
	if err != nil {
		return "", fmt.Errorf("provision the signature verifier: %w", err)
	}
	pack, err := e.resolveOne(verifierReference, verifierCapability, verifierMajor, search)
	if err != nil {
		return "", fmt.Errorf("provision the signature verifier: %w", err)
	}
	if !isVerifierBootstrap(pack) {
		return "", fmt.Errorf("provision the signature verifier: the resolved pack %q from registry %s is not the engine-bound identity %s in the %s area of %s",
			pack.Reference, pack.Registry, verifierCapability, verifierArea, sharedKernelModule)
	}
	if err := e.provisionOne(ctx, pack, ""); err != nil {
		return "", err
	}
	if err := e.proveVerifier(ctx, pack); err != nil {
		return "", err
	}
	return e.ToolPath(pack)
}

// proveVerifier runs the verifier pack's assertions against the installed
// binary: the install proof runs inside provisioning, never as a tenant gate.
func (e PackEngine) proveVerifier(ctx context.Context, pack ResolvedPack) error {
	toolPath, err := e.ToolPath(pack)
	if err != nil {
		return fmt.Errorf("prove the signature verifier: %w", err)
	}
	env := packEnvironment(pack.Descriptor.Provisioning.Environment)
	for _, assertion := range pack.Descriptor.Assertions {
		if assertion.Command != pack.Descriptor.Provisioning.Tool {
			return fmt.Errorf("the signature verifier assertion %q command %q must be the provisioned tool %q",
				assertion.Name, assertion.Command, pack.Descriptor.Provisioning.Tool)
		}
		output, err := e.ExecuteOutput(ctx, filepath.Dir(toolPath), toolPath, assertion.Args, env)
		if err != nil {
			return fmt.Errorf("the signature verifier install proof %q: %w", assertion.Name, err)
		}
		if !strings.Contains(string(output), assertion.Expect) {
			return fmt.Errorf("the signature verifier install proof %q requires the output to carry %q", assertion.Name, assertion.Expect)
		}
	}
	return nil
}

// provisionOne executes the recipe of one resolved pack. The signature proof
// runs through the provisioned verifier binary; a pack without a signature
// binding is provisioned digest-only only when it is the engine-bound
// verifier itself — every other pack fails closed.
func (e PackEngine) provisionOne(ctx context.Context, pack ResolvedPack, verifierTool string) error {
	provisioning := pack.Descriptor.Provisioning
	platform := e.GOOS + "-" + e.GOARCH
	artifact, bound := provisioning.Artifacts[platform]
	if !bound {
		return fmt.Errorf("capability pack %q binds no artifact for the runner platform %s", pack.Reference, platform)
	}
	data, err := e.Fetch(ctx, artifact.URL, maxPackArtifactBytes)
	if err != nil {
		return fmt.Errorf("download the artifact of capability pack %q: %w", pack.Reference, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != artifact.SHA256 {
		return fmt.Errorf("capability pack %q artifact digest mismatch: the downloaded artifact does not match the bound sha256", pack.Reference)
	}
	if artifact.Signature != "" {
		if err := e.verifySignature(ctx, pack, artifact, data, verifierTool); err != nil {
			return err
		}
	} else if !isVerifierBootstrap(pack) {
		return fmt.Errorf("capability pack %q binds no signature proof for the runner platform %s: only the engine-bound signature verifier is provisioned digest-only", pack.Reference, platform)
	}
	if err := e.install(pack, artifact, data); err != nil {
		return err
	}
	if artifact.Signature != "" {
		fmt.Fprintf(e.Stdout, "provisioned %s: %s %s (%s), sha256 and signature verified\n",
			pack.Reference, provisioning.Tool, provisioning.Version, platform)
	} else {
		fmt.Fprintf(e.Stdout, "provisioned %s: %s %s (%s), sha256 verified (the digest-only bootstrap exception)\n",
			pack.Reference, provisioning.Tool, provisioning.Version, platform)
	}
	return nil
}

// publisherAnchor binds the cosign keyless trust anchor of a release
// publisher. The anchor values are owned by the publisher's engine-level
// reference; for OpenTofu that is the canonical engine standard
// (DEVELOPER_PLATFORM_INFRASTRUCTURE_AS_CODE_OPENTOFU_STANDARD_REFERENCE_001),
// which binds the release-workflow certificate identity and the GitHub
// Actions OIDC issuer. A signature from a publisher without a bound anchor
// fails closed.
type publisherAnchor struct {
	name         string
	urlPrefix    string
	identityBase string
	issuer       string
}

// publisherAnchors is the machinery's trust-anchor registry, one entry per
// governed publisher.
var publisherAnchors = []publisherAnchor{
	{
		name:         "opentofu",
		urlPrefix:    "https://github.com/opentofu/opentofu/releases/download/",
		identityBase: "https://github.com/opentofu/opentofu/.github/workflows/release.yml@refs/heads/",
		issuer:       "https://token.actions.githubusercontent.com",
	},
}

// publisherAnchorFor returns the bound trust anchor for an artifact URL.
func publisherAnchorFor(url string) (publisherAnchor, bool) {
	for _, anchor := range publisherAnchors {
		if strings.HasPrefix(url, anchor.urlPrefix) {
			return anchor, true
		}
	}
	return publisherAnchor{}, false
}

// certificateIdentity derives the release-workflow certificate identity of
// the publisher for the pack's pinned tool version: the OpenTofu release
// workflow signs from the version-family branch (refs/heads/v<major>.<minor>).
func (a publisherAnchor) certificateIdentity(version string) string {
	return a.identityBase + releaseFamily(version)
}

// releaseFamily derives the version-family branch of a pinned tool version
// (1.12.5 → v1.12). The version form is proven by the descriptor validation.
func releaseFamily(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return "v" + parts[0] + "." + parts[1]
	}
	return "v" + version
}

// verifySignature verifies the bound cosign signature of the downloaded
// artifact through the provisioned verifier binary: the signature and its
// certificate (the cosign keyless .sig/.pem pair) are downloaded, and the
// verifier's verify-blob proves the artifact against the publisher's
// OIDC-bound release-workflow identity.
func (e PackEngine) verifySignature(ctx context.Context, pack ResolvedPack, artifact PackArtifact, data []byte, verifierTool string) error {
	anchor, bound := publisherAnchorFor(artifact.URL)
	if !bound {
		return fmt.Errorf("capability pack %q artifact publisher carries no bound trust anchor", pack.Reference)
	}
	if !strings.HasSuffix(artifact.Signature, ".sig") {
		return fmt.Errorf("capability pack %q signature reference must carry the cosign .sig form", pack.Reference)
	}
	signature, err := e.Fetch(ctx, artifact.Signature, maxPackSignatureBytes)
	if err != nil {
		return fmt.Errorf("download the signature of capability pack %q: %w", pack.Reference, err)
	}
	certificateURL := strings.TrimSuffix(artifact.Signature, ".sig") + ".pem"
	certificate, err := e.Fetch(ctx, certificateURL, maxPackSignatureBytes)
	if err != nil {
		return fmt.Errorf("download the signature certificate of capability pack %q: %w", pack.Reference, err)
	}
	staging, err := e.TempDir("pack-signature-")
	if err != nil {
		return fmt.Errorf("stage the signature material of capability pack %q: %w", pack.Reference, err)
	}
	defer e.RemoveAll(staging)
	artifactPath := filepath.Join(staging, "artifact.bin")
	signaturePath := filepath.Join(staging, "artifact.sig")
	certificatePath := filepath.Join(staging, "artifact.pem")
	if err := e.WriteFile(artifactPath, data, 0o600); err != nil {
		return fmt.Errorf("stage the artifact of capability pack %q: %w", pack.Reference, err)
	}
	if err := e.WriteFile(signaturePath, signature, 0o600); err != nil {
		return fmt.Errorf("stage the signature of capability pack %q: %w", pack.Reference, err)
	}
	if err := e.WriteFile(certificatePath, certificate, 0o600); err != nil {
		return fmt.Errorf("stage the signature certificate of capability pack %q: %w", pack.Reference, err)
	}
	output, err := e.ExecuteOutput(ctx, staging, verifierTool, []string{
		"verify-blob",
		"--certificate", certificatePath,
		"--signature", signaturePath,
		"--certificate-identity", anchor.certificateIdentity(pack.Descriptor.Provisioning.Version),
		"--certificate-oidc-issuer", anchor.issuer,
		artifactPath,
	}, nil)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("verify the signature of capability pack %q: the provisioned signature verifier is not executable: %w", pack.Reference, err)
		}
		return fmt.Errorf("the signature of capability pack %q is invalid: %w (%s)", pack.Reference, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// install places the pack's verified artifact into the pack tool cache. The
// artifact form derives from the bound URL: a .zip archive carries the tool
// as an entry; any other form is the raw tool binary itself. The output path
// is always the computed tool path — the install never derives an output
// location from the artifact, so no path traversal is possible; only the
// regular file carrying the tool is extracted from an archive, and every
// read is bounded.
func (e PackEngine) install(pack ResolvedPack, artifact PackArtifact, data []byte) error {
	toolPath, err := e.ToolPath(pack)
	if err != nil {
		return err
	}
	target := filepath.Dir(toolPath)
	if err := e.RemoveAll(target); err != nil {
		return fmt.Errorf("clean the pack tool cache of capability pack %q: %w", pack.Reference, err)
	}
	if err := e.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("create the pack tool cache of capability pack %q: %w", pack.Reference, err)
	}
	if !strings.HasSuffix(artifact.URL, ".zip") {
		// The raw-binary form: the verified artifact is the tool itself.
		if int64(len(data)) > e.maxToolBytes() {
			return fmt.Errorf("the artifact of capability pack %q exceeds the extraction bound", pack.Reference)
		}
		if err := e.WriteFile(toolPath, data, 0o755); err != nil {
			return fmt.Errorf("install the tool of capability pack %q: %w", pack.Reference, err)
		}
		if e.GOOS != "windows" {
			if err := e.Chmod(toolPath, 0o755); err != nil {
				return fmt.Errorf("mark the tool of capability pack %q executable: %w", pack.Reference, err)
			}
		}
		return nil
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("the artifact of capability pack %q is not a zip archive: %w", pack.Reference, err)
	}
	tool := e.toolExecutable(pack)
	extracted := false
	for _, entry := range reader.File {
		if !entry.FileInfo().Mode().IsRegular() {
			continue
		}
		if filepath.Base(entry.Name) != tool {
			continue
		}
		if extracted {
			return fmt.Errorf("the artifact of capability pack %q carries the tool %q more than once", pack.Reference, tool)
		}
		if err := e.extractToolEntry(entry, toolPath); err != nil {
			return fmt.Errorf("extract the tool of capability pack %q: %w", pack.Reference, err)
		}
		extracted = true
	}
	if !extracted {
		return fmt.Errorf("the artifact of capability pack %q does not contain the tool %q", pack.Reference, tool)
	}
	if e.GOOS != "windows" {
		if err := e.Chmod(toolPath, 0o755); err != nil {
			return fmt.Errorf("mark the tool of capability pack %q executable: %w", pack.Reference, err)
		}
	}
	return nil
}

// extractToolEntry opens, reads, and installs one tool archive entry.
func (e PackEngine) extractToolEntry(entry *zip.File, toolPath string) error {
	contents, err := entry.Open()
	if err != nil {
		return err
	}
	defer contents.Close()
	return e.extractTool(contents, toolPath)
}

// extractTool writes the bounded content of one archive entry to the tool
// path. The decompression read is bounded by the engine's MaxToolBytes, so a
// hostile archive never exhausts the lane.
func (e PackEngine) extractTool(contents io.Reader, toolPath string) error {
	data, err := io.ReadAll(io.LimitReader(contents, e.maxToolBytes()+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > e.maxToolBytes() {
		return errors.New("the decompressed tool exceeds the extraction bound")
	}
	return e.WriteFile(toolPath, data, 0o755)
}

// fetchURL is the production download seam of the provisioning recipe: a
// bounded HTTPS GET through the integrity channel.
func fetchURL(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("the download exceeds the %d byte bound", maxBytes)
	}
	return data, nil
}
