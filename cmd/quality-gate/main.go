// Command quality-gate is the single entry point of the Go quality lane. It
// reads the tenant's schema-validated quality configuration, asserts the
// controlled toolchain, executes the canonical gate set, and applies
// convention discovery for command binaries and fuzz targets. The provision
// mode resolves the tenant's declared capability packs and executes their
// digest- and signature-bound recipes. The provision-verifier mode provisions
// the engine-bound signature verifier for a lane that must sign and prints
// its deterministic tool cache path.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/t33n-software/go-quality-authority/internal/quality"
)

// configFileName is the canonical configuration seam name.
const configFileName = "git-governance.quality.json"

// version is the build-stamped tool version.
var version = "dev"

var (
	exitProcess          = os.Exit
	commandArgs          = os.Args
	readFile             = os.ReadFile
	runGate              = runQualityGate
	runProvision         = runQualityProvision
	runProvisionVerifier = runQualityProvisionVerifier
)

func main() {
	exitProcess(run(context.Background(), commandArgs[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := "."
	mode := ""
	for _, arg := range args {
		switch {
		case arg == "--version":
			fmt.Fprintf(stdout, "quality-gate %s\n", version)
			return 0
		case (arg == "provision" || arg == "provision-verifier") && mode == "":
			mode = arg
		case strings.HasPrefix(arg, "--repo="):
			root = strings.TrimPrefix(arg, "--repo=")
		default:
			fmt.Fprintf(stderr, "usage: quality-gate [--repo <path>] [--version] [provision | provision-verifier]\n")
			return 2
		}
	}
	contents, err := readFile(filepath.Join(root, configFileName))
	if err != nil {
		fmt.Fprintf(stderr, "read quality configuration: %v\n", err)
		return 1
	}
	config, err := quality.DecodeConfig(contents)
	if err != nil {
		fmt.Fprintf(stderr, "decode quality configuration: %v\n", err)
		return 1
	}
	if mode == "provision" {
		if err := runProvision(ctx, config, root, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "quality provision: %v\n", err)
			return 1
		}
		return 0
	}
	if mode == "provision-verifier" {
		if err := runProvisionVerifier(ctx, config, root, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "quality provision-verifier: %v\n", err)
			return 1
		}
		return 0
	}
	if err := runGate(ctx, config, root, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "quality gate: %v\n", err)
		return 1
	}
	return 0
}

// runQualityGate is the default gate execution seam.
func runQualityGate(ctx context.Context, config quality.Config, root string, stdout, stderr io.Writer) error {
	return quality.NewOrchestrator(config, stdout, stderr).Run(ctx, root)
}

// runQualityProvision is the default provision execution seam.
func runQualityProvision(ctx context.Context, config quality.Config, root string, stdout, stderr io.Writer) error {
	return quality.NewOrchestrator(config, stdout, stderr).Provision(ctx, root)
}

// runQualityProvisionVerifier is the verifier provisioning seam: the engine
// status is routed to stderr, so stdout carries exactly the deterministic
// tool cache path of the provisioned verifier for the calling lane.
func runQualityProvisionVerifier(ctx context.Context, config quality.Config, root string, stdout, stderr io.Writer) error {
	orchestrator := quality.NewOrchestrator(config, stdout, stderr)
	orchestrator.Packs.Stdout = stderr
	return orchestrator.ProvisionVerifier(ctx, root)
}
