// Command quality-gate is the single entry point of the Go quality lane. It
// reads the tenant's schema-validated quality configuration, asserts the
// controlled toolchain, executes the canonical gate set, and applies
// convention discovery for command binaries and fuzz targets.
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
	exitProcess = os.Exit
	commandArgs = os.Args
	readFile    = os.ReadFile
	runGate     = runQualityGate
)

func main() {
	exitProcess(run(context.Background(), commandArgs[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := "."
	for _, arg := range args {
		switch {
		case arg == "--version":
			fmt.Fprintf(stdout, "quality-gate %s\n", version)
			return 0
		case strings.HasPrefix(arg, "--repo="):
			root = strings.TrimPrefix(arg, "--repo=")
		default:
			fmt.Fprintf(stderr, "usage: quality-gate [--repo <path>] [--version]\n")
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
