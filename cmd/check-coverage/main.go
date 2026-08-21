// Command check-coverage enforces test-source presence and exact 100-percent
// statement coverage for every executable Go package.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/t33n-software/go-quality-authority/internal/quality"
)

// version is the build-stamped tool version.
var version = "dev"

var (
	exitProcess = os.Exit
	commandArgs = os.Args
	check       = checkCoverage
)

func main() {
	exitProcess(run(context.Background(), commandArgs[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := "."
	for _, arg := range args {
		switch {
		case arg == "--version":
			fmt.Fprintf(stdout, "check-coverage %s\n", version)
			return 0
		case strings.HasPrefix(arg, "--repo="):
			root = strings.TrimPrefix(arg, "--repo=")
		default:
			fmt.Fprintf(stderr, "usage: check-coverage [--repo <path>] [--version]\n")
			return 2
		}
	}
	if err := check(ctx, root, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "check-coverage: %v\n", err)
		return 1
	}
	return 0
}

// checkCoverage is the default coverage-gate seam.
func checkCoverage(ctx context.Context, root string, stdout, stderr io.Writer) error {
	return quality.NewCoverageRunner(stdout, stderr).Check(ctx, root)
}
