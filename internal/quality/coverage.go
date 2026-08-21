package quality

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// coverageArguments is the canonical coverage measurement invocation: serialized
// package test processes for a reproducible aggregate, atomic counters for
// concurrent code inside each test process.
var coverageArguments = []string{"test", "-count=1", "-p=1", "-cover", "-covermode=atomic", "./..."}

// CoverageRunner enforces test-source presence and complete statement coverage.
// It owns the measurement and the threshold, never the project's test layout.
type CoverageRunner struct {
	// Run executes the coverage measurement; it is the process seam.
	Run func(ctx context.Context, dir, executable string, args ...string) ([]byte, error)
	// Stdout receives the measurement output; Stderr receives the failure report.
	Stdout io.Writer
	Stderr io.Writer
}

// NewCoverageRunner returns a CoverageRunner bound to the real Go toolchain.
func NewCoverageRunner(stdout, stderr io.Writer) CoverageRunner {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return CoverageRunner{
		Run: func(ctx context.Context, dir, executable string, args ...string) ([]byte, error) {
			command := exec.CommandContext(ctx, executable, args...)
			command.Dir = dir
			return command.CombinedOutput()
		},
		Stdout: stdout,
		Stderr: stderr,
	}
}

// Check runs the coverage gate against a repository root. It fails closed when
// the measurement fails, when a package has no test file, or when an executable
// package is below exactly 100.0 percent statement coverage.
func (c CoverageRunner) Check(ctx context.Context, root string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(root) == "" {
		return fmt.Errorf("a repository root is required for the coverage gate")
	}
	output, err := c.Run(ctx, root, "go", coverageArguments...)
	if len(output) > 0 {
		_, _ = c.Stdout.Write(output)
	}
	if err != nil {
		return fmt.Errorf("run Go coverage: %w", err)
	}

	missing := PackagesWithoutTests(string(output))
	incomplete := IncompletePackages(string(output))
	for _, line := range missing {
		fmt.Fprintln(c.Stderr, line)
	}
	for _, line := range incomplete {
		fmt.Fprintln(c.Stderr, line)
	}
	if len(missing) > 0 || len(incomplete) > 0 {
		return fmt.Errorf("every Go package must contain a test file and every executable Go package must reach 100.0%% statement coverage (%d without tests, %d below threshold)", len(missing), len(incomplete))
	}
	fmt.Fprintln(c.Stdout, "All Go packages contain test files and all executable Go packages reached 100.0% statement coverage.")
	return nil
}

// PackagesWithoutTests returns the report lines for packages that declare no
// test files.
func PackagesWithoutTests(output string) []string {
	packages := make([]string, 0)
	for _, line := range coverageLines(output) {
		if strings.Contains(line, "[no test files]") {
			packages = append(packages, line)
		}
	}
	return packages
}

// IncompletePackages returns the report lines for executable packages whose
// statement coverage is below exactly 100.0 percent.
func IncompletePackages(output string) []string {
	incomplete := make([]string, 0)
	for _, line := range coverageLines(output) {
		fields := strings.Fields(line)
		for index, field := range fields {
			if field != "coverage:" || index+1 >= len(fields) {
				continue
			}
			if fields[index+1] != "100.0%" && fields[index+1] != "[no" {
				incomplete = append(incomplete, line)
			}
		}
	}
	return incomplete
}

// coverageLines normalizes line endings and splits the measurement output.
func coverageLines(output string) []string {
	return strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
}
