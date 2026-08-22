package quality

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCoverageRunnerCheckPass(t *testing.T) {
	var stdout, stderr strings.Builder
	runner := CoverageRunner{
		Run: func(ctx context.Context, dir, executable string, args ...string) ([]byte, error) {
			if executable != "go" {
				t.Fatalf("executable = %q", executable)
			}
			if dir != "." {
				t.Fatalf("dir = %q", dir)
			}
			return []byte("ok  \texample.com/a\t0.5s\tcoverage: 100.0% of statements\n"), nil
		},
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if err := runner.Check(context.Background(), "."); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.Contains(stdout.String(), "100.0%") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestCoverageRunnerCheckEmptyRoot(t *testing.T) {
	runner := CoverageRunner{Run: func(context.Context, string, string, ...string) ([]byte, error) {
		return nil, nil
	}}
	if err := runner.Check(context.Background(), " "); err == nil {
		t.Fatal("expected an error for an empty root")
	}
}

func TestCoverageRunnerCheckRunError(t *testing.T) {
	var stdout, stderr strings.Builder
	runner := CoverageRunner{
		Run: func(context.Context, string, string, ...string) ([]byte, error) {
			return []byte("partial output"), errors.New("boom")
		},
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if err := runner.Check(context.Background(), "."); err == nil {
		t.Fatal("expected the run error")
	}
	if !strings.Contains(stdout.String(), "partial output") {
		t.Fatal("expected the partial output to be written before the error")
	}
}

func TestCoverageRunnerCheckFailures(t *testing.T) {
	output := strings.Join([]string{
		"ok  \texample.com/tested\t0.5s\tcoverage: 100.0% of statements",
		"ok  \texample.com/notests\t0.3s\t[no test files]",
		"FAIL\texample.com/below\t0.2s\tcoverage: 87.2% of statements",
	}, "\n")
	var stdout, stderr strings.Builder
	runner := CoverageRunner{
		Run:    func(context.Context, string, string, ...string) ([]byte, error) { return []byte(output), nil },
		Stdout: &stdout,
		Stderr: &stderr,
	}
	err := runner.Check(context.Background(), ".")
	if err == nil {
		t.Fatal("expected a coverage failure")
	}
	if !strings.Contains(stderr.String(), "[no test files]") {
		t.Fatal("expected the no-test-files line to be reported")
	}
	if !strings.Contains(stderr.String(), "87.2%") {
		t.Fatal("expected the below-threshold line to be reported")
	}
}

func TestPackagesWithoutTests(t *testing.T) {
	output := "ok  \ta\t0.1s\tcoverage: 100.0% of statements\nok  \tb\t0.1s\t[no test files]\n"
	missing := PackagesWithoutTests(output)
	if len(missing) != 1 || !strings.Contains(missing[0], "[no test files]") {
		t.Fatalf("missing = %+v", missing)
	}
	if len(PackagesWithoutTests("ok  \ta\t0.1s\tcoverage: 100.0% of statements\n")) != 0 {
		t.Fatal("expected no missing packages")
	}
}

func TestIncompletePackages(t *testing.T) {
	output := strings.Join([]string{
		"ok  \ta\t0.1s\tcoverage: 100.0% of statements",
		"FAIL\tb\t0.1s\tcoverage: 87.2% of statements",
		"ok  \tc\t0.1s\t[no test files]",
		"ok  \td\t0.1s\tcoverage: [no statements]",
	}, "\n")
	incomplete := IncompletePackages(output)
	if len(incomplete) != 1 || !strings.Contains(incomplete[0], "87.2%") {
		t.Fatalf("incomplete = %+v", incomplete)
	}
}

func TestIncompletePackagesCRLF(t *testing.T) {
	output := "FAIL\tb\t0.1s\tcoverage: 87.2% of statements\r\n"
	if len(IncompletePackages(output)) != 1 {
		t.Fatal("expected CRLF tolerance")
	}
}

func TestNewCoverageRunnerDefaults(t *testing.T) {
	runner := NewCoverageRunner(nil, nil)
	if runner.Run == nil || runner.Stdout == nil || runner.Stderr == nil {
		t.Fatal("expected the default seams to be bound")
	}
}

// testNilContext returns a nil context through a function boundary so the
// nil-normalization guards stay testable without passing a literal nil.
func testNilContext() context.Context {
	return nil
}

func TestCoverageRunnerCheckNilContext(t *testing.T) {
	var stdout, stderr strings.Builder
	runner := CoverageRunner{
		Run:    func(context.Context, string, string, ...string) ([]byte, error) { return []byte("ok 100.0%"), nil },
		Stdout: &stdout,
		Stderr: &stderr,
	}
	// A nil context is normalized to the background context.
	if err := runner.Check(testNilContext(), "."); err != nil {
		t.Fatalf("Check with nil context: %v", err)
	}
}

func TestNewCoverageRunnerRealProcess(t *testing.T) {
	runner := NewCoverageRunner(io.Discard, io.Discard)
	output, err := runner.Run(context.Background(), ".", "go", "version")
	if err != nil {
		t.Fatalf("real process run: %v", err)
	}
	if !strings.Contains(string(output), "go version") {
		t.Fatalf("output = %q", output)
	}
}
