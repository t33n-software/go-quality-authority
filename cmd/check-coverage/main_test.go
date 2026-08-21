package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run --version = %d", code)
	}
	if !strings.Contains(stdout.String(), "check-coverage") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunUsageError(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"--bogus"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run --bogus = %d, want 2", code)
	}
}

func TestRunCheckError(t *testing.T) {
	defer func() { check = checkCoverage }()
	check = func(context.Context, string, io.Writer, io.Writer) error { return errors.New("boom") }
	var stdout, stderr strings.Builder
	code := run(context.Background(), []string{"--repo=" + t.TempDir()}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run with check error = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "check-coverage") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunSuccess(t *testing.T) {
	defer func() { check = checkCoverage }()
	dir := t.TempDir()
	check = func(_ context.Context, root string, _, _ io.Writer) error {
		if root != dir {
			t.Fatalf("root = %q", root)
		}
		return nil
	}
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"--repo=" + dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

func TestCheckCoverageDelegation(t *testing.T) {
	// The delegation constructs the production coverage runner; an empty root
	// fails fast, which exercises the seam without running a real measurement.
	if err := checkCoverage(context.Background(), " ", io.Discard, io.Discard); err == nil {
		t.Fatal("expected the delegation to surface the root error")
	}
}

func TestMain(t *testing.T) {
	defer func() { exitProcess = os.Exit }()
	defer func() { commandArgs = os.Args }()
	var code int
	exitProcess = func(c int) { code = c }
	commandArgs = []string{"check-coverage", "--version"}
	main()
	if code != 0 {
		t.Fatalf("main exit = %d", code)
	}
}
