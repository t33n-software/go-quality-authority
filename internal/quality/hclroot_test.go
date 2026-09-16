package quality

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// The full-surface fixture carries every extracted block form.
const rootModelFixture = `
variable "format" {
  type = string

  validation {
    condition     = contains(["GO"], var.format)
    error_message = "format"
  }
}

variable "free" {
  description = "no type constraint"
}

variable {}

variable "conditional" {
  type = string

  validation {
    error_message = "no condition attribute"
  }
}

locals {
  upper = upper(var.format)
}

resource "google_storage_bucket" "state_homes" {
  provisioner "local-exec" {}

  lifecycle {
    foo {}

    precondition {
      condition     = var.format != ""
      error_message = "format"
    }

    postcondition {
      condition     = self.name != ""
      error_message = "name"
    }
  }
}

resource "orphan" {}

data "google_project" "current" {
  lifecycle {
    postcondition {
      condition     = self.id != ""
      error_message = "id"
    }
  }
}

module "network" {}

output "endpoint" {
  value = "x"

  precondition {
    condition     = var.format != ""
    error_message = "format"
  }
}

check "health" {
  data "http" "endpoint" {}

  assert {
    condition     = data.http.endpoint.status_code == 200
    error_message = "health"
  }
}

terraform {
  encryption {
    key_provider "gcp_kms" "main" {}
  }
}

provider "google" {}
`

func TestBuildRootModel(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("main.tf", rootModelFixture)
	fs.addFile("notes.md", "# not an HCL file\n")
	fs.addFile("variables.tofutest.hcl", "run \"x\" {}\n")
	// A nested directory entry of the root is never a root file.
	fs.addFile("nested/ignored.tf", "resource \"nested\" {}\n")
	e := fakePackEngine(fs)
	model, err := e.buildRootModel(".")
	if err != nil {
		t.Fatalf("buildRootModel: %v", err)
	}
	if !model.variables["format"].Equals(cty.String) || model.variables["free"] != cty.DynamicPseudoType {
		t.Fatalf("variables = %+v", model.variables)
	}
	if _, found := model.locals["upper"]; !found {
		t.Fatalf("locals = %+v", model.locals)
	}
	if len(model.conditions) != 6 {
		t.Fatalf("conditions = %+v", model.conditions)
	}
	surfaces := []string{}
	for _, condition := range model.conditions {
		surfaces = append(surfaces, condition.surface+"|"+condition.owner)
	}
	joined := strings.Join(surfaces, ";")
	for _, want := range []string{
		`validation|variable "format"`,
		`precondition|resource "google_storage_bucket" "state_homes"`,
		`postcondition|resource "google_storage_bucket" "state_homes"`,
		`postcondition|data "google_project" "current"`,
		`precondition|output "endpoint"`,
		`assert|check "health"`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the model misses %q; got %q", want, joined)
		}
	}
	if !model.encrypted {
		t.Fatal("expected the encryption block to be detected")
	}
	if len(model.resources["google_storage_bucket"]) != 1 {
		t.Fatalf("resources = %+v", model.resources)
	}
	// A resource block without the type-and-name label pair is never indexed.
	if _, found := model.resources["orphan"]; found {
		t.Fatalf("a single-label resource block is never indexed: %+v", model.resources)
	}
	if len(model.data["google_project"]) != 1 || len(model.data["http"]) != 1 {
		t.Fatalf("data = %+v", model.data)
	}
	if len(model.modules) != 1 || model.modules[0] != "network" {
		t.Fatalf("modules = %+v", model.modules)
	}
}

func TestBuildRootModelReadDirError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.ReadDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("boom") }
	if _, err := e.buildRootModel("."); err == nil || !strings.Contains(err.Error(), "read the root directory") {
		t.Fatalf("expected the read-dir finding, got %v", err)
	}
}

func TestBuildRootModelReadFileError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("main.tf", "variable \"x\" {}\n")
	e := fakePackEngine(fs)
	e.ReadFile = func(string) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := e.buildRootModel("."); err == nil || !strings.Contains(err.Error(), "read main.tf") {
		t.Fatalf("expected the read finding, got %v", err)
	}
}

func TestBuildRootModelParseError(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("broken.tf", "variable {\n")
	e := fakePackEngine(fs)
	_, err := e.buildRootModel(".")
	if err == nil || !strings.Contains(err.Error(), "parse broken.tf") {
		t.Fatalf("expected the parse finding, got %v", err)
	}
}

func TestBuildRootModelInvalidTypeConstraint(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("main.tf", "variable \"x\" {\n  type = nosuchtype\n}\n")
	e := fakePackEngine(fs)
	_, err := e.buildRootModel(".")
	if err == nil || !strings.Contains(err.Error(), `variable "x" carries an invalid type constraint`) {
		t.Fatalf("expected the type-constraint finding, got %v", err)
	}
}

func TestFirstDiagnostic(t *testing.T) {
	if got := firstDiagnostic(nil); got != "no diagnostics" {
		t.Fatalf("firstDiagnostic of an empty set = %q", got)
	}
}

func TestOwnerNameWithoutLabels(t *testing.T) {
	if got := ownerName(&hclsyntax.Block{Type: "terraform"}); got != "terraform" {
		t.Fatalf("ownerName = %q", got)
	}
}
