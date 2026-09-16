package quality

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// parseExpression parses a standalone expression for the helper tests.
func parseExpression(t *testing.T, source string) hcl.Expression {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(source), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("ParseExpression %q: %s", source, firstDiagnostic(diags))
	}
	return expr
}

// guardFixture binds one .tf document as the root of a fake engine.
func guardFixture(t *testing.T, contents string) PackEngine {
	t.Helper()
	fs := newVirtualFS()
	fs.addFile("main.tf", contents)
	return fakePackEngine(fs)
}

// TestProveEvaluationSafetyFleetForms proves the guard against the fleet's
// real custom-condition forms: every form the governed repositories carry
// must be proven evaluation-safe.
func TestProveEvaluationSafetyFleetForms(t *testing.T) {
	cases := []struct {
		name     string
		contents string
	}{
		{
			name: "the can-regex form",
			contents: `variable "name" {
  type = string

  validation {
    condition     = can(regex("^[a-z]+$", var.name))
    error_message = "name"
  }
}
`,
		},
		{
			name: "the contains-membership form",
			contents: `variable "format" {
  type = string

  validation {
    condition     = contains(["GO", "NPM", "PYTHON", "GENERIC", "DOCKER"], var.format)
    error_message = "format"
  }
}
`,
		},
		{
			name: "the length-on-collection form",
			contents: `variable "items" {
  type = list(string)

  validation {
    condition     = length(var.items) > 0
    error_message = "items"
  }
}
`,
		},
		{
			name: "the length-on-string form",
			contents: `variable "name" {
  type = string

  validation {
    condition     = length(var.name) > 0
    error_message = "name"
  }
}
`,
		},
		{
			name: "the alltrue-for form over a map of objects",
			contents: `variable "zones" {
  type = map(object({
    dns_name = string
  }))

  validation {
    condition     = alltrue([for _, zone in var.zones : endswith(zone.dns_name, ".")])
    error_message = "zones"
  }
}
`,
		},
		{
			name: "the cidrhost form",
			contents: `variable "subnet_cidr" {
  type = string

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr"
  }
}
`,
		},
		{
			name: "the timecmp form",
			contents: `variable "end_time" {
  type = string

  validation {
    condition     = can(timecmp(var.end_time, "1970-01-01T00:00:00Z"))
    error_message = "end_time"
  }
}
`,
		},
		{
			name: "the setsubtract form with a sequence literal",
			contents: `variable "ecosystems" {
  type = set(string)

  validation {
    condition     = length(setsubtract(var.ecosystems, ["go", "npm", "python"])) == 0
    error_message = "ecosystems"
  }
}
`,
		},
		{
			name: "the keys-contains form",
			contents: `variable "homes" {
  type = map(string)

  validation {
    condition     = contains(keys(var.homes), "foundation")
    error_message = "homes"
  }
}
`,
		},
		{
			name: "the distinct-length equality form",
			contents: `variable "homes" {
  type = map(object({
    bucket = string
  }))

  validation {
    condition     = length(distinct([for identity, home in var.homes : home.bucket])) == length(var.homes)
    error_message = "homes"
  }
}
`,
		},
		{
			name: "the split-element form",
			contents: `variable "key" {
  type = string
}

variable "location" {
  type = string

  validation {
    condition     = length(split("/", var.key)) == 8 && element(split("/", var.key), 3) == var.location
    error_message = "key"
  }
}
`,
		},
		{
			name: "the nested for form with an outer loop reference",
			contents: `variable "homes" {
  type = map(object({
    members = set(string)
  }))

  validation {
    condition = alltrue([
      for identity, home in var.homes :
      length(home.members) > 0
      && alltrue([for member in home.members : can(regex("^user:", member))])
    ])
    error_message = "homes"
  }
}
`,
		},
		{
			name: "the null-guarded object iteration form",
			contents: `variable "upstream" {
  type = object({
    uri = optional(string)
  })
  default = null

  validation {
    condition     = var.upstream == null || length(compact([for _, value in var.upstream : value])) == 1
    error_message = "upstream"
  }
}
`,
		},
		{
			name: "the multi-line logical form",
			contents: `variable "network" {
  type = object({
    name   = string
    region = string
  })
  default = null

  validation {
    condition = var.network == null || (
      can(regex("^[a-z][a-z0-9-]*$", var.network.name)) &&
      length(var.network.region) > 0
    )
    error_message = "network"
  }
}
`,
		},
		{
			name: "the corrected string-matching form",
			contents: `variable "bucket" {
  type = string

  validation {
    condition     = !startswith(var.bucket, "goog") && !can(regex("google", var.bucket))
    error_message = "bucket"
  }
}
`,
		},
		{
			name: "the reference universe of a lifecycle condition",
			contents: `variable "input" {
  type = string
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = var.input != "" && self.name != "" && each.key != "" && count.index >= 0 && terraform.workspace != "" && path.module != ""
      error_message = "x"
    }

    postcondition {
      condition     = self.id != ""
      error_message = "x"
    }
  }
}

data "google_project" "current" {}

module "child" {}

check "combined" {
  data "http" "endpoint" {}

  assert {
    condition     = data.http.endpoint.status_code == 200 && google_storage_bucket.bucket.name != "" && module.child.id != "" && data.google_project.current.id != ""
    error_message = "x"
  }
}
`,
		},
		{
			name: "a condition over a local chain",
			contents: `variable "format" {
  type = string
}

locals {
  lowered = var.format
  wrapped = local.lowered
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = local.wrapped == var.format
      error_message = "x"
    }
  }
}
`,
		},
		{
			name: "a condition over a function-evaluated local",
			contents: `variable "homes" {
  type = map(string)
}

locals {
  names = keys(var.homes)
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = contains(local.names, "foundation")
      error_message = "x"
    }
  }
}
`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			e := guardFixture(t, testCase.contents)
			if err := e.proveEvaluationSafety("."); err != nil {
				t.Fatalf("the fleet form must be proven evaluation-safe: %v", err)
			}
		})
	}
}

// TestProveEvaluationSafetyFailures proves the guard fails closed on every
// defect class it exists to catch.
func TestProveEvaluationSafetyFailures(t *testing.T) {
	cases := []struct {
		name     string
		contents string
		want     []string
	}{
		{
			name: "the membership-on-string defect class",
			contents: `variable "bucket" {
  type = string

  validation {
    condition     = !contains(var.bucket, "google")
    error_message = "bucket"
  }
}
`,
			want: []string{`the validation of variable "bucket" is not evaluation-safe`, "list, tuple, or set"},
		},
		{
			name: "an unknown function",
			contents: `variable "name" {
  type = string

  validation {
    condition     = nosuchfunction(var.name)
    error_message = "name"
  }
}
`,
			want: []string{"not evaluation-safe", "nosuchfunction"},
		},
		{
			name: "an undeclared variable reference",
			contents: `variable "name" {
  type = string

  validation {
    condition     = var.nope == "x"
    error_message = "name"
  }
}
`,
			want: []string{"not evaluation-safe", "nope"},
		},
		{
			name: "an undeclared root reference",
			contents: `variable "name" {
  type = string

  validation {
    condition     = nosuchroot.name == "x"
    error_message = "name"
  }
}
`,
			want: []string{"not evaluation-safe"},
		},
		{
			name: "an undeclared local reference",
			contents: `variable "name" {
  type = string

  validation {
    condition     = local.nope == "x"
    error_message = "name"
  }
}
`,
			want: []string{"not evaluation-safe", "nope"},
		},
		{
			name: "an operator type error",
			contents: `variable "count" {
  type = number

  validation {
    condition     = var.count + "x" == 1
    error_message = "count"
  }
}
`,
			want: []string{"not evaluation-safe"},
		},
		{
			name: "an invalid regex pattern literal",
			contents: `variable "name" {
  type = string

  validation {
    condition     = can(regex("(unclosed", var.name))
    error_message = "name"
  }
}
`,
			want: []string{"not evaluation-safe", "regexp"},
		},
		{
			name: "the for-body defect over a declared element type",
			contents: `variable "items" {
  type = list(string)

  validation {
    condition     = alltrue([for item in var.items : contains(item, "a")])
    error_message = "items"
  }
}
`,
			want: []string{"the value expression of the for expression is not evaluation-safe", "list, tuple, or set"},
		},
		{
			name: "a for over an undeclared collection",
			contents: `variable "items" {
  type = list(string)

  validation {
    condition     = alltrue([for item in var.nope : item != ""])
    error_message = "items"
  }
}
`,
			want: []string{"the collection of the for expression is not evaluation-safe", "nope"},
		},
		{
			name: "a defective for key expression",
			contents: `variable "mapping" {
  type = map(string)

  validation {
    condition     = contains(keys({ for key, value in var.mapping : contains(key, "a") => value }), "a")
    error_message = "mapping"
  }
}
`,
			want: []string{"the key expression of the for expression is not evaluation-safe", "list, tuple, or set"},
		},
		{
			name: "a defective for filter expression",
			contents: `variable "items" {
  type = list(string)

  validation {
    condition     = alltrue([for item in var.items : item != "" if contains(item, "a")])
    error_message = "items"
  }
}
`,
			want: []string{"the condition expression of the for expression is not evaluation-safe", "list, tuple, or set"},
		},
		{
			name: "a nested for defect inside a for key expression",
			contents: `variable "mapping" {
  type = map(string)
}

variable "items" {
  type = list(string)
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = contains(keys({ for key, value in var.mapping : alltrue([for item in var.items : contains(item, "a")]) => value }), "x")
      error_message = "x"
    }
  }
}
`,
			want: []string{"not evaluation-safe", "list, tuple, or set"},
		},
		{
			name: "a nested for defect inside a for filter expression",
			contents: `variable "items" {
  type = list(string)
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = alltrue([for item in var.items : item != "" if alltrue([for member in var.items : contains(member, "a")])])
      error_message = "x"
    }
  }
}
`,
			want: []string{"not evaluation-safe", "list, tuple, or set"},
		},
		{
			name: "a nested for defect inside a for value expression",
			contents: `variable "items" {
  type = list(string)
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = alltrue([for item in var.items : alltrue([for member in var.items : contains(member, "a")])])
      error_message = "x"
    }
  }
}
`,
			want: []string{"not evaluation-safe", "list, tuple, or set"},
		},
		{
			name: "a cyclic local reference",
			contents: `variable "name" {
  type = string
}

locals {
  first  = local.second
  second = local.first
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = local.first == var.name
      error_message = "x"
    }
  }
}
`,
			want: []string{"cyclically"},
		},
		{
			name: "a broken local inside the condition reference closure",
			contents: `variable "name" {
  type = string
}

locals {
  broken = contains(var.name, "a")
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = local.broken == true
      error_message = "x"
    }
  }
}
`,
			want: []string{`the local "broken" referenced by a condition is not evaluation-safe`, "list, tuple, or set"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			e := guardFixture(t, testCase.contents)
			err := e.proveEvaluationSafety(".")
			if err == nil {
				t.Fatal("expected the guard to fail closed")
			}
			for _, want := range testCase.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the finding %q must contain %q", err.Error(), want)
				}
			}
		})
	}
}

// TestProveEvaluationSafetyLocalOutsideClosure proves that a broken local
// outside the condition reference closure never fails the guard: the guard
// proves exactly the condition reference closure, never beyond its mandate.
func TestProveEvaluationSafetyLocalOutsideClosure(t *testing.T) {
	e := guardFixture(t, `variable "name" {
  type = string
}

locals {
  broken = contains(var.name, "a")
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = var.name != ""
      error_message = "x"
    }
  }
}
`)
	if err := e.proveEvaluationSafety("."); err != nil {
		t.Fatalf("a local outside the condition reference closure must not fail the guard: %v", err)
	}
}

// TestProveEvaluationSafetyLocalForDefect proves the for-expression proof
// extends into the locals of the condition reference closure.
func TestProveEvaluationSafetyLocalForDefect(t *testing.T) {
	e := guardFixture(t, `variable "items" {
  type = list(string)
}

locals {
  broken = alltrue([for item in var.items : contains(item, "a")])
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = local.broken == true
      error_message = "x"
    }
  }
}
`)
	err := e.proveEvaluationSafety(".")
	if err == nil || !strings.Contains(err.Error(), `the local "broken" referenced by a condition is not evaluation-safe`) {
		t.Fatalf("expected the local for-body finding, got %v", err)
	}
}

// TestProveEvaluationSafetyReferenceCollision proves a declared resource type
// never overwrites the fixed context roots of the evaluation context.
func TestProveEvaluationSafetyReferenceCollision(t *testing.T) {
	e := guardFixture(t, `variable "input" {
  type = string
}

resource "terraform" "collision" {
  lifecycle {
    precondition {
      condition     = terraform.workspace != "" && var.input != ""
      error_message = "x"
    }
  }
}
`)
	if err := e.proveEvaluationSafety("."); err != nil {
		t.Fatalf("a colliding resource type never overwrites the context roots: %v", err)
	}
}

// TestProveEvaluationSafetyAcrossFiles proves the model merges the committed
// form across the root's files: a condition in one file resolves a variable
// declared in another.
func TestProveEvaluationSafetyAcrossFiles(t *testing.T) {
	fs := newVirtualFS()
	fs.addFile("variables.tf", `variable "name" {
  type = string
}
`)
	fs.addFile("main.tf", `resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = var.name != ""
      error_message = "x"
    }
  }
}
`)
	e := fakePackEngine(fs)
	if err := e.proveEvaluationSafety("."); err != nil {
		t.Fatalf("the cross-file form must be proven evaluation-safe: %v", err)
	}
}

func TestProveEvaluationSafetyReadDirError(t *testing.T) {
	e := fakePackEngine(newVirtualFS())
	e.ReadDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("boom") }
	if err := e.proveEvaluationSafety("."); err == nil || !strings.Contains(err.Error(), "read the root directory") {
		t.Fatalf("expected the read-dir finding, got %v", err)
	}
}

// TestProveEvaluationSafetyDescentForms proves the for-expression proof
// descends through every container expression form.
func TestProveEvaluationSafetyDescentForms(t *testing.T) {
	cases := []struct {
		name      string
		condition string
	}{
		{"a for inside a binary operation", `length([for item in var.items : item]) > 0`},
		{"a for inside a unary operation", `!alltrue([for item in var.items : item != ""])`},
		{"a for inside a conditional condition", `length([for item in var.items : item]) > 0 ? true : false`},
		{"a for inside a tuple constructor", `length([[for item in var.items : item]]) > 0`},
		{"a for inside an object constructor", `contains(keys({ group = [for item in var.items : item] }), "group")`},
		{"a for inside an index source", `length(([for item in var.items : item])[var.zero]) > 0`},
		{"a for inside a relative traversal source", `length(({ group = [for item in var.items : item] }).group) > 0`},
		{"a splat without a for", `length(var.items[*]) > 0`},
		{"a for inside a template", `"prefix ${length([for item in var.items : item])}" == "prefix 1"`},
		{"a for inside a pure interpolation", `"${length([for item in var.items : item])}" == "1"`},
		{"a for directive inside a template", `"%{ for item in var.items }${item}%{ endfor }" == ""`},
		{"an object for with a key expression", `contains(keys({ for key, value in var.mapping : key => value }), "a")`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			e := guardFixture(t, `variable "items" {
  type = list(string)
}

variable "mapping" {
  type = map(string)
}

variable "zero" {
  type = number
}

resource "google_storage_bucket" "bucket" {
  lifecycle {
    precondition {
      condition     = `+testCase.condition+`
      error_message = "x"
    }
  }
}
`)
			if err := e.proveEvaluationSafety("."); err != nil {
				t.Fatalf("the descent form must be proven evaluation-safe: %v", err)
			}
		})
	}
}

func TestLoopTypes(t *testing.T) {
	cases := []struct {
		name       string
		collection cty.Type
		wantKey    cty.Type
		wantValue  cty.Type
	}{
		{"map", cty.Map(cty.String), cty.String, cty.String},
		{"list", cty.List(cty.Bool), cty.Number, cty.Bool},
		{"set", cty.Set(cty.Number), cty.Number, cty.Number},
		{"uniform object", cty.Object(map[string]cty.Type{"a": cty.String, "b": cty.String}), cty.String, cty.String},
		{"divergent object", cty.Object(map[string]cty.Type{"a": cty.String, "b": cty.List(cty.String)}), cty.String, cty.DynamicPseudoType},
		{"uniform tuple", cty.Tuple([]cty.Type{cty.String, cty.String}), cty.Number, cty.String},
		{"divergent tuple", cty.Tuple([]cty.Type{cty.String, cty.List(cty.String)}), cty.Number, cty.DynamicPseudoType},
		{"dynamic", cty.DynamicPseudoType, cty.DynamicPseudoType, cty.DynamicPseudoType},
		{"non-collection", cty.Number, cty.DynamicPseudoType, cty.DynamicPseudoType},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			key, value := loopTypes(testCase.collection)
			if !key.Equals(testCase.wantKey) || !value.Equals(testCase.wantValue) {
				t.Fatalf("loopTypes = (%v, %v), want (%v, %v)", key, value, testCase.wantKey, testCase.wantValue)
			}
		})
	}
}

func TestLocalReferences(t *testing.T) {
	cases := []struct {
		source string
		want   []string
	}{
		{"local.x", []string{"x"}},
		{"local.a[0]", []string{"a"}},
		{"var.x", nil},
		{"var", nil},
		{"local[0]", nil},
	}
	for _, testCase := range cases {
		got := localReferences(parseExpression(t, testCase.source))
		if strings.Join(got, ",") != strings.Join(testCase.want, ",") {
			t.Fatalf("localReferences(%q) = %+v, want %+v", testCase.source, got, testCase.want)
		}
	}
}

func TestSortLocalsByDependency(t *testing.T) {
	locals := map[string]hcl.Expression{
		"first":  parseExpression(t, `"x"`),
		"second": parseExpression(t, "local.first"),
		"third":  parseExpression(t, "local.first"),
	}
	closure := map[string]struct{}{"first": {}, "second": {}, "third": {}}
	ordered, err := sortLocalsByDependency(locals, closure)
	if err != nil {
		t.Fatalf("sortLocalsByDependency: %v", err)
	}
	if strings.Join(ordered, ",") != "first,second,third" {
		t.Fatalf("ordered = %+v", ordered)
	}
}

func TestSortLocalsByDependencyCyclic(t *testing.T) {
	locals := map[string]hcl.Expression{
		"first":  parseExpression(t, "local.second"),
		"second": parseExpression(t, "local.first"),
	}
	closure := map[string]struct{}{"first": {}, "second": {}}
	if _, err := sortLocalsByDependency(locals, closure); err == nil || !strings.Contains(err.Error(), "cyclically") {
		t.Fatalf("expected the cycle finding, got %v", err)
	}
}

func TestSortLocalsByDependencyOutsideClosure(t *testing.T) {
	locals := map[string]hcl.Expression{
		"needed":  parseExpression(t, "local.outside"),
		"outside": parseExpression(t, `"x"`),
	}
	closure := map[string]struct{}{"needed": {}}
	ordered, err := sortLocalsByDependency(locals, closure)
	if err != nil {
		t.Fatalf("sortLocalsByDependency: %v", err)
	}
	if strings.Join(ordered, ",") != "needed" {
		t.Fatalf("a dependency outside the closure is never ordered: %+v", ordered)
	}
}

func TestFirstDiagnosticWarningFallback(t *testing.T) {
	diags := hcl.Diagnostics{{Severity: hcl.DiagWarning, Summary: "a warning"}}
	if got := firstDiagnostic(diags); got != "a warning" {
		t.Fatalf("firstDiagnostic warning fallback = %q", got)
	}
}

func TestRenderDiagnostic(t *testing.T) {
	got := renderDiagnostic(&hcl.Diagnostic{
		Summary: "summary",
		Detail:  "detail",
		Subject: &hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 3}},
	})
	if got != "summary: detail (main.tf:3)" {
		t.Fatalf("renderDiagnostic = %q", got)
	}
	got = renderDiagnostic(&hcl.Diagnostic{Summary: "summary"})
	if got != "summary" {
		t.Fatalf("renderDiagnostic minimal = %q", got)
	}
}

func TestConditionLocalClosure(t *testing.T) {
	model := rootModel{
		locals: map[string]hcl.Expression{
			"direct":     parseExpression(t, `"x"`),
			"transitive": parseExpression(t, "local.direct"),
			"unused":     parseExpression(t, `"y"`),
		},
		conditions: []rootCondition{
			{expr: parseExpression(t, "local.transitive")},
			{expr: parseExpression(t, "local.direct")},
			{expr: parseExpression(t, "local.undeclared")},
		},
	}
	closure := model.conditionLocalClosure()
	if _, found := closure["direct"]; !found {
		t.Fatalf("closure = %+v", closure)
	}
	if _, found := closure["transitive"]; !found {
		t.Fatalf("closure = %+v", closure)
	}
	if _, found := closure["unused"]; found {
		t.Fatalf("the unused local must not enter the closure: %+v", closure)
	}
	if _, found := closure["undeclared"]; found {
		t.Fatalf("an undeclared local never enters the closure: %+v", closure)
	}
}

// TestChildExpressions covers the container-expression descent of the
// for-expression proof directly, one parsed form per container case.
func TestChildExpressions(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   int
	}{
		{"binary operation", `a + b`, 2},
		{"unary operation", `!a`, 1},
		{"conditional", `a ? b : c`, 3},
		{"function call", `f(a, b)`, 2},
		{"tuple constructor", `[a, b]`, 2},
		{"object constructor", `{ k = v }`, 2},
		{"index", `f(a)[b]`, 2},
		{"relative traversal", `f(a).b`, 1},
		{"splat", `a[*]`, 1},
		{"template", `"x ${a} y"`, 3},
		{"template wrap", `"${a}"`, 1},
		{"parentheses", `(a)`, 1},
		{"leaf", `a`, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := childExpressions(parseExpression(t, testCase.source))
			if len(got) != testCase.want {
				t.Fatalf("childExpressions(%q) = %d children, want %d", testCase.source, len(got), testCase.want)
			}
		})
	}
}

// TestChildExpressionsTemplateJoin covers the template-join form produced by
// a for directive inside a template.
func TestChildExpressionsTemplateJoin(t *testing.T) {
	template := parseExpression(t, `"%{ for x in xs }${x}%{ endfor }"`)
	parts := childExpressions(template)
	if len(parts) != 1 {
		t.Fatalf("the template-for carries exactly one join part, got %d", len(parts))
	}
	if _, isJoin := parts[0].(*hclsyntax.TemplateJoinExpr); !isJoin {
		t.Fatalf("the template-for part is the join expression, got %T", parts[0])
	}
	if got := childExpressions(parts[0]); len(got) != 1 {
		t.Fatalf("the join expression carries its tuple, got %d", len(got))
	}
}
