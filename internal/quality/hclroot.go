package quality

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// rootModel is the static model of one HCL root directory, built from its
// clean staging so it always describes the committed form: the declared
// variable type constraints, the local definitions, every custom-condition
// body (every variable validation, every precondition and postcondition, and
// every check assertion), the referenceable symbols (resources, data sources,
// and module calls), and whether the root carries an encryption block.
type rootModel struct {
	// variables binds every declared input variable to its declared type
	// constraint (the dynamic pseudo type when the declaration carries no
	// type constraint).
	variables map[string]cty.Type
	// locals binds every local definition to its expression.
	locals map[string]hcl.Expression
	// conditions carries every custom-condition body of the root in a
	// deterministic order.
	conditions []rootCondition
	// resources indexes the declared resource instances by type and name.
	resources map[string][]string
	// data indexes the declared data source instances by type and name,
	// including the data sources scoped to a check block.
	data map[string][]string
	// modules carries the declared module call names.
	modules []string
	// encrypted reports whether the root carries an encryption block: its
	// initialization resolves encryption key material, which the offline
	// gate never carries.
	encrypted bool
}

// rootCondition is one custom-condition body with its provenance.
type rootCondition struct {
	// surface names the condition form: validation, precondition,
	// postcondition, or assert.
	surface string
	// owner names the carrying block, for example `variable "format"`.
	owner string
	// expr is the condition expression.
	expr hcl.Expression
}

// buildRootModel parses every .tf file directly carried by the given
// directory and extracts the static root model. Test files (*.tofutest.hcl
// and *.tftest.hcl) are the behavioral surface and are never part of the
// static model. A read failure, a parse error, and an invalid variable type
// constraint fail closed, naming the file.
func (e PackEngine) buildRootModel(dir string) (rootModel, error) {
	entries, err := e.ReadDir(dir)
	if err != nil {
		return rootModel{}, fmt.Errorf("read the root directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	model := rootModel{
		variables: map[string]cty.Type{},
		locals:    map[string]hcl.Expression{},
		resources: map[string][]string{},
		data:      map[string][]string{},
	}
	for _, name := range names {
		contents, err := e.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return rootModel{}, fmt.Errorf("read %s: %w", name, err)
		}
		file, diags := hclsyntax.ParseConfig(contents, filepath.Join(dir, name), hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			return rootModel{}, fmt.Errorf("parse %s: %s", name, firstDiagnostic(diags))
		}
		// The native parser always produces the native body form; the
		// assertion is the invariant, never a user-facing error path.
		body := file.Body.(*hclsyntax.Body)
		if err := extractRootModelBody(body, &model); err != nil {
			return rootModel{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	return model, nil
}

// extractRootModelBody extracts the static model surface of one parsed body.
func extractRootModelBody(body *hclsyntax.Body, model *rootModel) error {
	for _, block := range body.Blocks {
		switch block.Type {
		case "variable":
			if len(block.Labels) != 1 {
				continue
			}
			if err := extractVariableBlock(block, model); err != nil {
				return err
			}
		case "locals":
			for name, attr := range block.Body.Attributes {
				model.locals[name] = attr.Expr
			}
		case "resource":
			if len(block.Labels) == 2 {
				model.resources[block.Labels[0]] = append(model.resources[block.Labels[0]], block.Labels[1])
			}
			extractLifecycleConditions(block, model)
		case "data":
			if len(block.Labels) == 2 {
				model.data[block.Labels[0]] = append(model.data[block.Labels[0]], block.Labels[1])
			}
			extractLifecycleConditions(block, model)
		case "module":
			if len(block.Labels) == 1 {
				model.modules = append(model.modules, block.Labels[0])
			}
		case "output":
			extractConditionBlocks(block.Body, "precondition", block, model)
		case "check":
			extractCheckBlock(block, model)
		case "terraform":
			for _, inner := range block.Body.Blocks {
				if inner.Type == "encryption" {
					model.encrypted = true
				}
			}
		}
	}
	return nil
}

// extractVariableBlock extracts the declared type constraint and the
// validation conditions of one variable block.
func extractVariableBlock(block *hclsyntax.Block, model *rootModel) error {
	name := block.Labels[0]
	constraint := cty.DynamicPseudoType
	if attr, found := block.Body.Attributes["type"]; found {
		typ, diags := typeexpr.TypeConstraint(attr.Expr)
		if diags.HasErrors() {
			return fmt.Errorf("variable %q carries an invalid type constraint: %s", name, firstDiagnostic(diags))
		}
		constraint = typ
	}
	model.variables[name] = constraint
	extractConditionBlocks(block.Body, "validation", block, model)
	return nil
}

// extractLifecycleConditions extracts the precondition and postcondition
// bodies of one resource or data block.
func extractLifecycleConditions(block *hclsyntax.Block, model *rootModel) {
	for _, inner := range block.Body.Blocks {
		if inner.Type != "lifecycle" {
			continue
		}
		extractConditionBlocks(inner.Body, "precondition", block, model)
		extractConditionBlocks(inner.Body, "postcondition", block, model)
	}
}

// extractCheckBlock extracts the assertion bodies of one check block and
// indexes the data sources scoped to it.
func extractCheckBlock(block *hclsyntax.Block, model *rootModel) {
	for _, inner := range block.Body.Blocks {
		switch inner.Type {
		case "assert":
			extractConditionAttribute(inner, "assert", block, model)
		case "data":
			if len(inner.Labels) == 2 {
				model.data[inner.Labels[0]] = append(model.data[inner.Labels[0]], inner.Labels[1])
			}
		}
	}
}

// extractConditionBlocks extracts the condition body of every block of the
// given type carried by the given body.
func extractConditionBlocks(body *hclsyntax.Body, blockType string, owner *hclsyntax.Block, model *rootModel) {
	for _, block := range body.Blocks {
		if block.Type != blockType {
			continue
		}
		extractConditionAttribute(block, blockType, owner, model)
	}
}

// extractConditionAttribute extracts the condition body of one condition
// block. A condition block without a condition attribute carries no body and
// is skipped — the malformed block is the engine's validation domain, never
// the guard's.
func extractConditionAttribute(block *hclsyntax.Block, surface string, owner *hclsyntax.Block, model *rootModel) {
	attr, found := block.Body.Attributes["condition"]
	if !found {
		return
	}
	model.conditions = append(model.conditions, rootCondition{
		surface: surface,
		owner:   ownerName(owner),
		expr:    attr.Expr,
	})
}

// ownerName renders the canonical provenance name of a block, for example
// `variable "format"` or `resource "google_storage_bucket" "state_homes"`.
func ownerName(block *hclsyntax.Block) string {
	if len(block.Labels) == 0 {
		return block.Type
	}
	return fmt.Sprintf(`%s "%s"`, block.Type, strings.Join(block.Labels, `" "`))
}

// firstDiagnostic renders the first error diagnostic of a set with its
// source range for a fail-closed finding.
func firstDiagnostic(diags hcl.Diagnostics) string {
	for _, diag := range diags {
		if diag.Severity == hcl.DiagError {
			return renderDiagnostic(diag)
		}
	}
	if len(diags) > 0 {
		return renderDiagnostic(diags[0])
	}
	return "no diagnostics"
}

// renderDiagnostic renders one diagnostic as a single-line finding with its
// source range.
func renderDiagnostic(diag *hcl.Diagnostic) string {
	text := diag.Summary
	if diag.Detail != "" {
		text += ": " + diag.Detail
	}
	if diag.Subject != nil {
		text += fmt.Sprintf(" (%s:%d)", diag.Subject.Filename, diag.Subject.Start.Line)
	}
	return text
}
