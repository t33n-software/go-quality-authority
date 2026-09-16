package quality

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// proveEvaluationSafety is the static evaluation-safety guard of the pack
// execution: every custom-condition body of the root's committed form (the
// staged directory) is proven evaluation-safe against the declared variable
// types — every built-in function call receives signature-conformant argument
// types, every operator application is type-compatible, and every reference
// resolves. The guard fails closed on a parse error, an unknown function, an
// unresolvable reference, or a type error. It proves evaluation safety, never
// rejection or acceptance behavior: the behavioral proof of a condition is
// the pack's behavioral gate, and for an encryption-carrying root that proof
// is bound to the governed execution window.
func (e PackEngine) proveEvaluationSafety(dir string) error {
	model, err := e.buildRootModel(dir)
	if err != nil {
		return err
	}
	ctx, err := model.evalContext()
	if err != nil {
		return err
	}
	for _, condition := range model.conditions {
		if err := condition.prove(ctx); err != nil {
			return err
		}
	}
	return nil
}

// evalContext builds the guard's evaluation context: every declared variable
// bound to the unknown value of its declared type (the declared type is the
// proof surface, never a concrete value), the condition-referenced locals
// evaluated in dependency order, the documented context objects (self, count,
// each, terraform, path), the declared resources, data sources, and module
// calls as dynamically typed references, and the closed-world function
// surface.
func (m rootModel) evalContext() (*hcl.EvalContext, error) {
	locals, err := m.evaluatedLocals()
	if err != nil {
		return nil, err
	}
	root := m.baseReferences()
	root["var"] = cty.ObjectVal(unknownAttributes(m.variables))
	root["local"] = cty.ObjectVal(locals)
	return &hcl.EvalContext{
		Variables: root,
		Functions: guardFunctions,
	}, nil
}

// unknownAttributes binds every declared name to the unknown value of its
// declared type.
func unknownAttributes(declared map[string]cty.Type) map[string]cty.Value {
	attributes := make(map[string]cty.Value, len(declared))
	for name, constraint := range declared {
		attributes[name] = cty.UnknownVal(constraint)
	}
	return attributes
}

// baseReferences binds the documented context objects and the declared
// resources, data sources, and module calls. The fixed context roots are
// never overwritten by a declared symbol.
func (m rootModel) baseReferences() map[string]cty.Value {
	root := map[string]cty.Value{
		"self":      cty.UnknownVal(cty.DynamicPseudoType),
		"count":     cty.ObjectVal(map[string]cty.Value{"index": cty.UnknownVal(cty.Number)}),
		"each":      cty.ObjectVal(map[string]cty.Value{"key": cty.UnknownVal(cty.String), "value": cty.UnknownVal(cty.DynamicPseudoType)}),
		"terraform": cty.ObjectVal(map[string]cty.Value{"workspace": cty.UnknownVal(cty.String)}),
		"path": cty.ObjectVal(map[string]cty.Value{
			"module": cty.UnknownVal(cty.String),
			"root":   cty.UnknownVal(cty.String),
			"cwd":    cty.UnknownVal(cty.String),
		}),
	}
	for resourceType, names := range m.resources {
		if _, taken := root[resourceType]; taken {
			continue
		}
		root[resourceType] = cty.ObjectVal(dynamicInstances(names))
	}
	if len(m.data) > 0 {
		dataTypes := map[string]cty.Value{}
		for dataType, names := range m.data {
			dataTypes[dataType] = cty.ObjectVal(dynamicInstances(names))
		}
		root["data"] = cty.ObjectVal(dataTypes)
	}
	if len(m.modules) > 0 {
		root["module"] = cty.ObjectVal(dynamicInstances(m.modules))
	}
	return root
}

// dynamicInstances binds every instance name to the dynamic unknown.
func dynamicInstances(names []string) map[string]cty.Value {
	instances := make(map[string]cty.Value, len(names))
	for _, name := range names {
		instances[name] = cty.UnknownVal(cty.DynamicPseudoType)
	}
	return instances
}

// evaluatedLocals evaluates the condition-referenced locals in dependency
// order against the declared variable types. A local outside the condition
// reference closure binds as the dynamic unknown — declared, never evaluated
// — so the guard proves exactly the condition reference closure and never
// reaches beyond its mandate. A cyclic or unevaluable local inside the
// closure fails closed.
func (m rootModel) evaluatedLocals() (map[string]cty.Value, error) {
	closure := m.conditionLocalClosure()
	values := make(map[string]cty.Value, len(m.locals))
	for name := range m.locals {
		if _, needed := closure[name]; !needed {
			values[name] = cty.UnknownVal(cty.DynamicPseudoType)
		}
	}
	ordered, err := sortLocalsByDependency(m.locals, closure)
	if err != nil {
		return nil, err
	}
	for _, name := range ordered {
		ctx := &hcl.EvalContext{
			Variables: m.localsContext(values),
			Functions: guardFunctions,
		}
		value, diags := m.locals[name].Value(ctx)
		if diags.HasErrors() {
			return nil, fmt.Errorf("the local %q referenced by a condition is not evaluation-safe: %s", name, firstDiagnostic(diags))
		}
		if err := proveForExpressions(m.locals[name], ctx); err != nil {
			return nil, fmt.Errorf("the local %q referenced by a condition is not evaluation-safe: %s", name, err)
		}
		values[name] = value
	}
	return values, nil
}

// localsContext binds the base references plus the locals bound so far.
func (m rootModel) localsContext(bound map[string]cty.Value) map[string]cty.Value {
	root := m.baseReferences()
	root["var"] = cty.ObjectVal(unknownAttributes(m.variables))
	root["local"] = cty.ObjectVal(bound)
	return root
}

// conditionLocalClosure computes the set of local names referenced by the
// root's conditions, transitively closed over the locals' own references.
// An undeclared local reference is not part of the closure: it fails at the
// condition's own evaluation as an unresolvable reference.
func (m rootModel) conditionLocalClosure() map[string]struct{} {
	closure := map[string]struct{}{}
	var include func(expr hcl.Expression)
	include = func(expr hcl.Expression) {
		for _, name := range localReferences(expr) {
			if _, found := closure[name]; found {
				continue
			}
			if _, declared := m.locals[name]; !declared {
				continue
			}
			closure[name] = struct{}{}
			include(m.locals[name])
		}
	}
	for _, condition := range m.conditions {
		include(condition.expr)
	}
	return closure
}

// localReferences returns the names of the locals an expression references.
func localReferences(expr hcl.Expression) []string {
	names := []string{}
	for _, traversal := range expr.Variables() {
		if len(traversal) < 2 {
			continue
		}
		root, ok := traversal[0].(hcl.TraverseRoot)
		if !ok || root.Name != "local" {
			continue
		}
		attr, ok := traversal[1].(hcl.TraverseAttr)
		if !ok {
			continue
		}
		names = append(names, attr.Name)
	}
	return names
}

// sortLocalsByDependency orders the closure locals so that every local is
// evaluated after the locals it references; a cyclic reference fails closed.
func sortLocalsByDependency(locals map[string]hcl.Expression, closure map[string]struct{}) ([]string, error) {
	ordered := []string{}
	done := map[string]struct{}{}
	visiting := map[string]struct{}{}
	var visit func(name string) error
	visit = func(name string) error {
		if _, ok := done[name]; ok {
			return nil
		}
		if _, ok := visiting[name]; ok {
			return fmt.Errorf("the local %q is referenced cyclically", name)
		}
		visiting[name] = struct{}{}
		for _, dependency := range localReferences(locals[name]) {
			if _, needed := closure[dependency]; !needed {
				continue
			}
			if err := visit(dependency); err != nil {
				return err
			}
		}
		delete(visiting, name)
		done[name] = struct{}{}
		ordered = append(ordered, name)
		return nil
	}
	names := make([]string, 0, len(closure))
	for name := range closure {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

// prove proves every for-expression body of the condition against the
// element types of its collection first — the for machinery's attribution is
// the precise surface — and then evaluates the whole condition body against
// the guard's evaluation context. The expression evaluation never enters a
// for body over an unknown collection, so the guard proves the body against
// the declared element types directly.
func (c rootCondition) prove(ctx *hcl.EvalContext) error {
	if err := proveForExpressions(c.expr, ctx); err != nil {
		return fmt.Errorf("the %s of %s is not evaluation-safe: %s", c.surface, c.owner, err)
	}
	if _, diags := c.expr.Value(ctx); diags.HasErrors() {
		return fmt.Errorf("the %s of %s is not evaluation-safe: %s", c.surface, c.owner, firstDiagnostic(diags))
	}
	return nil
}

// proveForExpressions proves every for-expression of an expression against
// the element types of its collection, carrying the loop bindings of the
// enclosing for-expressions so a nested for body resolves its outer loop
// variables.
func proveForExpressions(expr hcl.Expression, ctx *hcl.EvalContext) error {
	forExpr, isFor := expr.(*hclsyntax.ForExpr)
	if !isFor {
		for _, child := range childExpressions(expr) {
			if err := proveForExpressions(child, ctx); err != nil {
				return err
			}
		}
		return nil
	}
	childCtx, err := forLoopContext(forExpr, ctx)
	if err != nil {
		return err
	}
	if forExpr.KeyExpr != nil {
		if _, diags := forExpr.KeyExpr.Value(childCtx); diags.HasErrors() {
			return fmt.Errorf("the key expression of the for expression is not evaluation-safe: %s", firstDiagnostic(diags))
		}
		if err := proveForExpressions(forExpr.KeyExpr, childCtx); err != nil {
			return err
		}
	}
	if _, diags := forExpr.ValExpr.Value(childCtx); diags.HasErrors() {
		return fmt.Errorf("the value expression of the for expression is not evaluation-safe: %s", firstDiagnostic(diags))
	}
	if err := proveForExpressions(forExpr.ValExpr, childCtx); err != nil {
		return err
	}
	if forExpr.CondExpr != nil {
		if _, diags := forExpr.CondExpr.Value(childCtx); diags.HasErrors() {
			return fmt.Errorf("the condition expression of the for expression is not evaluation-safe: %s", firstDiagnostic(diags))
		}
		if err := proveForExpressions(forExpr.CondExpr, childCtx); err != nil {
			return err
		}
	}
	return nil
}

// forLoopContext derives the loop bindings of a for-expression from the
// static type of its collection: the collection is evaluated for its type
// only (its value stays unknown), and the loop variables bind the unknown
// element types, so the body is proven against the declared element types.
func forLoopContext(expr *hclsyntax.ForExpr, ctx *hcl.EvalContext) (*hcl.EvalContext, error) {
	collection, diags := expr.CollExpr.Value(ctx)
	if diags.HasErrors() {
		return nil, fmt.Errorf("the collection of the for expression is not evaluation-safe: %s", firstDiagnostic(diags))
	}
	keyType, valueType := loopTypes(collection.Type())
	child := ctx.NewChild()
	child.Variables = map[string]cty.Value{}
	if expr.KeyVar != "" {
		child.Variables[expr.KeyVar] = cty.UnknownVal(keyType)
	}
	child.Variables[expr.ValVar] = cty.UnknownVal(valueType)
	return child, nil
}

// loopTypes derives the static key and value types of a for-expression's
// collection type: the key of a map or object is its string name, the key of
// a list or tuple is its numeric index, and the key of a set is the element
// itself. A dynamically typed collection binds both loop variables
// dynamically.
func loopTypes(collection cty.Type) (cty.Type, cty.Type) {
	switch {
	case collection.IsMapType():
		return cty.String, collection.ElementType()
	case collection.IsListType():
		return cty.Number, collection.ElementType()
	case collection.IsSetType():
		return collection.ElementType(), collection.ElementType()
	case collection.IsObjectType():
		attributes := make([]cty.Type, 0, len(collection.AttributeTypes()))
		for _, typ := range collection.AttributeTypes() {
			attributes = append(attributes, typ)
		}
		value, err := commonType(attributes)
		if err != nil {
			return cty.String, cty.DynamicPseudoType
		}
		return cty.String, value
	case collection.IsTupleType():
		value, err := commonType(collection.TupleElementTypes())
		if err != nil {
			return cty.Number, cty.DynamicPseudoType
		}
		return cty.Number, value
	default:
		return cty.DynamicPseudoType, cty.DynamicPseudoType
	}
}

// syntaxExpressions converts a native-syntax expression slice into the
// language-agnostic expression slice.
func syntaxExpressions(expressions []hclsyntax.Expression) []hcl.Expression {
	converted := make([]hcl.Expression, 0, len(expressions))
	for _, expression := range expressions {
		converted = append(converted, expression)
	}
	return converted
}

// childExpressions returns the child expressions of a container expression,
// so the for-expression proof descends through every expression form that can
// carry one. A splat's each expression is never descended into: its anonymous
// per-element binding is engine-internal and never resolvable statically.
func childExpressions(expr hcl.Expression) []hcl.Expression {
	switch node := expr.(type) {
	case *hclsyntax.BinaryOpExpr:
		return []hcl.Expression{node.LHS, node.RHS}
	case *hclsyntax.UnaryOpExpr:
		return []hcl.Expression{node.Val}
	case *hclsyntax.ConditionalExpr:
		return []hcl.Expression{node.Condition, node.TrueResult, node.FalseResult}
	case *hclsyntax.FunctionCallExpr:
		return syntaxExpressions(node.Args)
	case *hclsyntax.TupleConsExpr:
		return syntaxExpressions(node.Exprs)
	case *hclsyntax.ObjectConsExpr:
		children := []hcl.Expression{}
		for _, item := range node.Items {
			children = append(children, item.KeyExpr, item.ValueExpr)
		}
		return children
	case *hclsyntax.IndexExpr:
		return []hcl.Expression{node.Collection, node.Key}
	case *hclsyntax.RelativeTraversalExpr:
		return []hcl.Expression{node.Source}
	case *hclsyntax.SplatExpr:
		return []hcl.Expression{node.Source}
	case *hclsyntax.TemplateExpr:
		return syntaxExpressions(node.Parts)
	case *hclsyntax.TemplateWrapExpr:
		return []hcl.Expression{node.Wrapped}
	case *hclsyntax.TemplateJoinExpr:
		return []hcl.Expression{node.Tuple}
	case *hclsyntax.ParenthesesExpr:
		return []hcl.Expression{node.Expression}
	default:
		return nil
	}
}
