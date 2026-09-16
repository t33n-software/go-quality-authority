package quality

import (
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"time"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// guardFunctions is the closed-world function surface of the static
// evaluation-safety guard: exactly the built-in functions the fleet's
// governed custom conditions use, each proven signature-conformant against
// the declared argument types. The type check runs on the declared types of
// unknown values too, because the function machinery evaluates the type
// function before any unknown short-circuit. A condition calling a function
// outside this surface fails closed; extending the surface is an engine
// change, versioned with the orchestrator.
//
// The concrete implementations delegate to the verified go-cty standard
// library where it carries the function with the documented signature. The
// engine-local functions cover the documented OpenTofu signatures the
// standard library does not carry (can, alltrue, timecmp, cidrhost,
// startswith, endswith) or carries only with a stricter parameter surface
// than the documented engine behavior (contains, length, setsubtract).
var guardFunctions = map[string]function.Function{
	"alltrue":     allTrueFunc,
	"can":         canFunc,
	"cidrhost":    cidrHostFunc,
	"compact":     stdlib.CompactFunc,
	"contains":    containsFunc,
	"distinct":    stdlib.DistinctFunc,
	"element":     stdlib.ElementFunc,
	"endswith":    endsWithFunc,
	"keys":        keysFunc,
	"length":      lengthFunc,
	"regex":       stdlib.RegexFunc,
	"setsubtract": setSubtractFunc,
	"split":       stdlib.SplitFunc,
	"startswith":  startsWithFunc,
	"timecmp":     timeCmpFunc,
}

// elementTypeOf resolves the element type of a collection type: the element
// type of a list, set, or map, the unified element type of a tuple, and the
// dynamic pseudo type of a dynamically typed collection.
func elementTypeOf(collection cty.Type) (cty.Type, error) {
	switch {
	case collection.IsListType() || collection.IsSetType() || collection.IsMapType():
		return collection.ElementType(), nil
	case collection.IsTupleType():
		return commonType(collection.TupleElementTypes())
	case collection == cty.DynamicPseudoType:
		return cty.DynamicPseudoType, nil
	default:
		return cty.NilType, fmt.Errorf("a list, tuple, set, or map is required, got %s", collection.FriendlyName())
	}
}

// commonType unifies element types: the shared type when all agree, the
// dynamic pseudo type for an empty set, and a failure for divergent types.
func commonType(types []cty.Type) (cty.Type, error) {
	if len(types) == 0 {
		return cty.DynamicPseudoType, nil
	}
	unified, _ := convert.UnifyUnsafe(types)
	if unified == cty.NilType {
		return cty.NilType, fmt.Errorf("the element types do not unify")
	}
	return unified, nil
}

// containsFunc is the guard's contains: the first argument must be a list,
// tuple, or set, and the second argument must conform to the element type.
// The standard library carries the collection check only in its
// implementation, which the unknown short-circuit never reaches — the defect
// class (contains called on a string) is invisible without this type-time
// check.
var containsFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "collection", Type: cty.DynamicPseudoType, AllowDynamicType: true},
		{Name: "value", Type: cty.DynamicPseudoType, AllowDynamicType: true, AllowUnknown: true, AllowNull: true},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		collection := args[0].Type()
		// A dynamically typed collection is accepted optimistically: the
		// guard rejects known-wrong types, never an unknown type.
		if collection == cty.DynamicPseudoType {
			return cty.Bool, nil
		}
		if !(collection.IsListType() || collection.IsTupleType() || collection.IsSetType()) {
			return cty.NilType, function.NewArgErrorf(0, "contains requires a list, tuple, or set as its first argument, got %s", collection.FriendlyName())
		}
		element, err := elementTypeOf(collection)
		if err != nil {
			return cty.NilType, function.NewArgError(0, err)
		}
		if _, err := convert.Convert(args[1], element); err != nil {
			return cty.NilType, function.NewArgErrorf(1, "the value cannot conform to the collection's element type %s: %s", element.FriendlyName(), err)
		}
		return cty.Bool, nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return stdlib.Contains(args[0], args[1])
	},
})

// lengthFunc is the guard's length: the documented engine form accepts a
// string or any collection, while the standard library's type function
// rejects strings.
var lengthFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "value", Type: cty.DynamicPseudoType, AllowDynamicType: true},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		typ := args[0].Type()
		if !(typ == cty.String || typ.IsListType() || typ.IsTupleType() || typ.IsMapType() || typ.IsSetType() || typ == cty.DynamicPseudoType) {
			return cty.NilType, function.NewArgErrorf(0, "length requires a string or a collection, got %s", typ.FriendlyName())
		}
		return cty.Number, nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		if args[0].Type() == cty.String {
			return cty.NumberIntVal(int64(len([]rune(args[0].AsString())))), nil
		}
		return stdlib.Length(args[0])
	},
})

// setSubtractFunc is the guard's setsubtract: the documented engine form
// accepts sets and sequences on both sides, while the standard library's
// parameter surface accepts only sets.
var setSubtractFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "a", Type: cty.DynamicPseudoType, AllowDynamicType: true},
		{Name: "b", Type: cty.DynamicPseudoType, AllowDynamicType: true},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		for index, arg := range args {
			typ := arg.Type()
			if typ == cty.DynamicPseudoType {
				continue
			}
			if !(typ.IsSetType() || typ.IsListType() || typ.IsTupleType()) {
				return cty.NilType, function.NewArgErrorf(index, "setsubtract requires sets or sequences, got %s", typ.FriendlyName())
			}
		}
		element, err := elementTypeOf(args[0].Type())
		if err != nil {
			return cty.NilType, function.NewArgError(0, err)
		}
		return cty.Set(element), nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		if !args[0].IsWhollyKnown() || !args[1].IsWhollyKnown() {
			return cty.UnknownVal(retType), nil
		}
		element := retType.ElementType()
		subtrahend := []cty.Value{}
		for it := args[1].ElementIterator(); it.Next(); {
			_, value := it.Element()
			converted, err := convert.Convert(value, element)
			if err != nil {
				return cty.NilVal, function.NewArgErrorf(1, "the second collection's elements must conform to the first collection's element type %s: %s", element.FriendlyName(), err)
			}
			subtrahend = append(subtrahend, converted)
		}
		result := []cty.Value{}
		for it := args[0].ElementIterator(); it.Next(); {
			_, value := it.Element()
			// The type function unified the first collection's element types
			// to the result element type, so the conversion of its elements
			// holds by construction: a unified primitive target converts every
			// unified source value, and a non-unifiable collection never
			// reaches the implementation.
			converted, _ := convert.Convert(value, element)
			contained := false
			for _, candidate := range subtrahend {
				if converted.Equals(candidate).True() {
					contained = true
					break
				}
			}
			if !contained {
				result = append(result, converted)
			}
		}
		if len(result) == 0 {
			return cty.SetValEmpty(element), nil
		}
		return cty.SetVal(result), nil
	},
})

// keysFunc is the guard's keys: a map or an object, with the dynamic
// tolerance the guard's static semantics require — the standard library's
// type function rejects a dynamically typed mapping, which the for-expression
// forms produce.
var keysFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "mapping", Type: cty.DynamicPseudoType, AllowDynamicType: true},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		typ := args[0].Type()
		switch {
		case typ.IsMapType() || typ == cty.DynamicPseudoType:
			return cty.List(cty.String), nil
		case typ.IsObjectType():
			attributes := typ.AttributeTypes()
			if len(attributes) == 0 {
				return cty.EmptyTuple, nil
			}
			elements := make([]cty.Type, len(attributes))
			for index := range elements {
				elements[index] = cty.String
			}
			return cty.Tuple(elements), nil
		default:
			return cty.NilType, function.NewArgErrorf(0, "keys requires a map or an object, got %s", typ.FriendlyName())
		}
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return stdlib.Keys(args[0])
	},
})

// allTrueFunc is the guard's alltrue: a collection of boolean values. The
// standard library does not carry the function.
var allTrueFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "list", Type: cty.DynamicPseudoType, AllowDynamicType: true},
	},
	Type: func(args []cty.Value) (cty.Type, error) {
		typ := args[0].Type()
		if typ == cty.DynamicPseudoType {
			return cty.Bool, nil
		}
		if !(typ.IsListType() || typ.IsTupleType() || typ.IsSetType()) {
			return cty.NilType, function.NewArgErrorf(0, "alltrue requires a list, tuple, or set of boolean values, got %s", typ.FriendlyName())
		}
		element, err := elementTypeOf(typ)
		if err != nil {
			return cty.NilType, function.NewArgError(0, err)
		}
		if element != cty.DynamicPseudoType && !element.Equals(cty.Bool) {
			return cty.NilType, function.NewArgErrorf(0, "alltrue requires boolean elements, got %s", element.FriendlyName())
		}
		return cty.Bool, nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		if !args[0].IsWhollyKnown() {
			return cty.UnknownVal(cty.Bool), nil
		}
		result := true
		for it := args[0].ElementIterator(); it.Next(); {
			_, value := it.Element()
			if value.IsNull() {
				return cty.NilVal, function.NewArgError(0, fmt.Errorf("alltrue elements must not be null"))
			}
			if value.False() {
				result = false
			}
		}
		return cty.BoolVal(result), nil
	},
})

// canFunc is the guard's can: the argument expression is evaluated eagerly by
// the expression evaluation, so a signature violation inside it fails closed
// — the guard proves evaluation safety, and can's error-tolerant runtime
// semantics never mask a signature defect. The standard library does not
// carry the function.
var canFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "expression", Type: cty.DynamicPseudoType, AllowDynamicType: true, AllowUnknown: true, AllowNull: true},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		if !args[0].IsKnown() {
			return cty.UnknownVal(cty.Bool), nil
		}
		return cty.BoolVal(true), nil
	},
})

// cidrHostFunc is the guard's cidrhost: the host address at the given index
// within a CIDR prefix, with a negative index counting from the end — the
// documented engine form. The standard library does not carry the function.
var cidrHostFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "prefix", Type: cty.String},
		{Name: "hostnum", Type: cty.Number},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		prefix, err := netip.ParsePrefix(args[0].AsString())
		if err != nil {
			return cty.NilVal, function.NewArgErrorf(0, "the prefix must be a valid CIDR range: %s", err)
		}
		host, accuracy := args[1].AsBigFloat().Int64()
		if accuracy != big.Exact {
			return cty.NilVal, function.NewArgErrorf(1, "the host index must be a whole number")
		}
		address, err := cidrHostAddress(prefix, host)
		if err != nil {
			return cty.NilVal, function.NewArgError(1, err)
		}
		return cty.StringVal(address), nil
	},
})

// cidrHostAddress computes the host address at the given index within the
// prefix, preserving the address family of the prefix. The big-integer
// fill form is exact by construction: the range check above bounds the index
// to the prefix's host bits, so the family-length array always carries the
// result.
func cidrHostAddress(prefix netip.Prefix, host int64) (string, error) {
	base := prefix.Masked().Addr()
	hostBits := uint(base.BitLen() - prefix.Bits())
	count := new(big.Int).Lsh(big.NewInt(1), hostBits)
	index := new(big.Int).SetInt64(host)
	if index.Sign() < 0 {
		index.Add(index, count)
	}
	if index.Sign() < 0 || index.Cmp(count) >= 0 {
		return "", fmt.Errorf("the host index %d is outside the prefix %s", host, prefix)
	}
	address := new(big.Int).Add(new(big.Int).SetBytes(base.AsSlice()), index)
	if base.Is4() {
		var raw [4]byte
		address.FillBytes(raw[:])
		return netip.AddrFrom4(raw).String(), nil
	}
	var raw [16]byte
	address.FillBytes(raw[:])
	return netip.AddrFrom16(raw).String(), nil
}

// endsWithFunc is the guard's endswith; the standard library does not carry
// the function.
var endsWithFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "string", Type: cty.String},
		{Name: "suffix", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.BoolVal(strings.HasSuffix(args[0].AsString(), args[1].AsString())), nil
	},
})

// startsWithFunc is the guard's startswith; the standard library does not
// carry the function.
var startsWithFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "string", Type: cty.String},
		{Name: "prefix", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.BoolVal(strings.HasPrefix(args[0].AsString(), args[1].AsString())), nil
	},
})

// timeCmpFunc is the guard's timecmp: the RFC 3339 timestamp comparison of
// the documented engine form. The standard library does not carry the
// function.
var timeCmpFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "timestamp_a", Type: cty.String},
		{Name: "timestamp_b", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Number),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		first, err := time.Parse(time.RFC3339, args[0].AsString())
		if err != nil {
			return cty.NilVal, function.NewArgErrorf(0, "the first timestamp must be a valid RFC 3339 timestamp: %s", err)
		}
		second, err := time.Parse(time.RFC3339, args[1].AsString())
		if err != nil {
			return cty.NilVal, function.NewArgErrorf(1, "the second timestamp must be a valid RFC 3339 timestamp: %s", err)
		}
		switch {
		case first.Before(second):
			return cty.NumberIntVal(-1), nil
		case first.After(second):
			return cty.NumberIntVal(1), nil
		default:
			return cty.NumberIntVal(0), nil
		}
	},
})
