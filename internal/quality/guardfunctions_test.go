package quality

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// TestGuardFunctionTableSurface pins the closed-world function surface of the
// guard: exactly the documented built-in functions of the fleet's governed
// custom conditions.
func TestGuardFunctionTableSurface(t *testing.T) {
	want := []string{
		"alltrue", "can", "cidrhost", "compact", "contains", "distinct", "element",
		"endswith", "keys", "length", "regex", "setsubtract", "split", "startswith", "timecmp",
	}
	if len(guardFunctions) != len(want) {
		t.Fatalf("guard function surface = %d entries, want %d", len(guardFunctions), len(want))
	}
	for _, name := range want {
		if _, found := guardFunctions[name]; !found {
			t.Fatalf("the guard function surface misses %q", name)
		}
	}
}

func TestGuardContains(t *testing.T) {
	fn := guardFunctions["contains"]
	// The defect class: contains called on a string fails closed at type time,
	// even though the standard library's implementation-time check would never
	// be reached by an unknown value.
	if _, err := fn.Call([]cty.Value{cty.StringVal("abc"), cty.StringVal("a")}); err == nil ||
		!strings.Contains(err.Error(), "list, tuple, or set") {
		t.Fatalf("contains on a string must fail closed: %v", err)
	}
	// A tuple with divergent element types carries no element type.
	divergent := cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.ListValEmpty(cty.String)})
	if _, err := fn.Call([]cty.Value{divergent, cty.StringVal("a")}); err == nil ||
		!strings.Contains(err.Error(), "do not unify") {
		t.Fatalf("contains on a divergent tuple must fail closed: %v", err)
	}
	// A value that cannot conform to the element type fails closed.
	if _, err := fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.StringVal("a")}), cty.ListValEmpty(cty.String)}); err == nil ||
		!strings.Contains(err.Error(), "cannot conform") {
		t.Fatalf("contains with a non-conforming value must fail closed: %v", err)
	}
	// An unknown collection of a declared element type is proven by its type.
	result, err := fn.Call([]cty.Value{cty.UnknownVal(cty.List(cty.String)), cty.StringVal("a")})
	if err != nil || result.IsKnown() {
		t.Fatalf("contains on an unknown collection = %v, %v; want an unknown result without error", result, err)
	}
	// A dynamically typed collection is accepted optimistically.
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.DynamicPseudoType), cty.StringVal("a")})
	if err != nil || result.IsKnown() {
		t.Fatalf("contains on a dynamic collection = %v, %v; want an unknown result without error", result, err)
	}
	// The concrete path delegates to the verified standard library.
	result, err = fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}), cty.StringVal("a")})
	if err != nil || !result.True() {
		t.Fatalf("contains membership = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.StringVal("a")}), cty.StringVal("b")})
	if err != nil || !result.False() {
		t.Fatalf("contains non-membership = %v, %v", result, err)
	}
}

func TestGuardLength(t *testing.T) {
	fn := guardFunctions["length"]
	// The documented engine form accepts a string; the standard library's type
	// function rejects it, so the guard carries its own type surface.
	result, err := fn.Call([]cty.Value{cty.StringVal("héllo")})
	if err != nil || !result.RawEquals(cty.NumberIntVal(5)) {
		t.Fatalf("length of a string = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})})
	if err != nil || !result.RawEquals(cty.NumberIntVal(2)) {
		t.Fatalf("length of a list = %v, %v", result, err)
	}
	if _, err := fn.Call([]cty.Value{cty.NumberIntVal(1)}); err == nil ||
		!strings.Contains(err.Error(), "string or a collection") {
		t.Fatalf("length of a number must fail closed: %v", err)
	}
	// An unknown value of a declared collection type is proven by its type.
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.Map(cty.String))})
	if err != nil || result.IsKnown() {
		t.Fatalf("length of an unknown map = %v, %v; want an unknown result without error", result, err)
	}
	// A dynamically typed value is accepted optimistically.
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.DynamicPseudoType)})
	if err != nil || result.IsKnown() {
		t.Fatalf("length of a dynamic value = %v, %v; want an unknown result without error", result, err)
	}
}

func TestGuardSetSubtract(t *testing.T) {
	fn := guardFunctions["setsubtract"]
	if _, err := fn.Call([]cty.Value{cty.StringVal("a"), cty.ListValEmpty(cty.String)}); err == nil ||
		!strings.Contains(err.Error(), "sets or sequences") {
		t.Fatalf("setsubtract with a non-collection first argument must fail closed: %v", err)
	}
	if _, err := fn.Call([]cty.Value{cty.ListValEmpty(cty.String), cty.StringVal("a")}); err == nil ||
		!strings.Contains(err.Error(), "sets or sequences") {
		t.Fatalf("setsubtract with a non-collection second argument must fail closed: %v", err)
	}
	divergent := cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.ListValEmpty(cty.String)})
	if _, err := fn.Call([]cty.Value{divergent, cty.ListValEmpty(cty.String)}); err == nil ||
		!strings.Contains(err.Error(), "do not unify") {
		t.Fatalf("setsubtract with a divergent first collection must fail closed: %v", err)
	}
	// The documented engine form accepts sequences on both sides.
	result, err := fn.Call([]cty.Value{
		cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b"), cty.StringVal("c")}),
		cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("c")}),
	})
	if err != nil {
		t.Fatalf("setsubtract: %v", err)
	}
	if !result.HasElement(cty.StringVal("b")).True() || result.LengthInt() != 1 {
		t.Fatalf("setsubtract result = %v", result)
	}
	// The empty result carries the element type.
	result, err = fn.Call([]cty.Value{
		cty.ListVal([]cty.Value{cty.StringVal("a")}),
		cty.ListVal([]cty.Value{cty.StringVal("a")}),
	})
	if err != nil || result.LengthInt() != 0 {
		t.Fatalf("setsubtract empty result = %v, %v", result, err)
	}
	// A collection with unknown elements produces an unknown result.
	result, err = fn.Call([]cty.Value{
		cty.ListVal([]cty.Value{cty.UnknownVal(cty.String)}),
		cty.ListValEmpty(cty.String),
	})
	if err != nil || result.IsKnown() {
		t.Fatalf("setsubtract with unknown elements = %v, %v; want an unknown result without error", result, err)
	}
	// A dynamically typed collection is accepted optimistically.
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.DynamicPseudoType), cty.ListValEmpty(cty.String)})
	if err != nil || result.IsKnown() {
		t.Fatalf("setsubtract with a dynamic collection = %v, %v; want an unknown result without error", result, err)
	}
	// A second-collection element that cannot conform to the first
	// collection's unified element type fails closed.
	if _, err := fn.Call([]cty.Value{
		cty.TupleVal([]cty.Value{cty.NumberIntVal(1)}),
		cty.TupleVal([]cty.Value{cty.StringVal("abc")}),
	}); err == nil || !strings.Contains(err.Error(), "must conform") {
		t.Fatalf("setsubtract with a non-conforming second collection must fail closed: %v", err)
	}
}
func TestGuardAllTrue(t *testing.T) {
	fn := guardFunctions["alltrue"]
	if _, err := fn.Call([]cty.Value{cty.StringVal("a")}); err == nil ||
		!strings.Contains(err.Error(), "list, tuple, or set") {
		t.Fatalf("alltrue on a non-collection must fail closed: %v", err)
	}
	if _, err := fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.StringVal("a")})}); err == nil ||
		!strings.Contains(err.Error(), "boolean elements") {
		t.Fatalf("alltrue on non-boolean elements must fail closed: %v", err)
	}
	divergent := cty.TupleVal([]cty.Value{cty.BoolVal(true), cty.ListValEmpty(cty.String)})
	if _, err := fn.Call([]cty.Value{divergent}); err == nil || !strings.Contains(err.Error(), "do not unify") {
		t.Fatalf("alltrue on a divergent tuple must fail closed: %v", err)
	}
	result, err := fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.BoolVal(true), cty.BoolVal(true)})})
	if err != nil || !result.True() {
		t.Fatalf("alltrue all-true = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.BoolVal(true), cty.BoolVal(false)})})
	if err != nil || !result.False() {
		t.Fatalf("alltrue with a false element = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.ListValEmpty(cty.Bool)})
	if err != nil || !result.True() {
		t.Fatalf("alltrue of an empty collection = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.UnknownVal(cty.Bool)})})
	if err != nil || result.IsKnown() {
		t.Fatalf("alltrue with an unknown element = %v, %v; want an unknown result without error", result, err)
	}
	if _, err := fn.Call([]cty.Value{cty.ListVal([]cty.Value{cty.NullVal(cty.Bool)})}); err == nil ||
		!strings.Contains(err.Error(), "must not be null") {
		t.Fatalf("alltrue with a null element must fail closed: %v", err)
	}
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.List(cty.Bool))})
	if err != nil || result.IsKnown() {
		t.Fatalf("alltrue of an unknown collection = %v, %v; want an unknown result without error", result, err)
	}
}

func TestGuardCan(t *testing.T) {
	fn := guardFunctions["can"]
	result, err := fn.Call([]cty.Value{cty.StringVal("a")})
	if err != nil || !result.True() {
		t.Fatalf("can of a known value = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.String)})
	if err != nil || result.IsKnown() {
		t.Fatalf("can of an unknown value = %v, %v; want an unknown result without error", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.NullVal(cty.String)})
	if err != nil || !result.True() {
		t.Fatalf("can of a null value = %v, %v", result, err)
	}
}

func TestGuardCidrHost(t *testing.T) {
	fn := guardFunctions["cidrhost"]
	if _, err := fn.Call([]cty.Value{cty.StringVal("not-a-prefix"), cty.NumberIntVal(0)}); err == nil ||
		!strings.Contains(err.Error(), "valid CIDR") {
		t.Fatalf("cidrhost with an invalid prefix must fail closed: %v", err)
	}
	if _, err := fn.Call([]cty.Value{cty.StringVal("10.0.0.0/26"), cty.MustParseNumberVal("0.5")}); err == nil ||
		!strings.Contains(err.Error(), "whole number") {
		t.Fatalf("cidrhost with a fractional host index must fail closed: %v", err)
	}
	if _, err := fn.Call([]cty.Value{cty.StringVal("10.0.0.0/26"), cty.NumberIntVal(64)}); err == nil ||
		!strings.Contains(err.Error(), "outside the prefix") {
		t.Fatalf("cidrhost with a host index above the prefix must fail closed: %v", err)
	}
	if _, err := fn.Call([]cty.Value{cty.StringVal("10.0.0.0/26"), cty.NumberIntVal(-65)}); err == nil ||
		!strings.Contains(err.Error(), "outside the prefix") {
		t.Fatalf("cidrhost with a host index below the prefix must fail closed: %v", err)
	}
	cases := []struct {
		prefix string
		host   int64
		want   string
	}{
		{"10.0.0.0/26", 0, "10.0.0.0"},
		{"10.0.0.0/26", 1, "10.0.0.1"},
		{"10.0.0.0/26", -1, "10.0.0.63"},
		{"2001:db8::/64", 1, "2001:db8::1"},
	}
	for _, testCase := range cases {
		result, err := fn.Call([]cty.Value{cty.StringVal(testCase.prefix), cty.NumberIntVal(testCase.host)})
		if err != nil || !result.RawEquals(cty.StringVal(testCase.want)) {
			t.Fatalf("cidrhost(%s, %d) = %v, %v; want %s", testCase.prefix, testCase.host, result, err, testCase.want)
		}
	}
	result, err := fn.Call([]cty.Value{cty.UnknownVal(cty.String), cty.NumberIntVal(0)})
	if err != nil || result.IsKnown() {
		t.Fatalf("cidrhost of an unknown prefix = %v, %v; want an unknown result without error", result, err)
	}
}

func TestGuardKeys(t *testing.T) {
	fn := guardFunctions["keys"]
	// A map binds its keys as a list.
	result, err := fn.Call([]cty.Value{cty.MapVal(map[string]cty.Value{"a": cty.StringVal("1")})})
	if err != nil || !result.RawEquals(cty.ListVal([]cty.Value{cty.StringVal("a")})) {
		t.Fatalf("keys of a map = %v, %v", result, err)
	}
	// An object binds its attribute names as a tuple.
	result, err = fn.Call([]cty.Value{cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("1"), "b": cty.StringVal("2")})})
	if err != nil || !result.RawEquals(cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})) {
		t.Fatalf("keys of an object = %v, %v", result, err)
	}
	// The empty object carries no attributes.
	result, err = fn.Call([]cty.Value{cty.EmptyObjectVal})
	if err != nil || !result.RawEquals(cty.EmptyTupleVal) {
		t.Fatalf("keys of an empty object = %v, %v", result, err)
	}
	// A dynamically typed mapping is accepted optimistically.
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.DynamicPseudoType)})
	if err != nil || result.IsKnown() {
		t.Fatalf("keys of a dynamic mapping = %v, %v; want an unknown result without error", result, err)
	}
	// A non-mapping fails closed.
	if _, err := fn.Call([]cty.Value{cty.StringVal("abc")}); err == nil ||
		!strings.Contains(err.Error(), "map or an object") {
		t.Fatalf("keys of a string must fail closed: %v", err)
	}
}

func TestGuardEndsWith(t *testing.T) {
	fn := guardFunctions["endswith"]
	result, err := fn.Call([]cty.Value{cty.StringVal("example.com"), cty.StringVal(".com")})
	if err != nil || !result.True() {
		t.Fatalf("endswith match = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.StringVal("example.com"), cty.StringVal(".org")})
	if err != nil || !result.False() {
		t.Fatalf("endswith mismatch = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.String), cty.StringVal(".")})
	if err != nil || result.IsKnown() {
		t.Fatalf("endswith of an unknown string = %v, %v; want an unknown result without error", result, err)
	}
}

func TestGuardStartsWith(t *testing.T) {
	fn := guardFunctions["startswith"]
	result, err := fn.Call([]cty.Value{cty.StringVal("example.com"), cty.StringVal("example")})
	if err != nil || !result.True() {
		t.Fatalf("startswith match = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.StringVal("example.com"), cty.StringVal("www")})
	if err != nil || !result.False() {
		t.Fatalf("startswith mismatch = %v, %v", result, err)
	}
	result, err = fn.Call([]cty.Value{cty.UnknownVal(cty.String), cty.StringVal("g")})
	if err != nil || result.IsKnown() {
		t.Fatalf("startswith of an unknown string = %v, %v; want an unknown result without error", result, err)
	}
}

func TestGuardTimeCmp(t *testing.T) {
	fn := guardFunctions["timecmp"]
	if _, err := fn.Call([]cty.Value{cty.StringVal("not-a-time"), cty.StringVal("1970-01-01T00:00:00Z")}); err == nil ||
		!strings.Contains(err.Error(), "first timestamp") {
		t.Fatalf("timecmp with an invalid first timestamp must fail closed: %v", err)
	}
	if _, err := fn.Call([]cty.Value{cty.StringVal("1970-01-01T00:00:00Z"), cty.StringVal("not-a-time")}); err == nil ||
		!strings.Contains(err.Error(), "second timestamp") {
		t.Fatalf("timecmp with an invalid second timestamp must fail closed: %v", err)
	}
	cases := []struct {
		first  string
		second string
		want   int64
	}{
		{"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", -1},
		{"2027-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1},
		{"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 0},
	}
	for _, testCase := range cases {
		result, err := fn.Call([]cty.Value{cty.StringVal(testCase.first), cty.StringVal(testCase.second)})
		if err != nil || !result.RawEquals(cty.NumberIntVal(testCase.want)) {
			t.Fatalf("timecmp(%s, %s) = %v, %v; want %d", testCase.first, testCase.second, result, err, testCase.want)
		}
	}
	result, err := fn.Call([]cty.Value{cty.UnknownVal(cty.String), cty.StringVal("1970-01-01T00:00:00Z")})
	if err != nil || result.IsKnown() {
		t.Fatalf("timecmp of an unknown timestamp = %v, %v; want an unknown result without error", result, err)
	}
}

func TestGuardElementTypeOf(t *testing.T) {
	cases := []struct {
		name       string
		collection cty.Type
		want       cty.Type
		wantErr    string
	}{
		{"list", cty.List(cty.String), cty.String, ""},
		{"set", cty.Set(cty.String), cty.String, ""},
		{"map", cty.Map(cty.Number), cty.Number, ""},
		{"uniform tuple", cty.Tuple([]cty.Type{cty.String, cty.String}), cty.String, ""},
		{"divergent tuple", cty.Tuple([]cty.Type{cty.String, cty.List(cty.String)}), cty.NilType, "do not unify"},
		{"empty tuple", cty.EmptyTuple, cty.DynamicPseudoType, ""},
		{"dynamic", cty.DynamicPseudoType, cty.DynamicPseudoType, ""},
		{"non-collection", cty.Number, cty.NilType, "a list, tuple, set, or map is required"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := elementTypeOf(testCase.collection)
			if testCase.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
					t.Fatalf("elementTypeOf = %v, want an error containing %q", err, testCase.wantErr)
				}
				return
			}
			if err != nil || !got.Equals(testCase.want) {
				t.Fatalf("elementTypeOf = %v, %v; want %v", got, err, testCase.want)
			}
		})
	}
}

func TestGuardCommonType(t *testing.T) {
	got, err := commonType(nil)
	if err != nil || got != cty.DynamicPseudoType {
		t.Fatalf("commonType of an empty set = %v, %v; want the dynamic pseudo type", got, err)
	}
	got, err = commonType([]cty.Type{cty.String, cty.String})
	if err != nil || got != cty.String {
		t.Fatalf("commonType of uniform types = %v, %v", got, err)
	}
	if _, err := commonType([]cty.Type{cty.String, cty.List(cty.String)}); err == nil ||
		!strings.Contains(err.Error(), "do not unify") {
		t.Fatalf("commonType of divergent types must fail closed: %v", err)
	}
}
