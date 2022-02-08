package parser

import (
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/defsec/types"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

// Resource ...
type Resource struct {
	ctx     *FileContext
	rng     types.Range
	id      string
	comment string
	Inner   ResourceInner
}

// ResourceInner ...
type ResourceInner struct {
	Type       string               `json:"Type" yaml:"Type"`
	Properties map[string]*Property `json:"Properties" yaml:"Properties"`
}

// ConfigureResource ...
func (r *Resource) ConfigureResource(id, filepath string, ctx *FileContext) {

	defer func() {
		if r := recover(); r != nil {
			debug.Log("Captured an error processing %s", id)
		}
	}()

	r.setId(id)
	r.setFile(filepath)
	r.setContext(ctx)
}

func (r *Resource) setId(id string) {
	debug.Log("Updating resource id to %s", id)
	r.id = id

	for n, p := range r.properties() {
		p.setName(n)
	}

}

func (r *Resource) setFile(filepath string) {
	debug.Log("Setting the range on %s to %s", r.ID(), filepath)
	r.rng = types.NewRange(filepath, r.rng.GetStartLine(), r.rng.GetEndLine())

	for _, p := range r.Inner.Properties {
		p.setFileAndParentRange(filepath, r.rng)
	}
}

func (r *Resource) setContext(ctx *FileContext) {
	debug.Log("Updating the context for %s", r.ID())
	r.ctx = ctx

	for _, p := range r.Inner.Properties {
		p.SetLogicalResource(r.id)
		p.setContext(ctx)
	}
}

// UnmarshalYAML ...
func (r *Resource) UnmarshalYAML(value *yaml.Node) error {
	r.rng = types.NewRange("", value.Line-1, calculateEndLine(value))
	r.comment = value.LineComment
	return value.Decode(&r.Inner)
}

// UnmarshalJSONWithMetadata ...
func (r *Resource) UnmarshalJSONWithMetadata(node jfather.Node) error {
	r.rng = types.NewRange("", node.Range().Start.Line, node.Range().End.Line)
	return node.Decode(&r.Inner)
}

// ID ...
func (r *Resource) ID() string {
	return r.id
}

// Type ...
func (r *Resource) Type() string {
	return r.Inner.Type
}

// Range ...
func (r *Resource) Range() types.Range {
	return r.rng
}

// SourceFormat ...
func (r *Resource) SourceFormat() SourceFormat {
	return r.ctx.SourceFormat
}

// Metadata ...
func (r *Resource) Metadata() types.Metadata {
	return types.NewMetadata(r.Range(), NewCFReference(r.id, r.rng))
}

func (r *Resource) properties() map[string]*Property {
	return r.Inner.Properties
}

// IsNil ...
func (r *Resource) IsNil() bool {
	return r.id == ""
}

// GetProperty takes a path to the property separated by '.' and returns
// the resolved value
func (r *Resource) GetProperty(path string) *Property {

	pathParts := strings.Split(path, ".")

	first := pathParts[0]
	property := &Property{}

	for n, p := range r.properties() {
		if n == first {
			property = p
			break
		}
	}

	if len(pathParts) == 1 || property.IsNil() {
		resolved, _ := property.resolveValue()
		return resolved
	}

	if nestedProperty := property.GetProperty(strings.Join(pathParts[1:], ".")); nestedProperty != nil {
		return nestedProperty
	}

	return &Property{}
}

// GetStringProperty ...
func (r *Resource) GetStringProperty(path string, defaultValue ...string) types.StringValue {
	defVal := ""
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotString() {
		return r.StringDefault(defVal)
	}
	return prop.AsStringValue()
}

// GetBoolProperty ...
func (r *Resource) GetBoolProperty(path string, defaultValue ...bool) types.BoolValue {
	defVal := false
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotBool() {
		return r.inferBool(prop, defVal)
	}
	return prop.AsBoolValue()
}

// GetIntProperty ...
func (r *Resource) GetIntProperty(path string, defaultValue ...int) types.IntValue {
	defVal := 0
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotInt() {
		return r.IntDefault(defVal)
	}
	return prop.AsIntValue()
}

// StringDefault ...
func (r *Resource) StringDefault(defaultValue string) types.StringValue {
	return types.StringDefault(defaultValue, r.Metadata())
}

// BoolDefault ...
func (r *Resource) BoolDefault(defaultValue bool) types.BoolValue {
	return types.BoolDefault(defaultValue, r.Metadata())
}

// IntDefault ...
func (r *Resource) IntDefault(defaultValue int) types.IntValue {
	return types.IntDefault(defaultValue, r.Metadata())
}

func (r *Resource) inferBool(prop *Property, defaultValue bool) types.BoolValue {
	if prop.IsString() {
		if prop.EqualTo("true", IgnoreCase) {
			return types.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("yes", IgnoreCase) {
			return types.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("1", IgnoreCase) {
			return types.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("false", IgnoreCase) {
			return types.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("no", IgnoreCase) {
			return types.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("0", IgnoreCase) {
			return types.Bool(false, prop.Metadata())
		}
	}

	if prop.IsInt() {
		if prop.EqualTo(0) {
			return types.Bool(false, prop.Metadata())
		}
		if prop.EqualTo(1) {
			return types.Bool(true, prop.Metadata())
		}
	}

	return r.BoolDefault(defaultValue)
}
