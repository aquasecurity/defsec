package parser

import (
	"io/fs"
	"strings"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Resource struct {
	ctx     *FileContext
	rng     types2.Range
	id      string
	comment string
	Inner   ResourceInner
}

type ResourceInner struct {
	Type       string               `json:"Type" yaml:"Type"`
	Properties map[string]*Property `json:"Properties" yaml:"Properties"`
}

func (r *Resource) ConfigureResource(id string, target fs.FS, filepath string, ctx *FileContext) {
	r.setId(id)
	r.setFile(target, filepath)
	r.setContext(ctx)
}

func (r *Resource) setId(id string) {
	r.id = id

	for n, p := range r.properties() {
		p.setName(n)
	}
}

func (r *Resource) setFile(target fs.FS, filepath string) {
	r.rng = types2.NewRange(filepath, r.rng.GetStartLine(), r.rng.GetEndLine(), r.rng.GetSourcePrefix(), target)

	for _, p := range r.Inner.Properties {
		p.setFileAndParentRange(target, filepath, r.rng)
	}
}

func (r *Resource) setContext(ctx *FileContext) {
	r.ctx = ctx

	for _, p := range r.Inner.Properties {
		p.SetLogicalResource(r.id)
		p.setContext(ctx)
	}
}

func (r *Resource) UnmarshalYAML(value *yaml.Node) error {
	r.rng = types2.NewRange("", value.Line-1, calculateEndLine(value), "", nil)
	r.comment = value.LineComment
	return value.Decode(&r.Inner)
}

func (r *Resource) UnmarshalJSONWithMetadata(node jfather.Node) error {
	r.rng = types2.NewRange("", node.Range().Start.Line, node.Range().End.Line, "", nil)
	return node.Decode(&r.Inner)
}

func (r *Resource) ID() string {
	return r.id
}

func (r *Resource) Type() string {
	return r.Inner.Type
}

func (r *Resource) Range() types2.Range {
	return r.rng
}

func (r *Resource) SourceFormat() SourceFormat {
	return r.ctx.SourceFormat
}

func (r *Resource) Metadata() types2.Metadata {
	return types2.NewMetadata(r.Range(), NewCFReference(r.id, r.rng))
}

func (r *Resource) properties() map[string]*Property {
	return r.Inner.Properties
}

func (r *Resource) IsNil() bool {
	return r.id == ""
}

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
		if property.isFunction() {
			resolved, _ := property.resolveValue()
			return resolved
		}
		return property
	}

	if nestedProperty := property.GetProperty(strings.Join(pathParts[1:], ".")); nestedProperty != nil {
		return nestedProperty
	}

	return &Property{}
}

func (r *Resource) GetStringProperty(path string, defaultValue ...string) types2.StringValue {
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

func (r *Resource) GetBoolProperty(path string, defaultValue ...bool) types2.BoolValue {
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

func (r *Resource) GetIntProperty(path string, defaultValue ...int) types2.IntValue {
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

func (r *Resource) StringDefault(defaultValue string) types2.StringValue {
	return types2.StringDefault(defaultValue, r.Metadata())
}

func (r *Resource) BoolDefault(defaultValue bool) types2.BoolValue {
	return types2.BoolDefault(defaultValue, r.Metadata())
}

func (r *Resource) IntDefault(defaultValue int) types2.IntValue {
	return types2.IntDefault(defaultValue, r.Metadata())
}

func (r *Resource) inferBool(prop *Property, defaultValue bool) types2.BoolValue {
	if prop.IsString() {
		if prop.EqualTo("true", IgnoreCase) {
			return types2.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("yes", IgnoreCase) {
			return types2.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("1", IgnoreCase) {
			return types2.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("false", IgnoreCase) {
			return types2.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("no", IgnoreCase) {
			return types2.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("0", IgnoreCase) {
			return types2.Bool(false, prop.Metadata())
		}
	}

	if prop.IsInt() {
		if prop.EqualTo(0) {
			return types2.Bool(false, prop.Metadata())
		}
		if prop.EqualTo(1) {
			return types2.Bool(true, prop.Metadata())
		}
	}

	return r.BoolDefault(defaultValue)
}
