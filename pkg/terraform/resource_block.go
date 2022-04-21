package terraform

import (
	"bytes"
	"fmt"
	"text/template"
)

type PlanReference struct {
	Value interface{}
}

type PlanBlock struct {
	Type       string
	Name       string
	BlockType  string
	Blocks     map[string]map[string]interface{}
	Attributes map[string]interface{}
}

func NewResourceBlock(resourceType, resourceName string) *PlanBlock {
	return &PlanBlock{
		Type:       resourceType,
		Name:       resourceName,
		BlockType:  "resource",
		Blocks:     make(map[string]map[string]interface{}),
		Attributes: make(map[string]interface{}),
	}
}

func (rb *PlanBlock) HasAttribute(attribute string) bool {
	for k := range rb.Attributes {
		if k == attribute {
			return true
		}
	}
	return false
}

func (rb *PlanBlock) ToHCL() string {

	resourceTmpl, err := template.New("resource").Funcs(template.FuncMap{
		"RenderValue":     renderTemplateValue,
		"RenderPrimitive": renderPrimitive,
	}).Parse(resourceTemplate)
	if err != nil {
		panic(err)
	}

	var res bytes.Buffer
	if err := resourceTmpl.Execute(&res, map[string]interface{}{
		"Type":       rb.Type,
		"Name":       rb.Name,
		"Attributes": rb.Attributes,
		"Blocks":     rb.Blocks,
	}); err != nil {
		return ""
	}
	return res.String()
}

var resourceTemplate = `resource "{{ .Type }}" "{{ .Name }}" {
	{{ range $name, $value := .Attributes }}{{ if $value }}{{ $name }} {{ RenderValue $value }}
	{{end}}{{ end }}
	{{  range $name, $block := .Blocks }}{{ $name }} {
	{{ range $name, $value := $block }}{{ if $value }}{{ $name }} {{ RenderValue $value }}
	{{end}}{{ end }}}
	{{end}} 
}`

func renderTemplateValue(val interface{}) string {
	switch t := val.(type) {
	case map[string]interface{}:
		return fmt.Sprintf("= %s", renderMap(t))
	case []interface{}:
		return fmt.Sprintf("%s", renderSlice(t))
	default:
		return fmt.Sprintf("= %s", renderPrimitive(val))
	}
}

func renderPrimitive(val interface{}) string {
	switch t := val.(type) {
	case PlanReference:
		return fmt.Sprintf("%v", t.Value)
	case string:
		return fmt.Sprintf(`"%s"`, t)
	case []interface{}:
		return renderSlice(t)
	default:
		return fmt.Sprintf("%#v", t)
	}

}

func renderSlice(vals []interface{}) string {
	if len(vals) == 0 {
		return "[]"
	}

	val := vals[0]

	switch t := val.(type) {
	// if vals[0] is a map[string]interface this is a block, so render it as a map
	case map[string]interface{}:
		return renderMap(t)
	// otherwise its going to be just a list of primitives
	default:
		result := " = [\n"
		for _, v := range vals {
			result = fmt.Sprintf("%s\t%v\n", result, renderPrimitive(v))
		}
		result = fmt.Sprintf("%s]", result)
		return result
	}
}

func renderMap(val map[string]interface{}) string {
	if len(val) == 0 {
		return "{}"
	}

	result := "{\n"
	for k, v := range val {
		if v == nil {
			continue
		}
		result = fmt.Sprintf("%s\t%s = %s\n", result, k, renderPrimitive(v))
	}
	result = fmt.Sprintf("%s}", result)
	return result
}
