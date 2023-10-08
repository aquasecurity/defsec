package sources

import (
	"github.com/aquasecurity/defsec/pkg/providers/external"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/zclconf/go-cty/cty"
)

func Adapt(modules terraform.Modules) []external.Source {
	return adaptSources(modules)
}

func adaptSources(modules terraform.Modules) []external.Source {
	var sources []external.Source
	for _, module := range modules {
		for _, resource := range module.GetDatasByType("external") {
			sources = append(sources, adaptSource(resource))
		}
	}
	return sources
}

func adaptSource(resource *terraform.Block) external.Source {
	source := external.Source{
		Metadata:   resource.GetMetadata(),
		Program:    resource.GetAttribute("program").AsStringValueSliceOrEmpty(resource),
		WorkingDir: resource.GetAttribute("working_dir").AsStringValueOrDefault("", resource),
		Query:      defsecTypes.MapDefault(make(map[string]string), resource.GetMetadata()),
	}
	queryAttr := resource.GetAttribute("query")
	if queryAttr.IsNotNil() {
		query := make(map[string]string)
		_ = queryAttr.Each(func(key, val cty.Value) {
			if key.Type() == cty.String && val.Type() == cty.String {
				query[key.AsString()] = val.AsString()
			}
		})
		source.Query = defsecTypes.Map(query, queryAttr.GetMetadata())
	}
	return source
}
