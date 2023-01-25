package module

import (
	"github.com/aquasecurity/defsec/pkg/providers/terraform/module"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) []module.Module {
	return adaptModules(modules)
}

func adaptModules(rootmodules terraform.Modules) []module.Module {
	var modules []module.Module
	for _, module := range rootmodules {
		for _, resource := range module.GetBlocks() {
			if resource.Type() == "module" {
				modules = append(modules, adaptModule(resource))
			}
		}
	}
	return modules
}

func adaptModule(resource *terraform.Block) module.Module {
	m := module.Module{
		Metadata: resource.GetMetadata(),
		Source:   resource.GetAttribute("source").AsStringValueOrDefault("", resource),
		Version:  resource.GetAttribute("version").AsStringValueOrDefault("", resource),
	}
	return m
}
