package provisioner

import (
	"github.com/aquasecurity/defsec/pkg/providers/terraform/provisioner"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/zclconf/go-cty/cty"
)

func adaptLocalExecs(modules terraform.Modules) []provisioner.LocalExec {
	var execs []provisioner.LocalExec
	for _, module := range modules {
		for _, resource := range module.GetBlocks() {
			if resource.Type() != "resource" {
				continue
			}
			for _, provisioner := range resource.GetBlocks("provisioner") {
				if provisioner.TypeLabel() == "local-exec" {
					execs = append(execs, adaptLocalExec(provisioner))
				}
			}
		}
	}
	return execs
}

func adaptLocalExec(resource *terraform.Block) provisioner.LocalExec {
	exec := provisioner.LocalExec{
		Metadata:    resource.GetMetadata(),
		Command:     resource.GetAttribute("command").AsStringValueOrDefault("", resource),
		WorkingDir:  resource.GetAttribute("working_dir").AsStringValueOrDefault("", resource),
		Interpreter: resource.GetAttribute("interpreter").AsStringValueSliceOrEmpty(resource),
		Environment: defsecTypes.MapDefault(make(map[string]string), resource.GetMetadata()),
	}
	envAttr := resource.GetAttribute("environment")
	if envAttr.IsNotNil() {
		env := make(map[string]string)
		_ = envAttr.Each(func(key, val cty.Value) {
			if key.Type() == cty.String && val.Type() == cty.String {
				env[key.AsString()] = val.AsString()
			}
		})
		exec.Environment = defsecTypes.Map(env, envAttr.GetMetadata())
	}
	return exec
}
