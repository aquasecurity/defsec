package provisioner

import (
	"github.com/aquasecurity/defsec/pkg/providers/terraform/provisioner"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func adaptRemoteExecs(modules terraform.Modules) []provisioner.RemoteExec {
	var execs []provisioner.RemoteExec
	for _, module := range modules {
		for _, resource := range module.GetBlocks() {
			if resource.Type() != "resource" {
				continue
			}
			for _, prov := range resource.GetBlocks("provisioner") {
				if prov.TypeLabel() == "remote-exec" {
					execs = append(execs, adaptRemoteExec(resource, prov))
				}
			}
		}
	}
	return execs
}

func adaptRemoteExec(resource *terraform.Block, prov *terraform.Block) provisioner.RemoteExec {
	exec := provisioner.RemoteExec{
		Metadata:   prov.GetMetadata(),
		Connection: adaptConnection(resource, prov),
		Inline:     prov.GetAttribute("inline").AsStringValues(),
		Script:     prov.GetAttribute("script").AsStringValueOrDefault("", prov),
		Scripts:    prov.GetAttribute("scripts").AsStringValues(),
	}
	return exec
}
