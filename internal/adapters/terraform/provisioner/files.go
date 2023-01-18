package provisioner

import (
	"github.com/aquasecurity/defsec/pkg/providers/provisioner"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func adaptFiles(modules terraform.Modules) []provisioner.File {
	var files []provisioner.File
	for _, module := range modules {
		for _, resource := range module.GetBlocks() {
			if resource.Type() != "resource" {
				continue
			}
			for _, prov := range resource.GetBlocks("provisioner") {
				if prov.TypeLabel() == "file" {
					files = append(files, adaptFile(resource, prov))
				}
			}
		}
	}
	return files
}

func adaptFile(resource *terraform.Block, prov *terraform.Block) provisioner.File {
	file := provisioner.File{
		Metadata:    prov.GetMetadata(),
		Connection:  adaptConnection(resource, prov),
		Source:      prov.GetAttribute("source").AsStringValueOrDefault("", prov),
		Content:     prov.GetAttribute("content").AsStringValueOrDefault("", prov),
		Destination: prov.GetAttribute("destination").AsStringValueOrDefault("", prov),
	}

	return file
}
