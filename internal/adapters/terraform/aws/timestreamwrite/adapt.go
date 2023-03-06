package timestreamwrite

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/timestreamwrite"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) timestreamwrite.Timestream_write {
	return timestreamwrite.Timestream_write{
		ListDatabases: adaptListDatabases(modules),
	}
}

func adaptListDatabases(modules terraform.Modules) []timestreamwrite.Databases {
	var listDatabsesInfo []timestreamwrite.Databases
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_transfer_server") {
			listDatabsesInfo = append(listDatabsesInfo, adaptListDatabase(resource))
		}
	}
	return listDatabsesInfo
}

func adaptListDatabase(resource *terraform.Block) timestreamwrite.Databases {

	databaseinfo := timestreamwrite.Databases{
		Metadata: resource.GetMetadata(),
		Arn:      resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
		KmsKeyID: resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
	}

	return databaseinfo
}
