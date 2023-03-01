package athena

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/athena"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) athena.Athena {
	return athena.Athena{
		Databases:         adaptDatabases(modules),
		Workgroups:        adaptWorkgroups(modules),
		WorkGroupLocation: getOutputLocation(modules),
	}
}

func adaptDatabases(modules terraform.Modules) []athena.Database {
	var databases []athena.Database
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_athena_database") {
			databases = append(databases, adaptDatabase(resource))
		}
	}
	return databases
}

func getOutputLocation(modules terraform.Modules) (outputlocation athena.WorkGroupLocation) {
	for _, resource := range modules.GetResourcesByType("aws_athena_workgroup") {
		outputlocation = adaptOutputLocaiton(resource, modules)
	}

	return outputlocation
}

func adaptWorkgroups(modules terraform.Modules) []athena.Workgroup {
	var workgroups []athena.Workgroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_athena_workgroup") {
			workgroups = append(workgroups, adaptWorkgroup(resource))
		}
	}
	return workgroups
}

func adaptDatabase(resource *terraform.Block) athena.Database {
	database := athena.Database{
		Metadata: resource.GetMetadata(),
		Name:     resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Encryption: athena.EncryptionConfiguration{
			Metadata: resource.GetMetadata(),
			Type:     defsecTypes.StringDefault("", resource.GetMetadata()),
		},
	}
	if encryptionConfigBlock := resource.GetBlock("encryption_configuration"); encryptionConfigBlock.IsNotNil() {
		database.Encryption.Metadata = encryptionConfigBlock.GetMetadata()
		encryptionOptionAttr := encryptionConfigBlock.GetAttribute("encryption_option")
		database.Encryption.Type = encryptionOptionAttr.AsStringValueOrDefault("", encryptionConfigBlock)
	}

	return database
}

func adaptWorkgroup(resource *terraform.Block) athena.Workgroup {
	workgroup := athena.Workgroup{
		Metadata: resource.GetMetadata(),
		Name:     resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Encryption: athena.EncryptionConfiguration{
			Metadata: resource.GetMetadata(),
			Type:     defsecTypes.StringDefault("", resource.GetMetadata()),
		},
		EnforceConfiguration: defsecTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if configBlock := resource.GetBlock("configuration"); configBlock.IsNotNil() {

		enforceWGConfigAttr := configBlock.GetAttribute("enforce_workgroup_configuration")
		workgroup.EnforceConfiguration = enforceWGConfigAttr.AsBoolValueOrDefault(true, configBlock)

		if resultConfigBlock := configBlock.GetBlock("result_configuration"); configBlock.IsNotNil() {
			if encryptionConfigBlock := resultConfigBlock.GetBlock("encryption_configuration"); encryptionConfigBlock.IsNotNil() {
				encryptionOptionAttr := encryptionConfigBlock.GetAttribute("encryption_option")
				workgroup.Encryption.Metadata = encryptionConfigBlock.GetMetadata()
				workgroup.Encryption.Type = encryptionOptionAttr.AsStringValueOrDefault("", encryptionConfigBlock)
			}
		}
	}

	return workgroup
}

func adaptOutputLocaiton(resource *terraform.Block, modules terraform.Modules) athena.WorkGroupLocation {

	return athena.WorkGroupLocation{
		Metadata:       resource.GetMetadata(),
		OutputLocation: resource.GetAttribute("output_location").AsStringValueOrDefault("", resource),
	}
}
