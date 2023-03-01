package athena

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/athena"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getWorkGroups(cfFile parser.FileContext) []athena.Workgroup {

	var workgroups []athena.Workgroup

	workgroupResources := cfFile.GetResourcesByType("AWS::Athena::WorkGroup")

	for _, r := range workgroupResources {

		wg := athena.Workgroup{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("Name"),
			Encryption: athena.EncryptionConfiguration{
				Metadata: r.Metadata(),
				Type:     r.GetStringProperty("WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration.EncryptionOption"),
			},
			EnforceConfiguration: r.GetBoolProperty("WorkGroupConfiguration.EnforceWorkGroupConfiguration"),
		}

		workgroups = append(workgroups, wg)
	}

	return workgroups
}

func getWorkGroupLocation(ctx parser.FileContext) athena.WorkGroupLocation {

	var outputlocation athena.WorkGroupLocation
	GetLocationOutput := ctx.GetResourcesByType("AWS::Athena::WorkGroup")

	for _, r := range GetLocationOutput {

		var OutputLocation athena.WorkGroupLocation
		for range r.GetProperty("EncryptionConfiguration").AsString() {
			OutputLocation = athena.WorkGroupLocation{
				Metadata:       r.Metadata(),
				OutputLocation: r.GetStringProperty("KmsKey"),
			}
		}

		ol := OutputLocation
		outputlocation = ol
	}

	return outputlocation
}
