package athena

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/athena"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getWorkGroups(cfFile parser.FileContext) []athena.Workgroup {

	var workgroups []athena.Workgroup

	workgroupResources := cfFile.GetResourcesByType("AWS::Athena::WorkGroup")

	for _, r := range workgroupResources {
		var outputlocation defsecTypes.StringValue

		for range r.GetProperty("WorkGroupConfiguration").Type() {
			for range r.GetProperty("ResultConfiguration").Type() {
				outputlocation = r.GetStringProperty("OutputLocation")
			}
		}

		wg := athena.Workgroup{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("Name"),
			Encryption: athena.EncryptionConfiguration{
				Metadata: r.Metadata(),
				Type:     r.GetStringProperty("WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration.EncryptionOption"),
			},
			EnforceConfiguration: r.GetBoolProperty("WorkGroupConfiguration.EnforceWorkGroupConfiguration"),
			OutputLocation:       outputlocation,
		}

		workgroups = append(workgroups, wg)
	}

	return workgroups
}
