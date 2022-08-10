package ec2

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (a *adapter) getLaunchTemplates() ([]ec2.LaunchTemplate, error) {

	a.Tracker().SetServiceLabel("Discovering launch templates...")

	input := ec2api.DescribeLaunchTemplatesInput{}

	var apiTemplates []types.LaunchTemplate
	for {
		output, err := a.client.DescribeLaunchTemplates(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiTemplates = append(apiTemplates, output.LaunchTemplates...)
		a.Tracker().SetTotalResources(len(apiTemplates))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting launch templates...")
	return concurrency.Adapt(apiTemplates, a.RootAdapter, a.adaptLaunchTemplate), nil
}

func (a *adapter) adaptLaunchTemplate(template types.LaunchTemplate) (*ec2.LaunchTemplate, error) {

	metadata := a.CreateMetadataFromARN(*template.LaunchTemplateId)

	var version string
	if template.DefaultVersionNumber != nil {
		version = fmt.Sprintf("%d", *template.DefaultVersionNumber)
	} else if template.LatestVersionNumber != nil {
		version = fmt.Sprintf("%d", *template.LatestVersionNumber)
	}

	output, err := a.client.DescribeLaunchTemplateVersions(a.Context(), &ec2api.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: template.LaunchTemplateId,
		Versions:         []string{version},
	})
	if err != nil {
		return nil, err
	}

	if len(output.LaunchTemplateVersions) == 0 {
		return nil, fmt.Errorf("launch template not found")
	}

	templateData := output.LaunchTemplateVersions[0].LaunchTemplateData

	instance := ec2.NewInstance(metadata)
	if templateData.MetadataOptions != nil {
		instance.MetadataOptions.HttpTokens = defsecTypes.StringDefault(string(templateData.MetadataOptions.HttpTokens), metadata)
		instance.MetadataOptions.HttpEndpoint = defsecTypes.StringDefault(string(templateData.MetadataOptions.HttpEndpoint), metadata)
	}

	if templateData.BlockDeviceMappings != nil {
		for _, blockMapping := range templateData.BlockDeviceMappings {
			ebsDevice := &ec2.BlockDevice{
				Metadata:  metadata,
				Encrypted: defsecTypes.BoolDefault(false, metadata),
			}
			if blockMapping.Ebs != nil && blockMapping.Ebs.Encrypted != nil {
				ebsDevice.Encrypted = defsecTypes.BoolDefault(*blockMapping.Ebs.Encrypted, metadata)
			}
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, ebsDevice)
		}
	}

	return &ec2.LaunchTemplate{
		Metadata: metadata,
		Instance: instance,
	}, nil
}
