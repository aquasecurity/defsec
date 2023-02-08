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

	metadata := a.CreateMetadata("launch-template/" + *template.LaunchTemplateId)

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

	var LTV []ec2.LaunchTemplateVersion
	for _, V := range output.LaunchTemplateVersions {
		var imageId string
		if V.LaunchTemplateData != nil {
			imageId = *V.LaunchTemplateData.ImageId
		}
		LTV = append(LTV, ec2.LaunchTemplateVersion{
			Metadata:      metadata,
			VersionNumber: defsecTypes.Int(int(*V.VersionNumber), metadata),
			LaunchTemplateData: ec2.LaunchTemplateData{
				Metadata: metadata,
				ImageId:  defsecTypes.String(imageId, metadata),
			},
		})
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
		Metadata:               metadata,
		Id:                     defsecTypes.String(*template.LaunchTemplateId, metadata),
		DefaultVersion:         defsecTypes.Int(int(*template.DefaultVersionNumber), metadata),
		Instance:               *instance,
		LaunchTemplateVersions: LTV,
	}, nil
}

func (a *adapter) getNetworkInterfaces() ([]ec2.NetworkInterface, error) {

	a.Tracker().SetServiceLabel("Discovering Network Interfaces...")

	input := ec2api.DescribeNetworkInterfacesInput{}

	var apiNI []types.NetworkInterface
	for {
		output, err := a.client.DescribeNetworkInterfaces(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiNI = append(apiNI, output.NetworkInterfaces...)
		a.Tracker().SetTotalResources(len(apiNI))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting network interfaces...")
	return concurrency.Adapt(apiNI, a.RootAdapter, a.adaptNetworkInterface), nil
}

func (a *adapter) adaptNetworkInterface(NI types.NetworkInterface) (*ec2.NetworkInterface, error) {

	metadata := a.CreateMetadata("network-interface/" + *NI.NetworkInterfaceId)

	return &ec2.NetworkInterface{
		Metadata: metadata,
		Id:       defsecTypes.String(*NI.NetworkInterfaceId, metadata),
		Status:   defsecTypes.String(string(NI.Status), metadata),
	}, nil
}

func (a *adapter) getccountAttributes() ([]ec2.AccountAttribute, error) {

	a.Tracker().SetServiceLabel("Discovering Account Attributes..")

	input := ec2api.DescribeAccountAttributesInput{}

	var apiAccAtt []types.AccountAttribute
	for {
		output, err := a.client.DescribeAccountAttributes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiAccAtt = append(apiAccAtt, output.AccountAttributes...)
		a.Tracker().SetTotalResources(len(apiAccAtt))
		if output.AccountAttributes == nil {
			break
		}
	}

	a.Tracker().SetServiceLabel("Adapting network interfaces...")
	return concurrency.Adapt(apiAccAtt, a.RootAdapter, a.adaptAccountAttribute), nil
}

func (a *adapter) adaptAccountAttribute(api types.AccountAttribute) (*ec2.AccountAttribute, error) {

	metadata := a.CreateMetadata("account- attribute/" + *api.AttributeName)

	var AVs []defsecTypes.StringValue
	for _, AV := range api.AttributeValues {
		AVs = append(AVs, defsecTypes.String(*AV.AttributeValue, metadata))
	}
	return &ec2.AccountAttribute{
		Metadata:        metadata,
		AttributeName:   defsecTypes.String(*api.AttributeName, metadata),
		AttributeValues: AVs,
	}, nil
}
