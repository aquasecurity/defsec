package ec2

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
)

func (a *adapter) getSubnets() ([]ec2.Subnet, error) {

	a.Tracker().SetServiceLabel("Discovering subnets...")

	var input ec2api.DescribeSubnetsInput

	var apiSubnets []types.Subnet
	for {
		output, err := a.client.DescribeSubnets(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiSubnets = append(apiSubnets, output.Subnets...)
		a.Tracker().SetTotalResources(len(apiSubnets))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting subnets...")
	return concurrency.Adapt(apiSubnets, a.RootAdapter, a.adaptSubnet), nil
}

func (a *adapter) adaptSubnet(subnet types.Subnet) (*ec2.Subnet, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("subnet/%s", *subnet.SubnetId))
	var vpcid, cideBlock string
	if subnet.VpcId != nil {
		vpcid = *subnet.VpcId
	}

	if subnet.CidrBlock != nil {
		cideBlock = *subnet.CidrBlock
	}

	var mpIPOnLaunch bool
	if subnet.MapPublicIpOnLaunch != nil {
		mpIPOnLaunch = *subnet.MapPublicIpOnLaunch
	}

	return &ec2.Subnet{
		Metadata:                metadata,
		MapPublicIpOnLaunch:     defsecTypes.Bool(mpIPOnLaunch, metadata),
		SubnetId:                defsecTypes.String(*subnet.SubnetId, metadata),
		VPcId:                   defsecTypes.String(vpcid, metadata),
		CidrBlock:               defsecTypes.String(cideBlock, metadata),
		AvailableIpAddressCount: defsecTypes.Int(int(*subnet.AvailableIpAddressCount), metadata),
	}, nil
}

func (a *adapter) getImages() ([]ec2.Image, error) {

	a.Tracker().SetServiceLabel("Discovering images...")

	var input ec2api.DescribeImagesInput

	var apiImages []types.Image
	for {
		output, err := a.client.DescribeImages(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiImages = append(apiImages, output.Images...)
		a.Tracker().SetTotalResources(len(apiImages))
		if output.Images == nil {
			break
		}

	}

	a.Tracker().SetServiceLabel("Adapting image...")
	return concurrency.Adapt(apiImages, a.RootAdapter, a.adaptImage), nil
}

func (a *adapter) adaptImage(image types.Image) (*ec2.Image, error) {
	metadata := a.CreateMetadata(fmt.Sprintf("image/%s", *image.ImageId))

	var ebsBlock []ec2.EbsBlockDecive
	for _, r := range image.BlockDeviceMappings {
		ebsBlock = append(ebsBlock, ec2.EbsBlockDecive{
			Metadata:   metadata,
			Encryption: defsecTypes.Bool(*r.Ebs.Encrypted, metadata),
		})
	}
	return &ec2.Image{
		Metadata:        metadata,
		ImageId:         defsecTypes.String(*image.ImageId, metadata),
		DeprecationTime: defsecTypes.String(*image.DeprecationTime, metadata),
		Public:          defsecTypes.Bool(*image.Public, metadata),
		EbsBlockDecive:  ebsBlock,
	}, nil
}

func (a *adapter) gettags() ([]ec2.ResourceTags, error) {

	a.Tracker().SetServiceLabel("Discovering tags...")

	var input ec2api.DescribeTagsInput
	var apiTag []types.TagDescription
	for {
		output, err := a.client.DescribeTags(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiTag = append(apiTag, output.Tags...)
		a.Tracker().SetTotalResources(len(apiTag))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting subnets...")
	return concurrency.Adapt(apiTag, a.RootAdapter, a.adaptTag), nil
}

func (a *adapter) adaptTag(tag types.TagDescription) (*ec2.ResourceTags, error) {
	metadata := a.CreateMetadata(fmt.Sprintf("tag/%s", *tag.ResourceId))

	return &ec2.ResourceTags{
		Metadata:   metadata,
		Resourceid: defsecTypes.String(*tag.ResourceId, metadata),
		Key:        defsecTypes.String(*tag.Key, metadata),
		Value:      defsecTypes.String(*tag.Value, metadata),
	}, nil
}

func (a *adapter) getFlowLogs() ([]ec2.FlowLog, error) {

	a.Tracker().SetServiceLabel("Discovering flowlogs...")

	var input ec2api.DescribeFlowLogsInput

	var apiflowlog []types.FlowLog
	for {
		output, err := a.client.DescribeFlowLogs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiflowlog = append(apiflowlog, output.FlowLogs...)
		a.Tracker().SetTotalResources(len(apiflowlog))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting flowlogs...")
	return concurrency.Adapt(apiflowlog, a.RootAdapter, a.adaptflowlog), nil
}

func (a *adapter) adaptflowlog(flowlog types.FlowLog) (*ec2.FlowLog, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("tag/%s", *flowlog.FlowLogId))

	return &ec2.FlowLog{
		Metadata:   metadata,
		Id:         defsecTypes.String(*flowlog.FlowLogId, metadata),
		ResourceId: defsecTypes.String(*flowlog.ResourceId, metadata),
	}, nil
}
