package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getSubnets(ctx parser.FileContext) (subnets []ec2.Subnet) {

	subnetResources := ctx.GetResourcesByType("AWS::EC2::Subnet")
	for _, r := range subnetResources {

		subnet := ec2.Subnet{
			Metadata:            r.Metadata(),
			MapPublicIpOnLaunch: r.GetBoolProperty("MapPublicIpOnLaunch"),
			VPcId:               r.GetStringProperty("VpcId"),
			CidrBlock:           r.GetStringProperty("CidrBlock"),
			SubnetId:            r.GetStringProperty("SubnetId"),
		}

		subnets = append(subnets, subnet)
	}
	return subnets
}

func getImages(ctx parser.FileContext) (images []ec2.Image) {
	imageResource := ctx.GetResourcesByType("AWS::ImageBuilder::ContainerRecipe")

	for _, r := range imageResource {
		var ebsBD []ec2.EbsBlockDecive

		for _, BD := range r.GetProperty("BlockDeviceMappings").AsList() {
			ebsBD = append(ebsBD, ec2.EbsBlockDecive{
				Metadata:   BD.Metadata(),
				Encryption: BD.GetBoolProperty("Ebs.Encrypted"),
			})
		}
		image := ec2.Image{
			Metadata:        r.Metadata(),
			ImageId:         r.GetStringProperty("InstanceConfiguration.Image"),
			DeprecationTime: types.String("", r.Metadata()),
			EbsBlockDecive:  ebsBD,
		}
		images = append(images, image)
	}
	return images
}

func getFlowlogs(ctx parser.FileContext) (flowlogs []ec2.FlowLog) {

	flowlogResources := ctx.GetResourcesByType("AWS::EC2::FlowLog")
	for _, r := range flowlogResources {

		flowlog := ec2.FlowLog{
			Metadata:   r.Metadata(),
			Id:         types.String("", r.Metadata()),
			ResourceId: r.GetStringProperty("ResourceId"),
		}

		flowlogs = append(flowlogs, flowlog)
	}
	return flowlogs
}
