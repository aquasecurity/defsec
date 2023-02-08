package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func adaptSubnets(modules terraform.Modules) []ec2.Subnet {
	var subnets []ec2.Subnet
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_subnet") {
			subnets = append(subnets, adaptSubnet(resource, module))
		}
	}
	return subnets
}

func adaptSubnet(resource *terraform.Block, module *terraform.Module) ec2.Subnet {
	mapPublicIpOnLaunchAttr := resource.GetAttribute("map_public_ip_on_launch")
	mapPublicIpOnLaunchVal := mapPublicIpOnLaunchAttr.AsBoolValueOrDefault(false, resource)

	subnetIdAttr := resource.GetAttribute("id")
	subnetIdVal := subnetIdAttr.AsStringValueOrDefault("", resource)

	return ec2.Subnet{
		Metadata:            resource.GetMetadata(),
		MapPublicIpOnLaunch: mapPublicIpOnLaunchVal,
		SubnetId:            subnetIdVal,
		VPcId:               resource.GetAttribute("vpc_id").AsStringValueOrDefault("", resource),
		CidrBlock:           resource.GetAttribute("cidr_block").AsStringValueOrDefault("", resource),
	}
}

func adaptImages(modules terraform.Modules) []ec2.Image {
	var images []ec2.Image
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_imagebuilder_container_recipe") {
			images = append(images, adaptImage(resource))
		}
	}
	return images
}

func adaptImage(resource *terraform.Block) ec2.Image {
	var ebsblockdevice []ec2.EbsBlockDecive
	for _, r := range resource.GetBlocks("block_device_mapping") {
		ebsprop := r.GetBlock("ebs")
		encryattr := ebsprop.GetAttribute("encrypted").AsBoolValueOrDefault(false, r)
		ebsblockdevice = append(ebsblockdevice, ec2.EbsBlockDecive{
			Metadata:   r.GetMetadata(),
			Encryption: encryattr,
		})
	}

	return ec2.Image{
		Metadata:        resource.GetMetadata(),
		ImageId:         resource.GetAttribute("image").AsStringValueOrDefault("", resource),
		DeprecationTime: types.String("", resource.GetMetadata()),
		EbsBlockDecive:  ebsblockdevice,
	}
}

func adapttags(modules terraform.Modules) []ec2.ResourceTags {
	var tag []ec2.ResourceTags
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ec2_tag") {
			tag = append(tag, adapttag(resource))
		}
	}
	return tag
}

func adapttag(resource *terraform.Block) ec2.ResourceTags {

	return ec2.ResourceTags{
		Metadata:   resource.GetMetadata(),
		Resourceid: resource.GetAttribute("resource_id").AsStringValueOrDefault("", resource),
		Key:        resource.GetAttribute("key").AsStringValueOrDefault("", resource),
		Value:      resource.GetAttribute("value").AsStringValueOrDefault("", resource),
	}

}

func adaptflowlogs(modules terraform.Modules) []ec2.FlowLog {
	var flowlog []ec2.FlowLog
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_flow_log") {
			flowlog = append(flowlog, adaptflowlog(resource))
		}
	}
	return flowlog
}

func adaptflowlog(r *terraform.Block) ec2.FlowLog {
	return ec2.FlowLog{
		Metadata:   r.GetMetadata(),
		Id:         r.GetAttribute("id").AsStringValueOrDefault("", r),
		ResourceId: types.String("", r.GetMetadata()),
	}
}
