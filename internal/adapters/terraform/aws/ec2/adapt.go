package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) ec2.EC2 {

	naclAdapter := naclAdapter{naclRuleIDs: modules.GetChildResourceIDMapByType("aws_network_acl_rule")}
	sgAdapter := sgAdapter{sgRuleIDs: modules.GetChildResourceIDMapByType("aws_security_group_rule")}

	return ec2.EC2{
		Instances:                  getInstances(modules),
		VPCs:                       adaptVPCs(modules),
		VpcPeeringConnections:      adaptVPCPeerConnections(modules),
		VpcEndPoints:               adaptVPCEndPoints(modules),
		VpcEndPointService:         adaptVPCEPServices(modules),
		SecurityGroups:             sgAdapter.adaptSecurityGroups(modules),
		Subnets:                    adaptSubnets(modules),
		Images:                     adaptImages(modules),
		FlowLogs:                   adaptflowlogs(modules),
		Addresses:                  adaptAddresses(modules),
		NatGateways:                adaptNatGateways(modules),
		InternetGateways:           adaptInternetGateways(modules),
		EgressOnlyInternetGateways: adaptEgressonlyIGs(modules),
		VpnGateways:                adaptVpnGatways(modules),
		VpnConnections:             adaptVpnConnections(modules),
		NetworkACLs:                naclAdapter.adaptNetworkACLs(modules),
		LaunchConfigurations:       adaptLaunchConfigurations(modules),
		LaunchTemplates:            adaptLaunchTemplates(modules),
		Volumes:                    adaptVolumes(modules),
		RouteTables:                adaptRouteTables(modules),
		Snapshots:                  adaptSnapShots(modules),
		ResourceTags:               adapttags(modules),
		AccountAttributes:          nil,
		NetworkInterfaces:          adaptNetworkInterfaces(modules),
	}
}

func getInstances(modules terraform.Modules) []ec2.Instance {
	var instances []ec2.Instance

	blocks := modules.GetResourcesByType("aws_instance")

	for _, b := range blocks {

		metadataOptions := getMetadataOptions(b)
		userData := b.GetAttribute("user_data").AsStringValueOrDefault("", b)

		var instance_id, state_name types.StringValue
		instance_status := modules.GetReferencingResources(b, "aws_ec2_instance_state", "instance_id")
		for _, r := range instance_status {
			instance_id = r.GetAttribute("instance_id").AsStringValueOrDefault("", r)
			state_name = r.GetAttribute("state").AsStringValueOrDefault("pending", r)
		}

		var SIRid types.StringValue
		instance_spot := modules.GetReferencingResources(b, "aws_spot_instance_request", "spot_instance_id")
		for _, r := range instance_spot {
			SIRid = r.GetAttribute("id").AsStringValueOrDefault("", r)
		}

		instance := ec2.Instance{
			Metadata:        b.GetMetadata(),
			MetadataOptions: metadataOptions,
			CPUOptions: ec2.CPUOptions{
				Metadata:      b.GetMetadata(),
				CoreCount:     b.GetAttribute("cpu_core_count").AsIntValueOrDefault(1, b),
				ThreadPerCore: b.GetAttribute("cpu_threads_per_core").AsIntValueOrDefault(2, b),
			},
			UserData:              userData,
			VPCId:                 types.String("", b.GetMetadata()),
			ImageId:               types.String("", b.GetMetadata()),
			PublicIpAddress:       b.GetAttribute("public_ip").AsStringValueOrDefault("", b),
			SubnetId:              b.GetAttribute("subnet_id").AsStringValueOrDefault("", b),
			InstanceId:            instance_id,
			IamInstanceProfile:    b.GetAttribute("iam_instance_profile").AsStringValueOrDefault("", b),
			InstanceType:          b.GetAttribute("instance_type").AsStringValueOrDefault("", b),
			StateName:             state_name,
			InstanceLifecycle:     types.String("", b.GetMetadata()),
			MonitoringState:       b.GetAttribute("monitoring").AsBoolValueOrDefault(false, b),
			KeyName:               b.GetAttribute("key_name").AsStringValueOrDefault("", b),
			SpotInstanceRequestId: SIRid,
			SecurityGroups:        nil,
			RootBlockDevice: &ec2.BlockDevice{
				Metadata:  b.GetMetadata(),
				Encrypted: types.BoolDefault(false, b.GetMetadata()),
			},
			EBSBlockDevices:   nil,
			NetworkInterfaces: nil,
			Tags:              nil,
		}

		SGIdAttr := b.GetAttribute("enabled_cloudwatch_logs_exports")
		for _, SGid := range SGIdAttr.AsStringValues() {
			instance.SecurityGroupIds = append(instance.SecurityGroupIds, SGid)
		}

		if rootBlockDevice := b.GetBlock("root_block_device"); rootBlockDevice.IsNotNil() {
			instance.RootBlockDevice.Metadata = rootBlockDevice.GetMetadata()
			instance.RootBlockDevice.Encrypted = rootBlockDevice.GetAttribute("encrypted").AsBoolValueOrDefault(false, b)
			instance.RootBlockDevice.VolumeId = rootBlockDevice.GetAttribute("volume_id").AsStringValueOrDefault("", b)
		}

		for _, ebsBlock := range b.GetBlocks("ebs_block_device") {
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, &ec2.BlockDevice{
				Metadata:  ebsBlock.GetMetadata(),
				Encrypted: ebsBlock.GetAttribute("encrypted").AsBoolValueOrDefault(false, b),
				VolumeId:  ebsBlock.GetAttribute("volume_id").AsStringValueOrDefault("", b),
			})
		}

		for _, NIBlock := range b.GetBlocks("network_interface") {
			instance.NetworkInterfaces = append(instance.NetworkInterfaces, ec2.NetworkInterfaces{
				Metadata: NIBlock.GetMetadata(),
			})
		}

		for _, tagBlock := range b.GetBlocks("tags") {
			instance.Tags = append(instance.Tags, ec2.Tags{
				Metadata: tagBlock.GetMetadata(),
			})
		}

		for _, resource := range modules.GetResourcesByType("aws_ebs_encryption_by_default") {
			if resource.GetAttribute("enabled").NotEqual(false) {
				instance.RootBlockDevice.Encrypted = types.BoolDefault(true, resource.GetMetadata())
				for i := 0; i < len(instance.EBSBlockDevices); i++ {
					ebs := instance.EBSBlockDevices[i]
					ebs.Encrypted = types.BoolDefault(true, resource.GetMetadata())
				}
			}
		}

		instances = append(instances, instance)
	}

	return instances
}
