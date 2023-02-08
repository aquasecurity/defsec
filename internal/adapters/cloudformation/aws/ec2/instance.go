package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getInstances(ctx parser.FileContext) (instances []ec2.Instance) {

	instanceResources := ctx.GetResourcesByType("AWS::EC2::Instance")

	for _, r := range instanceResources {
		instance := ec2.Instance{
			Metadata: r.Metadata(),
			// metadata not supported by CloudFormation at the moment -
			// https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/655
			MetadataOptions: ec2.MetadataOptions{
				Metadata:     r.Metadata(),
				HttpTokens:   defsecTypes.StringDefault("optional", r.Metadata()),
				HttpEndpoint: defsecTypes.StringDefault("enabled", r.Metadata()),
			},
			CPUOptions: ec2.CPUOptions{
				Metadata:      r.Metadata(),
				CoreCount:     r.GetIntProperty("CpuOptions.CoreCount"),
				ThreadPerCore: r.GetIntProperty("CpuOptions.ThreadsPerCore"),
			},
			UserData:              r.GetStringProperty("UserData"),
			VPCId:                 defsecTypes.String("", r.Metadata()),
			ImageId:               r.GetStringProperty("ImageId"),
			PublicIpAddress:       r.GetStringProperty("PublicIp"),
			SubnetId:              r.GetStringProperty("SubnetId"),
			InstanceId:            defsecTypes.String("", r.Metadata()),
			InstanceType:          r.GetStringProperty("InstanceType"),
			IamInstanceProfile:    r.GetStringProperty("IamInstanceProfile"),
			InstanceLifecycle:     defsecTypes.String("", r.Metadata()),
			StateName:             defsecTypes.StringDefault("pending", r.Metadata()),
			MonitoringState:       r.GetBoolProperty("Monitoring"),
			KeyName:               r.GetStringProperty("KeyName"),
			SpotInstanceRequestId: defsecTypes.String("", r.Metadata()),
			SecurityGroupIds:      getSecurityGroupsIds(r),
			SecurityGroups:        nil,
			RootBlockDevice:       nil,
			EBSBlockDevices:       nil,
			Tags:                  nil,
			NetworkInterfaces:     getNetworkInterfaces(r),
		}
		blockDevices := getBlockDevices(r)
		for i, device := range blockDevices {
			copyDevice := device
			if i == 0 {
				instance.RootBlockDevice = copyDevice
				continue
			}
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, device)
		}
		for _, tags := range r.GetProperty("Tags").AsList() {
			instance.Tags = append(instance.Tags, ec2.Tags{
				Metadata: tags.Metadata(),
			})
		}

		instances = append(instances, instance)
	}

	return instances
}

func getBlockDevices(r *parser.Resource) []*ec2.BlockDevice {
	var blockDevices []*ec2.BlockDevice

	devicesProp := r.GetProperty("BlockDeviceMappings")

	if devicesProp.IsNil() {
		return blockDevices
	}

	for _, d := range devicesProp.AsList() {
		encrypted := d.GetProperty("Ebs.Encrypted")
		var result defsecTypes.BoolValue
		if encrypted.IsNil() {
			result = defsecTypes.BoolDefault(false, d.Metadata())
		} else {
			result = encrypted.AsBoolValue()
		}

		device := &ec2.BlockDevice{
			Metadata:  d.Metadata(),
			Encrypted: result,
			VolumeId:  defsecTypes.String("", d.Metadata()),
		}

		blockDevices = append(blockDevices, device)
	}

	return blockDevices
}

func getNetworkInterfaces(r *parser.Resource) []ec2.NetworkInterfaces {
	var networkInterfaces []ec2.NetworkInterfaces

	NIProp := r.GetProperty("NetworkInterfaces")
	if NIProp.IsNil() || NIProp.IsNotList() {
		return networkInterfaces
	}

	for _, NI := range NIProp.AsList() {
		networkInterfaces = append(networkInterfaces, ec2.NetworkInterfaces{
			Metadata: NI.Metadata(),
		})
	}
	return networkInterfaces
}

func getSecurityGroupsIds(r *parser.Resource) []defsecTypes.StringValue {
	var SGIds []defsecTypes.StringValue
	SGProp := r.GetProperty("SecurityGroupIds")
	if SGProp.IsNil() || SGProp.IsNotList() {
		return SGIds
	}

	for _, SGId := range SGProp.AsList() {
		SGIds = append(SGIds, SGId.AsStringValue())
	}
	return SGIds
}
