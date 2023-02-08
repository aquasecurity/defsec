package ec2

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"

	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/state"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type adapter struct {
	*aws2.RootAdapter
	client *ec2api.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "ec2"
}

func (a *adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = ec2api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.EC2.Instances, err = a.getInstances()
	if err != nil {
		return err
	}

	state.AWS.EC2.SecurityGroups, err = a.getSecurityGroups()
	if err != nil {
		return err
	}

	state.AWS.EC2.NetworkACLs, err = a.getNetworkACLs()
	if err != nil {
		return err
	}

	state.AWS.EC2.VPCs, err = a.getVPCs()
	if err != nil {
		return err
	}

	state.AWS.EC2.VpcPeeringConnections, err = a.getVPCPeerConnection()
	if err != nil {
		return err
	}

	state.AWS.EC2.VpcEndPointService, err = a.getVPCEPServices()
	if err != nil {
		return err
	}

	state.AWS.EC2.VpcEndPoints, err = a.getVPCEndPoints()
	if err != nil {
		return err
	}

	state.AWS.EC2.Addresses, err = a.getAddresses()
	if err != nil {
		return err
	}

	state.AWS.EC2.LaunchTemplates, err = a.getLaunchTemplates()
	if err != nil {
		return err
	}

	state.AWS.EC2.Volumes, err = a.getVolumes()
	if err != nil {
		return err
	}

	state.AWS.EC2.InternetGateways, err = a.getinternetGateways()
	if err != nil {
		return err
	}
	state.AWS.EC2.EgressOnlyInternetGateways, err = a.getEgressOnlyIGs()
	if err != nil {
		return err
	}
	state.AWS.EC2.NatGateways, err = a.getNatGateways()
	if err != nil {
		return err
	}

	state.AWS.EC2.VpnGateways, err = a.getVpnGateways()
	if err != nil {
		return err
	}
	state.AWS.EC2.VpnConnections, err = a.getVpnConnections()
	if err != nil {
		return err
	}
	state.AWS.EC2.Subnets, err = a.getSubnets()
	if err != nil {
		return err
	}

	state.AWS.EC2.AccountAttributes, err = a.getccountAttributes()
	if err != nil {
		return err
	}

	state.AWS.EC2.NetworkInterfaces, err = a.getNetworkInterfaces()
	if err != nil {
		return err
	}

	state.AWS.EC2.FlowLogs, err = a.getFlowLogs()
	if err != nil {
		return err
	}

	state.AWS.EC2.Images, err = a.getImages()
	if err != nil {
		return err
	}

	state.AWS.EC2.RouteTables, err = a.getRouteTable()
	if err != nil {
		return err
	}

	state.AWS.EC2.Snapshots, err = a.getSnapshots()
	if err != nil {
		return err
	}

	state.AWS.EC2.ResourceTags, err = a.gettags()
	if err != nil {
		return err
	}

	for i, vpc := range state.AWS.EC2.VPCs {
		for _, group := range state.AWS.EC2.SecurityGroups {
			if group.VPCID.EqualTo(vpc.ID.Value()) {
				state.AWS.EC2.VPCs[i].SecurityGroups = append(state.AWS.EC2.VPCs[i].SecurityGroups, group)
			}
		}
	}

	return nil
}

func (a *adapter) getInstances() (instances []ec2.Instance, err error) {

	a.Tracker().SetServiceLabel("Discovering instances...")
	var apiInstances []ec2Types.Instance
	input := &ec2api.DescribeInstancesInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	}

	for {
		output, err := a.client.DescribeInstances(a.Context(), input)
		if err != nil {
			return nil, err
		}
		for _, res := range output.Reservations {
			apiInstances = append(apiInstances, res.Instances...)
		}

		a.Tracker().SetTotalResources(len(apiInstances))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting instances...")
	return concurrency.Adapt(apiInstances, a.RootAdapter, a.adaptInstance), nil
}

func (a *adapter) adaptInstance(instance ec2Types.Instance) (*ec2.Instance, error) {

	volumeBlockMap := make(map[string]*ec2.BlockDevice)
	var volumeIds []string
	instanceMetadata := a.CreateMetadata("instance/" + *instance.InstanceId)

	i := ec2.NewInstance(instanceMetadata)
	if instance.MetadataOptions != nil {
		i.MetadataOptions.HttpTokens = defsecTypes.StringDefault(string(instance.MetadataOptions.HttpTokens), instanceMetadata)
		i.MetadataOptions.HttpEndpoint = defsecTypes.StringDefault(string(instance.MetadataOptions.HttpEndpoint), instanceMetadata)
	}

	if instance.CpuOptions != nil {
		i.CPUOptions.CoreCount = defsecTypes.Int(int(*instance.CpuOptions.CoreCount), instanceMetadata)
		i.CPUOptions.ThreadPerCore = defsecTypes.Int(int(*instance.CpuOptions.ThreadsPerCore), instanceMetadata)
	}

	if instance.VpcId != nil {
		i.VPCId = defsecTypes.String(*instance.VpcId, instanceMetadata)
	}

	if instance.InstanceId != nil {
		i.InstanceId = defsecTypes.String(*instance.InstanceId, instanceMetadata)
	}

	if instance.ImageId != nil {
		i.ImageId = defsecTypes.String(*instance.ImageId, instanceMetadata)
	}

	if instance.PublicIpAddress != nil {
		i.PublicIpAddress = defsecTypes.String(*instance.PublicIpAddress, instanceMetadata)
	}

	if instance.SubnetId != nil {
		i.SubnetId = defsecTypes.String(*instance.SubnetId, instanceMetadata)
	}

	i.InstanceLifecycle = defsecTypes.String(string(instance.InstanceLifecycle), instanceMetadata)

	if instance.State != nil {
		i.StateName = defsecTypes.String(string(instance.State.Name), instanceMetadata)
	}

	if instance.Monitoring.State == "enabled" {
		i.MonitoringState = defsecTypes.Bool(true, instanceMetadata)
	}

	i.InstanceType = defsecTypes.String(string(instance.InstanceType), instanceMetadata)

	if instance.KeyName != nil {
		i.KeyName = defsecTypes.String(*instance.KeyName, instanceMetadata)
	}

	if instance.SpotInstanceRequestId != nil {
		i.SpotInstanceRequestId = defsecTypes.String(*instance.SpotInstanceRequestId, instanceMetadata)
	}

	if instance.IamInstanceProfile != nil {
		i.IamInstanceProfile = defsecTypes.String(*instance.IamInstanceProfile.Arn, instanceMetadata)
	}

	if instance.Tags != nil {
		for range instance.Tags {
			i.Tags = append(i.Tags, ec2.Tags{
				Metadata: instanceMetadata,
			})
		}
	}

	if instance.BlockDeviceMappings != nil {
		for _, blockMapping := range instance.BlockDeviceMappings {
			volumeMetadata := a.CreateMetadata(fmt.Sprintf("volume/%s", *blockMapping.Ebs.VolumeId))
			ebsDevice := &ec2.BlockDevice{
				Metadata:  volumeMetadata,
				Encrypted: defsecTypes.BoolDefault(false, volumeMetadata),
				VolumeId:  defsecTypes.String(*blockMapping.Ebs.VolumeId, volumeMetadata),
			}
			if strings.EqualFold(*blockMapping.DeviceName, *instance.RootDeviceName) {
				// is root block device
				i.RootBlockDevice = ebsDevice
			} else {
				i.EBSBlockDevices = append(i.EBSBlockDevices, ebsDevice)
			}
			volumeBlockMap[*blockMapping.Ebs.VolumeId] = ebsDevice
			volumeIds = append(volumeIds, *blockMapping.Ebs.VolumeId)
		}
	}

	if instance.NetworkInterfaces != nil {
		for range instance.NetworkInterfaces {
			i.NetworkInterfaces = append(i.NetworkInterfaces, ec2.NetworkInterfaces{
				Metadata: instanceMetadata,
			})
		}
	}

	if instance.SecurityGroups != nil {
		for _, SG := range instance.SecurityGroups {
			i.SecurityGroupIds = append(i.SecurityGroupIds, defsecTypes.String(*SG.GroupId, instanceMetadata))
		}
	}

	volumes, err := a.client.DescribeVolumes(a.Context(), &ec2api.DescribeVolumesInput{
		VolumeIds: volumeIds,
	})
	if err != nil {
		return nil, err
	}

	for _, v := range volumes.Volumes {
		block := volumeBlockMap[*v.VolumeId]
		if block != nil {
			block.Encrypted = defsecTypes.BoolDefault(false, block.Metadata)
			if v.Encrypted != nil {
				block.Encrypted = defsecTypes.Bool(*v.Encrypted, block.Metadata)
			}
		}
	}
	return i, nil
}
