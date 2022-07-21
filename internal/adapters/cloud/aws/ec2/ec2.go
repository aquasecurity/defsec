package ec2

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aws/aws-sdk-go-v2/aws"

	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/state"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type adapter struct {
	*aws2.RootAdapter
	api *ec2api.Client
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
	a.api = ec2api.NewFromConfig(root.SessionConfig())
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

	state.AWS.EC2.DefaultVPCs, err = a.getDefaultVPCs()
	if err != nil {
		return err
	}

	state.AWS.EC2.LaunchTemplates, err = a.getLaunchTemplates()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getInstances() (instances []ec2.Instance, err error) {

	a.Tracker().SetServiceLabel("Scanning instances...")

	batchInstances, token, err := a.getInstanceBatch(nil)
	if err != nil {
		return instances, err
	}

	instances = append(instances, batchInstances...)

	for token != nil {
		instances, token, err = a.getInstanceBatch(token)
		if err != nil {
			return instances, err
		}
		instances = append(instances, batchInstances...)
	}

	return instances, nil
}

func (a *adapter) getInstanceBatch(token *string) (instances []ec2.Instance, nextToken *string, err error) {

	input := &ec2api.DescribeInstancesInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	}

	if token != nil {
		input.NextToken = token
	}

	apiInstances, err := a.api.DescribeInstances(a.Context(), input)
	if err != nil {
		return instances, nextToken, err
	}

	volumeBlockMap := make(map[string]*ec2.BlockDevice)
	var volumeIds []string

	for _, reservation := range apiInstances.Reservations {
		for _, instance := range reservation.Instances {

			instanceMetadata := a.CreateMetadata(*instance.InstanceId)

			i := ec2.NewInstance(instanceMetadata)
			if instance.MetadataOptions != nil {
				i.MetadataOptions.HttpTokens = types.StringDefault(string(instance.MetadataOptions.HttpTokens), instanceMetadata)
				i.MetadataOptions.HttpEndpoint = types.StringDefault(string(instance.MetadataOptions.HttpEndpoint), instanceMetadata)
			}

			if instance.BlockDeviceMappings != nil {
				for _, blockMapping := range instance.BlockDeviceMappings {
					volumeMetadata := a.CreateMetadata(fmt.Sprintf("volume/%s", *blockMapping.Ebs.VolumeId))
					ebsDevice := &ec2.BlockDevice{
						Metadata:  volumeMetadata,
						Encrypted: types.BoolDefault(false, volumeMetadata),
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

			instances = append(instances, i)
			a.Tracker().IncrementResource()
		}
	}

	volumes, err := a.api.DescribeVolumes(a.Context(), &ec2api.DescribeVolumesInput{
		VolumeIds: volumeIds,
	})

	for _, v := range volumes.Volumes {
		block := volumeBlockMap[*v.VolumeId]
		if block != nil {
			block.Encrypted = types.Bool(*v.Encrypted, block.Metadata)
		}
	}
	return instances, apiInstances.NextToken, nil
}
