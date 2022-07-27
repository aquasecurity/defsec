package ec2

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"

	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
)

type volumeDetails struct {
	encrypted bool
	size      int32
}

type instanceDetails struct {
	rootVolume *volumeDetails
	ebsVolume  []volumeDetails
}

func Test_EC2RootVolumeEncrypted(t *testing.T) {

	tests := []struct {
		name    string
		details instanceDetails
	}{
		{
			name: "simple instance with root volume encryption",
			details: instanceDetails{
				rootVolume: &volumeDetails{
					encrypted: true,
					size:      10,
				},
			},
		},
		{
			name: "simple instance with no root volume encryption",
			details: instanceDetails{
				rootVolume: &volumeDetails{
					encrypted: false,
					size:      10,
				},
			},
		},
		{
			name: "simple instance with root volume encryption and an encrypted ebs volume",
			details: instanceDetails{
				rootVolume: &volumeDetails{
					encrypted: false,
					size:      10,
				},
				ebsVolume: []volumeDetails{
					{
						encrypted: true,
						size:      10,
					},
				},
			},
		},
		{
			name: "simple instance with root volume encryption and an unencrypted ebs volume",
			details: instanceDetails{
				rootVolume: &volumeDetails{
					encrypted: false,
					size:      10,
				},
				ebsVolume: []volumeDetails{
					{
						encrypted: false,
						size:      10,
					},
				},
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instanceID := bootstrapEC2Instance(t, ra, tt.details)

			testState := &state.State{}
			ec2Adapter := &adapter{}
			err = ec2Adapter.Adapt(ra, testState)
			require.NoError(t, err)

			assert.Len(t, testState.AWS.EC2.Instances, 1)
			got := testState.AWS.EC2.Instances[0]

			if tt.details.rootVolume != nil {
				require.NotNil(t, got.RootBlockDevice)
				assert.Equal(t, tt.details.rootVolume.encrypted, got.RootBlockDevice.Encrypted.Value())
			} else {
				require.Nil(t, got.RootBlockDevice)
			}

			if len(tt.details.ebsVolume) > 0 {
				require.Len(t, got.EBSBlockDevices, len(tt.details.ebsVolume))
				assert.Equal(t, tt.details.ebsVolume[0].encrypted, got.EBSBlockDevices[0].Encrypted.Value())
			} else {
				require.Len(t, got.EBSBlockDevices, 0)
			}
			removeInstance(t, ra, instanceID)
		})
	}
}

func bootstrapEC2Instance(t *testing.T, ra *aws2.RootAdapter, spec instanceDetails) *string {

	api := ec2api.NewFromConfig(ra.SessionConfig())

	var blockMappings []ec2Types.BlockDeviceMapping

	if spec.rootVolume != nil {
		blockMappings = bootstrapVolume(blockMappings, "/dev/sda1", *spec.rootVolume)
	}

	for _, ebs := range spec.ebsVolume {
		blockMappings = bootstrapVolume(blockMappings, "/dev/xvd", ebs)
	}

	instanceResp, err := api.RunInstances(ra.Context(), &ec2api.RunInstancesInput{
		ImageId:             aws.String("ami-0b9c9f62b6a9b7c7a"),
		MinCount:            aws.Int32(1),
		MaxCount:            aws.Int32(1),
		BlockDeviceMappings: blockMappings,
	})
	require.NoError(t, err)

	return instanceResp.Instances[0].InstanceId
}

func bootstrapVolume(blockMappings []ec2Types.BlockDeviceMapping, deviceName string, volume volumeDetails) []ec2Types.BlockDeviceMapping {
	blockMappings = append(blockMappings, ec2Types.BlockDeviceMapping{
		DeviceName: aws.String(deviceName),
		Ebs: &ec2Types.EbsBlockDevice{
			Encrypted:           aws.Bool(volume.encrypted),
			VolumeSize:          aws.Int32(volume.size),
			DeleteOnTermination: aws.Bool(true),
		},
	})
	return blockMappings
}

func removeInstance(t *testing.T, ra *aws2.RootAdapter, instanceID *string) {

	api := ec2api.NewFromConfig(ra.SessionConfig())

	_, err := api.TerminateInstances(ra.Context(), &ec2api.TerminateInstancesInput{
		InstanceIds: []string{*instanceID},
	})
	require.NoError(t, err)
}
