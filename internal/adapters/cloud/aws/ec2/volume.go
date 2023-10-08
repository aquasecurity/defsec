package ec2

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
)

func (a *adapter) getVolumes() ([]ec2.Volume, error) {

	a.Tracker().SetServiceLabel("Discovering volumes...")

	var input ec2api.DescribeVolumesInput

	var apiVolumes []types.Volume
	for {
		output, err := a.client.DescribeVolumes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiVolumes = append(apiVolumes, output.Volumes...)
		a.Tracker().SetTotalResources(len(apiVolumes))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting volumes...")
	return concurrency.Adapt(apiVolumes, a.RootAdapter, a.adaptVolume), nil
}

func (a *adapter) adaptVolume(volume types.Volume) (*ec2.Volume, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("volume/%s", *volume.VolumeId))

	encrypted := volume.Encrypted != nil && *volume.Encrypted
	var kmsKeyId, volumeId string
	if volume.KmsKeyId != nil {
		kmsKeyId = *volume.KmsKeyId
	}
	if volume.VolumeId != nil {
		volumeId = *volume.VolumeId
	}

	var attachments []ec2.Attachment
	for _, attachment := range volume.Attachments {
		var instanceId string
		if attachment.InstanceId != nil {
			instanceId = *attachment.InstanceId
		}
		attachments = append(attachments, ec2.Attachment{
			Metadata:   metadata,
			InstanceId: defsecTypes.String(instanceId, metadata),
		})
	}

	ebsEncryptionbydefault, err := a.client.GetEbsEncryptionByDefault(a.Context(), &ec2api.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return nil, err
	}

	ebsDefaultkmskeyid, err := a.client.GetEbsDefaultKmsKeyId(a.Context(), &ec2api.GetEbsDefaultKmsKeyIdInput{})
	if err != nil {
		return nil, err
	}

	var tags []ec2.Tags
	for range volume.Tags {
		tags = append(tags, ec2.Tags{
			Metadata: metadata,
		})
	}

	return &ec2.Volume{
		Metadata:    metadata,
		VolumeId:    defsecTypes.String(volumeId, metadata),
		Attachments: attachments,
		Encryption: ec2.Encryption{
			Metadata: metadata,
			Enabled:  defsecTypes.Bool(encrypted, metadata),
			KMSKeyID: defsecTypes.String(kmsKeyId, metadata),
		},
		EbsEncryptionByDefault: defsecTypes.Bool(*ebsEncryptionbydefault.EbsEncryptionByDefault, metadata),
		EbsDefaultKmsKeyId:     defsecTypes.String(*ebsDefaultkmskeyid.KmsKeyId, metadata),
		Tags:                   tags,
	}, nil
}

func (a *adapter) getSnapshots() ([]ec2.Snapshot, error) {

	a.Tracker().SetServiceLabel("Discovering snapshots...")

	var input ec2api.DescribeSnapshotsInput

	var apiSnapshot []types.Snapshot
	for {
		output, err := a.client.DescribeSnapshots(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiSnapshot = append(apiSnapshot, output.Snapshots...)
		a.Tracker().SetTotalResources(len(apiSnapshot))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting snapshot...")
	return concurrency.Adapt(apiSnapshot, a.RootAdapter, a.adaptSnapshot), nil
}

func (a *adapter) adaptSnapshot(snapshot types.Snapshot) (*ec2.Snapshot, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("snapshot/%s", *snapshot.SnapshotId))

	var volumeId, ownerid string
	if snapshot.OwnerId != nil {
		ownerid = *snapshot.OwnerId
	}
	if snapshot.VolumeId != nil {
		volumeId = *snapshot.SnapshotId
	}

	var tags []ec2.Tags
	for range snapshot.Tags {
		tags = append(tags, ec2.Tags{
			Metadata: metadata,
		})
	}

	var CVP []ec2.CreateVolumePermission
	snapshotAttribute, err := a.client.DescribeSnapshotAttribute(a.Context(), &ec2api.DescribeSnapshotAttributeInput{
		SnapshotId: snapshot.SnapshotId,
	})
	if err != nil {
		return nil, err
	}

	for range snapshotAttribute.CreateVolumePermissions {
		CVP = append(CVP, ec2.CreateVolumePermission{
			Metadata: metadata,
		})
	}

	return &ec2.Snapshot{
		Metadata:                metadata,
		SnapshotId:              defsecTypes.String(*snapshot.SnapshotId, metadata),
		Ownerid:                 defsecTypes.String(ownerid, metadata),
		VolumeId:                defsecTypes.String(volumeId, metadata),
		Encrypted:               defsecTypes.Bool(*snapshot.Encrypted, metadata),
		Tags:                    tags,
		CreateVolumePermissions: CVP,
	}, nil
}
